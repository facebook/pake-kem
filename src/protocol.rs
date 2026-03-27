// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

//! The protocol implementation

use crate::errors::PakeKemError;
use crate::messages::{MessageOne, MessageThree, MessageTwo};
use crate::pake::CPaceRistretto255;
use crate::pake::Pake;
use crate::{Encoded, EncodedSizeUser};
use core::ops::{Add, Sub};
use hkdf::hmac::digest::array::typenum::U32;
use hkdf::hmac::digest::array::Array;
use hkdf::hmac::digest::block_api::BlockSizeUser;
use hkdf::hmac::digest::typenum::Sum;
use hkdf::hmac::digest::FixedOutput;
use hkdf::hmac::digest::OutputSizeUser;
use hkdf::hmac::{EagerHash, Hmac, KeyInit, Mac};
use hkdf::HkdfExtract;
use ml_kem::array::ArraySize;
use ml_kem::kem::KeySizeUser;
use ml_kem::kem::TryDecapsulate;
use ml_kem::{Encapsulate, Kem, KeyExport, TryKeyInit};
use rand_core::CryptoRng;

type Result<T> = core::result::Result<T, PakeKemError>;

/// Configures the primitives used in pake-kem:
/// * Pake: a (classically-secure) two-message PAKE protocol,
/// * Kem: a (quantum-resistant) key encapsulation mechanism, and
/// * Hash: a cryptographic hashing function.
pub trait CipherSuite {
    /// The PAKE protocol to use
    type Pake: Pake;
    /// The key encapsulation mechanism to use
    type Kem: Kem;
    /// The hashing function to use
    type Hash: EagerHash + FixedOutput;
}

/// The default [`CipherSuite`] for pake-kem, based on `CPaceRistretto255`, `MlKem768`, and `Sha256`
#[derive(Debug)]
pub struct DefaultCipherSuite;
impl CipherSuite for DefaultCipherSuite {
    type Pake = CPaceRistretto255;
    type Kem = ml_kem::MlKem768;
    type Hash = sha2::Sha256;
}

/// The input to the pake-kem protocol
pub struct Input {
    pub(crate) password: Vec<u8>,
    pub(crate) initiator_id: Vec<u8>,
    pub(crate) responder_id: Vec<u8>,
}

impl Input {
    /// Create a new [`Input`] object
    pub fn new(password: &[u8], initiator_id: &[u8], responder_id: &[u8]) -> Self {
        Self {
            password: password.to_vec(),
            initiator_id: initiator_id.to_vec(),
            responder_id: responder_id.to_vec(),
        }
    }
}

/// The output of the pake-kem protocol
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Output<CS: CipherSuite>(
    pub Array<u8, <<CS::Hash as EagerHash>::Core as OutputSizeUser>::OutputSize>,
);

/// The main struct for the initiator of the pake-kem protocol
#[derive(Debug)]
pub struct Initiator<CS: CipherSuite>(CS::Pake);

impl<CS: CipherSuite> Initiator<CS>
where
    <<CS::Pake as Pake>::Output as EncodedSizeUser>::EncodedSize:
        Sub<<<CS::Hash as EagerHash>::Core as BlockSizeUser>::BlockSize, Output = U32>,
{
    /// The first step of pake-kem, where the initiator starts the protocol
    pub fn start<R: CryptoRng>(input: &Input, rng: &mut R) -> Result<(Self, MessageOne<CS>)> {
        let (init_message, state) = CS::Pake::init(input, rng);

        Ok((Self(state), MessageOne { init_message }))
    }

    /// The third step of pake-kem, where the initiator finishes its role in the protocol, with
    /// input from the second message created by the responder
    pub fn finish<R: CryptoRng>(
        self,
        message_two: &MessageTwo<CS>,
        rng: &mut R,
    ) -> Result<(Output<CS>, MessageThree<CS>)> {
        let (mac_key, session_key) = match self.0.recv(&message_two.respond_message) {
            Some(pake_output) => pake_output_into_keys::<CS>(pake_output.as_bytes()),
            None => return Err(PakeKemError::InvalidPakeOutput),
        };

        // First, check the mac on ek
        let mut mac_verifier = Hmac::<CS::Hash>::new(&mac_key);
        mac_verifier.update(&message_two.ek.to_bytes());
        mac_verifier.verify_slice(&message_two.ek_tag)?;

        // Encapsulate a shared key to the holder of the decapsulation key, receive the shared
        // secret `k_send` and the encapsulated form `ct`.
        let (ct, k_send) = message_two.ek.encapsulate_with_rng(rng);

        // Next, construct another mac
        let mut mac_builder = Hmac::<CS::Hash>::new(&mac_key);
        mac_builder.update(&message_two.ek.to_bytes());
        mac_builder.update(ct.as_slice());
        let mac = mac_builder.finalize().into_bytes();

        let mut hkdf = HkdfExtract::<CS::Hash>::new(None);
        hkdf.input_ikm(&message_two.ek.to_bytes());
        hkdf.input_ikm(ct.as_slice());
        hkdf.input_ikm(&mac_key);
        hkdf.input_ikm(&session_key);
        hkdf.input_ikm(k_send.as_slice());
        let (res, _) = hkdf.finalize();

        Ok((Output(res), MessageThree { ct, ct_tag: mac }))
    }
}

/// The main struct for the responder of the pake-kem protocol
pub struct Responder<CS: CipherSuite> {
    pake_output: <CS::Pake as Pake>::Output,
    dk: <CS::Kem as Kem>::DecapsulationKey,
    ek: <CS::Kem as Kem>::EncapsulationKey,
}

impl<CS: CipherSuite> core::fmt::Debug for Responder<CS> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Responder")
            .field("pake_output", &self.pake_output)
            .finish_non_exhaustive()
    }
}

impl<CS: CipherSuite> Responder<CS>
where
    <<CS::Pake as Pake>::Output as EncodedSizeUser>::EncodedSize:
        Sub<<<CS::Hash as EagerHash>::Core as BlockSizeUser>::BlockSize, Output = U32>,
{
    /// The second step of pake-kem, where the responder starts its role in the protocol
    /// with input from the first message created by the initiator
    pub fn start<R: CryptoRng>(
        input: &Input,
        message_one: &MessageOne<CS>,
        rng: &mut R,
    ) -> Result<(Self, MessageTwo<CS>)> {
        let (wrapped_pake_output, respond_message) =
            CS::Pake::respond(input, &message_one.init_message, rng);
        let pake_output = match wrapped_pake_output {
            Some(pake_output) => pake_output,
            None => return Err(PakeKemError::InvalidPakeOutput),
        };
        let (mac_key, _) = pake_output_into_keys::<CS>(pake_output.as_bytes());

        let (decapsulation_key, encapsulation_key) = CS::Kem::generate_keypair_from_rng(rng);

        let ek_bytes = encapsulation_key.to_bytes();
        let ek_cloned = <CS::Kem as Kem>::EncapsulationKey::new(&ek_bytes)
            .map_err(|_| PakeKemError::Deserialization)?;

        let mut mac_builder = Hmac::<CS::Hash>::new(&mac_key);
        mac_builder.update(&ek_bytes);
        let mac = mac_builder.finalize().into_bytes();

        Ok((
            Self {
                pake_output,
                dk: decapsulation_key,
                ek: ek_cloned,
            },
            MessageTwo {
                respond_message,
                ek: encapsulation_key,
                ek_tag: mac,
            },
        ))
    }

    /// The fourth step of pake-kem, where the responder finishes its role in the protocol, with
    /// input from the third message created by the initiator
    pub fn finish(self, message_three: &MessageThree<CS>) -> Result<Output<CS>> {
        let (mac_key, session_key) = pake_output_into_keys::<CS>(self.pake_output.as_bytes());

        let mut mac_verifier = Hmac::<CS::Hash>::new(&mac_key);
        mac_verifier.update(&self.ek.to_bytes());
        mac_verifier.update(message_three.ct.as_slice());
        mac_verifier.verify_slice(&message_three.ct_tag)?;

        let k_recv = self
            .dk
            .try_decapsulate(&message_three.ct)
            .map_err(|_| PakeKemError::Deserialization)?;

        let mut hkdf = HkdfExtract::<CS::Hash>::new(None);
        hkdf.input_ikm(&self.ek.to_bytes());
        hkdf.input_ikm(message_three.ct.as_slice());
        hkdf.input_ikm(&mac_key);
        hkdf.input_ikm(&session_key);
        hkdf.input_ikm(k_recv.as_slice());
        let (res, _) = hkdf.finalize();

        Ok(Output(res))
    }
}

#[allow(clippy::type_complexity)]
fn pake_output_into_keys<CS: CipherSuite>(
    pake_output: Encoded<<CS::Pake as Pake>::Output>,
) -> (
    Array<u8, <<CS::Hash as EagerHash>::Core as BlockSizeUser>::BlockSize>,
    Array<u8, U32>,
)
where
    <<CS::Pake as Pake>::Output as EncodedSizeUser>::EncodedSize:
        Sub<<<CS::Hash as EagerHash>::Core as BlockSizeUser>::BlockSize, Output = U32>,
{
    pake_output.split()
}

impl<CS: CipherSuite> EncodedSizeUser for Initiator<CS> {
    type EncodedSize = <CS::Pake as EncodedSizeUser>::EncodedSize;

    fn from_bytes(enc: &Encoded<Self>) -> core::result::Result<Self, PakeKemError> {
        Ok(Self(CS::Pake::from_bytes(enc)?))
    }

    fn as_bytes(&self) -> Encoded<Self> {
        self.0.as_bytes()
    }
}

impl<CS: CipherSuite> EncodedSizeUser for Responder<CS>
where
    CS::Kem: ml_kem::kem::FromSeed,
    <CS::Kem as Kem>::DecapsulationKey: KeyExport + KeyInit,
    <CS::Kem as Kem>::EncapsulationKey: KeyExport + TryKeyInit,
    // Concatenation clauses
    <<CS::Kem as Kem>::DecapsulationKey as KeySizeUser>::KeySize:
        Add<<<CS::Kem as Kem>::EncapsulationKey as KeySizeUser>::KeySize>,
    Sum<
        <<CS::Kem as Kem>::DecapsulationKey as KeySizeUser>::KeySize,
        <<CS::Kem as Kem>::EncapsulationKey as KeySizeUser>::KeySize,
    >: ArraySize
        + Add<<<CS::Pake as Pake>::Output as EncodedSizeUser>::EncodedSize>
        + Sub<
            <<CS::Kem as Kem>::DecapsulationKey as KeySizeUser>::KeySize,
            Output = <<CS::Kem as Kem>::EncapsulationKey as KeySizeUser>::KeySize,
        >,
    Sum<
        Sum<
            <<CS::Kem as Kem>::DecapsulationKey as KeySizeUser>::KeySize,
            <<CS::Kem as Kem>::EncapsulationKey as KeySizeUser>::KeySize,
        >,
        <<CS::Pake as Pake>::Output as EncodedSizeUser>::EncodedSize,
    >: ArraySize
        + Sub<
            Sum<
                <<CS::Kem as Kem>::DecapsulationKey as KeySizeUser>::KeySize,
                <<CS::Kem as Kem>::EncapsulationKey as KeySizeUser>::KeySize,
            >,
            Output = <<CS::Pake as Pake>::Output as EncodedSizeUser>::EncodedSize,
        >,
{
    type EncodedSize = Sum<
        Sum<
            <<CS::Kem as Kem>::DecapsulationKey as KeySizeUser>::KeySize,
            <<CS::Kem as Kem>::EncapsulationKey as KeySizeUser>::KeySize,
        >,
        <<CS::Pake as Pake>::Output as EncodedSizeUser>::EncodedSize,
    >;

    fn from_bytes(enc: &Encoded<Self>) -> core::result::Result<Self, PakeKemError> {
        let (enc, pake_output) = enc.split_ref();
        let (dk_bytes, ek_bytes) = enc.split_ref();

        Ok(Self {
            pake_output: <CS::Pake as Pake>::Output::from_bytes(pake_output)?,
            dk: <<CS::Kem as Kem>::DecapsulationKey as KeyInit>::new(dk_bytes),
            ek: <<CS::Kem as Kem>::EncapsulationKey as TryKeyInit>::new(ek_bytes)
                .map_err(|_| PakeKemError::Deserialization)?,
        })
    }

    fn as_bytes(&self) -> Encoded<Self> {
        KeyExport::to_bytes(&self.dk)
            .concat(KeyExport::to_bytes(&self.ek))
            .concat(self.pake_output.as_bytes())
    }
}
