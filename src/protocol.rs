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
use core::ops::{Add, Sub};
use hkdf::hmac::digest::array::typenum::U32;
use hkdf::hmac::digest::array::Array;
use hkdf::hmac::digest::core_api::BlockSizeUser;
use hkdf::hmac::digest::typenum::Sum;
use hkdf::hmac::digest::FixedOutput;
use hkdf::hmac::digest::OutputSizeUser;
use hkdf::hmac::{EagerHash, Hmac, KeyInit, Mac};
use hkdf::HkdfExtract;
use kem::{Decapsulate, Encapsulate};
use ml_kem::ArraySize;
use ml_kem::Encoded;
use ml_kem::EncodedSizeUser;
use ml_kem::KemCore;
use rand_core::{CryptoRng, RngCore};

type Result<T> = core::result::Result<T, PakeKemError>;

/// Configures the primitives used in pake-kem:
/// * Pake: a (classically-secure) two-message PAKE protocol,
/// * Kem: a (quantum-resistant) key encapsulation mechanism, and
/// * Hash: a cryptographic hashing function.
pub trait CipherSuite {
    /// The PAKE protocol to use
    type Pake: Pake;
    /// The key encapsulation mechanism to use
    type Kem: KemCore;
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
pub struct Output<CS: CipherSuite>(pub Array<u8, <CS::Hash as OutputSizeUser>::OutputSize>);

/// The main struct for the initiator of the pake-kem protocol
#[derive(Debug)]
pub struct Initiator<CS: CipherSuite>(CS::Pake);

impl<CS: CipherSuite> Initiator<CS>
where
    <<CS::Pake as Pake>::Output as EncodedSizeUser>::EncodedSize:
        Sub<<<CS::Hash as EagerHash>::Core as BlockSizeUser>::BlockSize, Output = U32>,
{
    /// The first step of pake-kem, where the initiator starts the protocol
    pub fn start<R: RngCore + CryptoRng>(
        input: &Input,
        rng: &mut R,
    ) -> Result<(Self, MessageOne<CS>)> {
        let (init_message, state) = CS::Pake::init(input, rng);

        Ok((Self(state), MessageOne { init_message }))
    }

    /// The third step of pake-kem, where the initiator finishes its role in the protocol, with
    /// input from the second message created by the responder
    pub fn finish<R: RngCore + CryptoRng>(
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
        mac_verifier.update(&message_two.ek.as_bytes());
        mac_verifier.verify_slice(&message_two.ek_tag)?;

        // Encapsulate a shared key to the holder of the decapsulation key, receive the shared
        // secret `k_send` and the encapsulated form `ct`.
        let (ct, k_send) = message_two
            .ek
            .encapsulate(rng)
            .map_err(|_| PakeKemError::Deserialization)?;

        // Next, construct another mac
        let mut mac_builder = Hmac::<CS::Hash>::new(&mac_key);
        mac_builder.update(&message_two.ek.as_bytes());
        mac_builder.update(ct.as_slice());
        mac_builder.update(k_send.as_slice());
        let mac = mac_builder.finalize().into_bytes();

        let mut hkdf = HkdfExtract::<CS::Hash>::new(None);
        hkdf.input_ikm(&message_two.ek.as_bytes());
        hkdf.input_ikm(ct.as_slice());
        hkdf.input_ikm(&mac_key);
        hkdf.input_ikm(&session_key);
        hkdf.input_ikm(k_send.as_slice());
        let (res, _) = hkdf.finalize();

        Ok((Output(res), MessageThree { ct, ct_tag: mac }))
    }
}

/// The main struct for the responder of the pake-kem protocol
#[derive(Debug)]
pub struct Responder<CS: CipherSuite> {
    pake_output: <CS::Pake as Pake>::Output,
    dk: <CS::Kem as KemCore>::DecapsulationKey,
    ek: <CS::Kem as KemCore>::EncapsulationKey,
}

impl<CS: CipherSuite> Responder<CS>
where
    <<CS::Pake as Pake>::Output as EncodedSizeUser>::EncodedSize:
        Sub<<<CS::Hash as EagerHash>::Core as BlockSizeUser>::BlockSize, Output = U32>,
{
    /// The second step of pake-kem, where the responder starts its role in the protocol
    /// with input from the first message created by the initiator
    pub fn start<R: RngCore + CryptoRng>(
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

        let (decapsulation_key, encapsulation_key) = CS::Kem::generate(rng);

        let ek_bytes = encapsulation_key.as_bytes();
        let ek_cloned = <CS::Kem as KemCore>::EncapsulationKey::from_bytes(&ek_bytes);

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
        let k_recv = self
            .dk
            .decapsulate(&message_three.ct)
            .map_err(|_| PakeKemError::Deserialization)?;

        let mut mac_verifier = Hmac::<CS::Hash>::new(&mac_key);
        mac_verifier.update(&self.ek.as_bytes());
        mac_verifier.update(message_three.ct.as_slice());
        mac_verifier.update(k_recv.as_slice());
        mac_verifier.verify_slice(&message_three.ct_tag)?;

        let mut hkdf = HkdfExtract::<CS::Hash>::new(None);
        hkdf.input_ikm(&self.ek.as_bytes());
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

    fn from_bytes(enc: &Encoded<Self>) -> Self {
        Self(CS::Pake::from_bytes(enc))
    }

    fn as_bytes(&self) -> Encoded<Self> {
        self.0.as_bytes()
    }
}

impl<CS: CipherSuite> EncodedSizeUser for Responder<CS>
where
    // Concatenation clauses
    <<CS::Kem as KemCore>::DecapsulationKey as EncodedSizeUser>::EncodedSize:
        Add<<<CS::Kem as KemCore>::EncapsulationKey as EncodedSizeUser>::EncodedSize>,
    Sum<
        <<CS::Kem as KemCore>::DecapsulationKey as EncodedSizeUser>::EncodedSize,
        <<CS::Kem as KemCore>::EncapsulationKey as EncodedSizeUser>::EncodedSize,
    >: ArraySize
        + Add<<<CS::Pake as Pake>::Output as EncodedSizeUser>::EncodedSize>
        + Sub<
            <<CS::Kem as KemCore>::DecapsulationKey as EncodedSizeUser>::EncodedSize,
            Output = <<CS::Kem as KemCore>::EncapsulationKey as EncodedSizeUser>::EncodedSize,
        >,
    Sum<
        Sum<
            <<CS::Kem as KemCore>::DecapsulationKey as EncodedSizeUser>::EncodedSize,
            <<CS::Kem as KemCore>::EncapsulationKey as EncodedSizeUser>::EncodedSize,
        >,
        <<CS::Pake as Pake>::Output as EncodedSizeUser>::EncodedSize,
    >: ArraySize
        + Sub<
            Sum<
                <<CS::Kem as KemCore>::DecapsulationKey as EncodedSizeUser>::EncodedSize,
                <<CS::Kem as KemCore>::EncapsulationKey as EncodedSizeUser>::EncodedSize,
            >,
            Output = <<CS::Pake as Pake>::Output as EncodedSizeUser>::EncodedSize,
        >,
{
    type EncodedSize = Sum<
        Sum<
            <<CS::Kem as KemCore>::DecapsulationKey as EncodedSizeUser>::EncodedSize,
            <<CS::Kem as KemCore>::EncapsulationKey as EncodedSizeUser>::EncodedSize,
        >,
        <<CS::Pake as Pake>::Output as EncodedSizeUser>::EncodedSize,
    >;

    fn from_bytes(enc: &Encoded<Self>) -> Self {
        let (enc, pake_output) = enc.split_ref();
        let (dk_bytes, ek_bytes) = enc.split_ref();

        Self {
            pake_output: <CS::Pake as Pake>::Output::from_bytes(pake_output),
            dk: <CS::Kem as KemCore>::DecapsulationKey::from_bytes(dk_bytes),
            ek: <CS::Kem as KemCore>::EncapsulationKey::from_bytes(ek_bytes),
        }
    }

    fn as_bytes(&self) -> Encoded<Self> {
        self.dk
            .as_bytes()
            .concat(self.ek.as_bytes())
            .concat(self.pake_output.as_bytes())
    }
}
