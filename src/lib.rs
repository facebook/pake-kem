// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

//! An implementation of a password authenticate key exchange (PAKE) that
//! relies on quantum-resistant cryptographic primitives
//!
//! ⚠️ **Warning**: This implementation has not been audited. Use at your own risk!
//!
//! # Overview
//!
//! pake-kem is a protocol between two parties: an initiator and a responder.
//! At a high level, the initiator and responder each hold as input to the
//! protocol an [`Input`]. After exchanging the protocol messages, the initiator
//! and responder end up with an [`Output`]. If the two participants had matching
//! [`Input`]s, then they will end up with the same [`Output`]. Otherwise,
//! their [`Output`]s will not match, and in fact be (computationally) uncorrelated.
//!
//! # Setup
//!
//! In order to execute the protocol, the initiator and responder
//! must first agree on a collection of primitives to be kept consistent
//! throughout protocol execution. These include:
//! * a (classically-secure) two-message PAKE protocol,
//! * a (quantum-resistant) key encapsulation mechanism, and
//! * a hashing function.
//!
//! We will use the following choices in this example:
//! ```ignore
//! use pake_kem::CipherSuite;
//! struct Default;
//! impl CipherSuite for Default {
//!     type Pake = pake_kem::CPaceRistretto255;
//!     type Kem = ml_kem::MlKem768;
//!     type Hash = sha2::Sha256;
//! }
//! ```
//! See [examples/demo.rs](https://github.com/facebook/pake-kem/blob/main/examples/demo.rs)
//! for a working example for using pake-kem.
//!
//! Like any symmetric (balanced) PAKE, the initiator and responder will each begin with
//! their own input, exchange some messages as part of the protocol, and derive a
//! secret as the output of the protocol.
//!
//! If the initiator and responder used the exact same input to the protocol, then
//! they are guaranteed to end up with the same secret (this would be a "shared secret").
//!
//! If the initiator and responder used different inputs, then they will not
//! end up with the same shared secret (with overwhelming probability).
//!
//! The way an input is created in pake-kem is as follows:
//!
//! ```
//! use pake_kem::Input;
//! let input = Input::new(b"password", b"initiator", b"responder");
//! ```
//!
//! # Protocol Execution
//!
//! The pake-kem protocol occurs over four steps, involving three
//! messages between the initiator and responder.
//!
//! ## Initiator Start
//!
//! The initiator begins the protocol by invoking the following with
//! an [`Input`] and source of randomness:
//! ```
//! # use pake_kem::CipherSuite;
//! # struct Default;
//! # impl CipherSuite for Default {
//! #     type Pake = pake_kem::CPaceRistretto255;
//! #     type Kem = ml_kem::MlKem768;
//! #     type Hash = sha2::Sha256;
//! # }
//! # use pake_kem::Input;
//! # let input = Input::new(b"password", b"initiator", b"responder");
//! use pake_kem::EncodedSizeUser; // Needed for calling as_bytes()
//! use pake_kem::Initiator;
//! use rand_core::OsRng;
//!
//! let mut initiator_rng = OsRng;
//! let (initiator, message_one) = Initiator::<Default>::start(&input, &mut initiator_rng)
//!    .expect("Error with Initiator::start()");
//! let message_one_bytes = message_one.as_bytes();
//! // Send message_one_bytes over the wire to the responder
//! ```
//!
//! The initiator retains the [`Initiator`] object for the [third step](#initiator-finish), and sends
//! the [`MessageOne`] object over the wire to the responder.
//!
//! ## Responder Start
//!
//! Next, the responder invokes the following with an [`Input`], a [`MessageOne`]
//! object received from the initiator in the previous step, and a source of
//! randomness:
//!
//! ```
//! # use pake_kem::CipherSuite;
//! # struct Default;
//! # impl CipherSuite for Default {
//! #     type Pake = pake_kem::CPaceRistretto255;
//! #     type Kem = ml_kem::MlKem768;
//! #     type Hash = sha2::Sha256;
//! # }
//! # use pake_kem::Input;
//! # let input = Input::new(b"password", b"initiator", b"responder");
//! # use pake_kem::EncodedSizeUser; // Needed for calling as_bytes()
//! # use pake_kem::Initiator;
//! # use rand_core::OsRng;
//! #
//! # let mut initiator_rng = OsRng;
//! # let (initiator, message_one) = Initiator::<Default>::start(&input, &mut initiator_rng)
//! #    .expect("Error with Initiator::start()");
//! # let message_one_bytes = message_one.as_bytes();
//! # // Send message_one_bytes over the wire to the responder
//! use pake_kem::MessageOne;
//! use pake_kem::Responder;
//!
//! let mut responder_rng = OsRng;
//! let message_one = MessageOne::from_bytes(&message_one_bytes);
//! let (responder, message_two) =
//!     Responder::<Default>::start(&input, &message_one, &mut responder_rng)
//!        .expect("Error with Responder::start()");
//! let message_two_bytes = message_two.as_bytes();
//! // Send message_two_bytes over the wire to the initiator
//! ```
//!
//! The responder retains the [`Responder`] object for the [fourth step](#responder-finish), and sends
//! the [`MessageTwo`] object over the wire to the initiator.
//!
//! ## Initiator Finish
//!
//! Next, the initiator invokes the following with the already-initialized object
//! retained from [the first step](#initiator-start), a [`MessageTwo`] object received from the responder
//! in the previous step, and a source of randomness:
//!
//! ```
//! # use pake_kem::CipherSuite;
//! # struct Default;
//! # impl CipherSuite for Default {
//! #     type Pake = pake_kem::CPaceRistretto255;
//! #     type Kem = ml_kem::MlKem768;
//! #     type Hash = sha2::Sha256;
//! # }
//! # use pake_kem::Input;
//! # let input = Input::new(b"password", b"initiator", b"responder");
//! # use pake_kem::EncodedSizeUser; // Needed for calling as_bytes()
//! # use pake_kem::Initiator;
//! # use rand_core::OsRng;
//! #
//! # let mut initiator_rng = OsRng;
//! # let (initiator, message_one) = Initiator::<Default>::start(&input, &mut initiator_rng)
//! #    .expect("Error with Initiator::start()");
//! # let message_one_bytes = message_one.as_bytes();
//! # // Send message_one_bytes over the wire to the responder
//! # use pake_kem::MessageOne;
//! # use pake_kem::Responder;
//! #
//! # let mut responder_rng = OsRng;
//! # let message_one = MessageOne::from_bytes(&message_one_bytes);
//! # let (responder, message_two) =
//! #     Responder::<Default>::start(&input, &message_one, &mut responder_rng)
//! #        .expect("Error with Responder::start()");
//! # let message_two_bytes = message_two.as_bytes();
//! # // Send message_two_bytes over the wire to the initiator
//! use pake_kem::MessageTwo;
//!
//! let message_two = MessageTwo::from_bytes(&message_two_bytes);
//! let (initiator_output, message_three) =
//!     initiator.finish(&message_two, &mut initiator_rng)
//!         .expect("Error with Initiator::finish()");
//! let message_three_bytes = message_three.as_bytes();
//! // Send message_three_bytes over the wire to the responder
//! ```
//!
//! The initiator retains the [`Output`] object as the output of the pake-kem
//! protocol, and sends the [`MessageThree`] object over the wire to the responder.
//!
//! ## Responder Finish
//!
//! Finally, the responder invokes the following with the already-initialized object
//! retained from [the second step](#responder-start) and a [`MessageThree`] object received from the initiator
//! in the previous step:
//!
//! ```
//! # use pake_kem::CipherSuite;
//! # struct Default;
//! # impl CipherSuite for Default {
//! #     type Pake = pake_kem::CPaceRistretto255;
//! #     type Kem = ml_kem::MlKem768;
//! #     type Hash = sha2::Sha256;
//! # }
//! # use pake_kem::Input;
//! # let input = Input::new(b"password", b"initiator", b"responder");
//! # use pake_kem::EncodedSizeUser; // Needed for calling as_bytes()
//! # use pake_kem::Initiator;
//! # use rand_core::OsRng;
//! #
//! # let mut initiator_rng = OsRng;
//! # let (initiator, message_one) = Initiator::<Default>::start(&input, &mut initiator_rng)
//! #    .expect("Error with Initiator::start()");
//! # let message_one_bytes = message_one.as_bytes();
//! # // Send message_one_bytes over the wire to the responder
//! # use pake_kem::MessageOne;
//! # use pake_kem::Responder;
//! #
//! # let mut responder_rng = OsRng;
//! # let message_one = MessageOne::from_bytes(&message_one_bytes);
//! # let (responder, message_two) =
//! #     Responder::<Default>::start(&input, &message_one, &mut responder_rng)
//! #        .expect("Error with Responder::start()");
//! # let message_two_bytes = message_two.as_bytes();
//! # // Send message_two_bytes over the wire to the initiator
//! # use pake_kem::MessageTwo;
//! #
//! # let message_two = MessageTwo::from_bytes(&message_two_bytes);
//! # let (initiator_output, message_three) =
//! #     initiator.finish(&message_two, &mut initiator_rng)
//! #         .expect("Error with Initiator::finish()");
//! # let message_three_bytes = message_three.as_bytes();
//! # // Send message_three_bytes over the wire to the responder
//! use pake_kem::MessageThree;
//!
//! let message_three = MessageThree::from_bytes(&message_three_bytes);
//! let responder_output = responder.finish(&message_three)
//!    .expect("Error with Responder::finish()");
//! ```
//!
//! The responder retains the [`Output`] object as the output of the pake-kem
//! protocol.
//!
//!

#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(not(test), deny(unsafe_code))]
#![warn(clippy::doc_markdown, missing_docs, rustdoc::all)]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]

use core::ops::{Add, Sub};

use crate::hash::{Hash, ProxyHash};
use crate::pake::Pake;
use crate::pake::PakeOutput;
pub use errors::PakeKemError;
pub use hkdf::hmac::digest::array::Array;
use hkdf::hmac::digest::core_api::{BlockSizeUser, CoreProxy};
use hkdf::hmac::digest::typenum::{IsLess, IsLessOrEqual, Le, NonZero, Sum, U256, U64};
use hkdf::hmac::digest::FixedOutput;
use hkdf::hmac::digest::HashMarker;
use hkdf::hmac::digest::OutputSizeUser;
use hkdf::hmac::{EagerHash, Hmac, KeyInit, Mac};
use hkdf::HkdfExtract;
use kem::{Decapsulate, Encapsulate};
use ml_kem::ArraySize;
use ml_kem::Encoded;
pub use ml_kem::EncodedSizeUser;
use ml_kem::{Ciphertext, KemCore};
pub use rand_core;
use rand_core::{CryptoRng, RngCore};

mod errors;
mod hash;
mod pake;
pub use pake::CPaceRistretto255;

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
    type Hash: BlockSizeUser + FixedOutput + Default + HashMarker + EagerHash;
}

/// The default [`CipherSuite`] for pake-kem, based on `CPaceRistretto255`, `MlKem768`, and `Sha256`
pub struct DefaultCipherSuite;
impl CipherSuite for DefaultCipherSuite {
    type Pake = CPaceRistretto255;
    type Kem = ml_kem::MlKem768;
    type Hash = sha2::Sha256;
}

/// The input to the pake-kem protocol
pub struct Input {
    password: Vec<u8>,
    initiator_id: Vec<u8>,
    responder_id: Vec<u8>,
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
pub struct Output(pub Vec<u8>);

/// The main struct for the initiator of the pake-kem protocol
#[derive(Debug)]
pub struct Initiator<CS: CipherSuite>(CS::Pake);

impl<CS: CipherSuite> Initiator<CS>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
    CS::Hash: Hash,
    <CS::Hash as CoreProxy>::Core: ProxyHash,
    <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
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
    ) -> Result<(Output, MessageThree<CS>)> {
        let pake_output = self.0.recv(&message_two.respond_message);
        let (mac_key, session_key) = pake_output_into_keys(pake_output, rng);

        // First, check the mac on ek
        let mut mac_verifier = Hmac::<CS::Hash>::new_from_slice(&mac_key)?;
        mac_verifier.update(&message_two.ek.as_bytes());
        mac_verifier.verify_slice(&message_two.ek_tag)?;

        // Encapsulate a shared key to the holder of the decapsulation key, receive the shared
        // secret `k_send` and the encapsulated form `ct`.
        let (ct, k_send) = message_two
            .ek
            .encapsulate(rng)
            .map_err(|_| PakeKemError::Deserialization)?;

        // Next, construct another mac
        let mut mac_builder = Hmac::<CS::Hash>::new_from_slice(&mac_key)?;
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

        Ok((Output(res.to_vec()), MessageThree { ct, ct_tag: mac }))
    }
}

/// The main struct for the responder of the pake-kem protocol
#[derive(Debug)]
pub struct Responder<CS: CipherSuite> {
    mac_key: [u8; 32],
    session_key: [u8; 32],
    dk: <CS::Kem as KemCore>::DecapsulationKey,
    ek: <CS::Kem as KemCore>::EncapsulationKey,
}

impl<CS: CipherSuite> Responder<CS>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
    CS::Hash: Hash,
    <CS::Hash as CoreProxy>::Core: ProxyHash,
    <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    /// The second step of pake-kem, where the responder starts its role in the protocol
    /// with input from the first message created by the initiator
    pub fn start<R: RngCore + CryptoRng>(
        input: &Input,
        message_one: &MessageOne<CS>,
        rng: &mut R,
    ) -> Result<(Self, MessageTwo<CS>)> {
        let (pake_output, respond_message) =
            CS::Pake::respond(input, &message_one.init_message, rng);
        let (mac_key, enc_key) = pake_output_into_keys(pake_output, rng);

        let (decapsulation_key, encapsulation_key) = CS::Kem::generate(rng);

        let ek_bytes = encapsulation_key.as_bytes();
        let ek_cloned = <CS::Kem as KemCore>::EncapsulationKey::from_bytes(&ek_bytes);

        let mut mac_builder = Hmac::<CS::Hash>::new_from_slice(&mac_key)?;
        mac_builder.update(&ek_bytes);
        let mac = mac_builder.finalize().into_bytes();

        Ok((
            Self {
                mac_key,
                session_key: enc_key,
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
    pub fn finish(self, message_three: &MessageThree<CS>) -> Result<Output> {
        let k_recv = self
            .dk
            .decapsulate(&message_three.ct)
            .map_err(|_| PakeKemError::Deserialization)?;

        let mut mac_verifier = Hmac::<CS::Hash>::new_from_slice(&self.mac_key)?;
        mac_verifier.update(&self.ek.as_bytes());
        mac_verifier.update(message_three.ct.as_slice());
        mac_verifier.update(k_recv.as_slice());
        mac_verifier.verify_slice(&message_three.ct_tag)?;

        let mut hkdf = HkdfExtract::<CS::Hash>::new(None);
        hkdf.input_ikm(&self.ek.as_bytes());
        hkdf.input_ikm(message_three.ct.as_slice());
        hkdf.input_ikm(&self.mac_key);
        hkdf.input_ikm(&self.session_key);
        hkdf.input_ikm(k_recv.as_slice());
        let (res, _) = hkdf.finalize();

        Ok(Output(res.to_vec()))
    }
}

fn pake_output_into_keys<R: RngCore + CryptoRng>(
    pake_output: Option<PakeOutput>,
    rng: &mut R,
) -> ([u8; 32], [u8; 32]) {
    let mut key1 = [0u8; 32];
    let mut key2 = [0u8; 32];
    rng.fill_bytes(&mut key1);
    rng.fill_bytes(&mut key2);

    if let Some(pake_output) = pake_output {
        key1.copy_from_slice(&pake_output[..32]);
        key2.copy_from_slice(&pake_output[32..]);
    }

    (key1, key2)
}

/// The first message in the pake-kem protocol, created by the initiator
#[derive(Debug)]
pub struct MessageOne<CS: CipherSuite> {
    init_message: <CS::Pake as Pake>::InitMessage,
}

impl<CS: CipherSuite> EncodedSizeUser for MessageOne<CS> {
    type EncodedSize = <<CS::Pake as Pake>::InitMessage as EncodedSizeUser>::EncodedSize;

    fn from_bytes(enc: &Encoded<Self>) -> Self {
        Self {
            init_message: <CS::Pake as Pake>::InitMessage::from_bytes(enc),
        }
    }

    fn as_bytes(&self) -> Encoded<Self> {
        self.init_message.as_bytes()
    }
}

/// The second message in the pake-kem protocol, created by the responder
#[derive(Debug)]
pub struct MessageTwo<CS: CipherSuite>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
    CS::Hash: Hash,
    <CS::Hash as CoreProxy>::Core: ProxyHash,
    <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    respond_message: <CS::Pake as Pake>::RespondMessage,
    ek: <CS::Kem as KemCore>::EncapsulationKey,
    ek_tag: Array<u8, <<CS::Hash as EagerHash>::Core as OutputSizeUser>::OutputSize>,
}

impl<CS: CipherSuite> EncodedSizeUser for MessageTwo<CS>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
    CS::Hash: Hash,
    <CS::Hash as CoreProxy>::Core: ProxyHash,
    <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,

    // Concatenation clauses
    <<CS::Pake as Pake>::RespondMessage as EncodedSizeUser>::EncodedSize:
        Add<<<CS::Kem as KemCore>::EncapsulationKey as EncodedSizeUser>::EncodedSize>,
    Sum<
        <<CS::Pake as Pake>::RespondMessage as EncodedSizeUser>::EncodedSize,
        <<CS::Kem as KemCore>::EncapsulationKey as EncodedSizeUser>::EncodedSize,
    >: ArraySize
        + Add<<<CS::Hash as EagerHash>::Core as OutputSizeUser>::OutputSize>
        + Sub<
            <<CS::Pake as Pake>::RespondMessage as EncodedSizeUser>::EncodedSize,
            Output = <<CS::Kem as KemCore>::EncapsulationKey as EncodedSizeUser>::EncodedSize,
        >,
    Sum<
        Sum<
            <<CS::Pake as Pake>::RespondMessage as EncodedSizeUser>::EncodedSize,
            <<CS::Kem as KemCore>::EncapsulationKey as EncodedSizeUser>::EncodedSize,
        >,
        <<CS::Hash as EagerHash>::Core as OutputSizeUser>::OutputSize,
    >: ArraySize
        + Sub<
            Sum<
                <<CS::Pake as Pake>::RespondMessage as EncodedSizeUser>::EncodedSize,
                <<CS::Kem as KemCore>::EncapsulationKey as EncodedSizeUser>::EncodedSize,
            >,
            Output = <<CS::Hash as EagerHash>::Core as OutputSizeUser>::OutputSize,
        >,
{
    type EncodedSize = Sum<
        Sum<
            <<CS::Pake as Pake>::RespondMessage as EncodedSizeUser>::EncodedSize,
            <<CS::Kem as KemCore>::EncapsulationKey as EncodedSizeUser>::EncodedSize,
        >,
        <<CS::Hash as EagerHash>::Core as OutputSizeUser>::OutputSize,
    >;

    fn from_bytes(enc: &Encoded<Self>) -> Self {
        let (enc, ek_tag) = enc.split_ref();
        let (respond_message_bytes, ek_bytes) = enc.split_ref();
        Self {
            respond_message: <CS::Pake as Pake>::RespondMessage::from_bytes(respond_message_bytes),
            ek: <CS::Kem as KemCore>::EncapsulationKey::from_bytes(ek_bytes),
            ek_tag: ek_tag.clone(),
        }
    }

    fn as_bytes(&self) -> Encoded<Self> {
        self.respond_message
            .as_bytes()
            .concat(self.ek.as_bytes())
            .concat(self.ek_tag.clone())
    }
}

/// The third message in the pake-kem protocol, created by the initiator
#[derive(Debug)]
pub struct MessageThree<CS: CipherSuite>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
    CS::Hash: Hash,
    <CS::Hash as CoreProxy>::Core: ProxyHash,
    <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    ct: Ciphertext<CS::Kem>,
    ct_tag: Array<u8, <<CS::Hash as EagerHash>::Core as OutputSizeUser>::OutputSize>,
}

impl<CS: CipherSuite> EncodedSizeUser for MessageThree<CS>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
    CS::Hash: Hash,
    <CS::Hash as CoreProxy>::Core: ProxyHash,
    <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,

    // Concatenation clauses
    <CS::Kem as KemCore>::CiphertextSize:
        Add<<<CS::Hash as EagerHash>::Core as OutputSizeUser>::OutputSize>,
    Sum<
        <CS::Kem as KemCore>::CiphertextSize,
        <<CS::Hash as EagerHash>::Core as OutputSizeUser>::OutputSize,
    >: ArraySize
        + Sub<
            <CS::Kem as KemCore>::CiphertextSize,
            Output = <<CS::Hash as EagerHash>::Core as OutputSizeUser>::OutputSize,
        >,
{
    type EncodedSize = Sum<
        <CS::Kem as KemCore>::CiphertextSize,
        <<CS::Hash as EagerHash>::Core as OutputSizeUser>::OutputSize,
    >;

    fn from_bytes(enc: &Encoded<Self>) -> Self {
        let (ct, ct_tag) = enc.split_ref();
        Self {
            ct: ct.clone(),
            ct_tag: ct_tag.clone(),
        }
    }

    fn as_bytes(&self) -> Encoded<Self> {
        self.ct.clone().concat(self.ct_tag.clone())
    }
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
        + Add<U64>
        + Sub<
            <<CS::Kem as KemCore>::DecapsulationKey as EncodedSizeUser>::EncodedSize,
            Output = <<CS::Kem as KemCore>::EncapsulationKey as EncodedSizeUser>::EncodedSize,
        >,
    Sum<
        Sum<
            <<CS::Kem as KemCore>::DecapsulationKey as EncodedSizeUser>::EncodedSize,
            <<CS::Kem as KemCore>::EncapsulationKey as EncodedSizeUser>::EncodedSize,
        >,
        U64,
    >: ArraySize
        + Sub<
            Sum<
                <<CS::Kem as KemCore>::DecapsulationKey as EncodedSizeUser>::EncodedSize,
                <<CS::Kem as KemCore>::EncapsulationKey as EncodedSizeUser>::EncodedSize,
            >,
            Output = U64,
        >,
{
    type EncodedSize = Sum<
        Sum<
            <<CS::Kem as KemCore>::DecapsulationKey as EncodedSizeUser>::EncodedSize,
            <<CS::Kem as KemCore>::EncapsulationKey as EncodedSizeUser>::EncodedSize,
        >,
        U64,
    >;

    fn from_bytes(enc: &Encoded<Self>) -> Self {
        let (enc, both_keys) = enc.split_ref();
        let (dk_bytes, ek_bytes) = enc.split_ref();
        let mut mac_key: [u8; 32] = [0u8; 32];
        mac_key.copy_from_slice(&both_keys[..32]);
        let mut session_key: [u8; 32] = [0u8; 32];
        session_key.copy_from_slice(&both_keys[32..]);

        Self {
            mac_key,
            session_key,
            dk: <CS::Kem as KemCore>::DecapsulationKey::from_bytes(dk_bytes),
            ek: <CS::Kem as KemCore>::EncapsulationKey::from_bytes(ek_bytes),
        }
    }

    fn as_bytes(&self) -> Encoded<Self> {
        let mut both_keys = Array::<u8, U64>::default();
        both_keys[..32].copy_from_slice(&self.mac_key);
        both_keys[32..].copy_from_slice(&self.session_key);
        self.dk
            .as_bytes()
            .concat(self.ek.as_bytes())
            .concat(both_keys)
    }
}
