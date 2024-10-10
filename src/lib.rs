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
//! The way an input is represented in pake-kem is as follows:
//!
//! ```
//! use pake_kem::Input;
//! let input = Input {
//!     password: "password".to_string(),
//!     initiator_id: "initiator".to_string(),
//!     responder_id: "responder".to_string(),
//!     associated_data: Some("ad".to_string()),
//! };
//! ```
//!
//! # Protocol Execution
//!
//! ## Message One
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
//! # let input = Input {
//! #     password: "password".to_string(),
//! #     initiator_id: "initiator".to_string(),
//! #     responder_id: "responder".to_string(),
//! #     associated_data: Some("ad".to_string()),
//! # };
//! use pake_kem::EncodedSizeUser; // Needed for calling as_bytes()
//! use pake_kem::Initiator;
//! use rand_core::OsRng;
//!
//! let mut initiator_rng = OsRng;
//! let (initiator, message_one) = Initiator::<Default>::start(&input, &mut initiator_rng);
//! let message_one_bytes = message_one.as_bytes();
//! // Send message_one_bytes over the wire to the responder
//! ```
//!
//! ## Message Two
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
//! # let input = Input {
//! #     password: "password".to_string(),
//! #     initiator_id: "initiator".to_string(),
//! #     responder_id: "responder".to_string(),
//! #     associated_data: Some("ad".to_string()),
//! # };
//! # use pake_kem::EncodedSizeUser; // Needed for calling as_bytes()
//! # use pake_kem::Initiator;
//! # use rand_core::OsRng;
//! #
//! # let mut initiator_rng = OsRng;
//! # let (initiator, message_one) = Initiator::<Default>::start(&input, &mut initiator_rng);
//! # let message_one_bytes = message_one.as_bytes();
//! # // Send message_one_bytes over the wire to the responder
//! use pake_kem::MessageOne;
//! use pake_kem::Responder;
//!
//! let mut responder_rng = OsRng;
//! let message_one = MessageOne::from_bytes(&message_one_bytes);
//! let (responder, message_two) =
//!     Responder::<Default>::start(&input, &message_one, &mut responder_rng);
//! let message_two_bytes = message_two.as_bytes();
//! // Send message_two_bytes over the wire to the initiator
//! ```
//!
//! ## Message Three
//!
//! Next, the initiator invokes the following with the already-initialized object
//! retained from [the first step](#message-one), a [`MessageTwo`] object received from the responder
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
//! # let input = Input {
//! #     password: "password".to_string(),
//! #     initiator_id: "initiator".to_string(),
//! #     responder_id: "responder".to_string(),
//! #     associated_data: Some("ad".to_string()),
//! # };
//! # use pake_kem::EncodedSizeUser; // Needed for calling as_bytes()
//! # use pake_kem::Initiator;
//! # use rand_core::OsRng;
//! #
//! # let mut initiator_rng = OsRng;
//! # let (initiator, message_one) = Initiator::<Default>::start(&input, &mut initiator_rng);
//! # let message_one_bytes = message_one.as_bytes();
//! # // Send message_one_bytes over the wire to the responder
//! # use pake_kem::MessageOne;
//! # use pake_kem::Responder;
//! #
//! # let mut responder_rng = OsRng;
//! # let message_one = MessageOne::from_bytes(&message_one_bytes);
//! # let (responder, message_two) =
//! #     Responder::<Default>::start(&input, &message_one, &mut responder_rng);
//! # let message_two_bytes = message_two.as_bytes();
//! # // Send message_two_bytes over the wire to the initiator
//! use pake_kem::MessageTwo;
//!
//! let message_two = MessageTwo::from_bytes(&message_two_bytes);
//! let (initiator_output, message_three) =
//!     initiator.finish(&message_two, &mut initiator_rng);
//! let message_three_bytes = message_three.as_bytes();
//! # // Send message_three_bytes over the wire to the responder
//! ```
//!

use core::ops::{Add, Sub};

use crate::hash::{Hash, ProxyHash};
use crate::pake::Pake;
use crate::pake::PakeOutput;
use errors::PakeKemError;
use hkdf::hmac::digest::array::Array;
use hkdf::hmac::digest::core_api::{BlockSizeUser, CoreProxy};
use hkdf::hmac::digest::typenum::{IsLess, IsLessOrEqual, Le, NonZero, Sum, U256};
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
use rand_core::{CryptoRng, RngCore};

mod errors;
mod hash;
mod pake;
pub use pake::CPaceRistretto255;

type Result<T> = core::result::Result<T, PakeKemError>;

pub trait CipherSuite {
    type Pake: Pake;
    type Kem: KemCore;
    type Hash: BlockSizeUser + FixedOutput + Default + HashMarker + EagerHash;
}

pub trait Serializable: Sized {
    fn to_bytes(self) -> Vec<u8>;
    fn from_bytes(input: &[u8]) -> Result<Self>;
}

pub struct Input {
    pub password: String,
    pub initiator_id: String,
    pub responder_id: String,
    pub associated_data: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Output(Vec<u8>);

pub struct Initiator<CS: CipherSuite> {
    state: CS::Pake,
}

impl<CS: CipherSuite> Initiator<CS>
where
    <CS::Hash as OutputSizeUser>::OutputSize:
        IsLess<U256> + IsLessOrEqual<<CS::Hash as BlockSizeUser>::BlockSize>,
    CS::Hash: Hash,
    <CS::Hash as CoreProxy>::Core: ProxyHash,
    <<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize: IsLess<U256>,
    Le<<<CS::Hash as CoreProxy>::Core as BlockSizeUser>::BlockSize, U256>: NonZero,
{
    pub fn start<R: RngCore + CryptoRng>(input: &Input, _rng: &mut R) -> (Self, MessageOne<CS>) {
        let (init_message, state) = CS::Pake::init(input);

        (Self { state }, MessageOne { init_message })
    }

    pub fn finish<R: RngCore + CryptoRng>(
        self,
        message_two: &MessageTwo<CS>,
        rng: &mut R,
    ) -> (Output, MessageThree<CS>) {
        let pake_output = self.state.recv(&message_two.respond_message);

        // First, check the mac on ek
        let mut mac_verifier = Hmac::<CS::Hash>::new_from_slice(&pake_output[..32]).unwrap();
        mac_verifier.update(&message_two.ek.as_bytes());
        mac_verifier.verify_slice(&message_two.ek_tag).unwrap();

        // Encapsulate a shared key to the holder of the decapsulation key, receive the shared
        // secret `k_send` and the encapsulated form `ct`.
        let (ct, k_send) = message_two.ek.encapsulate(rng).unwrap();

        // Next, construct another mac
        let mut mac_builder = Hmac::<CS::Hash>::new_from_slice(&pake_output[..32]).unwrap();
        mac_builder.update(&message_two.ek.as_bytes());
        mac_builder.update(ct.as_slice());
        mac_builder.update(k_send.as_slice());
        let mac = mac_builder.finalize().into_bytes();

        let mut hkdf = HkdfExtract::<CS::Hash>::new(None);
        hkdf.input_ikm(&message_two.ek.as_bytes());
        hkdf.input_ikm(ct.as_slice());
        hkdf.input_ikm(&pake_output[..32]);
        hkdf.input_ikm(&pake_output[32..]);
        hkdf.input_ikm(k_send.as_slice());
        let (res, _) = hkdf.finalize();

        (Output(res.to_vec()), MessageThree { ct, ct_tag: mac })
    }
}

pub struct Responder<CS: CipherSuite> {
    pake_output: PakeOutput,
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
    pub fn start<R: RngCore + CryptoRng>(
        input: &Input,
        message_one: &MessageOne<CS>,
        rng: &mut R,
    ) -> (Self, MessageTwo<CS>) {
        let (pake_output, respond_message) = CS::Pake::respond(input, &message_one.init_message);

        let (decapsulation_key, encapsulation_key) = CS::Kem::generate(rng);

        let ek_bytes = encapsulation_key.as_bytes();
        let ek_cloned = <CS::Kem as KemCore>::EncapsulationKey::from_bytes(&ek_bytes);

        let mut mac_builder = Hmac::<CS::Hash>::new_from_slice(&pake_output[..32]).unwrap();
        mac_builder.update(&ek_bytes);
        let mac = mac_builder.finalize().into_bytes();

        (
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
        )
    }

    pub fn finish(self, message_three: &MessageThree<CS>) -> Output {
        let k_recv = self.dk.decapsulate(&message_three.ct).unwrap();

        let mut mac_verifier = Hmac::<CS::Hash>::new_from_slice(&self.pake_output[..32]).unwrap();
        mac_verifier.update(&self.ek.as_bytes());
        mac_verifier.update(message_three.ct.as_slice());
        mac_verifier.update(k_recv.as_slice());
        mac_verifier.verify_slice(&message_three.ct_tag).unwrap();

        let mut hkdf = HkdfExtract::<CS::Hash>::new(None);
        hkdf.input_ikm(&self.ek.as_bytes());
        hkdf.input_ikm(message_three.ct.as_slice());
        hkdf.input_ikm(&self.pake_output[..32]);
        hkdf.input_ikm(&self.pake_output[32..]);
        hkdf.input_ikm(k_recv.as_slice());
        let (res, _) = hkdf.finalize();

        Output(res.to_vec())
    }
}

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
