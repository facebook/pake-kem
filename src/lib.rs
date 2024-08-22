// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

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
use ml_kem::{Ciphertext, KemCore};
use ml_kem::{Encoded, EncodedSizeUser};
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
