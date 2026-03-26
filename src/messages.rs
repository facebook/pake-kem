// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

//! The messages used in the pake-kem protocol

use crate::pake::Pake;
use crate::{CipherSuite, Encoded, EncodedSizeUser, PakeKemError};
use core::ops::{Add, Sub};
use hkdf::hmac::digest::array::Array;
use hkdf::hmac::digest::typenum::Sum;
use hkdf::hmac::digest::OutputSizeUser;
use hkdf::hmac::EagerHash;
use ml_kem::array::ArraySize;
use ml_kem::kem::{FromSeed, KeySizeUser};
use ml_kem::{Ciphertext, Kem, KeyExport, TryKeyInit};

/// The first message in the pake-kem protocol, created by the initiator
#[derive(Debug)]
pub struct MessageOne<CS: CipherSuite> {
    pub(crate) init_message: <CS::Pake as Pake>::InitMessage,
}

impl<CS: CipherSuite> EncodedSizeUser for MessageOne<CS> {
    type EncodedSize = <<CS::Pake as Pake>::InitMessage as EncodedSizeUser>::EncodedSize;

    fn from_bytes(enc: &Encoded<Self>) -> Result<Self, PakeKemError> {
        Ok(Self {
            init_message: <CS::Pake as Pake>::InitMessage::from_bytes(enc)?,
        })
    }

    fn as_bytes(&self) -> Encoded<Self> {
        self.init_message.as_bytes()
    }
}

/// The second message in the pake-kem protocol, created by the responder
#[derive(Debug)]
pub struct MessageTwo<CS: CipherSuite> {
    pub(crate) respond_message: <CS::Pake as Pake>::RespondMessage,
    pub(crate) ek: <CS::Kem as Kem>::EncapsulationKey,
    pub(crate) ek_tag: Array<u8, <<CS::Hash as EagerHash>::Core as OutputSizeUser>::OutputSize>,
}

impl<CS: CipherSuite> EncodedSizeUser for MessageTwo<CS>
where
    CS::Kem: FromSeed,
    <CS::Kem as Kem>::EncapsulationKey: KeyExport + TryKeyInit,
    // Concatenation clauses
    <<CS::Pake as Pake>::RespondMessage as EncodedSizeUser>::EncodedSize:
        Add<<<CS::Kem as Kem>::EncapsulationKey as KeySizeUser>::KeySize>,
    Sum<
        <<CS::Pake as Pake>::RespondMessage as EncodedSizeUser>::EncodedSize,
        <<CS::Kem as Kem>::EncapsulationKey as KeySizeUser>::KeySize,
    >: ArraySize
        + Add<<<CS::Hash as EagerHash>::Core as OutputSizeUser>::OutputSize>
        + Sub<
            <<CS::Pake as Pake>::RespondMessage as EncodedSizeUser>::EncodedSize,
            Output = <<CS::Kem as Kem>::EncapsulationKey as KeySizeUser>::KeySize,
        >,
    Sum<
        Sum<
            <<CS::Pake as Pake>::RespondMessage as EncodedSizeUser>::EncodedSize,
            <<CS::Kem as Kem>::EncapsulationKey as KeySizeUser>::KeySize,
        >,
        <<CS::Hash as EagerHash>::Core as OutputSizeUser>::OutputSize,
    >: ArraySize
        + Sub<
            Sum<
                <<CS::Pake as Pake>::RespondMessage as EncodedSizeUser>::EncodedSize,
                <<CS::Kem as Kem>::EncapsulationKey as KeySizeUser>::KeySize,
            >,
            Output = <<CS::Hash as EagerHash>::Core as OutputSizeUser>::OutputSize,
        >,
{
    type EncodedSize = Sum<
        Sum<
            <<CS::Pake as Pake>::RespondMessage as EncodedSizeUser>::EncodedSize,
            <<CS::Kem as Kem>::EncapsulationKey as KeySizeUser>::KeySize,
        >,
        <<CS::Hash as EagerHash>::Core as OutputSizeUser>::OutputSize,
    >;

    fn from_bytes(enc: &Encoded<Self>) -> Result<Self, PakeKemError> {
        let (enc, ek_tag) = enc.split_ref();
        let (respond_message_bytes, ek_bytes) = enc.split_ref();
        Ok(Self {
            respond_message: <CS::Pake as Pake>::RespondMessage::from_bytes(respond_message_bytes)?,
            ek: <<CS::Kem as Kem>::EncapsulationKey as TryKeyInit>::new(ek_bytes)
                .map_err(|_| PakeKemError::Deserialization)?,
            ek_tag: ek_tag.clone(),
        })
    }

    fn as_bytes(&self) -> Encoded<Self> {
        self.respond_message
            .as_bytes()
            .concat(KeyExport::to_bytes(&self.ek))
            .concat(self.ek_tag.clone())
    }
}

/// The third message in the pake-kem protocol, created by the initiator
#[derive(Debug)]
pub struct MessageThree<CS: CipherSuite> {
    pub(crate) ct: Ciphertext<CS::Kem>,
    pub(crate) ct_tag: Array<u8, <<CS::Hash as EagerHash>::Core as OutputSizeUser>::OutputSize>,
}

impl<CS: CipherSuite> EncodedSizeUser for MessageThree<CS>
where
    // Concatenation clauses
    <CS::Kem as Kem>::CiphertextSize:
        Add<<<CS::Hash as EagerHash>::Core as OutputSizeUser>::OutputSize>,
    Sum<
        <CS::Kem as Kem>::CiphertextSize,
        <<CS::Hash as EagerHash>::Core as OutputSizeUser>::OutputSize,
    >: ArraySize
        + Sub<
            <CS::Kem as Kem>::CiphertextSize,
            Output = <<CS::Hash as EagerHash>::Core as OutputSizeUser>::OutputSize,
        >,
{
    type EncodedSize = Sum<
        <CS::Kem as Kem>::CiphertextSize,
        <<CS::Hash as EagerHash>::Core as OutputSizeUser>::OutputSize,
    >;

    fn from_bytes(enc: &Encoded<Self>) -> Result<Self, PakeKemError> {
        let (ct, ct_tag) = enc.split_ref();
        Ok(Self {
            ct: ct.clone(),
            ct_tag: ct_tag.clone(),
        })
    }

    fn as_bytes(&self) -> Encoded<Self> {
        self.ct.clone().concat(self.ct_tag.clone())
    }
}
