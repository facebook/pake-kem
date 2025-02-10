// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

//! The messages used in the pake-kem protocol

use crate::pake::Pake;
use crate::CipherSuite;
use core::ops::{Add, Sub};
use hkdf::hmac::digest::array::Array;
use hkdf::hmac::digest::typenum::Sum;
use hkdf::hmac::digest::OutputSizeUser;
use hkdf::hmac::EagerHash;
use ml_kem::ArraySize;
use ml_kem::Ciphertext;
use ml_kem::Encoded;
use ml_kem::EncodedSizeUser;
use ml_kem::KemCore;

/// The first message in the pake-kem protocol, created by the initiator
#[derive(Debug)]
pub struct MessageOne<CS: CipherSuite> {
    pub(crate) init_message: <CS::Pake as Pake>::InitMessage,
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
pub struct MessageTwo<CS: CipherSuite> {
    pub(crate) respond_message: <CS::Pake as Pake>::RespondMessage,
    pub(crate) ek: <CS::Kem as KemCore>::EncapsulationKey,
    pub(crate) ek_tag: Array<u8, <<CS::Hash as EagerHash>::Core as OutputSizeUser>::OutputSize>,
}

impl<CS: CipherSuite> EncodedSizeUser for MessageTwo<CS>
where
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
pub struct MessageThree<CS: CipherSuite> {
    pub(crate) ct: Ciphertext<CS::Kem>,
    pub(crate) ct_tag: Array<u8, <<CS::Hash as EagerHash>::Core as OutputSizeUser>::OutputSize>,
}

impl<CS: CipherSuite> EncodedSizeUser for MessageThree<CS>
where
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
