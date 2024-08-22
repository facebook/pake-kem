// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

use core::fmt::Debug;
use hkdf::hmac::digest::array::typenum::{U32, U48};
use ml_kem::{Encoded, EncodedSizeUser};
use pake_cpace::{CPace, Step1Out, STEP1_PACKET_BYTES, STEP2_PACKET_BYTES};

use crate::Input;

const PAKE_OUTPUT_SIZE: usize = 64;
pub type PakeOutput = [u8; PAKE_OUTPUT_SIZE];

pub trait Pake {
    type InitMessage: EncodedSizeUser + Debug + PartialEq;
    type RespondMessage: EncodedSizeUser + Debug + PartialEq;

    fn init(input: &Input) -> (Self::InitMessage, Self);
    fn respond(
        input: &Input,
        init_message: &Self::InitMessage,
    ) -> (PakeOutput, Self::RespondMessage);
    fn recv(self, respond_message: &Self::RespondMessage) -> PakeOutput;
}
pub struct CPaceRistretto255 {
    step_one_out: Step1Out,
}

#[derive(Debug, PartialEq)]
pub struct CPaceRistretto255InitMessage([u8; STEP1_PACKET_BYTES]);

impl EncodedSizeUser for CPaceRistretto255InitMessage {
    type EncodedSize = U48;

    fn from_bytes(enc: &Encoded<Self>) -> Self {
        let mut arr = [0u8; STEP1_PACKET_BYTES];
        arr.clone_from_slice(&enc[..STEP1_PACKET_BYTES]);
        Self(arr)
    }

    fn as_bytes(&self) -> Encoded<Self> {
        self.0.into()
    }
}

#[derive(Debug, PartialEq)]
pub struct CPaceRistretto255RespondMessage([u8; STEP2_PACKET_BYTES]);

impl EncodedSizeUser for CPaceRistretto255RespondMessage {
    type EncodedSize = U32;

    fn from_bytes(enc: &Encoded<Self>) -> Self {
        let mut arr = [0u8; STEP2_PACKET_BYTES];
        arr.clone_from_slice(&enc[..STEP2_PACKET_BYTES]);
        Self(arr)
    }

    fn as_bytes(&self) -> Encoded<Self> {
        self.0.into()
    }
}

impl Pake for CPaceRistretto255 {
    type InitMessage = CPaceRistretto255InitMessage;
    type RespondMessage = CPaceRistretto255RespondMessage;

    fn init(input: &Input) -> (Self::InitMessage, Self) {
        let step_one_out = CPace::step1(
            &input.password,
            &input.initiator_id,
            &input.responder_id,
            input.associated_data.as_deref(),
        )
        .unwrap();

        let packet = step_one_out.packet();

        (CPaceRistretto255InitMessage(packet), Self { step_one_out })
    }

    fn respond(
        input: &Input,
        init_message: &Self::InitMessage,
    ) -> (PakeOutput, Self::RespondMessage) {
        let step_two_out = CPace::step2(
            &init_message.0,
            &input.password,
            &input.initiator_id,
            &input.responder_id,
            input.associated_data.as_deref(),
        )
        .unwrap();

        let packet = step_two_out.packet();

        let mut output: PakeOutput = [0; PAKE_OUTPUT_SIZE];
        output[..32].clone_from_slice(&step_two_out.shared_keys().k1);
        output[32..].clone_from_slice(&step_two_out.shared_keys().k2);

        (output, CPaceRistretto255RespondMessage(packet))
    }

    fn recv(self, respond_message: &Self::RespondMessage) -> PakeOutput {
        let shared_keys = self.step_one_out.step3(&respond_message.0).unwrap();
        let mut output: PakeOutput = [0; PAKE_OUTPUT_SIZE];
        output[..32].clone_from_slice(&shared_keys.k1);
        output[32..].clone_from_slice(&shared_keys.k2);

        output
    }
}
