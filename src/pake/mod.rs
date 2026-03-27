// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

mod cpace;
#[cfg(test)]
mod tests;

use crate::EncodedSizeUser;
use crate::Input;
use core::fmt::Debug;
pub use cpace::CPaceRistretto255;
use rand_core::CryptoRng;

pub trait Pake: EncodedSizeUser {
    type InitMessage: EncodedSizeUser + Debug + PartialEq;
    type RespondMessage: EncodedSizeUser + Debug + PartialEq;
    type Output: EncodedSizeUser + Debug + PartialEq;

    fn init<R: CryptoRng>(input: &Input, rng: &mut R) -> (Self::InitMessage, Self);
    fn respond<R: CryptoRng>(
        input: &Input,
        init_message: &Self::InitMessage,
        rng: &mut R,
    ) -> (Option<Self::Output>, Self::RespondMessage);
    fn recv(self, respond_message: &Self::RespondMessage) -> Option<Self::Output>;
}
