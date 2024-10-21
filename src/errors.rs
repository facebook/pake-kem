// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

use thiserror::Error;

/// The library's error type
#[derive(Error, Debug)]
pub enum PakeKemError {
    /// Error for when a deserialization fails
    #[error("Issue with deserialization")]
    Deserialization,
    /// Error for when an input has an invalid length
    #[error(transparent)]
    InvalidLength(#[from] hkdf::hmac::digest::InvalidLength),
    /// Error for when the protocol emits a failure that should abort
    #[error(transparent)]
    MacError(#[from] hkdf::hmac::digest::MacError),
}
