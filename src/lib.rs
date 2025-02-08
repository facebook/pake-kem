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
//! struct DefaultCipherSuite;
//! impl CipherSuite for DefaultCipherSuite {
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
//! end up with the same shared secret (with overwhelming probability). Moreover, the
//! protocol execution is likely to end early (after [`Initiator::finish()`] or [`Responder::finish()`])
//! with an error returned.
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
//! # struct DefaultCipherSuite;
//! # impl CipherSuite for DefaultCipherSuite {
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
//! let (initiator, message_one) = Initiator::<DefaultCipherSuite>::start(&input, &mut initiator_rng)
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
//! # struct DefaultCipherSuite;
//! # impl CipherSuite for DefaultCipherSuite {
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
//! # let (initiator, message_one) = Initiator::<DefaultCipherSuite>::start(&input, &mut initiator_rng)
//! #    .expect("Error with Initiator::start()");
//! # let message_one_bytes = message_one.as_bytes();
//! # // Send message_one_bytes over the wire to the responder
//! use pake_kem::MessageOne;
//! use pake_kem::Responder;
//!
//! let mut responder_rng = OsRng;
//! let message_one = MessageOne::from_bytes(&message_one_bytes);
//! let (responder, message_two) =
//!     Responder::<DefaultCipherSuite>::start(&input, &message_one, &mut responder_rng)
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
//! # struct DefaultCipherSuite;
//! # impl CipherSuite for DefaultCipherSuite {
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
//! # let (initiator, message_one) = Initiator::<DefaultCipherSuite>::start(&input, &mut initiator_rng)
//! #    .expect("Error with Initiator::start()");
//! # let message_one_bytes = message_one.as_bytes();
//! # // Send message_one_bytes over the wire to the responder
//! # use pake_kem::MessageOne;
//! # use pake_kem::Responder;
//! #
//! # let mut responder_rng = OsRng;
//! # let message_one = MessageOne::from_bytes(&message_one_bytes);
//! # let (responder, message_two) =
//! #     Responder::<DefaultCipherSuite>::start(&input, &message_one, &mut responder_rng)
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
//! # struct DefaultCipherSuite;
//! # impl CipherSuite for DefaultCipherSuite {
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
//! # let (initiator, message_one) = Initiator::<DefaultCipherSuite>::start(&input, &mut initiator_rng)
//! #    .expect("Error with Initiator::start()");
//! # let message_one_bytes = message_one.as_bytes();
//! # // Send message_one_bytes over the wire to the responder
//! # use pake_kem::MessageOne;
//! # use pake_kem::Responder;
//! #
//! # let mut responder_rng = OsRng;
//! # let message_one = MessageOne::from_bytes(&message_one_bytes);
//! # let (responder, message_two) =
//! #     Responder::<DefaultCipherSuite>::start(&input, &message_one, &mut responder_rng)
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

mod errors;
mod messages;
mod pake;
mod protocol;

// Exports
pub use errors::PakeKemError;
pub use messages::{MessageOne, MessageThree, MessageTwo};
pub use pake::CPaceRistretto255;
pub use protocol::{CipherSuite, DefaultCipherSuite, Initiator, Input, Output, Responder};

// Re-exports
pub use hkdf::hmac::digest::array::Array;
pub use ml_kem::EncodedSizeUser;
pub use rand_core;

#[cfg(test)]
mod tests;
