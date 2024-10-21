// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

use ml_kem::EncodedSizeUser;
use pake_kem::rand_core::OsRng;
use pake_kem::DefaultCipherSuite;
use pake_kem::Initiator;
use pake_kem::Input;
use pake_kem::MessageOne;
use pake_kem::MessageThree;
use pake_kem::MessageTwo;
use pake_kem::Responder;

fn main() {
    let input = Input::new(b"password", b"initiator", b"responder");

    let mut initiator_rng = OsRng;
    let mut responder_rng = OsRng;

    let (initiator, message_one) =
        Initiator::<DefaultCipherSuite>::start(&input, &mut initiator_rng)
            .expect("Error with Initiator::start()");

    let initiator_serialized = initiator.as_bytes();
    println!(
        "initiator bytes ({} bytes): {:?}",
        initiator_serialized.len(),
        hex::encode(initiator_serialized)
    );

    let message_one_serialized = message_one.as_bytes();
    println!(
        "message_one bytes ({} bytes): {:?}",
        message_one_serialized.len(),
        hex::encode(message_one_serialized)
    );
    let message_one_deserialized = MessageOne::from_bytes(&message_one_serialized);

    let (responder, message_two) = Responder::<DefaultCipherSuite>::start(
        &input,
        &message_one_deserialized,
        &mut responder_rng,
    )
    .expect("Error with Responder::start()");
    let responder_serialized = responder.as_bytes();
    println!(
        "responder bytes ({} bytes): {:?}",
        responder_serialized.len(),
        hex::encode(responder_serialized)
    );

    let message_two_serialized = message_two.as_bytes();
    println!(
        "message_two bytes ({} bytes): {:?}",
        message_two_serialized.len(),
        hex::encode(message_two_serialized)
    );
    let message_two_deserialized = MessageTwo::from_bytes(&message_two_serialized);

    let initiator = Initiator::<DefaultCipherSuite>::from_bytes(&initiator_serialized);
    let (initiator_output, message_three) = initiator
        .finish(&message_two_deserialized, &mut initiator_rng)
        .expect("Error with Initiator::finish()");

    let message_three_serialized = message_three.as_bytes();
    println!(
        "message_three bytes ({} bytes): {:?}",
        message_three_serialized.len(),
        hex::encode(message_three_serialized)
    );
    let message_three_deserialized = MessageThree::from_bytes(&message_three_serialized);

    let responder_output = Responder::<DefaultCipherSuite>::from_bytes(&responder_serialized)
        .finish(&message_three_deserialized)
        .expect("Error with Responder::finish()");

    println!(
        "initiator_output: ({} bytes): {:?}",
        initiator_output.0.len(),
        initiator_output
    );

    assert_eq!(initiator_output, responder_output);
}
