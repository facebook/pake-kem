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
    let input = Input {
        password: "password".to_string(),
        initiator_id: "initiator".to_string(),
        responder_id: "responder".to_string(),
    };

    let mut initiator_rng = OsRng;
    let mut responder_rng = OsRng;

    let (initiator, message_one) =
        Initiator::<DefaultCipherSuite>::start(&input, &mut initiator_rng);

    let message_one_serialized = message_one.as_bytes();
    println!(
        "message_one bytes: {:?}",
        hex::encode(message_one_serialized)
    );
    let message_one_deserialized = MessageOne::from_bytes(&message_one_serialized);

    let (responder, message_two) = Responder::<DefaultCipherSuite>::start(
        &input,
        &message_one_deserialized,
        &mut responder_rng,
    );

    let message_two_serialized = message_two.as_bytes();
    println!(
        "message_two bytes: {:?}",
        hex::encode(message_two_serialized)
    );
    let message_two_deserialized = MessageTwo::from_bytes(&message_two_serialized);

    let (initiator_output, message_three) =
        initiator.finish(&message_two_deserialized, &mut initiator_rng);

    let message_three_serialized = message_three.as_bytes();
    println!(
        "message_three bytes: {:?}",
        hex::encode(message_three_serialized)
    );
    let message_three_deserialized = MessageThree::from_bytes(&message_three_serialized);

    let responder_output = responder.finish(&message_three_deserialized);

    assert_eq!(initiator_output, responder_output);
}
