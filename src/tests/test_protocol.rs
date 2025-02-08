// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

use crate::{DefaultCipherSuite, PakeKemError};

use crate::EncodedSizeUser; // Needed for calling as_bytes()
use crate::Initiator;
use crate::Input;
use crate::MessageOne;
use crate::MessageThree;
use crate::MessageTwo;
use crate::Responder;
use rand_core::OsRng;

#[test]
fn test_protocol() {
    let passwords = ["pw1", "pw2"];
    let initiators = ["i1", "i2"];
    let responders = ["r1", "r2"];

    for initiator_password in passwords.iter() {
        for responder_password in passwords.iter() {
            for initiator_init_id in initiators.iter() {
                for responder_init_id in initiators.iter() {
                    for initiator_resp_id in responders.iter() {
                        for responder_resp_id in responders.iter() {
                            let result = run_protocol(
                                Input::new(
                                    initiator_password.as_bytes(),
                                    initiator_init_id.as_bytes(),
                                    initiator_resp_id.as_bytes(),
                                ),
                                Input::new(
                                    responder_password.as_bytes(),
                                    responder_init_id.as_bytes(),
                                    responder_resp_id.as_bytes(),
                                ),
                            );

                            let computed_result = result.is_ok();
                            let expected_result = initiator_password == responder_password
                                && initiator_init_id == responder_init_id
                                && initiator_resp_id == responder_resp_id;
                            assert_eq!(computed_result, expected_result);
                        }
                    }
                }
            }
        }
    }
}

fn run_protocol(initiator_input: Input, responder_input: Input) -> Result<(), PakeKemError> {
    let mut initiator_rng = OsRng;
    let (initiator, message_one) =
        Initiator::<DefaultCipherSuite>::start(&initiator_input, &mut initiator_rng)
            .expect("Error with Initiator::start()");
    let message_one_bytes = message_one.as_bytes();

    // Send message_one_bytes over the wire to the responder

    let mut responder_rng = OsRng;
    let message_one = MessageOne::from_bytes(&message_one_bytes);
    let (responder, message_two) =
        Responder::<DefaultCipherSuite>::start(&responder_input, &message_one, &mut responder_rng)
            .expect("Error with Responder::start()");
    let message_two_bytes = message_two.as_bytes();
    // Send message_two_bytes over the wire to the initiator

    let message_two = MessageTwo::from_bytes(&message_two_bytes);
    let (initiator_output, message_three) = initiator.finish(&message_two, &mut initiator_rng)?;
    let message_three_bytes = message_three.as_bytes();
    // Send message_three_bytes over the wire to the responder

    let message_three = MessageThree::from_bytes(&message_three_bytes);
    let responder_output = responder.finish(&message_three)?;

    match initiator_output.0 == responder_output.0 {
        true => Ok(()),
        false => Err(PakeKemError::InvalidPakeOutput),
    }
}
