use rand_core::OsRng;

use crate::{
    DefaultCipherSuite, EncodedSizeUser, Initiator, Input, MessageOne, MessageThree, MessageTwo,
    PakeKemError, Responder,
};

struct TestStructs {
    input: Input,
    initiator: Initiator<DefaultCipherSuite>,
    responder: Responder<DefaultCipherSuite>,
    message_one: MessageOne<DefaultCipherSuite>,
    message_two: MessageTwo<DefaultCipherSuite>,
    message_three: MessageThree<DefaultCipherSuite>,
}

fn prepare_test_structs() -> TestStructs {
    let input = Input::new(b"password", b"initiator_id", b"responder_id");
    let (initiator, message_one) = Initiator::<DefaultCipherSuite>::start(&input, &mut OsRng)
        .expect("Error with Initiator::start()");
    let initiator_clone = Initiator::from_bytes(&initiator.as_bytes());

    let (responder, message_two) =
        Responder::<DefaultCipherSuite>::start(&input, &message_one, &mut OsRng)
            .expect("Error with Responder::start()");

    let (_, message_three) = initiator_clone
        .finish(&message_two, &mut OsRng)
        .expect("Error with Initiator::finish()");

    TestStructs {
        input,
        initiator,
        responder,
        message_one,
        message_two,
        message_three,
    }
}

fn corrupt_struct<T: EncodedSizeUser>(input: &T) -> T {
    let mut bad_bytes = input.as_bytes();
    for i in 0..bad_bytes.len() {
        bad_bytes[i] = bad_bytes[i].wrapping_add(1);
    }
    T::from_bytes(&bad_bytes)
}

#[test]
fn test_normal_deserialization_for_structs() {
    let structs = prepare_test_structs();
    assert_eq!(
        structs.initiator.as_bytes(),
        Initiator::<DefaultCipherSuite>::from_bytes(&structs.initiator.as_bytes()).as_bytes()
    );
    assert_eq!(
        structs.responder.as_bytes(),
        Responder::<DefaultCipherSuite>::from_bytes(&structs.responder.as_bytes()).as_bytes()
    );
    assert_eq!(
        structs.message_one.as_bytes(),
        MessageOne::<DefaultCipherSuite>::from_bytes(&structs.message_one.as_bytes()).as_bytes()
    );
    assert_eq!(
        structs.message_two.as_bytes(),
        MessageTwo::<DefaultCipherSuite>::from_bytes(&structs.message_two.as_bytes()).as_bytes()
    );
    assert_eq!(
        structs.message_three.as_bytes(),
        MessageThree::<DefaultCipherSuite>::from_bytes(&structs.message_three.as_bytes())
            .as_bytes()
    );
}

#[test]
fn test_corrupt_initiator() {
    let structs = prepare_test_structs();
    let corrupt_initiator = corrupt_struct::<Initiator<DefaultCipherSuite>>(&structs.initiator);
    match corrupt_initiator.finish(&structs.message_two, &mut OsRng) {
        Err(PakeKemError::MacError(_)) => {}
        _ => panic!("Expected PakeKemError::MacError"),
    }
}

#[test]
fn test_corrupt_responder() {
    let structs = prepare_test_structs();
    let corrupt_responder = corrupt_struct::<Responder<DefaultCipherSuite>>(&structs.responder);
    match corrupt_responder.finish(&structs.message_three) {
        Err(PakeKemError::MacError(_)) => {}
        _ => panic!("Expected PakeKemError::MacError"),
    }
}

#[test]
fn test_corrupt_message_one() {
    let structs = prepare_test_structs();
    let corrupt_message_one =
        corrupt_struct::<MessageOne<DefaultCipherSuite>>(&structs.message_one);
    assert!(Responder::start(&structs.input, &corrupt_message_one, &mut OsRng).is_ok());
}

#[test]
fn test_corrupt_message_two() {
    let structs = prepare_test_structs();
    let corrupt_message_two =
        corrupt_struct::<MessageTwo<DefaultCipherSuite>>(&structs.message_two);
    match structs.initiator.finish(&corrupt_message_two, &mut OsRng) {
        Err(PakeKemError::MacError(_)) => {}
        _ => panic!("Expected PakeKemError::MacError"),
    }
}

#[test]
fn test_corrupt_message_three() {
    let structs = prepare_test_structs();
    let corrupt_message_three =
        corrupt_struct::<MessageThree<DefaultCipherSuite>>(&structs.message_three);
    match structs.responder.finish(&corrupt_message_three) {
        Err(PakeKemError::MacError(_)) => {}
        _ => panic!("Expected PakeKemError::MacError"),
    }
}
