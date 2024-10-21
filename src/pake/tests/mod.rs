// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

use super::cpace::*;
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::Scalar;
use serde_json::Value;

mod cpace_test_vectors;
mod test_serialization;

fn rfc_to_json(input: &str) -> Value {
    let mut output = String::new();
    for line in input.lines() {
        let trimmed_line = line.trim().replace("#", "");
        output.push_str(&trimmed_line);
    }
    let decoded = String::from_utf8(
        BASE64_STANDARD
            .decode(&output)
            .expect("Could not decode from base64"),
    )
    .expect("Could not encode the decoded base64 into a utf8 String");
    let json = serde_json::from_str(decoded.as_str()).expect("Could not parse into json");
    json
}

fn parse_json_key(json: &Value, key: &str) -> String {
    let value = json.get(key).expect("Could not get the key");
    let value = value
        .as_str()
        .unwrap_or_else(|| panic!("Could not get the value as a string: {}", value));
    let value = value.replace("\"", "");
    value.to_lowercase()
}

#[test]
fn test_prepend_len() {
    let vectors = rfc_to_json(cpace_test_vectors::PREPEND_LEN_TEST_VECTORS);
    assert_eq!(
        parse_json_key(&vectors, "prepend_len(b)"),
        hex::encode(prepend_len(b""))
    );
    assert_eq!(
        parse_json_key(&vectors, "prepend_len(b\"1234\")"),
        hex::encode(prepend_len(b"1234"))
    );
    assert_eq!(
        parse_json_key(&vectors, "prepend_len(bytes(range(127)))"),
        hex::encode(prepend_len(&(0..127).collect::<Vec<u8>>()))
    );
    assert_eq!(
        parse_json_key(&vectors, "prepend_len(bytes(range(128)))"),
        hex::encode(prepend_len(&(0..128).collect::<Vec<u8>>()))
    );
}

#[test]
fn test_lv_cat() {
    // Taken from <https://www.ietf.org/archive/id/draft-irtf-cfrg-cpace-12.html#appendix-A.1.4>
    // lv_cat(b"1234",b"5",b"",b"6789"): (length: 13 bytes)
    // 04313233340135000436373839
    assert_eq!(
        "04313233340135000436373839",
        hex::encode(lv_cat(&[b"1234", b"5", b"", b"6789"]))
    );
}

#[test]
fn test_transcript_ir() {
    /*
    Taken from <https://www.ietf.org/archive/id/draft-irtf-cfrg-cpace-12.html#appendix-A.3.5>
      transcript_ir(b"123", b"PartyA", b"234",b"PartyB"):
        (length: 22 bytes)
            03313233065061727479410332333406506172747942
        transcript_ir(b"3456",b"PartyA",b"2345",b"PartyB"):
        (length: 24 bytes)
            043334353606506172747941043233343506506172747942
    */
    assert_eq!(
        "03313233065061727479410332333406506172747942",
        hex::encode(transcript_ir(b"123", b"PartyA", b"234", b"PartyB"))
    );
    assert_eq!(
        "043334353606506172747941043233343506506172747942",
        hex::encode(transcript_ir(b"3456", b"PartyA", b"2345", b"PartyB"))
    );
}

fn compute_generator_test_vectors() -> RistrettoPoint {
    let vectors = rfc_to_json(cpace_test_vectors::CALCULATE_GENERATOR_TEST_VECTORS);

    calculate_generator(
        &hex::decode(parse_json_key(&vectors, "PRS")).unwrap(),
        &hex::decode(parse_json_key(&vectors, "CI")).unwrap(),
        &hex::decode(parse_json_key(&vectors, "sid")).unwrap(),
    )
}

#[test]
fn test_calculate_generator() {
    let vectors = rfc_to_json(cpace_test_vectors::CALCULATE_GENERATOR_TEST_VECTORS);

    assert_eq!(
        parse_json_key(&vectors, "generator_string(G.DSI,PRS,CI,sid,H.s_in_bytes)"),
        hex::encode(generator_string(
            &hex::decode(parse_json_key(&vectors, "DSI")).unwrap(),
            &hex::decode(parse_json_key(&vectors, "PRS")).unwrap(),
            &hex::decode(parse_json_key(&vectors, "CI")).unwrap(),
            &hex::decode(parse_json_key(&vectors, "sid")).unwrap(),
            vectors.get("H.s_in_bytes").unwrap().as_i64().unwrap() as i32
        )),
    );

    assert_eq!(
        parse_json_key(&vectors, "encoded generator g"),
        hex::encode(
            calculate_generator(
                &hex::decode(parse_json_key(&vectors, "PRS")).unwrap(),
                &hex::decode(parse_json_key(&vectors, "CI")).unwrap(),
                &hex::decode(parse_json_key(&vectors, "sid")).unwrap(),
            )
            .compress()
            .to_bytes()
        ),
    );
}

#[test]
fn test_initiator_message_from_generator() {
    let g = compute_generator_test_vectors();

    /*
    Taken from <https://www.ietf.org/archive/id/draft-irtf-cfrg-cpace-12.html#appendix-B.3.2>
        Inputs
            ADa = b'ADa'
            ya (little endian): (length: 32 bytes)
            da3d23700a9e5699258aef94dc060dfda5ebb61f02a5ea77fad53f4f
            f0976d08
        Outputs
            Ya: (length: 32 bytes)
            d40fb265a7abeaee7939d91a585fe59f7053f982c296ec413c624c66
            9308f87a
    */

    assert_eq!(
        "d40fb265a7abeaee7939d91a585fe59f7053f982c296ec413c624c669308f87a",
        hex::encode(
            initiator_message_from_generator(
                &g,
                hex::decode("da3d23700a9e5699258aef94dc060dfda5ebb61f02a5ea77fad53f4ff0976d08")
                    .unwrap()
                    .try_into()
                    .ok()
                    .and_then(|bytes| Scalar::from_canonical_bytes(bytes).into())
                    .unwrap(),
            )
            .compress()
            .to_bytes()
        ),
    );
}

#[test]
fn test_responder_message_from_generator() {
    let g = compute_generator_test_vectors();

    /*
    Taken from <https://www.ietf.org/archive/id/draft-irtf-cfrg-cpace-12.html#appendix-B.3.3>
        Inputs
            ADb = b'ADb'
            yb (little endian): (length: 32 bytes)
            d2316b454718c35362d83d69df6320f38578ed5984651435e2949762
            d900b80d
        Outputs
            Yb: (length: 32 bytes)
            08bcf6e9777a9c313a3db6daa510f2d398403319c2341bd506a92e67
            2eb7e307
    */

    assert_eq!(
        "08bcf6e9777a9c313a3db6daa510f2d398403319c2341bd506a92e672eb7e307",
        hex::encode(
            responder_message_from_generator(
                &g,
                hex::decode("d2316b454718c35362d83d69df6320f38578ed5984651435e2949762d900b80d")
                    .unwrap()
                    .try_into()
                    .ok()
                    .and_then(|bytes| Scalar::from_canonical_bytes(bytes).into())
                    .unwrap(),
            )
            .compress()
            .to_bytes()
        ),
    );
}

#[test]
fn test_scalar_mult_vfy() {
    /*
    Taken from <https://www.ietf.org/archive/id/draft-irtf-cfrg-cpace-12.html#appendix-B.3.4>
    scalar_mult_vfy(ya,Yb): (length: 32 bytes)
        e22b1ef7788f661478f3cddd4c600774fc0f41e6b711569190ff88fa
        0e607e09
    scalar_mult_vfy(yb,Ya): (length: 32 bytes)
        e22b1ef7788f661478f3cddd4c600774fc0f41e6b711569190ff88fa
        0e607e09
    */
    assert_eq!(
        "e22b1ef7788f661478f3cddd4c600774fc0f41e6b711569190ff88fa0e607e09",
        hex::encode(
            scalar_mult_vfy(
                &hex::decode("08bcf6e9777a9c313a3db6daa510f2d398403319c2341bd506a92e672eb7e307")
                    .unwrap(),
                &hex::decode("da3d23700a9e5699258aef94dc060dfda5ebb61f02a5ea77fad53f4ff0976d08")
                    .unwrap()
                    .try_into()
                    .ok()
                    .and_then(|bytes| Scalar::from_canonical_bytes(bytes).into())
                    .unwrap(),
            )
            .compress()
            .to_bytes()
        ),
    );

    assert_eq!(
        "e22b1ef7788f661478f3cddd4c600774fc0f41e6b711569190ff88fa0e607e09",
        hex::encode(
            scalar_mult_vfy(
                &hex::decode("d40fb265a7abeaee7939d91a585fe59f7053f982c296ec413c624c669308f87a")
                    .unwrap(),
                &hex::decode("d2316b454718c35362d83d69df6320f38578ed5984651435e2949762d900b80d")
                    .unwrap()
                    .try_into()
                    .ok()
                    .and_then(|bytes| Scalar::from_canonical_bytes(bytes).into())
                    .unwrap(),
            )
            .compress()
            .to_bytes()
        ),
    );
}

#[test]
fn test_calculate_isk() {
    let vectors = rfc_to_json(cpace_test_vectors::TEST_VECTORS);
    println!("{}", serde_json::to_string_pretty(&vectors).unwrap());

    assert_eq!(
        parse_json_key(&vectors, "ISK_IR"),
        hex::encode(calculate_isk(
            &hex::decode(parse_json_key(&vectors, "sid")).unwrap(),
            &hex::decode(parse_json_key(&vectors, "K")).unwrap(),
            &hex::decode(parse_json_key(&vectors, "Ya")).unwrap(),
            &hex::decode(parse_json_key(&vectors, "ADa")).unwrap(),
            &hex::decode(parse_json_key(&vectors, "Yb")).unwrap(),
            &hex::decode(parse_json_key(&vectors, "ADb")).unwrap(),
        ))
    );
}
