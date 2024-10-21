// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This source code is dual-licensed under either the MIT license found in the
// LICENSE-MIT file in the root directory of this source tree or the Apache
// License, Version 2.0 found in the LICENSE-APACHE file in the root directory
// of this source tree. You may select, at your option, one of the above-listed
// licenses.

use super::*;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::traits::Identity;
use curve25519_dalek::Scalar;
use hkdf::hmac::digest::array::typenum::{U32, U64};
use ml_kem::{Encoded, EncodedSizeUser};
use rand_core::{CryptoRng, RngCore};
use sha2::Digest;
use sha2::Sha512;

/// Constant defined in <https://www.ietf.org/archive/id/draft-irtf-cfrg-cpace-12.html#section-7.3>
const DSI: &[u8; 17] = b"CPaceRistretto255";
const DSI_ISK: &[u8; 21] = b"CPaceRistretto255_ISK";

/// Constant defined in <https://www.ietf.org/archive/id/draft-irtf-cfrg-cpace-12.html#section-5.1>
const SHA512_S_IN_BYTES: i32 = 128;

/// An implementation of the `CPace` protocol using Ristretto255 and SHA-512.
pub struct CPaceRistretto255 {
    init_message_bytes: [u8; 32],
    scalar: Scalar,
}

#[derive(Debug, PartialEq)]
pub struct CPaceRistretto255InitMessage([u8; 32]);

impl EncodedSizeUser for CPaceRistretto255InitMessage {
    type EncodedSize = U32;

    fn from_bytes(enc: &Encoded<Self>) -> Self {
        let mut arr = [0u8; 32];
        arr.clone_from_slice(&enc[..32]);
        Self(arr)
    }

    fn as_bytes(&self) -> Encoded<Self> {
        self.0.into()
    }
}

#[derive(Debug, PartialEq)]
pub struct CPaceRistretto255RespondMessage([u8; 32]);

impl EncodedSizeUser for CPaceRistretto255RespondMessage {
    type EncodedSize = U32;

    fn from_bytes(enc: &Encoded<Self>) -> Self {
        let mut arr = [0u8; 32];
        arr.clone_from_slice(&enc[..32]);
        Self(arr)
    }

    fn as_bytes(&self) -> Encoded<Self> {
        self.0.into()
    }
}

impl EncodedSizeUser for CPaceRistretto255 {
    type EncodedSize = U64;

    fn from_bytes(enc: &Encoded<Self>) -> Self {
        let mut arr = [0u8; 32];
        arr.clone_from_slice(&enc[..32]);
        let mut scalar_bytes = [0u8; 32];
        scalar_bytes.clone_from_slice(&enc[32..]);
        Self {
            init_message_bytes: arr,
            scalar: Scalar::from_bytes_mod_order(scalar_bytes),
        }
    }

    fn as_bytes(&self) -> Encoded<Self> {
        let mut arr = [0u8; 64];
        arr[..32].clone_from_slice(&self.init_message_bytes);
        arr[32..].clone_from_slice(&self.scalar.to_bytes());
        arr.into()
    }
}

impl Pake for CPaceRistretto255 {
    type InitMessage = CPaceRistretto255InitMessage;
    type RespondMessage = CPaceRistretto255RespondMessage;

    fn init<R: RngCore + CryptoRng>(input: &Input, rng: &mut R) -> (Self::InitMessage, Self) {
        let context = [
            prepend_len(&input.initiator_id),
            prepend_len(&input.responder_id),
        ]
        .concat();
        let g = calculate_generator(&input.password, &context, &[]);
        let scalar = Scalar::random(rng);
        let message = initiator_message_from_generator(&g, scalar);
        let init_message_bytes = message.compress().to_bytes();

        (
            CPaceRistretto255InitMessage(init_message_bytes),
            Self {
                init_message_bytes,
                scalar,
            },
        )
    }

    fn respond<R: RngCore + CryptoRng>(
        input: &Input,
        init_message: &Self::InitMessage,
        rng: &mut R,
    ) -> (Option<PakeOutput>, Self::RespondMessage) {
        let context = [
            prepend_len(&input.initiator_id),
            prepend_len(&input.responder_id),
        ]
        .concat();
        let g = calculate_generator(&input.password, &context, &[]);
        let scalar = Scalar::random(rng);
        let message = responder_message_from_generator(&g, scalar);
        let respond_message_bytes = message.compress().to_bytes();

        let k = scalar_mult_vfy(&init_message.0, &scalar);
        let output = match k == RistrettoPoint::identity() {
            true => None,
            false => Some(calculate_isk(
                &[],
                &k.compress().to_bytes(),
                &init_message.0,
                &[],
                &message.compress().to_bytes(),
                &[],
            )),
        };

        (
            output,
            CPaceRistretto255RespondMessage(respond_message_bytes),
        )
    }

    fn recv(self, respond_message: &Self::RespondMessage) -> Option<PakeOutput> {
        let k = scalar_mult_vfy(&respond_message.0, &self.scalar);

        match k == RistrettoPoint::identity() {
            true => None,
            false => Some(calculate_isk(
                &[],
                &k.compress().to_bytes(),
                &self.init_message_bytes,
                &[],
                &respond_message.0,
                &[],
            )),
        }
    }
}

/*
Defined here: <https://www.ietf.org/archive/id/draft-irtf-cfrg-cpace-12.html#appendix-A.1.1>

def prepend_len(data):
"prepend LEB128 encoding of length"
length = len(data)
length_encoded = b""
while True:
    if length < 128:
        length_encoded += bytes([length])
    else:
        length_encoded += bytes([(length & 0x7f) + 0x80])
    length = int(length >> 7)
    if length == 0:
        break;
return length_encoded + data
*/
pub(crate) fn prepend_len(data: &[u8]) -> Vec<u8> {
    let mut length = data.len();
    let mut length_encoded = Vec::new();
    loop {
        if length < 128 {
            length_encoded.push(length as u8);
        } else {
            length_encoded.push((length & 0x7f) as u8 + 0x80);
        }
        length >>= 7;
        if length == 0 {
            break;
        }
    }
    length_encoded.extend_from_slice(data);
    length_encoded
}

/*
Defined here: <https://www.ietf.org/archive/id/draft-irtf-cfrg-cpace-12.html#appendix-A.1.3>
  def lv_cat(*args):
      result = b""
      for arg in args:
          result += prepend_len(arg)
      return result
*/
pub(crate) fn lv_cat(args: &[&[u8]]) -> Vec<u8> {
    let mut result = Vec::new();
    for arg in args {
        result.extend_from_slice(&prepend_len(arg));
    }
    result
}

/*
Taken from <https://www.ietf.org/archive/id/draft-irtf-cfrg-cpace-12.html#appendix-A.2>
def generator_string(DSI,PRS,CI,sid,s_in_bytes):
    # Concat all input fields with prepended length information.
    # Add zero padding in the first hash block after DSI and PRS.
    len_zpad = max(0,s_in_bytes - 1 - len(prepend_len(PRS))
                     - len(prepend_len(DSI)))
    return lv_cat(DSI, PRS, zero_bytes(len_zpad),
                           CI, sid)
*/
pub(crate) fn generator_string(
    dsi: &[u8],
    prs: &[u8],
    ci: &[u8],
    sid: &[u8],
    s_in_bytes: i32,
) -> Vec<u8> {
    let len_zpad = core::cmp::max(
        0,
        s_in_bytes - 1 - prepend_len(prs).len() as i32 - prepend_len(dsi).len() as i32,
    );
    let zpad = vec![0u8; len_zpad as usize];

    lv_cat(&[dsi, prs, &zpad, ci, sid])
}

pub(crate) fn calculate_generator(prs: &[u8], ci: &[u8], sid: &[u8]) -> RistrettoPoint {
    let gen_str = generator_string(&DSI[..], prs, ci, sid, SHA512_S_IN_BYTES);
    let mut hasher = Sha512::new();
    hasher.update(gen_str);
    let hash_output = hasher.finalize();
    RistrettoPoint::from_uniform_bytes(&hash_output.into())
}

pub(crate) fn initiator_message_from_generator(g: &RistrettoPoint, ya: Scalar) -> RistrettoPoint {
    g * ya
}

pub(crate) fn responder_message_from_generator(g: &RistrettoPoint, yb: Scalar) -> RistrettoPoint {
    g * yb
}

pub(crate) fn scalar_mult_vfy(point_bytes: &[u8], scalar: &Scalar) -> RistrettoPoint {
    let point = CompressedRistretto::from_slice(point_bytes)
        .unwrap_or(RistrettoPoint::identity().compress())
        .decompress()
        .filter(|point| point != &RistrettoPoint::identity())
        .unwrap_or(RistrettoPoint::identity());
    point * scalar
}

pub(crate) fn calculate_isk(
    sid: &[u8],
    k: &[u8],
    ya: &[u8],
    ada: &[u8],
    yb: &[u8],
    adb: &[u8],
) -> [u8; 64] {
    let prefix = lv_cat(&[&DSI_ISK[..], sid, k]);
    let transcript = transcript_ir(ya, ada, yb, adb);
    let mut hasher = Sha512::new();
    hasher.update(prefix);
    hasher.update(transcript);

    let mut output = [0u8; 64];
    output.copy_from_slice(&hasher.finalize());
    output
}

/*
Taken from <https://www.ietf.org/archive/id/draft-irtf-cfrg-cpace-12.html#appendix-A.3.4>
def transcript_ir(Ya,ADa,Yb,ADb):
    result = lv_cat(Ya,ADa) + lv_cat(Yb,ADb)
    return result
*/
pub(crate) fn transcript_ir(ya: &[u8], ada: &[u8], yb: &[u8], adb: &[u8]) -> Vec<u8> {
    [lv_cat(&[ya, ada]), lv_cat(&[yb, adb])].concat()
}
