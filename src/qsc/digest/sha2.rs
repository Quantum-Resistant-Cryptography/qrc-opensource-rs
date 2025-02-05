/* 
* 2022 John G. Underhill
* All Rights Reserved.
*
* NOTICE:  All information contained herein is, and remains
* the property of John G. Underhill.
* The intellectual and technical concepts contained
* herein are proprietary to John G. Underhill
* and his suppliers and may be covered by U.S. and Foreign Patents,
* patents in process, and are protected by trade secret or copyright law.
* Dissemination of this information or reproduction of this material
* is strictly forbidden unless prior written permission is obtained
* from Digital Freedom Defense Incorporated.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
* 
* This library was pub(crate)lished pub(crate)licly in hopes that it would aid in prototyping
* post-quantum secure primitives for educational purposes only.
* All and any commercial uses of this library are exclusively reserved by the author
* John G. Underhill.
* Any use of this library in a commercial context must be approved by the author
* in writing.
* All rights for commercial and/or non-educational purposes, are fully reserved
* by the author.
* Contact: john.underhill@protonmail.com
*/

/*
#### Sha2
The SHA2 and HMAC implementations use two different forms of api: short-form and long-form.
The short-form api, which initializes the state, processes a message, and finalizes by producing output, all in a single function call, for example; qsc_sha512_compute(), the entire message array is processed and the hash code is written to the output array.
The long-form api uses an initialization call to prepare the state, a update call to process the message, and the finalize call, which finalizes the state and generates a hash or mac-code.
The HKDF key derivation functions HKDF(HMAC(SHA2-256/512)), use only the short-form api, single-call functions, to generate pseudo-random to an output array.
Each of the function families (SHA2, HMAC, HKDF), have a corresponding set of reference constants associated with that member, example; QSC_HKDF_256_KEY_SIZE is the minimum expected HKDF-256 key size in bytes, QSC_HMAC_512_MAC_SIZE is the minimum size of the HMAC-512 output mac-code output array.

NIST: [The SHA-2 Standard](http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf)
[Analysis of SIMD Applicability to SHA Algorithms](https://software.intel.com/sites/default/files/m/b/9/b/aciicmez.pdf)

Author: John Underhill - May 23, 2019
Updated: September 12, 2020
Rust Translation: 2024

The primary public api for SHA2 Implementation:
```rust
use qrc_opensource_rs::{
  digest::sha2::{
    qsc_hmac512_compute,
    QSC_SHA2_512_HASH, QSC_SHA2_512_RATE,
  },
  provider::rcrng::qsc_rcrng_generate,
};

let hash = &mut [0u8; QSC_SHA2_512_HASH];
let msg = &mut [0u8; QSC_SHA2_512_RATE];
qsc_rcrng_generate(msg, QSC_SHA2_512_RATE);
let key = &mut [0u8; 50];
qsc_rcrng_generate(key, 50);

/* compact api */
qsc_hmac512_compute(hash, msg, QSC_SHA2_512_RATE, key, 50);
```
```rust
use qrc_opensource_rs::{
  digest::sha2::{
    qsc_sha512_initialize, qsc_sha512_blockupdate, qsc_sha512_finalize,
    QSC_SHA2_512_HASH, QSC_SHA2_512_RATE,
    QscSha512State,
  },
  provider::rcrng::qsc_rcrng_generate,
};

let hash = &mut [0u8; QSC_SHA2_512_HASH];
let msg = &mut [0u8; QSC_SHA2_512_RATE];
qsc_rcrng_generate(msg, QSC_SHA2_512_RATE);

/* long-form api */
let ctx = &mut QscSha512State::default();
qsc_sha512_initialize(ctx);
qsc_sha512_blockupdate(ctx, msg, 1);
qsc_sha512_finalize(ctx, hash, msg, QSC_SHA2_512_RATE);
```
*/

use crate::qsc::tools::intutils::{
	qsc_intutils_be8to32,
	qsc_intutils_be8to64,
	qsc_intutils_be32to8,
	qsc_intutils_be64to8,
	qsc_intutils_clear8,
	qsc_intutils_min,
};

use std::mem::size_of;


/*
\def HMAC_256_MAC
* The HMAC-256 mac-code size in bytes
*/
pub const QSC_HMAC_256_MAC: usize = 32;

/*
\def HMAC_512_MAC
* The HMAC-512 mac-code size in bytes
*/
pub const QSC_HMAC_512_MAC: usize = 64;

/*
\def SHA2_256_HASH
* The SHA2-256 hash size in bytes
*/
pub const QSC_SHA2_256_HASH: usize = 32;

/*
\def SHA2_512_HASH
* The SHA2-512 hash size in bytes
*/
pub const QSC_SHA2_512_HASH: usize = 64;

/*
\def SHA2_256_RATE
* The SHA-256 byte absorption rate
*/
pub const QSC_SHA2_256_RATE: usize = 64;

/*
\def SHA2_512_RATE
* The SHA2-512 byte absorption rate
*/
pub const QSC_SHA2_512_RATE: usize = 128;

/*
\def SHA2_256_STATESIZE
* The SHA2-256 state array size
*/
const QSC_SHA2_STATE_SIZE: usize = 8;

/* sha2-256 */

/* \struct sha256_state
* The SHA2-256 digest state array
*/
pub struct QscSha256State {
	pub(crate) state: [u32; 8],
    pub(crate) t: u64
}
impl Default for QscSha256State {
    fn default() -> Self {
        Self {
            state: [Default::default(); 8],
            t: Default::default(),
        }
    }
}

/* \struct sha512_state
* The SHA2-512 digest state array
*/
pub struct QscSha512State {
	pub(crate) state: [u64; 8],
	pub(crate) t: [u64; 2]
}
impl Default for QscSha512State {
    fn default() -> Self {
        Self {
            state: [Default::default(); 8],
            t: [Default::default(); 2],
        }
    }
}

/* \struct hmac256_state
* The HMAC(SHA2-256) state array
*/
pub struct QscHmac256State {
	pub pstate: QscSha256State,
	pub ipad: [u8; QSC_SHA2_256_RATE],
	pub opad: [u8; QSC_SHA2_256_RATE],
}
impl Default for QscHmac256State {
    fn default() -> Self {
        Self {
            pstate: QscSha256State::default(),
            ipad: [Default::default(); QSC_SHA2_256_RATE],
            opad: [Default::default(); QSC_SHA2_256_RATE],
        }
    }
}

/* \struct hmac512_state
* The HMAC(SHA2-512) state array
*/
pub struct QscHmac512State {
	pub pstate: QscSha512State,
	pub ipad: [u8; QSC_SHA2_512_RATE],
	pub opad: [u8; QSC_SHA2_512_RATE],
}
impl Default for QscHmac512State {
    fn default() -> Self {
        Self {
            pstate: QscSha512State::default(),
            ipad: [Default::default(); QSC_SHA2_512_RATE],
            opad: [Default::default(); QSC_SHA2_512_RATE],
        }
    }
}

const SHA256_IV: [u32; 8] = [
	0x6A09E667,
	0xBB67AE85,
	0x3C6EF372,
	0xA54FF53A,
	0x510E527F,
	0x9B05688C,
	0x1F83D9AB,
	0x5BE0CD19
];
const SHA512_IV: [u64; 8] = [
	0x6A09E667F3BCC908,
	0xBB67AE8584CAA73B,
	0x3C6EF372FE94F82B,
	0xA54FF53A5F1D36F1,
	0x510E527FADE682D1,
	0x9B05688C2B3E6C1F,
	0x1F83D9ABFB41BD6B,
	0x5BE0CD19137E2179
];


fn qsc_sha256_increase(state: &mut QscSha256State, msglen: usize) {
	state.t += msglen as u64;
}
fn qsc_sha512_increase(state: &mut QscSha512State, length: usize) {
	state.t[0] += length as u64;

	if state.t[0] > 0x1FFFFFFFFFFFFFFF {
		state.t[1] += (state.t[0] >> 61) as u64;
		state.t[0] &= 0x1FFFFFFFFFFFFFFF;
	}
}


pub fn qsc_sha256_blockupdate(state: &mut QscSha256State, message: &[u8], nblocks: usize) {
    for i in 0..nblocks {
		qsc_sha256_permute(&mut state.state, &message[(i * QSC_SHA2_256_RATE)..]);
		qsc_sha256_increase(state, QSC_SHA2_256_RATE);
	}
}
pub fn qsc_sha512_blockupdate(state: &mut QscSha512State, message: &[u8], nblocks: usize) {
	for i in 0..nblocks {
		qsc_sha512_permute(&mut state.state, &message[(i * QSC_SHA2_512_RATE)..]);
		qsc_sha512_increase(state, QSC_SHA2_512_RATE);
	}
}

/**
* \brief Finalize the message state and returns the hash value in output.
* Long form api: must be used in conjunction with the initialize and update functions.
* Produces a 32-byte output code.
*
* \warning The output array must be sized correctly.
* Finalizes the message state, can not be used in consecutive calls.
* State must be initialized by the caller.
*
* \param ctx: [struct] The function state; must be initialized
* \param output: The output byte array; receives the hash code
*/
pub fn qsc_sha256_finalize(state: &mut QscSha256State, output: &mut [u8], message: &[u8], mut msglen: usize) {
	let pad = &mut [0u8; QSC_SHA2_256_RATE];

	for i in 0..msglen {
		pad[i] = message[i];
	}

	qsc_sha256_increase(state, msglen);
	let bitlen = state.t << 3;

	if msglen == QSC_SHA2_256_RATE {
		qsc_sha256_permute(&mut state.state, pad);
		msglen = 0;
	}

	pad[msglen] = 128;
	msglen += 1;

	/* padding */
	if msglen < QSC_SHA2_256_RATE {
		qsc_intutils_clear8(&mut pad[msglen..], QSC_SHA2_256_RATE - msglen);
	}

	if msglen > 56 {
		qsc_sha256_permute(&mut state.state, pad);
		qsc_intutils_clear8(pad, QSC_SHA2_256_RATE);
	}

	/* finalize state with counter and last compression */
	qsc_intutils_be32to8(&mut pad[56..], (bitlen >> 32) as u32);
	qsc_intutils_be32to8(&mut pad[60..], bitlen as u32);
	qsc_sha256_permute(&mut state.state, pad);

	for i in (0..QSC_SHA2_256_HASH).step_by(size_of::<u32>()) {
		qsc_intutils_be32to8(&mut output[i..], state.state[i / size_of::<u32>()]);
	}
}

/**
* \brief Finalize the message state and returns the SHA2-512 hash value in output.
* Long form api: must be used in conjunction with the initialize and update functions.
* Produces a 64 byte output code.
*
* \warning The output array must be sized correctly.
* Finalizes the message state, can not be used in consecutive calls.
* State must be initialized by the caller.
*
* \param ctx: [struct] The function state; must be initialized
* \param output: The output byte array; receives the hash code
*/
pub fn qsc_sha512_finalize(state: &mut QscSha512State, output: &mut [u8], message: &[u8], mut msglen: usize) {
    let pad = &mut [0u8; QSC_SHA2_512_RATE];

	qsc_sha512_increase(state, msglen);
	let bitlen = state.t[0] << 3;

	for i in 0..msglen {
		pad[i] = message[i];
	}

	if msglen == QSC_SHA2_512_RATE	{
		qsc_sha512_permute(&mut state.state, pad);
		msglen = 0;
	}

	pad[msglen] = 128;
	msglen += 1;

	/* padding */
	if msglen < QSC_SHA2_512_RATE {
		qsc_intutils_clear8(&mut pad[msglen..], QSC_SHA2_512_RATE - msglen);
	}

	if msglen > 112 {
		qsc_sha512_permute(&mut state.state, pad);
		qsc_intutils_clear8(pad, QSC_SHA2_512_RATE);
	}

	/* finalize state with counter and last compression */
	qsc_intutils_be64to8(&mut pad[112..], state.t[1]);
	qsc_intutils_be64to8(&mut pad[120..], bitlen);
	qsc_sha512_permute(&mut state.state, pad);

	for i in (0..QSC_SHA2_512_HASH).step_by(size_of::<u64>()) {
		qsc_intutils_be64to8(&mut output[i..], state.state[i / 8]);
	}
}

/**
* \brief Initializes a SHA2-256 state structure, must be called before message processing.
* Long form api: must be used in conjunction with the update and finalize functions.
*
* \param ctx: [struct] The function state
*/
pub fn qsc_sha256_initialize(state: &mut QscSha256State) {
	for i in 0..QSC_SHA2_STATE_SIZE {
		state.state[i] = SHA256_IV[i];
	}
	state.t = 0;
}

/**
* \brief Initializes a SHA2-512 state structure, must be called before message processing.
* Long form api: must be used in conjunction with the update and finalize functions.
*
* \param ctx: [struct] The function state
*/
pub fn qsc_sha512_initialize(state: &mut QscSha512State) {
    for i in 0..QSC_SHA2_STATE_SIZE {
		state.state[i] = SHA512_IV[i];
	}
	state.t[0] = 0;
	state.t[1] = 0;
}

/**
* \brief The SHA2-256 permutation function.
* Internal function: called by protocol hash and generation functions, or in the construction of other external protocols.
* Absorbs a message and permutes the state array.
*
* \param output: The function output; must be initialized
* \param input: [const] The input message byte array
*/
fn qsc_sha256_permute(output: &mut [u32], message: &[u8]) {
	let mut a = output[0];
    let mut b = output[1];
    let mut c = output[2];
    let mut d = output[3];
    let mut e = output[4];
    let mut f = output[5];
    let mut g = output[6];
    let mut h = output[7];

    let mut w = [0u32; 64];

    for i in 0..16 {
        w[i] = qsc_intutils_be8to32(&message[i * 4..i * 4 + 4]);
    }

    for i in 16..64 {
        let s0 = w[i-15].rotate_right(7) ^ w[i-15].rotate_right(18) ^ (w[i-15] >> 3);
        let s1 = w[i-2].rotate_right(17) ^ w[i-2].rotate_right(19) ^ (w[i-2] >> 10);
        w[i] = w[i-16].wrapping_add(s0).wrapping_add(w[i-7]).wrapping_add(s1);
    }

    let k: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];

    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let temp1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(k[i]).wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(maj);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }

    output[0] = output[0].wrapping_add(a);
    output[1] = output[1].wrapping_add(b);
    output[2] = output[2].wrapping_add(c);
    output[3] = output[3].wrapping_add(d);
    output[4] = output[4].wrapping_add(e);
    output[5] = output[5].wrapping_add(f);
    output[6] = output[6].wrapping_add(g);
    output[7] = output[7].wrapping_add(h);
}

/**
* \brief The SHA2-512 permutation function.
* Internal function: called by protocol hash and generation functions, or in the construction of other external protocols.
* Absorbs a message and permutes the state array.
*
* \param output: The function output; must be initialized
* \param input: [const] The input message byte array
*/
fn qsc_sha512_permute(output: &mut [u64], message: &[u8]) {
	let mut a = output[0];
    let mut b = output[1];
    let mut c = output[2];
    let mut d = output[3];
    let mut e = output[4];
    let mut f = output[5];
    let mut g = output[6];
    let mut h = output[7];

    let mut w = [0u64; 80];

    for i in 0..16 {
		w[i] = qsc_intutils_be8to64(&message[i * 8..i * 8 + 8]);
    }

    for i in 16..80 {
        let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
        let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
    }

    let k: [u64; 80] = [
        0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
        0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
        0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
        0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
        0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
        0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
        0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
        0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
        0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
        0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
        0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
        0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
        0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
        0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
        0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
        0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
        0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
        0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
    ];

    for i in 0..80 {
        let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
        let ch = (e & f) ^ ((!e) & g);
        let temp1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(k[i]).wrapping_add(w[i]);
        let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(maj);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }

    output[0] = output[0].wrapping_add(a);
    output[1] = output[1].wrapping_add(b);
    output[2] = output[2].wrapping_add(c);
    output[3] = output[3].wrapping_add(d);
    output[4] = output[4].wrapping_add(e);
    output[5] = output[5].wrapping_add(f);
    output[6] = output[6].wrapping_add(g);
    output[7] = output[7].wrapping_add(h);
}

/**
* \brief Process a message with HMAC(SHA2-256) and returns the hash code in the output byte array.
* Short form api: processes the key and complete message, and generates the MAC code with a single call.
*
* \warning The output array must be at least 32 bytes in length.
*
* \param output: The output byte array; receives the hash code
* \param message: [const] The message input byte array
* \param msglen: The number of message bytes to process
* \param key: [const] The secret key array
* \param keylen: The key array length
*/
pub fn qsc_hmac256_compute(output: &mut [u8], mut message: &[u8], mut msglen: usize, key: &[u8], mut keylen: usize) {
	let bipad = 0x36 as u8;
	let bopad = 0x5C as u8;
	let ipad = &mut [0u8; QSC_SHA2_256_RATE];
	let opad = &mut [0u8; QSC_SHA2_256_RATE];
	let tmpv = &mut [0u8; QSC_SHA2_256_HASH];
	let state = &mut QscSha256State::default();

	if keylen > QSC_SHA2_256_RATE {
		qsc_sha256_initialize(state);

		while keylen > QSC_SHA2_256_RATE {
			qsc_sha256_blockupdate(state, key, 1);
			keylen -= QSC_SHA2_256_RATE;
		}

		qsc_sha256_finalize(state, ipad, key, keylen);
	} else {
		for i in 0..keylen {
			ipad[i] = key[i];
		}
	}

	for i in 0..QSC_SHA2_256_RATE {
		opad[i] = ipad[i];
		opad[i] ^= bopad;
		ipad[i] ^= bipad;
	}

	qsc_sha256_initialize(state);
	qsc_sha256_blockupdate(state, ipad, 1);

	while msglen >= QSC_SHA2_256_RATE {
		qsc_sha256_blockupdate(state, message, 1);
		msglen -= QSC_SHA2_256_RATE;
		message = &message[QSC_SHA2_256_RATE..];
	}

	qsc_sha256_finalize(state, tmpv, message, msglen);
	qsc_sha256_initialize(state);
	qsc_sha256_blockupdate(state, opad, 1);
	qsc_sha256_finalize(state, output, tmpv, QSC_SHA2_256_HASH);
}

/**
* \brief Process a message with SHA2-512 and returns the hash code in the output byte array.
* Short form api: processes the key and complete message, and generates the MAC code with a single call.
*
* \warning The output array must be at least 128 bytes in length.
*
* \param output: The output byte array; receives the hash code
* \param message: [const] The message input byte array
* \param msglen: The number of message bytes to process
* \param key: [const] The secret key array
* \param keylen: The key array length
*/
pub fn qsc_hmac512_compute(output: &mut [u8], mut message: &[u8], mut msglen: usize, key: &[u8], mut keylen: usize) {
    let bipad = 0x36 as u8;
	let bopad = 0x5C as u8;
	let ipad = &mut [0u8; QSC_SHA2_512_RATE];
	let opad = &mut [0u8; QSC_SHA2_512_RATE];
	let tmpv = &mut [0u8; QSC_SHA2_512_RATE];
	let state = &mut QscSha512State::default();

	if keylen > QSC_SHA2_512_RATE {
		qsc_sha512_initialize(state);

		while keylen > QSC_SHA2_512_RATE {
			qsc_sha512_blockupdate(state, key, 1);
			keylen -= QSC_SHA2_512_RATE;
		}

		qsc_sha512_finalize(state, ipad, key, keylen);
	} else {
		for i in 0..keylen {
			ipad[i] = key[i];
		}
	}

	for i in 0..QSC_SHA2_512_RATE {
		opad[i] = ipad[i];
		opad[i] ^= bopad;
		ipad[i] ^= bipad;
	}

	qsc_sha512_initialize(state);
	qsc_sha512_blockupdate(state, ipad, 1);

	while msglen >= QSC_SHA2_512_RATE {
		qsc_sha512_blockupdate(state, message, 1);
		msglen -= QSC_SHA2_512_RATE;
		message = &message[QSC_SHA2_512_RATE..];
	}

	qsc_sha512_finalize(state, tmpv, message, msglen);
	qsc_sha512_initialize(state);
	qsc_sha512_blockupdate(state, opad, 1);
	qsc_sha512_finalize(state, output, tmpv, QSC_SHA2_512_HASH);
}


fn qsc_hmac256_blockupdate(state: &mut QscHmac256State, message: &[u8], nblocks: usize) {
	qsc_sha256_blockupdate(&mut state.pstate, message, nblocks);
}
fn qsc_hmac512_blockupdate(state: &mut QscHmac512State, message: &[u8], nblocks: usize) {
	qsc_sha512_blockupdate(&mut state.pstate, message, nblocks);
}

/**
* \brief Finalize the HMAC-256 message state and return the hash value in output.
* Long form api: must be used in conjunction with the initialize and update functions.
* Produces a 32 byte output code.
*
* \warning The output array must be sized correctly.
* Finalizes the message state, can not be used in consecutive calls.
* State must be initialized by the caller.
*
* \param ctx: [struct] The function state; must be initialized
* \param output: The output byte array; receives the hash code
*/

fn qsc_hmac256_finalize(state: &mut QscHmac256State, output: &mut [u8], message: &[u8], mut msglen: usize) {
	let tmpv = &mut [0u8; QSC_SHA2_256_HASH];
	let mut oft = 0;

	while msglen >= QSC_SHA2_256_RATE {
		qsc_sha256_blockupdate(&mut state.pstate, &message[oft..], 1);
		oft += QSC_SHA2_256_RATE;
		msglen -= QSC_SHA2_256_RATE;
	}

	qsc_sha256_finalize(&mut state.pstate, tmpv, &message[oft..], msglen);
	qsc_sha256_initialize(&mut state.pstate);
	qsc_sha256_blockupdate(&mut state.pstate, &state.opad, 1);
	qsc_sha256_finalize(&mut state.pstate, output, tmpv, QSC_SHA2_256_HASH);
}

/**
* \brief Finalize the HMAC-512 message state and return the hash value in output.
* Long form api: must be used in conjunction with the initialize and update functions.
* Produces a 64 byte output code.
*
* \warning The output array must be sized correctly.
* Finalizes the message state, can not be used in consecutive calls.
* State must be initialized by the caller.
*
* \param ctx: [struct] The function state; must be initialized
* \param output: The output byte array; receives the hash code
*/

fn qsc_hmac512_finalize(state: &mut QscHmac512State, output: &mut [u8], message: &[u8], mut msglen: usize) {
	let tmpv = &mut [0u8; QSC_SHA2_512_HASH];
	let mut oft = 0;

	while msglen >= QSC_SHA2_512_RATE {
		qsc_sha512_blockupdate(&mut state.pstate, &message[oft..], 1);
		oft += QSC_SHA2_512_RATE;
		msglen -= QSC_SHA2_512_RATE;
	}

	qsc_sha512_finalize(&mut state.pstate, tmpv, &message[oft..], msglen);
	qsc_sha512_initialize(&mut state.pstate);
	qsc_sha512_blockupdate(&mut state.pstate, &state.opad, 1);
	qsc_sha512_finalize(&mut state.pstate, output, tmpv, QSC_SHA2_512_HASH);
}

/**
* \brief Initializes an HMAC-256 state structure with a key, must be called before message processing.
* Long form api: must be used in conjunction with the update and finalize functions.
*
* \param ctx: [struct] The function state
* \param key: [const] The secret key array
* \param keylen: The key array length
*/
fn qsc_hmac256_initialize(state: &mut QscHmac256State, key: &[u8], mut keylen: usize) {
	let bipad = 0x36;
	let bopad = 0x5C;

	let mut oft = 0;
	qsc_intutils_clear8(&mut state.ipad, QSC_SHA2_256_RATE);

	if keylen > QSC_SHA2_256_RATE {
		qsc_sha256_initialize(&mut state.pstate);

		while keylen > QSC_SHA2_256_RATE {
			qsc_sha256_blockupdate(&mut state.pstate, &key[oft..], 1);
			oft += QSC_SHA2_256_RATE;
			keylen -= QSC_SHA2_256_RATE;
		}

		qsc_sha256_finalize(&mut state.pstate, &mut state.ipad, &key[oft..], keylen);
	} else {
		for i in 0..keylen {
			state.ipad[i] = key[i];
		}
	}

	for i in 0..QSC_SHA2_256_RATE {
		state.opad[i] = state.ipad[i];
		state.opad[i] ^= bopad;
		state.ipad[i] ^= bipad;
	}

	qsc_sha256_initialize(&mut state.pstate);
	qsc_sha256_blockupdate(&mut state.pstate, &mut state.ipad, 1);
}

/**
* \brief Initializes an HMAC-512 state structure with a key, must be called before message processing.
* Long form api: must be used in conjunction with the update and finalize functions.
*
* \param ctx: [struct] The function state
* \param key: [const] The secret key array
* \param keylen: The key array length
*/

fn qsc_hmac512_initialize(state: &mut QscHmac512State, key: &[u8], mut keylen: usize) {
	let bipad = 0x36;
	let bopad = 0x5C;

	let mut oft = 0;
	qsc_intutils_clear8(&mut state.ipad, QSC_SHA2_512_RATE);

	if keylen > QSC_SHA2_512_RATE	{
		qsc_sha512_initialize(&mut state.pstate);

		while keylen > QSC_SHA2_512_RATE {
			qsc_sha512_blockupdate(&mut state.pstate, &key[oft..], 1);
			keylen -= QSC_SHA2_512_RATE;
			oft += QSC_SHA2_512_RATE;
		}

		qsc_sha512_finalize(&mut state.pstate, &mut state.ipad, &key[oft..], keylen);
	} else {
		for i in 0..keylen {
			state.ipad[i] = key[i];
		}
	}

	for i in 0..QSC_SHA2_512_RATE {
		state.opad[i] = state.ipad[i];
		state.opad[i] ^= bopad;
		state.ipad[i] ^= bipad;
	}

	qsc_sha512_initialize(&mut state.pstate);
	qsc_sha512_blockupdate(&mut state.pstate, &mut state.ipad, 1);
}

/**
* \brief Initialize an instance of HKDF(HMAC(SHA2-256)), and output an array of pseudo-random.
* Short form api: initializes with the key and user info, and generates the output pseudo-random with a single call.
*
* \param output: The output pseudo-random byte array
* \param outlen: The output array length
* \param key: [const] The HKDF key array
* \param keylen: The key array length
* \param info: [const] The info array
* \param infolen: The info array length
*/
pub fn qsc_hkdf256_expand(mut output: &mut [u8], mut outlen: usize, key: &[u8], keylen: usize, info: &[u8], infolen: usize) {
	let state = &mut QscHmac256State::default();
	let msg = &mut [0u8; QSC_SHA2_256_RATE];
    let otp = &mut [0u8; QSC_SHA2_256_HASH];

	let mut ctr = 0;

	while outlen != 0 {
		qsc_hmac256_initialize(state, key, keylen);
		let mut mlen = infolen;
		let mut ioft = 0;

		if ctr != 0	{
			for i in 0..QSC_SHA2_256_HASH {
				msg[i] = otp[i];
			}

			let mut slen = QSC_SHA2_256_HASH;

			if infolen >= QSC_SHA2_256_HASH {
				for i in 0..QSC_SHA2_256_HASH {
					msg[slen + i] = info[i];
				}

				qsc_hmac256_blockupdate(state, msg, 1);
				mlen -= QSC_SHA2_256_HASH;
				ioft += QSC_SHA2_256_HASH;
				slen = 0;
			}

			if infolen > 0 {
				while mlen >= QSC_SHA2_256_RATE {
					qsc_hmac256_blockupdate(state, &info[ioft..], 1);
					ioft += QSC_SHA2_256_RATE;
					mlen -= QSC_SHA2_256_RATE;
				}

				for i in 0..mlen {
					msg[slen + i] = info[ioft + i];
				}
			}

			ctr += 1;
			msg[slen + mlen] = ctr as u8;
			qsc_hmac256_finalize(state, otp, msg, slen + mlen + 1);
		} else {
			while mlen >= QSC_SHA2_256_RATE {
				qsc_hmac256_blockupdate(state, &info[ioft..], 1);
				ioft += QSC_SHA2_256_RATE;
				mlen -= QSC_SHA2_256_RATE;
			}

			if infolen > 0 {
				for i in 0..mlen {
					msg[i] = info[ioft + i];
				}
			}

			ctr += 1;
			msg[mlen] = ctr;
			qsc_hmac256_finalize(state, otp, msg, mlen + 1);
		}

		let rmd = qsc_intutils_min(outlen, QSC_SHA2_256_HASH);

		for i in 0..rmd {
			output[i] = otp[i];
		}

		outlen -= rmd;
		output = &mut output[rmd..];
	}
}

/**
* \brief Initialize an instance of HKDF(HMAC(SHA2-512)), and output an array of pseudo-random.
* Short form api: initializes with the key and user info, and generates the output pseudo-random with a single call.
*
* \param output: The output pseudo-random byte array
* \param outlen: The output array length
* \param key: [const] The HKDF key array
* \param keylen: The key array length
* \param info: [const] The info array
* \param infolen: The info array length
*/
pub fn qsc_hkdf512_expand(mut output: &mut [u8], mut outlen: usize, key: &[u8], keylen: usize, info: &[u8], infolen: usize) {
    let state = &mut QscHmac512State::default();
	let msg = &mut [0u8; QSC_SHA2_512_RATE];
    let otp = &mut [0u8; QSC_SHA2_512_HASH];

	let mut ctr = 0;

	while outlen != 0 {
		qsc_hmac512_initialize(state, key, keylen);
		let mut mlen = infolen;
		let mut ioft = 0;

		if ctr != 0	{
			for i in 0..QSC_SHA2_512_HASH {
				msg[i] = otp[i];
			}

			let mut slen = QSC_SHA2_512_HASH;

			if infolen >= QSC_SHA2_512_HASH {
				for i in 0..QSC_SHA2_512_HASH {
					msg[slen + i] = info[i];
				}

				qsc_hmac512_blockupdate(state, msg, 1);
				mlen -= QSC_SHA2_512_HASH;
				ioft += QSC_SHA2_512_HASH;
				slen = 0;
			}

			if infolen > 0 {
				while mlen >= QSC_SHA2_512_RATE {
					qsc_hmac512_blockupdate(state, &info[ioft..], 1);
					ioft += QSC_SHA2_512_RATE;
					mlen -= QSC_SHA2_512_RATE;
				}

				for i in 0..mlen {
					msg[slen + i] = info[ioft + i];
				}
			}

			ctr += 1;
			msg[slen + mlen] = ctr;
			qsc_hmac512_finalize(state, otp, msg, slen + mlen + 1);
		} else {
			while mlen >= QSC_SHA2_512_RATE	{
				qsc_hmac512_blockupdate(state, &info[ioft..], 1);
				ioft += QSC_SHA2_512_RATE;
				mlen -= QSC_SHA2_512_RATE;
			}

			if infolen > 0 {
				for i in 0..mlen {
					msg[i] = info[ioft + i];
				}
			}

			ctr += 1;
			msg[mlen] = ctr;
			qsc_hmac512_finalize(state, otp, msg, mlen + 1);
		}

		let rmd = qsc_intutils_min(outlen, QSC_SHA2_512_HASH);

		for i in 0..rmd {
			output[i] = otp[i];
		}

		outlen -= rmd;
		output = &mut output[rmd..];
	}
}

/**
* \brief Extract a key from a combined key and salt input using HMAC(SHA2-256).
*
* \param output: The output pseudo-random byte array
* \param outlen: The output array length
* \param key: [const] The HKDF key array
* \param keylen: The key array length
* \param salt: [const] The salt array
* \param saltlen: The salt array length
*/
pub fn qsc_hkdf256_extract(output: &mut [u8], key: &[u8], keylen: usize, salt: &[u8], saltlen: usize) {
    let state = &mut QscHmac256State::default();

	if saltlen != 0 {
		qsc_hmac256_initialize(state, salt, saltlen);
	} else {
		let tmp = &mut [0u8; QSC_HMAC_256_MAC];
		qsc_hmac256_initialize(state, tmp, QSC_HMAC_256_MAC);
	}

	qsc_hmac256_finalize(state, output, key, keylen);
}

/**
* \brief Extract a key from a combined key and salt input using HMAC(SHA2-512).
*
* \param output: The output pseudo-random byte array
* \param outlen: The output array length
* \param key: [const] The HKDF key array
* \param keylen: The key array length
* \param salt: [const] The salt array
* \param saltlen: The salt array length
*/
pub fn qsc_hkdf512_extract(output: &mut [u8], key: &[u8], keylen: usize, salt: &[u8], saltlen: usize) {
	let state = &mut QscHmac512State::default();

	if saltlen != 0	{
		qsc_hmac512_initialize(state, salt, saltlen);
	} else {
        let tmp = &mut [0u8; QSC_HMAC_512_MAC];
		qsc_hmac512_initialize(state, tmp, QSC_HMAC_512_MAC);
	}

	qsc_hmac512_finalize(state, output, key, keylen);
}