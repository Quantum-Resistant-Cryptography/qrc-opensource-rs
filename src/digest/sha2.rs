/* The AGPL version 3 License (AGPLv3)
*
* Copyright (c) 2024 DFD & QRC Eurosmart SA
* This file is part of the QRC Cryptographic library
*
* This program is free software : you can redistribute it and / or modify
* it under the terms of the GNU Affero General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
* See the GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU Affero General Public License
* along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

use crate::tools::intutils::{qrc_intutils_be32to8, qrc_intutils_be64to8, qrc_intutils_be8to32, qrc_intutils_be8to64, qrc_intutils_clear32, qrc_intutils_clear64, qrc_intutils_clear8, qrc_intutils_copy32, qrc_intutils_copy64, qrc_intutils_copy8, qrc_intutils_min};

use core::{mem::size_of, default::Default};

/*
\def HKDF_256_KEY
* The HKDF-256 key size in bytes
*/
pub const QRC_HKDF_256_KEY_SIZE: usize = 32;

/*
\def HKDF_512_KEY
* The HKDF-512 key size in bytes
*/
pub const QRC_HKDF_512_KEY_SIZE: usize = 64;

/*
\def HMAC_256_KEY
* The recommended HMAC(SHA2-256) key size, minimum is 32 bytes
*/
pub const QRC_HMAC_256_KEY_SIZE: usize = 64;

/*
\def HMAC_512_KEY
* The recommended HMAC(SHA2-512) key size minimum is 64 bytes
*/
pub const QRC_HMAC_512_KEY_SIZE: usize = 128;

/*
\def HMAC_256_MAC
* The HMAC-256 mac-code size in bytes
*/
pub const QRC_HMAC_256_MAC_SIZE: usize = 32;

/*
\def HMAC_512_MAC
* The HMAC-512 mac-code size in bytes
*/
pub const QRC_HMAC_512_MAC_SIZE: usize = 64;

/*
\def SHA2_256_HASH
* The SHA2-256 hash size in bytes
*/
pub const QRC_SHA2_256_HASH_SIZE: usize = 32;

/*
* \def QRC_SHA2_384_HASH_SIZE
* \brief The SHA2-384 hash size in bytes
*/
pub const QRC_SHA2_384_HASH_SIZE: usize = 48;

/*
\def SHA2_512_HASH
* The SHA2-512 hash size in bytes
*/
pub const QRC_SHA2_512_HASH_SIZE: usize = 64;

/*
\def SHA2_256_ROUNDS
* the number of rounds in the compact SHA2-256 permutation
*/
pub const QRC_SHA2_256_ROUNDS: usize = 64;

/*
\def SHA2_384_ROUNDS
* the number of rounds in the compact SHA2-384 permutation
*/
pub const QRC_SHA2_384_ROUNDS: usize = 80;

/*
\def SHA2_512_ROUNDS
* the number of rounds in the compact SHA2-512 permutation
*/
pub const QRC_SHA2_512_ROUNDS: usize = 80;

/*
\def SHA2_256_RATE
* The SHA-256 byte absorption rate
*/
pub const QRC_SHA2_256_RATE: usize = 64;

/*
\def SHA2_384_RATE
* The SHA2-384 byte absorption rate
*/
pub const QRC_SHA2_384_RATE: usize = 128;

/*
\def SHA2_512_RATE
* The SHA2-512 byte absorption rate
*/
pub const QRC_SHA2_512_RATE: usize = 128;

/*
* \def QRC_HMAC_512_RATE
* \brief The HMAC-512 input rate size in bytes
*/
pub const QRC_HMAC_512_RATE: usize = 128;

/*
\def SHA2_256_STATESIZE
* The SHA2-256 state array size
*/
pub const QRC_SHA2_STATE_SIZE: usize = 8;

/* sha2-256 */

/* \struct sha256_state
* The SHA2-256 digest state array
*/
pub struct QrcSha256State {
	pub state: [u32; QRC_SHA2_STATE_SIZE],
	pub buffer: [u8; QRC_SHA2_256_RATE],
    pub t: u64,
	pub position: usize,
}
impl Default for QrcSha256State {
    fn default() -> Self {
        Self {
            state: [Default::default(); QRC_SHA2_STATE_SIZE],
			buffer: [Default::default(); QRC_SHA2_256_RATE],
            t: Default::default(),
			position: Default::default(),
        }
    }
}

/*
* \brief Process a message with SHA2-256 and returns the hash code in the output byte array.
* Short form api: processes the entire message and computes the hash code with a single call.
*
* \warning The output array must be at least 32 bytes in length.
*
* \param output: The output byte array; receives the hash code
* \param message: [const] The message input byte array
* \param msglen: The number of message bytes to process
*/
pub fn qrc_sha256_blockcompute(output: &mut [u8], message: &[u8], mut msglen: usize) {
	let state = &mut QrcSha256State::default();

	qrc_sha256_initialize(state);
	let blocks = msglen / QRC_SHA2_256_RATE;

	if msglen >= QRC_SHA2_256_RATE {
		qrc_sha256_blockupdate(state, message, blocks);
		msglen -= blocks * QRC_SHA2_256_RATE;
	}

	qrc_sha256_blockfinalize(state, output, &message[blocks * QRC_SHA2_256_RATE..], msglen);
}

/*
* \brief Process a message with SHA2-256 and returns the hash code in the output byte array.
* Short form api: processes the entire message and computes the hash code with a single call.
*
* \warning The output array must be at least 32 bytes in length.
*
* \param output: The output byte array; receives the hash code
* \param message: [const] The message input byte array
* \param msglen: The number of message bytes to process
*/
pub fn qrc_sha256_compute(output: &mut [u8], message: &[u8], msglen: usize) {
	let state = &mut QrcSha256State::default();

	qrc_sha256_initialize(state);
	qrc_sha256_update(state, message, msglen);
	qrc_sha256_finalize(state, output);
}

/*
* \brief Dispose of the SHA2-256 state.
* This function destroys the internal state of the cipher.
*
* \param ctx: [struct] The cipher state structure
*/
pub fn qrc_sha256_dispose(state: &mut QrcSha256State) {
	qrc_intutils_clear32(&mut state.state, QRC_SHA2_STATE_SIZE);
	qrc_intutils_clear8(&mut state.buffer, QRC_SHA2_256_RATE);
	state.t = 0;
	state.position = 0;
}

/*
* \brief Update SHA2-256 with blocks of input.
* Long form api: must be used in conjunction with the initialize and finalize functions.
* Absorbs a multiple of 64-byte block lengths of input message into the state.
*
* \warning Message length must be a multiple of the rate size. \n
* State must be initialized by the caller.
*
* \param state: [struct] The function state
* \param message: [const] The input message byte array
* \param nblocks: The number of rate sized blocks to process
*/
pub fn qrc_sha256_blockupdate(state: &mut QrcSha256State, message: &[u8], nblocks: usize) {
    for i in 0..nblocks {
		qrc_sha256_permute(&mut state.state, &message[(i * QRC_SHA2_256_RATE)..]);
		qrc_sha256_increase(state, QRC_SHA2_256_RATE);
	}
}

/*
* \brief Update SHA2-256 with message input.
* Long form api: must be used in conjunction with the initialize and finalize functions.
* Absorbs a length of message input into the hash function.
*
* \warning State must be initialized by the caller.
*
* \param ctx: [struct] The function state
* \param message: [const] The input message byte array
* \param msglen: The number of message bytes to process
*/
pub fn qrc_sha256_update(state: &mut QrcSha256State, mut message: &[u8], mut msglen: usize) {
	if msglen != 0	{
		if state.position != 0 && (state.position + msglen >= QRC_SHA2_256_RATE) {
			let rmdlen = QRC_SHA2_256_RATE - state.position;

			if rmdlen != 0 {
				qrc_intutils_copy8(&mut state.buffer[state.position..], message, rmdlen);
			}

			qrc_sha256_permute(&mut state.state, &state.buffer);
			qrc_sha256_increase(state, QRC_SHA2_256_RATE);
			state.position = 0;
			message = &message[rmdlen..];
			msglen -= rmdlen;
		}

		/* sequential loop through blocks */
		while msglen >= QRC_SHA2_256_RATE {
			qrc_sha256_permute(&mut state.state, message);
			qrc_sha256_increase(state, QRC_SHA2_256_RATE);
			message = &message[QRC_SHA2_256_RATE..];
			msglen -= QRC_SHA2_256_RATE;
		}

		/* store unaligned bytes */
		if msglen != 0 {
			qrc_intutils_copy8(&mut state.buffer[state.position..], message, msglen);
			state.position += msglen;
		}
	}
}


/*
* \brief Finalize the message state and returns the hash value in output.
* Long form api: must be used in conjunction with the initialize and blockupdate functions.
* Absorb the last block of message and creates the hash value. \n
* Produces a 32 byte output code.
*
* \warning The output array must be sized correctly. \n
* Finalizes the message state, can not be used in consecutive calls.
* State must be initialized by the caller.
*
* \param state: [struct] The function state; must be initialized
* \param output: The output byte array; receives the hash code
* \param message: [const] The input message byte array
* \param msglen: The number of message bytes to process
*/
pub fn qrc_sha256_blockfinalize(state: &mut QrcSha256State, output: &mut [u8], message: &[u8], mut msglen: usize) {
	let pad = &mut [0u8; QRC_SHA2_256_RATE];

	for i in 0..msglen {
		pad[i] = message[i];
	}

	qrc_sha256_increase(state, msglen);
	let bitlen = state.t << 3;

	if msglen == QRC_SHA2_256_RATE {
		qrc_sha256_permute(&mut state.state, pad);
		msglen = 0;
	}

	pad[msglen] = 128;
	msglen += 1;

	/* padding */
	if msglen < QRC_SHA2_256_RATE {
		qrc_intutils_clear8(&mut pad[msglen..], QRC_SHA2_256_RATE - msglen);
	}

	if msglen > 56 {
		qrc_sha256_permute(&mut state.state, pad);
		qrc_intutils_clear8(pad, QRC_SHA2_256_RATE);
	}

	/* finalize state with counter and last compression */
	qrc_intutils_be32to8(&mut pad[56..], (bitlen >> 32) as u32);
	qrc_intutils_be32to8(&mut pad[60..], bitlen as u32);
	qrc_sha256_permute(&mut state.state, pad);

	for i in (0..QRC_SHA2_256_HASH_SIZE).step_by(size_of::<u32>()) {
		qrc_intutils_be32to8(&mut output[i..], state.state[i / size_of::<u32>()]);
	}
}

/*
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
pub fn qrc_sha256_finalize(state: &mut QrcSha256State, output: &mut [u8]) {
	let pad = &mut [0u8; QRC_SHA2_256_RATE];

	qrc_intutils_copy8(pad, &state.buffer, state.position);
	qrc_sha256_increase(state, state.position);
	let bitlen = state.t << 3;


	if state.position == QRC_SHA2_256_RATE {
		qrc_sha256_permute(&mut state.state, pad);
		state.position = 0;
	}

	pad[state.position] = 128;
	state.position += 1;

	/* padding */
	if state.position < QRC_SHA2_256_RATE {
		qrc_intutils_clear8(&mut pad[state.position..], QRC_SHA2_256_RATE - state.position);
	}

	if state.position > 56	{
		qrc_sha256_permute(&mut state.state, pad);
		qrc_intutils_clear8(pad, QRC_SHA2_256_RATE);
	}

	/* finalize state with counter and last compression */
	qrc_intutils_be32to8(&mut pad[56..], (bitlen >> 32) as u32);
	qrc_intutils_be32to8(&mut pad[60..], bitlen as u32);
	qrc_sha256_permute(&mut state.state, pad);

	for i in (0..QRC_SHA2_256_HASH_SIZE).step_by(size_of::<u32>()) {
		qrc_intutils_be32to8(&mut output[i..], state.state[i / size_of::<u32>()]);
	}

	qrc_sha256_dispose(state);
}

/*
* \brief Initializes a SHA2-256 state structure, must be called before message processing.
* Long form api: must be used in conjunction with the blockupdate and finalize functions.
*
* \param state: [struct] The function state
*/
pub fn qrc_sha256_initialize(state: &mut QrcSha256State) {
	qrc_intutils_copy32(&mut state.state, &SHA256_IV, 8);
	qrc_intutils_clear8(&mut state.buffer, QRC_SHA2_256_RATE);
	state.t = 0;
	state.position = 0;
}

/*
* \brief The SHA2-256 permution function.
* Internal function: called by protocol hash and generation functions, or in the construction of other external protocols.
* Permutes the state array.
*
* \param output: The function state; must be initialized
* \param input: [const] The input message byte array
*/
pub fn qrc_sha256_permute(output: &mut [u32], message: &[u8]) {
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
        w[i] = qrc_intutils_be8to32(&message[i * 4..i * 4 + 4]);
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

/* sha2-384 */

/* \struct sha384_state
* The SHA2-384 digest state array
*/
pub struct QrcSha384State {
	pub state: [u64; QRC_SHA2_STATE_SIZE],
	pub buffer: [u8; QRC_SHA2_384_RATE],
	pub t: [u64; 2],
	pub position: usize,
}
impl Default for QrcSha384State {
    fn default() -> Self {
        Self {
            state: [Default::default(); QRC_SHA2_STATE_SIZE],
			buffer: [Default::default(); QRC_SHA2_384_RATE],
            t: [Default::default(); 2],
			position: Default::default(),
        }
    }
}

/*
* \brief Process a message with SHA2-384 and returns the hash code in the output byte array.
* Short form api: processes the entire message and computes the hash code with a single call.
*
* \warning The output array must be at least 48 bytes in length.
*
* \param output: The output byte array; receives the hash code
* \param message: [const] The message input byte array
* \param msglen The number of message bytes to process
*/
pub fn qrc_sha384_blockcompute(output: &mut [u8], message: &[u8], mut msglen: usize) {
	let state = &mut QrcSha384State::default();

	qrc_sha384_initialize(state);
	let blocks = msglen / QRC_SHA2_384_RATE;

	if msglen >= QRC_SHA2_384_RATE {
		qrc_sha384_blockupdate(state, message, blocks);
		msglen -= blocks * QRC_SHA2_384_RATE;
	}

	qrc_sha384_blockfinalize(state, output, &message[blocks * QRC_SHA2_384_RATE..], msglen);
}

/**
* \brief Process a message with SHA2-384 and returns the hash code in the output byte array.
* Short form api: processes the entire message and computes the hash code with a single call.
*
* \warning The output array must be at least 48 bytes in length.
*
* \param output: The output byte array; receives the hash code
* \param message: [const] The message input byte array
* \param msglen The number of message bytes to process
*/
pub fn qrc_sha384_compute(output: &mut [u8], message: &[u8], msglen: usize) {
	let state = &mut QrcSha384State::default();

	qrc_sha384_initialize(state);
	qrc_sha384_update(state, message, msglen);
	qrc_sha384_finalize(state, output);
}

/*
* \brief Dispose of the SHA2-384 state.
* This function destroys the internal state of the cipher.
*
* \param ctx: [struct] The cipher state structure
*/
pub fn qrc_sha384_dispose(state: &mut QrcSha384State) {
	qrc_intutils_clear64(&mut state.state, QRC_SHA2_STATE_SIZE);
	qrc_intutils_clear8(&mut state.buffer, QRC_SHA2_384_RATE);
	state.t[0] = 0;
	state.t[1] = 0;
	state.position = 0;
}

/*
* \brief Update SHA2-384 with blocks of input.
* Long form api: must be used in conjunction with the initialize and finalize functions.
* Absorbs a multiple of 128-byte block sized lengths of input message into the state.
*
* \warning Message length must be a multiple of the rate size. \n
* State must be initialized by the caller.
*
* \param state: [struct] The function state
* \param message:[const] The input message byte array
* \param nblocks The number of rate sized blocks to process
*/
pub fn qrc_sha384_blockupdate(state: &mut QrcSha384State, message: &[u8], nblocks: usize) {
	for i in 0..nblocks {
		qrc_sha384_permute(&mut state.state, &message[(i * QRC_SHA2_384_RATE)..]);
		qrc_sha384_increase(state, QRC_SHA2_384_RATE);
	}
}

/*
* \brief Update SHA2-384 with blocks of input.
* Long form api: must be used in conjunction with the initialize and finalize functions.
* Absorbs a length of input into the hash function.
*
* \warning State must be initialized by the caller.
*
* \param ctx: [struct] The function state
* \param message: [const] The input message byte array
* \param msglen: The number of message bytes to process
*/
pub fn qrc_sha384_update(state: &mut QrcSha384State, mut message: &[u8], mut msglen: usize) {
	if msglen != 0	{
		if state.position != 0 && (state.position + msglen >= QRC_SHA2_384_RATE) {
			let rmdlen = QRC_SHA2_384_RATE - state.position;

			if rmdlen != 0 {
				qrc_intutils_copy8(&mut state.buffer[state.position..], message, rmdlen);
			}

			qrc_sha384_permute(&mut state.state, &state.buffer);
			qrc_sha384_increase(state, QRC_SHA2_384_RATE);
			state.position = 0;
			message = &message[rmdlen..];
			msglen -= rmdlen;
		}

		/* sequential loop through blocks */
		while msglen >= QRC_SHA2_384_RATE {
			qrc_sha384_permute(&mut state.state, message);
			qrc_sha384_increase(state, QRC_SHA2_384_RATE);
			message = &message[QRC_SHA2_384_RATE..];
			msglen -= QRC_SHA2_384_RATE;
		}

		/* store unaligned bytes */
		if msglen != 0 {
			qrc_intutils_copy8(&mut state.buffer[state.position..], message, msglen);
			state.position += msglen;
		}
	}
}



/*
* \brief Finalize the message state and returns the SHA2-384 hash value in output.
* Long form api: must be used in conjunction with the initialize and blockupdate functions.
* Absorb the last block of message and creates the hash value. \n
* Produces a 48 byte output code.
*
* \warning The output array must be sized correctly. \n
* Finalizes the message state, can not be used in consecutive calls.
* State must be initialized by the caller.
*
* \param state: [struct] The function state; must be initialized
* \param output: The output byte array; receives the hash code
* \param message: [const] The input message byte array
* \param msglen: The number of message bytes to process
*/
pub fn qrc_sha384_blockfinalize(state: &mut QrcSha384State, output: &mut [u8], message: &[u8], mut msglen: usize) {
    let pad = &mut [0u8; QRC_SHA2_384_RATE];

	qrc_sha384_increase(state, msglen);
	let bitlen = state.t[0] << 3;

	for i in 0..msglen {
		pad[i] = message[i];
	}

	if msglen == QRC_SHA2_384_RATE	{
		qrc_sha384_permute(&mut state.state, pad);
		msglen = 0;
	}

	pad[msglen] = 128;
	msglen += 1;

	/* padding */
	if msglen < QRC_SHA2_384_RATE {
		qrc_intutils_clear8(&mut pad[msglen..], QRC_SHA2_384_RATE - msglen);
	}

	if msglen > 112 {
		qrc_sha384_permute(&mut state.state, pad);
		qrc_intutils_clear8(pad, QRC_SHA2_384_RATE);
	}

	/* finalize state with counter and last compression */
	qrc_intutils_be64to8(&mut pad[112..], state.t[1]);
	qrc_intutils_be64to8(&mut pad[120..], bitlen);
	qrc_sha384_permute(&mut state.state, pad);

	for i in (0..QRC_SHA2_384_HASH_SIZE).step_by(size_of::<u64>()) {
		qrc_intutils_be64to8(&mut output[i..], state.state[i / size_of::<u64>()]);
	}
}

/*
* \brief Finalize the message state and returns the SHA2-384 hash value in output.
* Long form api: must be used in conjunction with the initialize and update functions.
* Produces a 48 byte output code.
*
* \warning The output array must be sized correctly.
* Finalizes the message state, can not be used in consecutive calls.
* State must be initialized by the caller.
*
* \param ctx: [struct] The function state; must be initialized
* \param output: The output byte array; receives the hash code
*/
pub fn qrc_sha384_finalize(state: &mut QrcSha384State, output: &mut [u8]) {
	let pad = &mut [0u8; QRC_SHA2_384_RATE];

	qrc_sha384_increase(state, state.position);
	let bitlen = state.t[0] << 3;
	qrc_intutils_copy8(pad, &state.buffer, state.position);

	if state.position == QRC_SHA2_384_RATE {
		qrc_sha384_permute(&mut state.state, pad);
		state.position = 0;
	}

	pad[state.position] = 128;
	state.position += 1;

	/* padding */
	if state.position < QRC_SHA2_384_RATE {
		qrc_intutils_clear8(&mut pad[state.position..], QRC_SHA2_384_RATE - state.position);
	}

	if state.position > 112	{
		qrc_sha384_permute(&mut state.state, pad);
		qrc_intutils_clear8(pad, QRC_SHA2_384_RATE);
	}

	/* finalize state with counter and last compression */
	qrc_intutils_be64to8(&mut pad[112..], state.t[1]);
	qrc_intutils_be64to8(&mut pad[120..], bitlen);
	qrc_sha384_permute(&mut state.state, pad);

	for i in (0..QRC_SHA2_384_HASH_SIZE).step_by(size_of::<u64>()) {
		qrc_intutils_be64to8(&mut output[i..], state.state[i / size_of::<u64>()]);
	}

	qrc_sha384_dispose(state);
}


/*
* \brief Initializes a SHA2-384 state structure, must be called before message processing.
* Long form api: must be used in conjunction with the blockupdate and finalize functions.
*
* \param state: [struct] The function state
*/
pub fn qrc_sha384_initialize(state: &mut QrcSha384State) {
	qrc_intutils_copy64(&mut state.state, &SHA384_IV, 8);
	qrc_intutils_clear8(&mut state.buffer, QRC_SHA2_384_RATE);
	state.t[0] = 0;
	state.t[1] = 0;
	state.position = 0;
}

/*
* \brief The SHA2-384 permution function.
* Internal function: called by protocol hash and generation functions, or in the construction of other external protocols.
* Permutes the state array.
*
* \param state: The function state; must be initialized
* \param message: [const] The input message byte array
*/
pub fn qrc_sha384_permute(output: &mut [u64], message: &[u8]) {
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
		w[i] = qrc_intutils_be8to64(&message[i * 8..i * 8 + 8]);
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


/* sha2-512 */

/* \struct sha512_state
* The SHA2-512 digest state array
*/
pub struct QrcSha512State {
	pub state: [u64; QRC_SHA2_STATE_SIZE],
	pub buffer: [u8; QRC_SHA2_512_RATE],
	pub t: [u64; 2],
	pub position: usize,
}
impl Default for QrcSha512State {
    fn default() -> Self {
        Self {
            state: [Default::default(); QRC_SHA2_STATE_SIZE],
			buffer: [Default::default(); QRC_SHA2_512_RATE],
            t: [Default::default(); 2],
			position: Default::default(),
        }
    }
}

/*
* \brief Process a message with SHA2-512 and returns the hash code in the output byte array.
* Short form api: processes the entire message and computes the hash code with a single call.
*
* \warning The output array must be at least 64 bytes in length.
*
* \param output: The output byte array; receives the hash code
* \param message: [const] The message input byte array
* \param msglen The number of message bytes to process
*/
pub fn qrc_sha512_blockcompute(output: &mut [u8], message: &[u8], mut msglen: usize) {
	let state = &mut QrcSha512State::default();

	qrc_sha512_initialize(state);
	let blocks = msglen / QRC_SHA2_512_RATE;

	if msglen >= QRC_SHA2_512_RATE {
		qrc_sha512_blockupdate(state, message, blocks);
		msglen -= blocks * QRC_SHA2_512_RATE;
	}

	qrc_sha512_blockfinalize(state, output, &message[blocks * QRC_SHA2_512_RATE..], msglen);
}

/**
* \brief Process a message with SHA2-512 and returns the hash code in the output byte array.
* Short form api: processes the entire message and computes the hash code with a single call.
*
* \warning The output array must be at least 64 bytes in length.
*
* \param output: The output byte array; receives the hash code
* \param message: [const] The message input byte array
* \param msglen The number of message bytes to process
*/
pub fn qrc_sha512_compute(output: &mut [u8], message: &[u8], msglen: usize) {
	let state = &mut QrcSha512State::default();

	qrc_sha512_initialize(state);
	qrc_sha512_update(state, message, msglen);
	qrc_sha512_finalize(state, output);
}

/*
* \brief Dispose of the SHA2-512 state.
* This function destroys the internal state of the cipher.
*
* \param ctx: [struct] The cipher state structure
*/
pub fn qrc_sha512_dispose(state: &mut QrcSha512State) {
	qrc_intutils_clear64(&mut state.state, QRC_SHA2_STATE_SIZE);
	qrc_intutils_clear8(&mut state.buffer, QRC_SHA2_512_RATE);
	state.t[0] = 0;
	state.t[1] = 0;
	state.position = 0;
}

/*
* \brief Update SHA2-512 with blocks of input.
* Long form api: must be used in conjunction with the initialize and finalize functions.
* Absorbs a multiple of 128-byte block sized lengths of input message into the state.
*
* \warning Message length must be a multiple of the rate size. \n
* State must be initialized by the caller.
*
* \param state: [struct] The function state
* \param message:[const] The input message byte array
* \param nblocks The number of rate sized blocks to process
*/
pub fn qrc_sha512_blockupdate(state: &mut QrcSha512State, message: &[u8], nblocks: usize) {
	for i in 0..nblocks {
		qrc_sha512_permute(&mut state.state, &message[(i * QRC_SHA2_512_RATE)..]);
		qrc_sha512_increase(state, QRC_SHA2_512_RATE);
	}
}

/*
* \brief Update SHA2-512 with blocks of input.
* Long form api: must be used in conjunction with the initialize and finalize functions.
* Absorbs a length of input into the hash function.
*
* \warning State must be initialized by the caller.
*
* \param ctx: [struct] The function state
* \param message: [const] The input message byte array
* \param msglen: The number of message bytes to process
*/
pub fn qrc_sha512_update(state: &mut QrcSha512State, mut message: &[u8], mut msglen: usize) {
	if msglen != 0	{
		if state.position != 0 && (state.position + msglen >= QRC_SHA2_512_RATE) {
			let rmdlen = QRC_SHA2_512_RATE - state.position;

			if rmdlen != 0 {
				qrc_intutils_copy8(&mut state.buffer[state.position..], message, rmdlen);
			}

			qrc_sha512_permute(&mut state.state, &state.buffer);
			qrc_sha512_increase(state, QRC_SHA2_512_RATE);
			state.position = 0;
			message = &message[rmdlen..];
			msglen -= rmdlen;
		}

		/* sequential loop through blocks */
		while msglen >= QRC_SHA2_512_RATE {
			qrc_sha512_permute(&mut state.state, message);
			qrc_sha512_increase(state, QRC_SHA2_512_RATE);
			message = &message[QRC_SHA2_512_RATE..];
			msglen -= QRC_SHA2_512_RATE;
		}

		/* store unaligned bytes */
		if msglen != 0 {
			qrc_intutils_copy8(&mut state.buffer[state.position..], message, msglen);
			state.position += msglen;
		}
	}
}


/*
* \brief Finalize the message state and returns the SHA2-512 hash value in output.
* Long form api: must be used in conjunction with the initialize and blockupdate functions.
* Absorb the last block of message and creates the hash value. \n
* Produces a 64 byte output code.
*
* \warning The output array must be sized correctly. \n
* Finalizes the message state, can not be used in consecutive calls.
* State must be initialized by the caller.
*
* \param state: [struct] The function state; must be initialized
* \param output: The output byte array; receives the hash code
* \param message: [const] The input message byte array
* \param msglen: The number of message bytes to process
*/
pub fn qrc_sha512_blockfinalize(state: &mut QrcSha512State, output: &mut [u8], message: &[u8], mut msglen: usize) {
    let pad = &mut [0u8; QRC_SHA2_512_RATE];

	qrc_sha512_increase(state, msglen);
	let bitlen = state.t[0] << 3;

	for i in 0..msglen {
		pad[i] = message[i];
	}

	if msglen == QRC_SHA2_512_RATE	{
		qrc_sha512_permute(&mut state.state, pad);
		msglen = 0;
	}

	pad[msglen] = 128;
	msglen += 1;

	/* padding */
	if msglen < QRC_SHA2_512_RATE {
		qrc_intutils_clear8(&mut pad[msglen..], QRC_SHA2_512_RATE - msglen);
	}

	if msglen > 112 {
		qrc_sha512_permute(&mut state.state, pad);
		qrc_intutils_clear8(pad, QRC_SHA2_512_RATE);
	}

	/* finalize state with counter and last compression */
	qrc_intutils_be64to8(&mut pad[112..], state.t[1]);
	qrc_intutils_be64to8(&mut pad[120..], bitlen);
	qrc_sha512_permute(&mut state.state, pad);

	for i in (0..QRC_SHA2_512_HASH_SIZE).step_by(size_of::<u64>()) {
		qrc_intutils_be64to8(&mut output[i..], state.state[i / size_of::<u64>()]);
	}
}
/*
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
pub fn qrc_sha512_finalize(state: &mut QrcSha512State, output: &mut [u8]) {
	let pad = &mut [0u8; QRC_SHA2_512_RATE];

	qrc_sha512_increase(state, state.position);
	let bitlen = state.t[0] << 3;
	qrc_intutils_copy8(pad, &state.buffer, state.position);

	if state.position == QRC_SHA2_512_RATE {
		qrc_sha512_permute(&mut state.state, pad);
		state.position = 0;
	}

	pad[state.position] = 128;
	state.position += 1;

	/* padding */
	if state.position < QRC_SHA2_512_RATE {
		qrc_intutils_clear8(&mut pad[state.position..], QRC_SHA2_512_RATE - state.position);
	}

	if state.position > 112	{
		qrc_sha512_permute(&mut state.state, pad);
		qrc_intutils_clear8(pad, QRC_SHA2_512_RATE);
	}

	/* finalize state with counter and last compression */
	qrc_intutils_be64to8(&mut pad[112..], state.t[1]);
	qrc_intutils_be64to8(&mut pad[120..], bitlen);
	qrc_sha512_permute(&mut state.state, pad);

	for i in (0..QRC_SHA2_512_HASH_SIZE).step_by(size_of::<u64>()) {
		qrc_intutils_be64to8(&mut output[i..], state.state[i / size_of::<u64>()]);
	}

	qrc_sha512_dispose(state);
}

/*
* \brief Initializes a SHA2-512 state structure, must be called before message processing.
* Long form api: must be used in conjunction with the blockupdate and finalize functions.
*
* \param state: [struct] The function state
*/
pub fn qrc_sha512_initialize(state: &mut QrcSha512State) {
	qrc_intutils_copy64(&mut state.state, &SHA512_IV, 8);
	qrc_intutils_clear8(&mut state.buffer, QRC_SHA2_512_RATE);
	state.t[0] = 0;
	state.t[1] = 0;
	state.position = 0;
}

/*
* \brief The SHA2-512 permution function.
* Internal function: called by protocol hash and generation functions, or in the construction of other external protocols.
* Permutes the state array.
*
* \param state: The function state; must be initialized
* \param message: [const] The input message byte array
*/
pub fn qrc_sha512_permute(output: &mut [u64], message: &[u8]) {
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
		w[i] = qrc_intutils_be8to64(&message[i * 8..i * 8 + 8]);
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


/* hmac-256 */

/* \struct hmac256_state
* The HMAC(SHA2-256) state array
*/
pub struct QrcHmac256State {
	pub pstate: QrcSha256State,
	pub ipad: [u8; QRC_SHA2_256_RATE],
	pub opad: [u8; QRC_SHA2_256_RATE],
}
impl Default for QrcHmac256State {
    fn default() -> Self {
        Self {
            pstate: QrcSha256State::default(),
            ipad: [Default::default(); QRC_SHA2_256_RATE],
            opad: [Default::default(); QRC_SHA2_256_RATE],
        }
    }
}

/*
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
pub fn qrc_hmac256_blockcompute(output: &mut [u8], mut message: &[u8], mut msglen: usize, key: &[u8], mut keylen: usize) {
	let bipad = 0x36 as u8;
	let bopad = 0x5C as u8;
	let ipad = &mut [0u8; QRC_SHA2_256_RATE];
	let opad = &mut [0u8; QRC_SHA2_256_RATE];
	let tmpv = &mut [0u8; QRC_SHA2_256_HASH_SIZE];
	let state = &mut QrcSha256State::default();

	if keylen > QRC_SHA2_256_RATE {
		qrc_sha256_initialize(state);

		while keylen > QRC_SHA2_256_RATE {
			qrc_sha256_blockupdate(state, key, 1);
			keylen -= QRC_SHA2_256_RATE;
		}

		qrc_sha256_blockfinalize(state, ipad, key, keylen);
	} else {
		for i in 0..keylen {
			ipad[i] = key[i];
		}
	}

	for i in 0..QRC_SHA2_256_RATE {
		opad[i] = ipad[i];
		opad[i] ^= bopad;
		ipad[i] ^= bipad;
	}

	qrc_sha256_initialize(state);
	qrc_sha256_blockupdate(state, ipad, 1);

	while msglen >= QRC_SHA2_256_RATE {
		qrc_sha256_blockupdate(state, message, 1);
		msglen -= QRC_SHA2_256_RATE;
		message = &message[QRC_SHA2_256_RATE..];
	}

	qrc_sha256_blockfinalize(state, tmpv, message, msglen);
	qrc_sha256_initialize(state);
	qrc_sha256_blockupdate(state, opad, 1);
	qrc_sha256_blockfinalize(state, output, tmpv, QRC_SHA2_256_HASH_SIZE);
}

/*
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
pub fn qrc_hmac256_compute(output: &mut [u8], message: &[u8], msglen: usize, key: &[u8], keylen: usize) {
	let state = &mut QrcHmac256State::default();
	
	qrc_hmac256_initialize(state, key, keylen);
	qrc_hmac256_update(state, message, msglen);
	qrc_hmac256_finalize(state, output);
}

/*
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
pub fn qrc_hmac256_dispose(state: &mut QrcHmac256State) {
	qrc_intutils_clear8(&mut state.ipad, QRC_SHA2_256_RATE);
	qrc_intutils_clear8(&mut state.opad, QRC_SHA2_256_RATE);
	qrc_sha256_dispose(&mut state.pstate);
}

/*
* \brief Update HMAC-256 with blocks of input.
* Long form api: must be used in conjunction with the initialize and finalize functions.
* Absorbs a multiple of 64-byte block lengths of input message into the state.
*
* \warning Message length must be a multiple of the rate size. \n
* State must be initialized by the caller.
*
* \param state: [struct] The function state
* \param message: [const] The input message byte array
* \param nblocks: The number of rate sized blocks to process
*/
pub fn qrc_hmac256_blockupdate(state: &mut QrcHmac256State, message: &[u8], nblocks: usize) {
	qrc_sha256_blockupdate(&mut state.pstate, message, nblocks);
}

/*
* \brief Update HMAC-256 with message input.
* Long form api: must be used in conjunction with the initialize and finalize functions.
*
* State must be initialized by the caller.
*
* \param ctx: [struct] The function state
* \param message: [const] The input message byte array
* \param msglen: The number of message bytes to process
*/
pub fn qrc_hmac256_update(state: &mut QrcHmac256State, message: &[u8], msglen: usize) {
	qrc_sha256_update(&mut state.pstate, message, msglen);
}

/*
* \brief Finalize the HMAC-256 message state and return the hash value in output.
* Long form api: must be used in conjunction with the initialize and blockupdate functions.
* Absorb the last block of message and creates the hash value. \n
* Produces a 32 byte output code.
*
* \warning The output array must be sized correctly. \n
* Finalizes the message state, can not be used in consecutive calls.
* State must be initialized by the caller.
*
* \param state: [struct] The function state; must be initialized
* \param output: The output byte array; receives the hash code
* \param message: [const] The input message byte array
* \param msglen: The number of message bytes to process
*/
pub fn qrc_hmac256_blockfinalize(state: &mut QrcHmac256State, output: &mut [u8], message: &[u8], mut msglen: usize) {
	let tmpv = &mut [0u8; QRC_SHA2_256_HASH_SIZE];
	let mut oft = 0;

	while msglen >= QRC_SHA2_256_RATE {
		qrc_sha256_blockupdate(&mut state.pstate, &message[oft..], 1);
		oft += QRC_SHA2_256_RATE;
		msglen -= QRC_SHA2_256_RATE;
	}

	qrc_sha256_blockfinalize(&mut state.pstate, tmpv, &message[oft..], msglen);
	qrc_sha256_initialize(&mut state.pstate);
	qrc_sha256_blockupdate(&mut state.pstate, &state.opad, 1);
	qrc_sha256_blockfinalize(&mut state.pstate, output, tmpv, QRC_SHA2_256_HASH_SIZE);
}

/*
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
pub fn qrc_hmac256_finalize(state: &mut QrcHmac256State, output: &mut [u8]) {
	let tmpv = &mut [0u8; QRC_SHA2_256_HASH_SIZE];

	qrc_sha256_finalize(&mut state.pstate, tmpv);
	qrc_sha256_initialize(&mut state.pstate);
	qrc_sha256_update(&mut state.pstate, &state.opad, QRC_SHA2_256_RATE);
	qrc_sha256_update(&mut state.pstate, tmpv, QRC_SHA2_256_HASH_SIZE);
	qrc_sha256_finalize(&mut state.pstate, output);
	qrc_hmac256_dispose(state);
}

/*
* \brief Initializes a HMAC-256 state structure with a key, must be called before message processing.
* Long form api: must be used in conjunction with the blockupdate and finalize functions.
*
* \param state: [struct] The function state
* \param key: [const] The secret key array
* \param keylen: The key array length
*/
pub fn qrc_hmac256_initialize(state: &mut QrcHmac256State, key: &[u8], mut keylen: usize) {
	let bipad = 0x36;
	let bopad = 0x5C;

	let mut oft = 0;
	qrc_intutils_clear8(&mut state.ipad, QRC_SHA2_256_RATE);

	if keylen > QRC_SHA2_256_RATE {
		qrc_sha256_initialize(&mut state.pstate);

		while keylen > QRC_SHA2_256_RATE {
			qrc_sha256_blockupdate(&mut state.pstate, &key[oft..], 1);
			oft += QRC_SHA2_256_RATE;
			keylen -= QRC_SHA2_256_RATE;
		}

		qrc_sha256_blockfinalize(&mut state.pstate, &mut state.ipad, &key[oft..], keylen);
	} else {
		for i in 0..keylen {
			state.ipad[i] = key[i];
		}
	}

	for i in 0..QRC_SHA2_256_RATE {
		state.opad[i] = state.ipad[i];
		state.opad[i] ^= bopad;
		state.ipad[i] ^= bipad;
	}

	qrc_sha256_initialize(&mut state.pstate);
	qrc_sha256_blockupdate(&mut state.pstate, &mut state.ipad, 1);
}

/* hmac-512 */

/* \struct hmac512_state
* The HMAC(SHA2-512) state array
*/
pub struct QrcHmac512State {
	pub pstate: QrcSha512State,
	pub ipad: [u8; QRC_SHA2_512_RATE],
	pub opad: [u8; QRC_SHA2_512_RATE],
}
impl Default for QrcHmac512State {
    fn default() -> Self {
        Self {
            pstate: QrcSha512State::default(),
            ipad: [Default::default(); QRC_SHA2_512_RATE],
            opad: [Default::default(); QRC_SHA2_512_RATE],
        }
    }
}

/*
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
pub fn qrc_hmac512_blockcompute(output: &mut [u8], mut message: &[u8], mut msglen: usize, key: &[u8], mut keylen: usize) {
    let bipad = 0x36 as u8;
	let bopad = 0x5C as u8;
	let ipad = &mut [0u8; QRC_SHA2_512_RATE];
	let opad = &mut [0u8; QRC_SHA2_512_RATE];
	let tmpv = &mut [0u8; QRC_SHA2_512_RATE];
	let state = &mut QrcSha512State::default();

	if keylen > QRC_SHA2_512_RATE {
		qrc_sha512_initialize(state);

		while keylen > QRC_SHA2_512_RATE {
			qrc_sha512_blockupdate(state, key, 1);
			keylen -= QRC_SHA2_512_RATE;
		}

		qrc_sha512_blockfinalize(state, ipad, key, keylen);
	} else {
		for i in 0..keylen {
			ipad[i] = key[i];
		}
	}

	for i in 0..QRC_SHA2_512_RATE {
		opad[i] = ipad[i];
		opad[i] ^= bopad;
		ipad[i] ^= bipad;
	}

	qrc_sha512_initialize(state);
	qrc_sha512_blockupdate(state, ipad, 1);

	while msglen >= QRC_SHA2_512_RATE {
		qrc_sha512_blockupdate(state, message, 1);
		msglen -= QRC_SHA2_512_RATE;
		message = &message[QRC_SHA2_512_RATE..];
	}

	qrc_sha512_blockfinalize(state, tmpv, message, msglen);
	qrc_sha512_initialize(state);
	qrc_sha512_blockupdate(state, opad, 1);
	qrc_sha512_blockfinalize(state, output, tmpv, QRC_SHA2_512_HASH_SIZE);
}

/*
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
pub fn qrc_hmac512_compute(output: &mut [u8], message: &[u8], msglen: usize, key: &[u8], keylen: usize) {
	let state = &mut QrcHmac512State::default();
	
	qrc_hmac512_initialize(state, key, keylen);
	qrc_hmac512_update(state, message, msglen);
	qrc_hmac512_finalize(state, output);
}

/*
* \brief Dispose of the HMAC-512 state.
*
* \warning The dispose function must be called when disposing of the cipher.
* This function destroys the internal state of the cipher.
*
* \param ctx: [struct] The cipher state structure
*/
pub fn qrc_hmac512_dispose(state: &mut QrcHmac512State) {
	qrc_intutils_clear8(&mut state.ipad, QRC_SHA2_512_RATE);
	qrc_intutils_clear8(&mut state.opad, QRC_SHA2_512_RATE);
	qrc_sha512_dispose(&mut state.pstate);
}

/*
* \brief Update HMAC-512 with blocks of input.
* Long form api: must be used in conjunction with the initialize and finalize functions.
* Absorbs a multiple of 128-byte block lengths of input message into the state.
*
* \warning Message length must be a multiple of the rate size. \n
* State must be initialized by the caller.
*
* \param state: [struct] The function state
* \param message: [const] The input message byte array
* \param nblocks: The number of rate sized blocks to process
*/
pub fn qrc_hmac512_blockupdate(state: &mut QrcHmac512State, message: &[u8], nblocks: usize) {
	qrc_sha512_blockupdate(&mut state.pstate, message, nblocks);
}

/*
* \brief Update HMAC-512 with message input.
* Long form api: must be used in conjunction with the initialize and finalize functions.
*
* State must be initialized by the caller.
*
* \param ctx: [struct] The function state
* \param message: [const] The input message byte array
* \param msglen: The number of message bytes to process
*/
pub fn qrc_hmac512_update(state: &mut QrcHmac512State, message: &[u8], msglen: usize) {
	qrc_sha512_update(&mut state.pstate, message, msglen);
}


/*
* \brief Finalize the HMAC-512 message state and return the hash value in output.
* Long form api: must be used in conjunction with the initialize and blockupdate functions.
* Absorb the last block of message and creates the hash value. \n
* Produces a 64 byte output code.
*
* \warning The output array must be sized correctly. \n
* Finalizes the message state, can not be used in consecutive calls.
* State must be initialized by the caller.
*
* \param state: [struct] The function state; must be initialized
* \param output: The output byte array; receives the hash code
* \param message: [const] The input message byte array
* \param msglen: The number of message bytes to process
*/
pub fn qrc_hmac512_blockfinalize(state: &mut QrcHmac512State, output: &mut [u8], message: &[u8], mut msglen: usize) {
	let tmpv = &mut [0u8; QRC_SHA2_512_HASH_SIZE];
	let mut oft = 0;

	while msglen >= QRC_SHA2_512_RATE {
		qrc_sha512_blockupdate(&mut state.pstate, &message[oft..], 1);
		oft += QRC_SHA2_512_RATE;
		msglen -= QRC_SHA2_512_RATE;
	}

	qrc_sha512_blockfinalize(&mut state.pstate, tmpv, &message[oft..], msglen);
	qrc_sha512_initialize(&mut state.pstate);
	qrc_sha512_blockupdate(&mut state.pstate, &state.opad, 1);
	qrc_sha512_blockfinalize(&mut state.pstate, output, tmpv, QRC_SHA2_512_HASH_SIZE);
}

/*
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
pub fn qrc_hmac512_finalize(state: &mut QrcHmac512State, output: &mut [u8]) {
	let tmpv = &mut [0u8; QRC_SHA2_512_HASH_SIZE];

	qrc_sha512_finalize(&mut state.pstate, tmpv);
	qrc_sha512_initialize(&mut state.pstate);
	qrc_sha512_update(&mut state.pstate, &state.opad, QRC_SHA2_512_RATE);
	qrc_sha512_update(&mut state.pstate, tmpv, QRC_SHA2_512_HASH_SIZE);
	qrc_sha512_finalize(&mut state.pstate, output);
	qrc_hmac512_dispose(state);
}


/*
* \brief Initializes a HMAC-512 state structure with a key, must be called before message processing.
* Long form api: must be used in conjunction with the blockupdate and finalize functions.
*
* \param state: [struct] The function state
* \param key: [const] The secret key array
* \param keylen: The key array length
*/
pub fn qrc_hmac512_initialize(state: &mut QrcHmac512State, key: &[u8], mut keylen: usize) {
	let bipad = 0x36;
	let bopad = 0x5C;

	let mut oft = 0;
	qrc_intutils_clear8(&mut state.ipad, QRC_SHA2_512_RATE);

	if keylen > QRC_SHA2_512_RATE	{
		qrc_sha512_initialize(&mut state.pstate);

		while keylen > QRC_SHA2_512_RATE {
			qrc_sha512_blockupdate(&mut state.pstate, &key[oft..], 1);
			keylen -= QRC_SHA2_512_RATE;
			oft += QRC_SHA2_512_RATE;
		}

		qrc_sha512_blockfinalize(&mut state.pstate, &mut state.ipad, &key[oft..], keylen);
	} else {
		for i in 0..keylen {
			state.ipad[i] = key[i];
		}
	}

	for i in 0..QRC_SHA2_512_RATE {
		state.opad[i] = state.ipad[i];
		state.opad[i] ^= bopad;
		state.ipad[i] ^= bipad;
	}

	qrc_sha512_initialize(&mut state.pstate);
	qrc_sha512_blockupdate(&mut state.pstate, &mut state.ipad, 1);
}


/* hkdf */

/*
* \brief Initialize and instance of HKDF(HMAC(SHA2-256)), and output an array of pseudo-random.
* Short form api: initializes with the key and user info, and generates the output pseudo-random with a single call.
*
* \param output: The output pseudo-random byte array
* \param key: [const] The HKDF key array
* \param keylen: The key array length
* \param info: [const] The info array
* \param infolen: The info array length
*/
pub fn qrc_hkdf256_expand(mut output: &mut [u8], mut outlen: usize, key: &[u8], keylen: usize, info: &[u8], infolen: usize) {
	let state = &mut QrcHmac256State::default();
	let msg = &mut [0u8; QRC_SHA2_256_RATE];
    let otp = &mut [0u8; QRC_SHA2_256_HASH_SIZE];

	let mut ctr = 0;

	while outlen != 0 {
		qrc_hmac256_initialize(state, key, keylen);
		let mut mlen = infolen;
		let mut ioft = 0;

		if ctr != 0	{
			for i in 0..QRC_SHA2_256_HASH_SIZE {
				msg[i] = otp[i];
			}

			let mut slen = QRC_SHA2_256_HASH_SIZE;

			if infolen >= QRC_SHA2_256_HASH_SIZE {
				for i in 0..QRC_SHA2_256_HASH_SIZE {
					msg[slen + i] = info[i];
				}

				qrc_hmac256_blockupdate(state, msg, 1);
				mlen -= QRC_SHA2_256_HASH_SIZE;
				ioft += QRC_SHA2_256_HASH_SIZE;
				slen = 0;
			}

			if infolen > 0 {
				while mlen >= QRC_SHA2_256_RATE {
					qrc_hmac256_blockupdate(state, &info[ioft..], 1);
					ioft += QRC_SHA2_256_RATE;
					mlen -= QRC_SHA2_256_RATE;
				}

				for i in 0..mlen {
					msg[slen + i] = info[ioft + i];
				}
			}

			ctr += 1;
			msg[slen + mlen] = ctr as u8;
			qrc_hmac256_blockfinalize(state, otp, msg, slen + mlen + 1);
		} else {
			while mlen >= QRC_SHA2_256_RATE {
				qrc_hmac256_blockupdate(state, &info[ioft..], 1);
				ioft += QRC_SHA2_256_RATE;
				mlen -= QRC_SHA2_256_RATE;
			}

			if infolen > 0 {
				for i in 0..mlen {
					msg[i] = info[ioft + i];
				}
			}

			ctr += 1;
			msg[mlen] = ctr;
			qrc_hmac256_blockfinalize(state, otp, msg, mlen + 1);
		}

		let rmd = qrc_intutils_min(outlen, QRC_SHA2_256_HASH_SIZE);

		for i in 0..rmd {
			output[i] = otp[i];
		}

		outlen -= rmd;
		output = &mut output[rmd..];
	}
}


/*
* \brief Extract a key from a combined key and salt input using HMAC(SHA2-256).
*
* \param output: The output pseudo-random byte array
* \param key: [const] The HKDF key array
* \param keylen: The key array length
* \param salt: [const] The salt array
* \param saltlen: The salt array length
*/
pub fn qrc_hkdf256_extract(output: &mut [u8], key: &[u8], keylen: usize, salt: &[u8], saltlen: usize) {
    let state = &mut QrcHmac256State::default();

	if saltlen != 0 {
		qrc_hmac256_initialize(state, salt, saltlen);
	} else {
		let tmp = &mut [0u8; QRC_HMAC_256_MAC_SIZE];
		qrc_hmac256_initialize(state, tmp, QRC_HMAC_256_MAC_SIZE);
	}

	qrc_hmac256_blockfinalize(state, output, key, keylen);
}

/*
* \brief Initialize and instance of HKDF(HMAC(SHA2-512)), and output an array of pseudo-random.
* Short form api: initializes with the key and user info, and generates the output pseudo-random with a single call.
*
* \param output: The output pseudo-random byte array
* \param key: [const] The HKDF key array
* \param keylen: The key array length
* \param info: [const] The info array
* \param infolen: The info array length
*/
pub fn qrc_hkdf512_expand(mut output: &mut [u8], mut outlen: usize, key: &[u8], keylen: usize, info: &[u8], infolen: usize) {
    let state = &mut QrcHmac512State::default();
	let msg = &mut [0u8; QRC_SHA2_512_RATE];
    let otp = &mut [0u8; QRC_SHA2_512_HASH_SIZE];

	let mut ctr = 0;

	while outlen != 0 {
		qrc_hmac512_initialize(state, key, keylen);
		let mut mlen = infolen;
		let mut ioft = 0;

		if ctr != 0	{
			for i in 0..QRC_SHA2_512_HASH_SIZE {
				msg[i] = otp[i];
			}

			let mut slen = QRC_SHA2_512_HASH_SIZE;

			if infolen >= QRC_SHA2_512_HASH_SIZE {
				for i in 0..QRC_SHA2_512_HASH_SIZE {
					msg[slen + i] = info[i];
				}

				qrc_hmac512_blockupdate(state, msg, 1);
				mlen -= QRC_SHA2_512_HASH_SIZE;
				ioft += QRC_SHA2_512_HASH_SIZE;
				slen = 0;
			}

			if infolen > 0 {
				while mlen >= QRC_SHA2_512_RATE {
					qrc_hmac512_blockupdate(state, &info[ioft..], 1);
					ioft += QRC_SHA2_512_RATE;
					mlen -= QRC_SHA2_512_RATE;
				}

				for i in 0..mlen {
					msg[slen + i] = info[ioft + i];
				}
			}

			ctr += 1;
			msg[slen + mlen] = ctr;
			qrc_hmac512_blockfinalize(state, otp, msg, slen + mlen + 1);
		} else {
			while mlen >= QRC_SHA2_512_RATE	{
				qrc_hmac512_blockupdate(state, &info[ioft..], 1);
				ioft += QRC_SHA2_512_RATE;
				mlen -= QRC_SHA2_512_RATE;
			}

			if infolen > 0 {
				for i in 0..mlen {
					msg[i] = info[ioft + i];
				}
			}

			ctr += 1;
			msg[mlen] = ctr;
			qrc_hmac512_blockfinalize(state, otp, msg, mlen + 1);
		}

		let rmd = qrc_intutils_min(outlen, QRC_SHA2_512_HASH_SIZE);

		for i in 0..rmd {
			output[i] = otp[i];
		}

		outlen -= rmd;
		output = &mut output[rmd..];
	}
}


/*
* \brief Extract a key from a combined key and salt input using HMAC(SHA2-512).
*
* \param output: The output pseudo-random byte array
* \param key: [const] The HKDF key array
* \param keylen: The key array length
* \param salt: [const] The salt array
* \param saltlen: The salt array length
*/
pub fn qrc_hkdf512_extract(output: &mut [u8], key: &[u8], keylen: usize, salt: &[u8], saltlen: usize) {
	let state = &mut QrcHmac512State::default();

	if saltlen != 0	{
		qrc_hmac512_initialize(state, salt, saltlen);
	} else {
        let tmp = &mut [0u8; QRC_HMAC_512_MAC_SIZE];
		qrc_hmac512_initialize(state, tmp, QRC_HMAC_512_MAC_SIZE);
	}

	qrc_hmac512_blockfinalize(state, output, key, keylen);
}

/* SHA2-256 */

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

fn qrc_sha256_increase(state: &mut QrcSha256State, msglen: usize) {
	state.t += msglen as u64;
}


/* SHA2-384 */

const SHA384_IV: [u64; 8] = [
	0xCBBB9D5DC1059ED8,
	0x629A292A367CD507,
	0x9159015A3070DD17,
	0x152FECD8F70E5939,
	0x67332667FFC00B31,
	0x8EB44A8768581511,
	0xDB0C2E0D64F98FA7,
	0x47B5481DBEFA4FA4
];

fn qrc_sha384_increase(state: &mut QrcSha384State, length: usize) {
	state.t[0] += length as u64;

	if state.t[0] > 0x1FFFFFFFFFFFFFFF {
		state.t[1] += (state.t[0] >> 61) as u64;
		state.t[0] &= 0x1FFFFFFFFFFFFFFF;
	}
}


/* SHA2-512 */

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

fn qrc_sha512_increase(state: &mut QrcSha512State, length: usize) {
	state.t[0] += length as u64;

	if state.t[0] > 0x1FFFFFFFFFFFFFFF {
		state.t[1] += (state.t[0] >> 61) as u64;
		state.t[0] &= 0x1FFFFFFFFFFFFFFF;
	}
}