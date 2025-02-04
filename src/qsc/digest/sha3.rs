/* The AGPL version 3 License (AGPLv3)
*
* Copyright (c) 2024 DFD & QRC Eurosmart SA
* This file is part of the QSC Cryptographic library
*
* This program is free software : you can redistribute it and / or modify
* it under the terms of the GNU Affero General pub(crate)lic License as pub(crate)lished by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
* See the GNU Affero General pub(crate)lic License for more details.
*
* You should have received a copy of the GNU Affero General pub(crate)lic License
* along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

/**
* \file sha3.h
* \author John Underhill
* \date October 27, 2019
* \updated February 7, 2024
* \c to rust 2024-2025
*
* \brief SHA3 header definition \n
* Contains the pub(crate)lic api and documentation for SHA3 digest, SHAKE, cSHAKE, and KMAC implementations.
*
* Usage Examples \n
*
* SHA3-512 hash computation using long-form api \n
* \code
	fn Sha3_512() {
		let ctx = &mut QscKeccakState::default();
		let hash = &mut [0u8; QSC_SHA3_512_HASH_SIZE];
		let msg = &mut [0u8; 200];

		qsc_sha3_initialize(ctx);
		qsc_sha3_update(ctx, QscKeccakRate::QscKeccakRate512 as usize, msg, 200);
		qsc_sha3_finalize(ctx, QscKeccakRate::QscKeccakRate512 as usize, hash);
	}
* \endcode
*
* KMAC-256 MAC code generation using long-form api \n
* \code
	fn kmac_512() {
		let ctx = &mut QscKeccakState::default();
		let hash = &mut [0u8; 64];
		let msg = &mut [0u8; 200];
		let key = &mut [0u8; 50];
		let cust = &mut [0u8; 100];

		qsc_kmac_initialize(ctx, QscKeccakRate::QscKeccakRate512 as usize, key, 50, cust, 100);
		qsc_kmac_update(ctx, QscKeccakRate::QscKeccakRate512 as usize, msg, 200);
		qsc_kmac_finalize(ctx, QscKeccakRate::QscKeccakRate512 as usize, hash, 64);
	}
* \endcode
*
* cSHAKE-512 pseudo-random generation using long-form api \n
* \code
	fn cshake_512() {
		let ctx = &mut QscKeccakState::default();
		let hash = &mut [0u8; 64];
		let msg = &mut [0u8; 200];
		let cust = &mut [0u8; 15];

		qsc_cshake_initialize(ctx, QscKeccakRate::QscKeccakRate512 as usize, msg, 200, &[], 0, cust, 15);
		qsc_cshake_squeezeblocks(ctx, QscKeccakRate::QscKeccakRate512 as usize, hash, 1);
	}
* \endcode
*
* \remarks
* \par
* The SHA3, SHAKE, cSHAKE, and KMAC implementations all share two forms of api: short-form and long-form. \n
* The short-form api, which initializes the state, processes a message, and finalizes by producing output, all in a single function call,
* for example; qsc_sha3_compute512(uint8_t* output, const uint8_t* message, size_t msglen),
* the entire message array is processed and the hash code is written to the output array. \n
* The long-form api uses an initialization call to prepare the state, a blockupdate call if the message is longer than a single message block,
* and the finalize call, which finalizes the state and generates a hash, mac-code, or an array of pseudo-random. \n
* Each of the function families (SHA3, SHAKE, KMAC), have a corresponding set of reference constants associated with that member, example;
* SHAKE_256_KEY is the minimum expected SHAKE-256 key size in bytes, QSC_KMAC_512_MAC_SIZE is the minimum size of the KMAC-512 output mac-code output array,
* and QSC_KECCAK_512_RATE is the SHA3-512 message absorption rate.
*
* For additional usage examples, see sha3_test.h. \n
*
* \par
* NIST: SHA3 Fips202 http://nvlpub(crate)s.nist.gov/nistpub(crate)s/FIPS/NIST.FIPS.202.pdf \n
* NIST: SP800-185 http://nvlpub(crate)s.nist.gov/nistpub(crate)s/Specialpub(crate)lications/NIST.SP.800-185.pdf \n
* NIST: SHA3 Keccak Submission http://keccak.noekeon.org/Keccak-submission-3.pdf \n
* NIST: SHA3 Keccak Slides http://csrc.nist.gov/groups/ST/hash/sha-3/documents/Keccak-slides-at-NIST.pdf \n
* NIST: SHA3 Third-Round Report http://nvlpub(crate)s.nist.gov/nistpub(crate)s/ir/2012/NIST.IR.7896.pdf \n
* Team Keccak: Specifications summary https://keccak.team/keccak_specs_summary.html
*/

use crate::qsc::{
	common::common::QSC_SYSTEM_IS_LITTLE_ENDIAN,
	tools::{
		memutils::{
			qsc_memutils_xor,
			qsc_memutils_copy,
			qsc_memutils_clear,
		},
		intutils::{
			qsc_intutils_le8to64,
			qsc_intutils_le64to8,
			qsc_intutils_rotl64,
		},
	},
};

use std::mem::size_of;
use bytemuck::{cast_slice, cast_slice_mut};


/*
* \def QSC_SHA3_256_HASH_SIZE
* \brief The SHA-256 hash size in bytes (32)
*/
pub const QSC_SHA3_256_HASH_SIZE: usize = 32;

/*
* \def QSC_KECCAK_CSHAKE_DOMAIN_ID
* \brief The cSHAKE domain id
*/
pub const QSC_KECCAK_CSHAKE_DOMAIN_ID: u8 = 0x04;

/*
* \def QSC_KECCAK_KMAC_DOMAIN_ID
* \brief The KMAC domain id
*/
pub const QSC_KECCAK_KMAC_DOMAIN_ID: u8 = 0x04;

/*
* \def QSC_KECCAK_PERMUTATION_ROUNDS
* \brief The standard number of permutation rounds
*/
pub const QSC_KECCAK_PERMUTATION_ROUNDS: usize = 24;

/*
* \def QSC_KECCAK_PERMUTATION_MAX_ROUNDS
* \brief The maximum number of permutation rounds
*/
const QSC_KECCAK_PERMUTATION_MAX_ROUNDS: usize = 48;

/*
* \def QSC_KECCAK_SHA3_DOMAIN_ID
* \brief The SHA3 domain id
*/

pub const QSC_KECCAK_SHA3_DOMAIN_ID: u8 = 0x06;

/* 
* \def QSC_KECCAK_SHAKE_DOMAIN_ID
* \brief The SHAKE domain id
*/
pub const QSC_KECCAK_SHAKE_DOMAIN_ID: u8 = 0x1F;


/*
* \def QSC_KECCAK_128_RATE
* \brief The KMAC-128 byte absorption rate
*/
pub(crate) const QSC_KECCAK_128_RATE: usize = 168;

/*
* \def QSC_KECCAK_256_RATE
* \brief The KMAC-256 byte absorption rate
*/
pub(crate) const QSC_KECCAK_256_RATE: usize = 136;

/*
* \def QSC_KECCAK_512_RATE
* \brief The KMAC-512 byte absorption rate
*/
pub(crate) const QSC_KECCAK_512_RATE: usize = 72;

/*
* \def QSC_KECCAK_STATE_SIZE
* \brief The Keccak SHA3 uint64 state array size
*/
pub const QSC_KECCAK_STATE_SIZE: usize = 25;

/*
* \def QSC_KECCAK_STATE_BYTE_SIZE
* \brief The Keccak SHA3 state size in bytes
*/
pub const QSC_KECCAK_STATE_BYTE_SIZE: usize = 200;

/*
* \def QSC_SHA3_512_HASH_SIZE
* \brief The SHA-512 hash size in bytes (64)
*/
pub const QSC_SHA3_512_HASH_SIZE: usize = 64;


/* common */

/*
* \struct qsc_keccak_state
* \brief The Keccak state array; state array must be initialized by the caller
*/
//QSC_EXPORT_API 
#[derive(PartialEq, Debug)]
pub struct QscKeccakState {
	pub state: [u64; QSC_KECCAK_STATE_SIZE],			/*< The SHA3 state  */
	pub buffer: [u8; QSC_KECCAK_STATE_BYTE_SIZE],		/*< The message buffer  */
	pub position: usize,								/*< The buffer position  */
}
impl Default for QscKeccakState {
    fn default() -> Self {
        Self {
			state: [Default::default(); QSC_KECCAK_STATE_SIZE],
            buffer: [Default::default(); QSC_KECCAK_STATE_BYTE_SIZE],
			position: Default::default(),
        }
    }
}

/*
* \enum qsc_keccak_rate
* \brief The Keccak rate; determines which security strength is used by the function, 128, 256, or 512-bit
*/

#[derive(Clone, Copy, PartialEq)]
pub enum QscKeccakRate {
	QscKeccakRate128 = QSC_KECCAK_128_RATE as isize,		/*< The Keccak 128-bit rate  */
	QscKeccakRate256 = QSC_KECCAK_256_RATE as isize,		/*< The Keccak 256-bit rate  */
	QscKeccakRate512 = QSC_KECCAK_512_RATE as isize,		/*< The Keccak 512-bit rate  */
}

/* keccak round constants */
const KECCAK_ROUND_CONSTANTS: [u64; QSC_KECCAK_PERMUTATION_MAX_ROUNDS] =
[
	0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
	0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
	0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
	0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
	0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
	0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
	0x8000000080008082, 0x800000008000800A, 0x8000000000000003, 0x8000000080000009,
	0x8000000000008082, 0x0000000000008009, 0x8000000000000080, 0x0000000000008083,
	0x8000000000000081, 0x0000000000000001, 0x000000000000800B, 0x8000000080008001,
	0x0000000000000080, 0x8000000000008000, 0x8000000080008001, 0x0000000000000009,
	0x800000008000808B, 0x0000000000000081, 0x8000000000000082, 0x000000008000008B,
	0x8000000080008009, 0x8000000080000000, 0x0000000080000080, 0x0000000080008003
];


/* Common */

fn keccak_fast_absorb(state: &mut [u64], message: &[u8], msglen: usize) {
	if QSC_SYSTEM_IS_LITTLE_ENDIAN {
		let byte_slice = cast_slice_mut(state);
		qsc_memutils_xor(byte_slice, message, msglen);
	} else {
		for i in 0..(msglen/size_of::<u64>()) {
			state[i] ^= qsc_intutils_le8to64(&message[(size_of::<u64>() * i)..]);
		}
	}
}


fn keccak_left_encode(buffer: &mut [u8], value: usize) -> usize {
    let mut v: usize = value;
    let mut n: usize = 0;
    
    while v != 0 && n < size_of::<usize>() {
        n += 1;
        v >>= 8;
    }

	if n == 0 {
		n = 1;
	}

	for i in 1..=n {
        buffer[i] = (value >> (8 * (n - i))) as u8;
    }
    
    buffer[0] = n as u8;

	return n + 1;
}

fn keccak_right_encode(buffer: &mut [u8], value: usize) -> usize {
    let mut v: usize = value;
    let mut n: usize = 0;
    
    while v != 0 && n < size_of::<usize>() {
        n += 1;
        v >>= 8;
    }

	if n == 0 {
		n = 1;
	}

	for i in 1..=n {
        buffer[i - 1] = (value >> (8 * (n - i))) as u8;
    }
    
    buffer[n] = n as u8;


	return n + 1;
}

/* Keccak */

/**
* \brief Absorb an input message into the Keccak state
*
* \param ctx: [struct] A reference to the Keccak state; must be initialized
* \param rate: The rate of absorption in bytes
* \param message: [const] The input message byte array
* \param msglen: The number of message bytes to process
* \param domain: The function domain id
* \param rounds: The number of permutation rounds, the default is 24, maximum is 48
*/
fn qsc_keccak_absorb(ctx: &mut QscKeccakState, rate: usize, mut message: &[u8], mut msglen: usize, domain: u8, rounds: usize) {
	if !message.is_empty() {
		let msg = &mut [0u8; QSC_KECCAK_STATE_BYTE_SIZE];

		while msglen >= rate {
			if QSC_SYSTEM_IS_LITTLE_ENDIAN {
				let byte_slice = cast_slice_mut(&mut ctx.state);
				qsc_memutils_xor(byte_slice, message, rate);
			} else {
				for i in 0..(rate/size_of::<u64>()) {
					ctx.state[i] ^= qsc_intutils_le8to64(&message[(size_of::<u64>() * i)..]);
				}
			}

			qsc_keccak_permute(ctx, rounds);
			msglen -= rate;
			message = &message[rate..];
		}

		qsc_memutils_copy(msg, message, msglen);
		msg[msglen] = domain;
		qsc_memutils_clear(&mut msg[(msglen + 1)..]);
		msg[rate - 1] |= 128;

		if QSC_SYSTEM_IS_LITTLE_ENDIAN {
			let byte_slice = cast_slice_mut(&mut ctx.state);
			qsc_memutils_xor(byte_slice, msg, rate);
		} else {
			for i in 0..(rate/8) {
				ctx.state[i] ^= qsc_intutils_le8to64(&msg[(8 * i)..]);
			}
		}
	}
}

/**
* \brief Absorb the custom, and name arrays into the Keccak state
*
* \param ctx: [struct] The Keccak state structure
* \param rate: The rate of absorption in bytes
* \param custom: [const] The customization string
* \param custlen: The byte length of the customization string
* \param name: [const] The function name string
* \param namelen: The byte length of the function name
* \param rounds: The number of permutation rounds, the default is 24, maximum is 48
*/
fn qsc_keccak_absorb_custom(ctx: &mut QscKeccakState, rate: usize, custom: &[u8], custlen: usize, name: &[u8], namelen: usize, rounds: usize) {
	let pad = &mut [0u8; QSC_KECCAK_STATE_BYTE_SIZE];

	let mut oft: usize = keccak_left_encode(pad, rate);
	oft += keccak_left_encode(&mut pad[oft..], namelen * 8);

	if !name.is_empty() {
		for i in 0..namelen {
			if oft == rate {
				keccak_fast_absorb(&mut ctx.state, pad, rate);
				qsc_keccak_permute(ctx, rounds);
				oft = 0;
			}

			pad[oft] = name[i];
			oft = oft + 1;
		}
	}

	oft = oft + keccak_left_encode(&mut pad[oft..], custlen * 8);

	if !custom.is_empty() {
		for i in 0..custlen {
			if oft == rate {
				keccak_fast_absorb(&mut ctx.state, pad, rate);
				qsc_keccak_permute(ctx, rounds);
				oft = 0;
			}

			pad[oft] = custom[i];
			oft = oft + 1;
		}
	}

	qsc_memutils_clear(&mut pad[oft..]);
	keccak_fast_absorb(&mut ctx.state, pad, rate);
	qsc_keccak_permute(ctx, rounds);
}

/**
* \brief Absorb the custom, name, and key arrays into the Keccak state.
*
* \param ctx: [struct] The Keccak state structure
* \param rate: The rate of absorption in bytes
* \param key: [const] The input key byte array
* \param keylen: The number of key bytes to process
* \param custom: [const] The customization string
* \param custlen: The byte length of the customization string
* \param name: [const] The function name string
* \param namelen: The byte length of the function name
* \param rounds: The number of permutation rounds, the default is 24, maximum is 48
*/
fn qsc_keccak_absorb_key_custom(ctx: &mut QscKeccakState, rate: usize, key: &[u8], keylen: usize, custom: &[u8], custlen: usize, name: &[u8], namelen: usize, rounds: usize) {
	let pad = &mut [0u8; QSC_KECCAK_STATE_BYTE_SIZE];

	let bytes = ctx.state.as_mut_slice();
    let byte_slice = cast_slice_mut::<u64, u8>(bytes);

	qsc_memutils_clear(byte_slice);
	qsc_memutils_clear(&mut ctx.buffer);
	ctx.position = 0;

	/* stage 1: name + custom */

	let mut oft = keccak_left_encode(pad, rate);
	oft = oft + keccak_left_encode(&mut pad[oft..], namelen * 8);

	if !name.is_empty() {
		for i in 0..namelen {
			pad[oft + i] = name[i];
		}
	}

	oft += namelen;
	oft += keccak_left_encode(&mut pad[oft..], custlen * 8);

	if !custom.is_empty() {
		for i in 0..custlen {
			if oft == rate {
				keccak_fast_absorb(&mut ctx.state, pad, rate);
				qsc_keccak_permute(ctx, rounds);
				oft = 0;
			}

			pad[oft] = custom[i];
			oft = oft + 1;
		}
	}

	qsc_memutils_clear(&mut pad[oft..]);
	keccak_fast_absorb(&mut ctx.state, pad, rate);
	qsc_keccak_permute(ctx, rounds);


	/* stage 2: key */

	qsc_memutils_clear(pad);

	oft = keccak_left_encode(pad, rate);
	oft += keccak_left_encode(&mut pad[oft..], keylen * 8);

	if !key.is_empty() {
		for i in 0..keylen {
			if oft == rate {
				keccak_fast_absorb(&mut ctx.state, pad, rate);
				qsc_keccak_permute(ctx, rounds);
				oft = 0;
			}

			pad[oft] = key[i];
			oft = oft + 1;
		}
	}

	qsc_memutils_clear(&mut pad[oft..]);
	keccak_fast_absorb(&mut ctx.state, pad, rate);
	qsc_keccak_permute(ctx, rounds);
}

/**
* \brief Dispose of the Keccak state.
*
* \warning The dispose function must be called when disposing of the function state.
* This function safely destroys the internal state.
*
* \param ctx: [struct] The Keccak state structure
*/
pub fn qsc_keccak_dispose(ctx: &mut QscKeccakState) {
	let bytes = ctx.state.as_mut_slice();
    let byte_slice = cast_slice_mut::<u64, u8>(bytes);

	qsc_memutils_clear(byte_slice);
	qsc_memutils_clear(&mut ctx.buffer);
	ctx.position = 0;
}

/**
* \brief Finalize the Keccak state
*
* \param ctx: [struct] The Keccak state structure
* \param rate: The rate of absorption in bytes
* \param output: The output byte array
* \param outlen: The number of output bytes to generate
* \param domain: The function domain id
* \param rounds: The number of permutation rounds, the default is 24, maximum is 48
*/
fn qsc_keccak_finalize(ctx: &mut QscKeccakState, rate: usize, mut output: &mut [u8], mut outlen: usize, domain: usize, rounds: usize) {

	let buf = &mut [0u8; size_of::<usize>() + 1];
	let pad = &mut [0u8; QSC_KECCAK_STATE_BYTE_SIZE];

	qsc_memutils_copy(pad, &ctx.buffer, ctx.position);
	let bitlen = keccak_right_encode(buf, outlen * 8);

	if ctx.position + bitlen >= rate {
		keccak_fast_absorb(&mut ctx.state, pad, ctx.position);
		qsc_keccak_permute(ctx, rounds);
		ctx.position = 0;
	}

	qsc_memutils_copy(&mut pad[ctx.position..], buf, bitlen);

	pad[ctx.position + bitlen] = domain as u8;
	pad[rate - 1] |= 128;
	keccak_fast_absorb(&mut ctx.state, pad, rate);

	while outlen >= rate {
		qsc_keccak_squeezeblocks(ctx, pad, 1, rate, rounds);
		qsc_memutils_copy(output, pad, rate);
		output = &mut output[rate..];
		outlen -= rate;
	}

	if outlen > 0 {
		qsc_keccak_squeezeblocks(ctx, pad, 1, rate, rounds);
		qsc_memutils_copy(output, pad, outlen);
	}
	qsc_memutils_clear(&mut ctx.buffer);
	ctx.position = 0;
}

/**
* \brief Absorb bytes into state incrementally
*
* \param ctx: The function state
* \param rate: The rate of absorption in bytes
* \param message: [const] The input message array
* \param msglen: The number of message bytes
*/
pub(crate) fn qsc_keccak_incremental_absorb(ctx: &mut QscKeccakState, rate: usize, mut message: &[u8], mut msglen: usize) {
	let t = &mut [0u8; 8];
	
	if ctx.position & 7 > 0	{
		let mut i = ctx.position & 7;
		while i < 8 && msglen > 0 {
			t[i] = message[i];
			message = &message[1..];
			i = i + 1;
			msglen = msglen - 1;
			ctx.position = ctx.position + 1;
		}

		ctx.state[(ctx.position - i) / 8] ^= qsc_intutils_le8to64(t);
	}

	if ctx.position >= rate - ctx.position && msglen >= rate - ctx.position {
		for i in 0..((rate - ctx.position) / 8) {
			ctx.state[(ctx.position / 8) + i] ^= qsc_intutils_le8to64(&message[(8 * i)..]);
		}

		message = &message[(rate - ctx.position)..];
		msglen -= rate - ctx.position;
		ctx.position = 0;
		qsc_keccak_permute_p1600c(&mut ctx.state, QSC_KECCAK_PERMUTATION_ROUNDS);
	}

	while msglen >= rate {
		for i in 0..(rate / 8) {
			ctx.state[i as usize] ^= qsc_intutils_le8to64(&message[(8 * i as usize)..]);
		}

		message = &message[rate..];
		msglen -= rate;
		qsc_keccak_permute_p1600c(&mut ctx.state, QSC_KECCAK_PERMUTATION_ROUNDS);
	}

	let mut i = 0;
	while i < msglen / 8 {
		ctx.state[(ctx.position / 8) + i] ^= qsc_intutils_le8to64(&message[(8 * i)..]);
		i += 1;
	}

	message = &message[(8 * i)..];
	msglen -= 8 * i;
	ctx.position = ctx.position + (8 * i);

	if msglen > 0 {
		for i in 0..8 {
			t[i] = 0;
		}

		for i in 0..msglen {
			t[i] = message[i];
		}

		ctx.state[ctx.position / 8] ^= qsc_intutils_le8to64(t);
		ctx.position = ctx.position + msglen;
	}
}

/**
* \brief Finalize state added incrementally
*
* \param ctx: The function state
* \param rate: The rate of absorption in bytes
* \param domain: The function domain id
*/
pub(crate) fn qsc_keccak_incremental_finalize(ctx: &mut QscKeccakState, rate: usize, domain: u8) {
    let i = ctx.position >> 3;
    let j = ctx.position & 7;
    ctx.state[i] ^= (domain as u64) << (8 * j);
    ctx.state[(rate / 8) - 1] ^= 1 << 63;
    ctx.position = 0;
}

/**
* \brief Extract an array of bytes from the Keccak state
*
* \param ctx: The function state
* \param output: The output byte array
* \param outlen: The number of output bytes to generate
* \param rate: The rate of absorption in bytes
*/
pub(crate) fn qsc_keccak_incremental_squeeze(ctx: &mut QscKeccakState, rate: usize, mut output: &mut [u8], mut outlen: usize) {
	let mut i: usize;
	let t = &mut [0u8; 8];

	if (ctx.position & 7) > 0 {
		qsc_intutils_le64to8(t, ctx.state[ctx.position / 8]);
		i = ctx.position & 7;

		while i < 8 && outlen > 0 {
			output[i] = t[i];
			output = &mut output[1..];
			i = i + 1;
			outlen = outlen - 1;
			ctx.position = ctx.position + 1;
		}
	}

	if ctx.position >= rate - ctx.position && outlen >= rate - ctx.position {
		for i in 0..(rate - ctx.position) / 8 {
			qsc_intutils_le64to8(&mut output[(8 * i)..], ctx.state[(ctx.position / 8) + i]);
		}

		output = &mut output[(rate - ctx.position)..];
		outlen -= rate - ctx.position;
		ctx.position = 0;
	}

	while outlen >= rate {
		qsc_keccak_permute_p1600c(&mut ctx.state, QSC_KECCAK_PERMUTATION_ROUNDS);

		for i in 0..rate / 8 {
			qsc_intutils_le64to8(&mut output[(8 * i)..], ctx.state[i]);
		}

		output = &mut output[rate..];
		outlen -= rate;
	}

	if outlen > 0 {
		if ctx.position == 0 {
			qsc_keccak_permute_p1600c(&mut ctx.state, QSC_KECCAK_PERMUTATION_ROUNDS);
		}

		let mut i = 0;
		while i < outlen / 8 {
			qsc_intutils_le64to8(&mut output[(8 * i)..], ctx.state[(ctx.position / 8) + i]);
			i += 1;
		}

		output = &mut output[(8 * i)..];
		outlen -= 8 * i;
		ctx.position += 8 * i;

		qsc_intutils_le64to8(t, ctx.state[ctx.position / 8]);

		for i in 0..outlen {
			output[i] = t[i];
		}

		ctx.position += outlen;
	}
}

/**
* \brief The Keccak permute function.
* Internal function: Permutes the state array, can be used in external constructions.
*
* \param ctx: [struct] The function state; must be initialized
* \param rounds: The number of permutation rounds, the default and maximum is 24
*/
fn qsc_keccak_permute(ctx: &mut QscKeccakState, rounds: usize) {
	let qsc_keccak_unrolled_permutation = false;
	if qsc_keccak_unrolled_permutation == true {
		qsc_keccak_permute_p1600u(&mut ctx.state)
	} else {
		qsc_keccak_permute_p1600c(&mut ctx.state, rounds);
	}
}

/**
* \brief The compact Keccak permute function.
* Internal function: Permutes the state array, can be used in external constructions.
*
* \param state: The state array; must be initialized
* \param rounds: The number of permutation rounds, the default and maximum is 24
*/
fn qsc_keccak_permute_p1600c(state: &mut [u64], rounds: usize) {
	/* copyFromState(A, state) */
	let mut aba = state[0];
	let mut abe = state[1];
	let mut abi = state[2];
	let mut abo = state[3];
	let mut abu = state[4];
	let mut aga = state[5];
	let mut age = state[6];
	let mut agi = state[7];
	let mut ago = state[8];
	let mut agu = state[9];
	let mut aka = state[10];
	let mut ake = state[11];
	let mut aki = state[12];
	let mut ako = state[13];
	let mut aku = state[14];
	let mut ama = state[15];
	let mut ame = state[16];
	let mut ami = state[17];
	let mut amo = state[18];
	let mut amu = state[19];
	let mut asa = state[20];
	let mut ase = state[21];
	let mut asi = state[22];
	let mut aso = state[23];
	let mut asu = state[24];

	
	for i in (0..rounds).step_by(2) {
		/* prepareTheta */
		let mut bca = aba ^ aga ^ aka ^ ama ^ asa;
		let mut bce = abe ^ age ^ ake ^ ame ^ ase;
		let mut bci = abi ^ agi ^ aki ^ ami ^ asi;
		let mut bco = abo ^ ago ^ ako ^ amo ^ aso;
		let mut bcu = abu ^ agu ^ aku ^ amu ^ asu;

		/* thetaRhoPiChiIotaPrepareTheta */
		let mut da = bcu ^ qsc_intutils_rotl64(bce, 1);
		let mut de = bca ^ qsc_intutils_rotl64(bci, 1);
		let mut di = bce ^ qsc_intutils_rotl64(bco, 1);
		let mut dz = bci ^ qsc_intutils_rotl64(bcu, 1);
		let mut du = bco ^ qsc_intutils_rotl64(bca, 1);

		aba ^= da;
		bca = aba;
		age ^= de;
		bce = qsc_intutils_rotl64(age, 44);
		aki ^= di;
		bci = qsc_intutils_rotl64(aki, 43);
		amo ^= dz;
		bco = qsc_intutils_rotl64(amo, 21);
		asu ^= du;
		bcu = qsc_intutils_rotl64(asu, 14);
		let mut eba = bca ^ ((!bce) & bci);
		eba ^= KECCAK_ROUND_CONSTANTS[i];
		let mut ebe = bce ^ ((!bci) & bco);
		let mut ebi = bci ^ ((!bco) & bcu);
		let mut ebo = bco ^ ((!bcu) & bca);
		let mut ebu = bcu ^ ((!bca) & bce);

		abo ^= dz;
		bca = qsc_intutils_rotl64(abo, 28);
		agu ^= du;
		bce = qsc_intutils_rotl64(agu, 20);
		aka ^= da;
		bci = qsc_intutils_rotl64(aka, 3);
		ame ^= de;
		bco = qsc_intutils_rotl64(ame, 45);
		asi ^= di;
		bcu = qsc_intutils_rotl64(asi, 61);
		let mut ega = bca ^ ((!bce) & bci);
		let mut ege = bce ^ ((!bci) & bco);
		let mut egi = bci ^ ((!bco) & bcu);
		let mut ego = bco ^ ((!bcu) & bca);
		let mut egu = bcu ^ ((!bca) & bce);

		abe ^= de;
		bca = qsc_intutils_rotl64(abe, 1);
		agi ^= di;
		bce = qsc_intutils_rotl64(agi, 6);
		ako ^= dz;
		bci = qsc_intutils_rotl64(ako, 25);
		amu ^= du;
		bco = qsc_intutils_rotl64(amu, 8);
		asa ^= da;
		bcu = qsc_intutils_rotl64(asa, 18);
		let mut eka = bca ^ ((!bce) & bci);
		let mut eke = bce ^ ((!bci) & bco);
		let mut eki = bci ^ ((!bco) & bcu);
		let mut eko = bco ^ ((!bcu) & bca);
		let mut eku = bcu ^ ((!bca) & bce);

		abu ^= du;
		bca = qsc_intutils_rotl64(abu, 27);
		aga ^= da;
		bce = qsc_intutils_rotl64(aga, 36);
		ake ^= de;
		bci = qsc_intutils_rotl64(ake, 10);
		ami ^= di;
		bco = qsc_intutils_rotl64(ami, 15);
		aso ^= dz;
		bcu = qsc_intutils_rotl64(aso, 56);
		let mut ema = bca ^ ((!bce) & bci);
		let mut eme = bce ^ ((!bci) & bco);
		let mut emi = bci ^ ((!bco) & bcu);
		let mut emo = bco ^ ((!bcu) & bca);
		let mut emu = bcu ^ ((!bca) & bce);

		abi ^= di;
		bca = qsc_intutils_rotl64(abi, 62);
		ago ^= dz;
		bce = qsc_intutils_rotl64(ago, 55);
		aku ^= du;
		bci = qsc_intutils_rotl64(aku, 39);
		ama ^= da;
		bco = qsc_intutils_rotl64(ama, 41);
		ase ^= de;
		bcu = qsc_intutils_rotl64(ase, 2);
		let mut esa = bca ^ ((!bce) & bci);
		let mut ese = bce ^ ((!bci) & bco);
		let mut esi = bci ^ ((!bco) & bcu);
		let mut eso = bco ^ ((!bcu) & bca);
		let mut esu = bcu ^ ((!bca) & bce);

		/* prepareTheta */
		bca = eba ^ ega ^ eka ^ ema ^ esa;
		bce = ebe ^ ege ^ eke ^ eme ^ ese;
		bci = ebi ^ egi ^ eki ^ emi ^ esi;
		bco = ebo ^ ego ^ eko ^ emo ^ eso;
		bcu = ebu ^ egu ^ eku ^ emu ^ esu;

		/* thetaRhoPiChiIotaPrepareTheta */
		da = bcu ^ qsc_intutils_rotl64(bce, 1);
		de = bca ^ qsc_intutils_rotl64(bci, 1);
		di = bce ^ qsc_intutils_rotl64(bco, 1);
		dz = bci ^ qsc_intutils_rotl64(bcu, 1);
		du = bco ^ qsc_intutils_rotl64(bca, 1);

		eba ^= da;
		bca = eba;
		ege ^= de;
		bce = qsc_intutils_rotl64(ege, 44);
		eki ^= di;
		bci = qsc_intutils_rotl64(eki, 43);
		emo ^= dz;
		bco = qsc_intutils_rotl64(emo, 21);
		esu ^= du;
		bcu = qsc_intutils_rotl64(esu, 14);
		aba = bca ^ ((!bce) & bci);
		aba ^= KECCAK_ROUND_CONSTANTS[i + 1];
		abe = bce ^ ((!bci) & bco);
		abi = bci ^ ((!bco) & bcu);
		abo = bco ^ ((!bcu) & bca);
		abu = bcu ^ ((!bca) & bce);

		ebo ^= dz;
		bca = qsc_intutils_rotl64(ebo, 28);
		egu ^= du;
		bce = qsc_intutils_rotl64(egu, 20);
		eka ^= da;
		bci = qsc_intutils_rotl64(eka, 3);
		eme ^= de;
		bco = qsc_intutils_rotl64(eme, 45);
		esi ^= di;
		bcu = qsc_intutils_rotl64(esi, 61);
		aga = bca ^ ((!bce) & bci);
		age = bce ^ ((!bci) & bco);
		agi = bci ^ ((!bco) & bcu);
		ago = bco ^ ((!bcu) & bca);
		agu = bcu ^ ((!bca) & bce);

		ebe ^= de;
		bca = qsc_intutils_rotl64(ebe, 1);
		egi ^= di;
		bce = qsc_intutils_rotl64(egi, 6);
		eko ^= dz;
		bci = qsc_intutils_rotl64(eko, 25);
		emu ^= du;
		bco = qsc_intutils_rotl64(emu, 8);
		esa ^= da;
		bcu = qsc_intutils_rotl64(esa, 18);
		aka = bca ^ ((!bce) & bci);
		ake = bce ^ ((!bci) & bco);
		aki = bci ^ ((!bco) & bcu);
		ako = bco ^ ((!bcu) & bca);
		aku = bcu ^ ((!bca) & bce);

		ebu ^= du;
		bca = qsc_intutils_rotl64(ebu, 27);
		ega ^= da;
		bce = qsc_intutils_rotl64(ega, 36);
		eke ^= de;
		bci = qsc_intutils_rotl64(eke, 10);
		emi ^= di;
		bco = qsc_intutils_rotl64(emi, 15);
		eso ^= dz;
		bcu = qsc_intutils_rotl64(eso, 56);
		ama = bca ^ ((!bce) & bci);
		ame = bce ^ ((!bci) & bco);
		ami = bci ^ ((!bco) & bcu);
		amo = bco ^ ((!bcu) & bca);
		amu = bcu ^ ((!bca) & bce);

		ebi ^= di;
		bca = qsc_intutils_rotl64(ebi, 62);
		ego ^= dz;
		bce = qsc_intutils_rotl64(ego, 55);
		eku ^= du;
		bci = qsc_intutils_rotl64(eku, 39);
		ema ^= da;
		bco = qsc_intutils_rotl64(ema, 41);
		ese ^= de;
		bcu = qsc_intutils_rotl64(ese, 2);
		asa = bca ^ ((!bce) & bci);
		ase = bce ^ ((!bci) & bco);
		asi = bci ^ ((!bco) & bcu);
		aso = bco ^ ((!bcu) & bca);
		asu = bcu ^ ((!bca) & bce);
	}

	/* copy to state */
	state[0] = aba;
	state[1] = abe;
	state[2] = abi;
	state[3] = abo;
	state[4] = abu;
	state[5] = aga;
	state[6] = age;
	state[7] = agi;
	state[8] = ago;
	state[9] = agu;
	state[10] = aka;
	state[11] = ake;
	state[12] = aki;
	state[13] = ako;
	state[14] = aku;
	state[15] = ama;
	state[16] = ame;
	state[17] = ami;
	state[18] = amo;
	state[19] = amu;
	state[20] = asa;
	state[21] = ase;
	state[22] = asi;
	state[23] = aso;
	state[24] = asu;
}

/**
* \brief The unrolled Keccak permute function.
* Internal function: Permutes the state array, can be used in external constructions.
*
* \param state: The state array; must be initialized
*/
fn qsc_keccak_permute_p1600u(state: &mut [u64]) {
	let mut aba = state[0];
	let mut abe = state[1];
	let mut abi = state[2];
	let mut abo = state[3];
	let mut abu = state[4];
	let mut aga = state[5];
	let mut age = state[6];
	let mut agi = state[7];
	let mut ago = state[8];
	let mut agu = state[9];
	let mut aka = state[10];
	let mut ake = state[11];
	let mut aki = state[12];
	let mut ako = state[13];
	let mut aku = state[14];
	let mut ama = state[15];
	let mut ame = state[16];
	let mut ami = state[17];
	let mut amo = state[18];
	let mut amu = state[19];
	let mut asa = state[20];
	let mut ase = state[21];
	let mut asi = state[22];
	let mut aso = state[23];
	let mut asu = state[24];

	/* round 1 */
	let mut ca = aba ^ aga ^ aka ^ ama ^ asa;
	let mut ce = abe ^ age ^ ake ^ ame ^ ase;
	let mut ci = abi ^ agi ^ aki ^ ami ^ asi;
	let mut co = abo ^ ago ^ ako ^ amo ^ aso;
	let mut cu = abu ^ agu ^ aku ^ amu ^ asu;
	let mut da = cu ^ qsc_intutils_rotl64(ce, 1);
	let mut de = ca ^ qsc_intutils_rotl64(ci, 1);
	let mut di = ce ^ qsc_intutils_rotl64(co, 1);
	let mut dz = ci ^ qsc_intutils_rotl64(cu, 1);
	let mut du = co ^ qsc_intutils_rotl64(ca, 1);
	aba ^= da;
	ca = aba;
	age ^= de;
	ce = qsc_intutils_rotl64(age, 44);
	aki ^= di;
	ci = qsc_intutils_rotl64(aki, 43);
	amo ^= dz;
	co = qsc_intutils_rotl64(amo, 21);
	asu ^= du;
	cu = qsc_intutils_rotl64(asu, 14);
	let mut eba = ca ^ ((!ce) & ci);
	eba ^= 0x0000000000000001;
	let mut ebe = ce ^ ((!ci) & co);
	let mut ebi = ci ^ ((!co) & cu);
	let mut ebo = co ^ ((!cu) & ca);
	let mut ebu = cu ^ ((!ca) & ce);
	abo ^= dz;
	ca = qsc_intutils_rotl64(abo, 28);
	agu ^= du;
	ce = qsc_intutils_rotl64(agu, 20);
	aka ^= da;
	ci = qsc_intutils_rotl64(aka, 3);
	ame ^= de;
	co = qsc_intutils_rotl64(ame, 45);
	asi ^= di;
	cu = qsc_intutils_rotl64(asi, 61);
	let mut ega = ca ^ ((!ce) & ci);
	let mut ege = ce ^ ((!ci) & co);
	let mut egi = ci ^ ((!co) & cu);
	let mut ego = co ^ ((!cu) & ca);
	let mut egu = cu ^ ((!ca) & ce);
	abe ^= de;
	ca = qsc_intutils_rotl64(abe, 1);
	agi ^= di;
	ce = qsc_intutils_rotl64(agi, 6);
	ako ^= dz;
	ci = qsc_intutils_rotl64(ako, 25);
	amu ^= du;
	co = qsc_intutils_rotl64(amu, 8);
	asa ^= da;
	cu = qsc_intutils_rotl64(asa, 18);
	let mut eka = ca ^ ((!ce) & ci);
	let mut eke = ce ^ ((!ci) & co);
	let mut eki = ci ^ ((!co) & cu);
	let mut eko = co ^ ((!cu) & ca);
	let mut eku = cu ^ ((!ca) & ce);
	abu ^= du;
	ca = qsc_intutils_rotl64(abu, 27);
	aga ^= da;
	ce = qsc_intutils_rotl64(aga, 36);
	ake ^= de;
	ci = qsc_intutils_rotl64(ake, 10);
	ami ^= di;
	co = qsc_intutils_rotl64(ami, 15);
	aso ^= dz;
	cu = qsc_intutils_rotl64(aso, 56);
	let mut ema = ca ^ ((!ce) & ci);
	let mut eme = ce ^ ((!ci) & co);
	let mut emi = ci ^ ((!co) & cu);
	let mut emo = co ^ ((!cu) & ca);
	let mut emu = cu ^ ((!ca) & ce);
	abi ^= di;
	ca = qsc_intutils_rotl64(abi, 62);
	ago ^= dz;
	ce = qsc_intutils_rotl64(ago, 55);
	aku ^= du;
	ci = qsc_intutils_rotl64(aku, 39);
	ama ^= da;
	co = qsc_intutils_rotl64(ama, 41);
	ase ^= de;
	cu = qsc_intutils_rotl64(ase, 2);
	let mut esa = ca ^ ((!ce) & ci);
	let mut ese = ce ^ ((!ci) & co);
	let mut esi = ci ^ ((!co) & cu);
	let mut eso = co ^ ((!cu) & ca);
	let mut esu = cu ^ ((!ca) & ce);
	/* round 2 */
	ca = eba ^ ega ^ eka ^ ema ^ esa;
	ce = ebe ^ ege ^ eke ^ eme ^ ese;
	ci = ebi ^ egi ^ eki ^ emi ^ esi;
	co = ebo ^ ego ^ eko ^ emo ^ eso;
	cu = ebu ^ egu ^ eku ^ emu ^ esu;
	da = cu ^ qsc_intutils_rotl64(ce, 1);
	de = ca ^ qsc_intutils_rotl64(ci, 1);
	di = ce ^ qsc_intutils_rotl64(co, 1);
	dz = ci ^ qsc_intutils_rotl64(cu, 1);
	du = co ^ qsc_intutils_rotl64(ca, 1);
	eba ^= da;
	ca = eba;
	ege ^= de;
	ce = qsc_intutils_rotl64(ege, 44);
	eki ^= di;
	ci = qsc_intutils_rotl64(eki, 43);
	emo ^= dz;
	co = qsc_intutils_rotl64(emo, 21);
	esu ^= du;
	cu = qsc_intutils_rotl64(esu, 14);
	aba = ca ^ ((!ce) & ci);
	aba ^= 0x0000000000008082;
	abe = ce ^ ((!ci) & co);
	abi = ci ^ ((!co) & cu);
	abo = co ^ ((!cu) & ca);
	abu = cu ^ ((!ca) & ce);
	ebo ^= dz;
	ca = qsc_intutils_rotl64(ebo, 28);
	egu ^= du;
	ce = qsc_intutils_rotl64(egu, 20);
	eka ^= da;
	ci = qsc_intutils_rotl64(eka, 3);
	eme ^= de;
	co = qsc_intutils_rotl64(eme, 45);
	esi ^= di;
	cu = qsc_intutils_rotl64(esi, 61);
	aga = ca ^ ((!ce) & ci);
	age = ce ^ ((!ci) & co);
	agi = ci ^ ((!co) & cu);
	ago = co ^ ((!cu) & ca);
	agu = cu ^ ((!ca) & ce);
	ebe ^= de;
	ca = qsc_intutils_rotl64(ebe, 1);
	egi ^= di;
	ce = qsc_intutils_rotl64(egi, 6);
	eko ^= dz;
	ci = qsc_intutils_rotl64(eko, 25);
	emu ^= du;
	co = qsc_intutils_rotl64(emu, 8);
	esa ^= da;
	cu = qsc_intutils_rotl64(esa, 18);
	aka = ca ^ ((!ce) & ci);
	ake = ce ^ ((!ci) & co);
	aki = ci ^ ((!co) & cu);
	ako = co ^ ((!cu) & ca);
	aku = cu ^ ((!ca) & ce);
	ebu ^= du;
	ca = qsc_intutils_rotl64(ebu, 27);
	ega ^= da;
	ce = qsc_intutils_rotl64(ega, 36);
	eke ^= de;
	ci = qsc_intutils_rotl64(eke, 10);
	emi ^= di;
	co = qsc_intutils_rotl64(emi, 15);
	eso ^= dz;
	cu = qsc_intutils_rotl64(eso, 56);
	ama = ca ^ ((!ce) & ci);
	ame = ce ^ ((!ci) & co);
	ami = ci ^ ((!co) & cu);
	amo = co ^ ((!cu) & ca);
	amu = cu ^ ((!ca) & ce);
	ebi ^= di;
	ca = qsc_intutils_rotl64(ebi, 62);
	ego ^= dz;
	ce = qsc_intutils_rotl64(ego, 55);
	eku ^= du;
	ci = qsc_intutils_rotl64(eku, 39);
	ema ^= da;
	co = qsc_intutils_rotl64(ema, 41);
	ese ^= de;
	cu = qsc_intutils_rotl64(ese, 2);
	asa = ca ^ ((!ce) & ci);
	ase = ce ^ ((!ci) & co);
	asi = ci ^ ((!co) & cu);
	aso = co ^ ((!cu) & ca);
	asu = cu ^ ((!ca) & ce);
	/* round 3 */
	ca = aba ^ aga ^ aka ^ ama ^ asa;
	ce = abe ^ age ^ ake ^ ame ^ ase;
	ci = abi ^ agi ^ aki ^ ami ^ asi;
	co = abo ^ ago ^ ako ^ amo ^ aso;
	cu = abu ^ agu ^ aku ^ amu ^ asu;
	da = cu ^ qsc_intutils_rotl64(ce, 1);
	de = ca ^ qsc_intutils_rotl64(ci, 1);
	di = ce ^ qsc_intutils_rotl64(co, 1);
	dz = ci ^ qsc_intutils_rotl64(cu, 1);
	du = co ^ qsc_intutils_rotl64(ca, 1);
	aba ^= da;
	ca = aba;
	age ^= de;
	ce = qsc_intutils_rotl64(age, 44);
	aki ^= di;
	ci = qsc_intutils_rotl64(aki, 43);
	amo ^= dz;
	co = qsc_intutils_rotl64(amo, 21);
	asu ^= du;
	cu = qsc_intutils_rotl64(asu, 14);
	eba = ca ^ ((!ce) & ci);
	eba ^= 0x800000000000808A;
	ebe = ce ^ ((!ci) & co);
	ebi = ci ^ ((!co) & cu);
	ebo = co ^ ((!cu) & ca);
	ebu = cu ^ ((!ca) & ce);
	abo ^= dz;
	ca = qsc_intutils_rotl64(abo, 28);
	agu ^= du;
	ce = qsc_intutils_rotl64(agu, 20);
	aka ^= da;
	ci = qsc_intutils_rotl64(aka, 3);
	ame ^= de;
	co = qsc_intutils_rotl64(ame, 45);
	asi ^= di;
	cu = qsc_intutils_rotl64(asi, 61);
	ega = ca ^ ((!ce) & ci);
	ege = ce ^ ((!ci) & co);
	egi = ci ^ ((!co) & cu);
	ego = co ^ ((!cu) & ca);
	egu = cu ^ ((!ca) & ce);
	abe ^= de;
	ca = qsc_intutils_rotl64(abe, 1);
	agi ^= di;
	ce = qsc_intutils_rotl64(agi, 6);
	ako ^= dz;
	ci = qsc_intutils_rotl64(ako, 25);
	amu ^= du;
	co = qsc_intutils_rotl64(amu, 8);
	asa ^= da;
	cu = qsc_intutils_rotl64(asa, 18);
	eka = ca ^ ((!ce) & ci);
	eke = ce ^ ((!ci) & co);
	eki = ci ^ ((!co) & cu);
	eko = co ^ ((!cu) & ca);
	eku = cu ^ ((!ca) & ce);
	abu ^= du;
	ca = qsc_intutils_rotl64(abu, 27);
	aga ^= da;
	ce = qsc_intutils_rotl64(aga, 36);
	ake ^= de;
	ci = qsc_intutils_rotl64(ake, 10);
	ami ^= di;
	co = qsc_intutils_rotl64(ami, 15);
	aso ^= dz;
	cu = qsc_intutils_rotl64(aso, 56);
	ema = ca ^ ((!ce) & ci);
	eme = ce ^ ((!ci) & co);
	emi = ci ^ ((!co) & cu);
	emo = co ^ ((!cu) & ca);
	emu = cu ^ ((!ca) & ce);
	abi ^= di;
	ca = qsc_intutils_rotl64(abi, 62);
	ago ^= dz;
	ce = qsc_intutils_rotl64(ago, 55);
	aku ^= du;
	ci = qsc_intutils_rotl64(aku, 39);
	ama ^= da;
	co = qsc_intutils_rotl64(ama, 41);
	ase ^= de;
	cu = qsc_intutils_rotl64(ase, 2);
	esa = ca ^ ((!ce) & ci);
	ese = ce ^ ((!ci) & co);
	esi = ci ^ ((!co) & cu);
	eso = co ^ ((!cu) & ca);
	esu = cu ^ ((!ca) & ce);
	/* round 4 */
	ca = eba ^ ega ^ eka ^ ema ^ esa;
	ce = ebe ^ ege ^ eke ^ eme ^ ese;
	ci = ebi ^ egi ^ eki ^ emi ^ esi;
	co = ebo ^ ego ^ eko ^ emo ^ eso;
	cu = ebu ^ egu ^ eku ^ emu ^ esu;
	da = cu ^ qsc_intutils_rotl64(ce, 1);
	de = ca ^ qsc_intutils_rotl64(ci, 1);
	di = ce ^ qsc_intutils_rotl64(co, 1);
	dz = ci ^ qsc_intutils_rotl64(cu, 1);
	du = co ^ qsc_intutils_rotl64(ca, 1);
	eba ^= da;
	ca = eba;
	ege ^= de;
	ce = qsc_intutils_rotl64(ege, 44);
	eki ^= di;
	ci = qsc_intutils_rotl64(eki, 43);
	emo ^= dz;
	co = qsc_intutils_rotl64(emo, 21);
	esu ^= du;
	cu = qsc_intutils_rotl64(esu, 14);
	aba = ca ^ ((!ce) & ci);
	aba ^= 0x8000000080008000;
	abe = ce ^ ((!ci) & co);
	abi = ci ^ ((!co) & cu);
	abo = co ^ ((!cu) & ca);
	abu = cu ^ ((!ca) & ce);
	ebo ^= dz;
	ca = qsc_intutils_rotl64(ebo, 28);
	egu ^= du;
	ce = qsc_intutils_rotl64(egu, 20);
	eka ^= da;
	ci = qsc_intutils_rotl64(eka, 3);
	eme ^= de;
	co = qsc_intutils_rotl64(eme, 45);
	esi ^= di;
	cu = qsc_intutils_rotl64(esi, 61);
	aga = ca ^ ((!ce) & ci);
	age = ce ^ ((!ci) & co);
	agi = ci ^ ((!co) & cu);
	ago = co ^ ((!cu) & ca);
	agu = cu ^ ((!ca) & ce);
	ebe ^= de;
	ca = qsc_intutils_rotl64(ebe, 1);
	egi ^= di;
	ce = qsc_intutils_rotl64(egi, 6);
	eko ^= dz;
	ci = qsc_intutils_rotl64(eko, 25);
	emu ^= du;
	co = qsc_intutils_rotl64(emu, 8);
	esa ^= da;
	cu = qsc_intutils_rotl64(esa, 18);
	aka = ca ^ ((!ce) & ci);
	ake = ce ^ ((!ci) & co);
	aki = ci ^ ((!co) & cu);
	ako = co ^ ((!cu) & ca);
	aku = cu ^ ((!ca) & ce);
	ebu ^= du;
	ca = qsc_intutils_rotl64(ebu, 27);
	ega ^= da;
	ce = qsc_intutils_rotl64(ega, 36);
	eke ^= de;
	ci = qsc_intutils_rotl64(eke, 10);
	emi ^= di;
	co = qsc_intutils_rotl64(emi, 15);
	eso ^= dz;
	cu = qsc_intutils_rotl64(eso, 56);
	ama = ca ^ ((!ce) & ci);
	ame = ce ^ ((!ci) & co);
	ami = ci ^ ((!co) & cu);
	amo = co ^ ((!cu) & ca);
	amu = cu ^ ((!ca) & ce);
	ebi ^= di;
	ca = qsc_intutils_rotl64(ebi, 62);
	ego ^= dz;
	ce = qsc_intutils_rotl64(ego, 55);
	eku ^= du;
	ci = qsc_intutils_rotl64(eku, 39);
	ema ^= da;
	co = qsc_intutils_rotl64(ema, 41);
	ese ^= de;
	cu = qsc_intutils_rotl64(ese, 2);
	asa = ca ^ ((!ce) & ci);
	ase = ce ^ ((!ci) & co);
	asi = ci ^ ((!co) & cu);
	aso = co ^ ((!cu) & ca);
	asu = cu ^ ((!ca) & ce);
	/* round 5 */
	ca = aba ^ aga ^ aka ^ ama ^ asa;
	ce = abe ^ age ^ ake ^ ame ^ ase;
	ci = abi ^ agi ^ aki ^ ami ^ asi;
	co = abo ^ ago ^ ako ^ amo ^ aso;
	cu = abu ^ agu ^ aku ^ amu ^ asu;
	da = cu ^ qsc_intutils_rotl64(ce, 1);
	de = ca ^ qsc_intutils_rotl64(ci, 1);
	di = ce ^ qsc_intutils_rotl64(co, 1);
	dz = ci ^ qsc_intutils_rotl64(cu, 1);
	du = co ^ qsc_intutils_rotl64(ca, 1);
	aba ^= da;
	ca = aba;
	age ^= de;
	ce = qsc_intutils_rotl64(age, 44);
	aki ^= di;
	ci = qsc_intutils_rotl64(aki, 43);
	amo ^= dz;
	co = qsc_intutils_rotl64(amo, 21);
	asu ^= du;
	cu = qsc_intutils_rotl64(asu, 14);
	eba = ca ^ ((!ce) & ci);
	eba ^= 0x000000000000808B;
	ebe = ce ^ ((!ci) & co);
	ebi = ci ^ ((!co) & cu);
	ebo = co ^ ((!cu) & ca);
	ebu = cu ^ ((!ca) & ce);
	abo ^= dz;
	ca = qsc_intutils_rotl64(abo, 28);
	agu ^= du;
	ce = qsc_intutils_rotl64(agu, 20);
	aka ^= da;
	ci = qsc_intutils_rotl64(aka, 3);
	ame ^= de;
	co = qsc_intutils_rotl64(ame, 45);
	asi ^= di;
	cu = qsc_intutils_rotl64(asi, 61);
	ega = ca ^ ((!ce) & ci);
	ege = ce ^ ((!ci) & co);
	egi = ci ^ ((!co) & cu);
	ego = co ^ ((!cu) & ca);
	egu = cu ^ ((!ca) & ce);
	abe ^= de;
	ca = qsc_intutils_rotl64(abe, 1);
	agi ^= di;
	ce = qsc_intutils_rotl64(agi, 6);
	ako ^= dz;
	ci = qsc_intutils_rotl64(ako, 25);
	amu ^= du;
	co = qsc_intutils_rotl64(amu, 8);
	asa ^= da;
	cu = qsc_intutils_rotl64(asa, 18);
	eka = ca ^ ((!ce) & ci);
	eke = ce ^ ((!ci) & co);
	eki = ci ^ ((!co) & cu);
	eko = co ^ ((!cu) & ca);
	eku = cu ^ ((!ca) & ce);
	abu ^= du;
	ca = qsc_intutils_rotl64(abu, 27);
	aga ^= da;
	ce = qsc_intutils_rotl64(aga, 36);
	ake ^= de;
	ci = qsc_intutils_rotl64(ake, 10);
	ami ^= di;
	co = qsc_intutils_rotl64(ami, 15);
	aso ^= dz;
	cu = qsc_intutils_rotl64(aso, 56);
	ema = ca ^ ((!ce) & ci);
	eme = ce ^ ((!ci) & co);
	emi = ci ^ ((!co) & cu);
	emo = co ^ ((!cu) & ca);
	emu = cu ^ ((!ca) & ce);
	abi ^= di;
	ca = qsc_intutils_rotl64(abi, 62);
	ago ^= dz;
	ce = qsc_intutils_rotl64(ago, 55);
	aku ^= du;
	ci = qsc_intutils_rotl64(aku, 39);
	ama ^= da;
	co = qsc_intutils_rotl64(ama, 41);
	ase ^= de;
	cu = qsc_intutils_rotl64(ase, 2);
	esa = ca ^ ((!ce) & ci);
	ese = ce ^ ((!ci) & co);
	esi = ci ^ ((!co) & cu);
	eso = co ^ ((!cu) & ca);
	esu = cu ^ ((!ca) & ce);
	/* round 6 */
	ca = eba ^ ega ^ eka ^ ema ^ esa;
	ce = ebe ^ ege ^ eke ^ eme ^ ese;
	ci = ebi ^ egi ^ eki ^ emi ^ esi;
	co = ebo ^ ego ^ eko ^ emo ^ eso;
	cu = ebu ^ egu ^ eku ^ emu ^ esu;
	da = cu ^ qsc_intutils_rotl64(ce, 1);
	de = ca ^ qsc_intutils_rotl64(ci, 1);
	di = ce ^ qsc_intutils_rotl64(co, 1);
	dz = ci ^ qsc_intutils_rotl64(cu, 1);
	du = co ^ qsc_intutils_rotl64(ca, 1);
	eba ^= da;
	ca = eba;
	ege ^= de;
	ce = qsc_intutils_rotl64(ege, 44);
	eki ^= di;
	ci = qsc_intutils_rotl64(eki, 43);
	emo ^= dz;
	co = qsc_intutils_rotl64(emo, 21);
	esu ^= du;
	cu = qsc_intutils_rotl64(esu, 14);
	aba = ca ^ ((!ce) & ci);
	aba ^= 0x0000000080000001;
	abe = ce ^ ((!ci) & co);
	abi = ci ^ ((!co) & cu);
	abo = co ^ ((!cu) & ca);
	abu = cu ^ ((!ca) & ce);
	ebo ^= dz;
	ca = qsc_intutils_rotl64(ebo, 28);
	egu ^= du;
	ce = qsc_intutils_rotl64(egu, 20);
	eka ^= da;
	ci = qsc_intutils_rotl64(eka, 3);
	eme ^= de;
	co = qsc_intutils_rotl64(eme, 45);
	esi ^= di;
	cu = qsc_intutils_rotl64(esi, 61);
	aga = ca ^ ((!ce) & ci);
	age = ce ^ ((!ci) & co);
	agi = ci ^ ((!co) & cu);
	ago = co ^ ((!cu) & ca);
	agu = cu ^ ((!ca) & ce);
	ebe ^= de;
	ca = qsc_intutils_rotl64(ebe, 1);
	egi ^= di;
	ce = qsc_intutils_rotl64(egi, 6);
	eko ^= dz;
	ci = qsc_intutils_rotl64(eko, 25);
	emu ^= du;
	co = qsc_intutils_rotl64(emu, 8);
	esa ^= da;
	cu = qsc_intutils_rotl64(esa, 18);
	aka = ca ^ ((!ce) & ci);
	ake = ce ^ ((!ci) & co);
	aki = ci ^ ((!co) & cu);
	ako = co ^ ((!cu) & ca);
	aku = cu ^ ((!ca) & ce);
	ebu ^= du;
	ca = qsc_intutils_rotl64(ebu, 27);
	ega ^= da;
	ce = qsc_intutils_rotl64(ega, 36);
	eke ^= de;
	ci = qsc_intutils_rotl64(eke, 10);
	emi ^= di;
	co = qsc_intutils_rotl64(emi, 15);
	eso ^= dz;
	cu = qsc_intutils_rotl64(eso, 56);
	ama = ca ^ ((!ce) & ci);
	ame = ce ^ ((!ci) & co);
	ami = ci ^ ((!co) & cu);
	amo = co ^ ((!cu) & ca);
	amu = cu ^ ((!ca) & ce);
	ebi ^= di;
	ca = qsc_intutils_rotl64(ebi, 62);
	ego ^= dz;
	ce = qsc_intutils_rotl64(ego, 55);
	eku ^= du;
	ci = qsc_intutils_rotl64(eku, 39);
	ema ^= da;
	co = qsc_intutils_rotl64(ema, 41);
	ese ^= de;
	cu = qsc_intutils_rotl64(ese, 2);
	asa = ca ^ ((!ce) & ci);
	ase = ce ^ ((!ci) & co);
	asi = ci ^ ((!co) & cu);
	aso = co ^ ((!cu) & ca);
	asu = cu ^ ((!ca) & ce);
	/* round 7 */
	ca = aba ^ aga ^ aka ^ ama ^ asa;
	ce = abe ^ age ^ ake ^ ame ^ ase;
	ci = abi ^ agi ^ aki ^ ami ^ asi;
	co = abo ^ ago ^ ako ^ amo ^ aso;
	cu = abu ^ agu ^ aku ^ amu ^ asu;
	da = cu ^ qsc_intutils_rotl64(ce, 1);
	de = ca ^ qsc_intutils_rotl64(ci, 1);
	di = ce ^ qsc_intutils_rotl64(co, 1);
	dz = ci ^ qsc_intutils_rotl64(cu, 1);
	du = co ^ qsc_intutils_rotl64(ca, 1);
	aba ^= da;
	ca = aba;
	age ^= de;
	ce = qsc_intutils_rotl64(age, 44);
	aki ^= di;
	ci = qsc_intutils_rotl64(aki, 43);
	amo ^= dz;
	co = qsc_intutils_rotl64(amo, 21);
	asu ^= du;
	cu = qsc_intutils_rotl64(asu, 14);
	eba = ca ^ ((!ce) & ci);
	eba ^= 0x8000000080008081;
	ebe = ce ^ ((!ci) & co);
	ebi = ci ^ ((!co) & cu);
	ebo = co ^ ((!cu) & ca);
	ebu = cu ^ ((!ca) & ce);
	abo ^= dz;
	ca = qsc_intutils_rotl64(abo, 28);
	agu ^= du;
	ce = qsc_intutils_rotl64(agu, 20);
	aka ^= da;
	ci = qsc_intutils_rotl64(aka, 3);
	ame ^= de;
	co = qsc_intutils_rotl64(ame, 45);
	asi ^= di;
	cu = qsc_intutils_rotl64(asi, 61);
	ega = ca ^ ((!ce) & ci);
	ege = ce ^ ((!ci) & co);
	egi = ci ^ ((!co) & cu);
	ego = co ^ ((!cu) & ca);
	egu = cu ^ ((!ca) & ce);
	abe ^= de;
	ca = qsc_intutils_rotl64(abe, 1);
	agi ^= di;
	ce = qsc_intutils_rotl64(agi, 6);
	ako ^= dz;
	ci = qsc_intutils_rotl64(ako, 25);
	amu ^= du;
	co = qsc_intutils_rotl64(amu, 8);
	asa ^= da;
	cu = qsc_intutils_rotl64(asa, 18);
	eka = ca ^ ((!ce) & ci);
	eke = ce ^ ((!ci) & co);
	eki = ci ^ ((!co) & cu);
	eko = co ^ ((!cu) & ca);
	eku = cu ^ ((!ca) & ce);
	abu ^= du;
	ca = qsc_intutils_rotl64(abu, 27);
	aga ^= da;
	ce = qsc_intutils_rotl64(aga, 36);
	ake ^= de;
	ci = qsc_intutils_rotl64(ake, 10);
	ami ^= di;
	co = qsc_intutils_rotl64(ami, 15);
	aso ^= dz;
	cu = qsc_intutils_rotl64(aso, 56);
	ema = ca ^ ((!ce) & ci);
	eme = ce ^ ((!ci) & co);
	emi = ci ^ ((!co) & cu);
	emo = co ^ ((!cu) & ca);
	emu = cu ^ ((!ca) & ce);
	abi ^= di;
	ca = qsc_intutils_rotl64(abi, 62);
	ago ^= dz;
	ce = qsc_intutils_rotl64(ago, 55);
	aku ^= du;
	ci = qsc_intutils_rotl64(aku, 39);
	ama ^= da;
	co = qsc_intutils_rotl64(ama, 41);
	ase ^= de;
	cu = qsc_intutils_rotl64(ase, 2);
	esa = ca ^ ((!ce) & ci);
	ese = ce ^ ((!ci) & co);
	esi = ci ^ ((!co) & cu);
	eso = co ^ ((!cu) & ca);
	esu = cu ^ ((!ca) & ce);
	/* round 8 */
	ca = eba ^ ega ^ eka ^ ema ^ esa;
	ce = ebe ^ ege ^ eke ^ eme ^ ese;
	ci = ebi ^ egi ^ eki ^ emi ^ esi;
	co = ebo ^ ego ^ eko ^ emo ^ eso;
	cu = ebu ^ egu ^ eku ^ emu ^ esu;
	da = cu ^ qsc_intutils_rotl64(ce, 1);
	de = ca ^ qsc_intutils_rotl64(ci, 1);
	di = ce ^ qsc_intutils_rotl64(co, 1);
	dz = ci ^ qsc_intutils_rotl64(cu, 1);
	du = co ^ qsc_intutils_rotl64(ca, 1);
	eba ^= da;
	ca = eba;
	ege ^= de;
	ce = qsc_intutils_rotl64(ege, 44);
	eki ^= di;
	ci = qsc_intutils_rotl64(eki, 43);
	emo ^= dz;
	co = qsc_intutils_rotl64(emo, 21);
	esu ^= du;
	cu = qsc_intutils_rotl64(esu, 14);
	aba = ca ^ ((!ce) & ci);
	aba ^= 0x8000000000008009;
	abe = ce ^ ((!ci) & co);
	abi = ci ^ ((!co) & cu);
	abo = co ^ ((!cu) & ca);
	abu = cu ^ ((!ca) & ce);
	ebo ^= dz;
	ca = qsc_intutils_rotl64(ebo, 28);
	egu ^= du;
	ce = qsc_intutils_rotl64(egu, 20);
	eka ^= da;
	ci = qsc_intutils_rotl64(eka, 3);
	eme ^= de;
	co = qsc_intutils_rotl64(eme, 45);
	esi ^= di;
	cu = qsc_intutils_rotl64(esi, 61);
	aga = ca ^ ((!ce) & ci);
	age = ce ^ ((!ci) & co);
	agi = ci ^ ((!co) & cu);
	ago = co ^ ((!cu) & ca);
	agu = cu ^ ((!ca) & ce);
	ebe ^= de;
	ca = qsc_intutils_rotl64(ebe, 1);
	egi ^= di;
	ce = qsc_intutils_rotl64(egi, 6);
	eko ^= dz;
	ci = qsc_intutils_rotl64(eko, 25);
	emu ^= du;
	co = qsc_intutils_rotl64(emu, 8);
	esa ^= da;
	cu = qsc_intutils_rotl64(esa, 18);
	aka = ca ^ ((!ce) & ci);
	ake = ce ^ ((!ci) & co);
	aki = ci ^ ((!co) & cu);
	ako = co ^ ((!cu) & ca);
	aku = cu ^ ((!ca) & ce);
	ebu ^= du;
	ca = qsc_intutils_rotl64(ebu, 27);
	ega ^= da;
	ce = qsc_intutils_rotl64(ega, 36);
	eke ^= de;
	ci = qsc_intutils_rotl64(eke, 10);
	emi ^= di;
	co = qsc_intutils_rotl64(emi, 15);
	eso ^= dz;
	cu = qsc_intutils_rotl64(eso, 56);
	ama = ca ^ ((!ce) & ci);
	ame = ce ^ ((!ci) & co);
	ami = ci ^ ((!co) & cu);
	amo = co ^ ((!cu) & ca);
	amu = cu ^ ((!ca) & ce);
	ebi ^= di;
	ca = qsc_intutils_rotl64(ebi, 62);
	ego ^= dz;
	ce = qsc_intutils_rotl64(ego, 55);
	eku ^= du;
	ci = qsc_intutils_rotl64(eku, 39);
	ema ^= da;
	co = qsc_intutils_rotl64(ema, 41);
	ese ^= de;
	cu = qsc_intutils_rotl64(ese, 2);
	asa = ca ^ ((!ce) & ci);
	ase = ce ^ ((!ci) & co);
	asi = ci ^ ((!co) & cu);
	aso = co ^ ((!cu) & ca);
	asu = cu ^ ((!ca) & ce);
	/* round 9 */
	ca = aba ^ aga ^ aka ^ ama ^ asa;
	ce = abe ^ age ^ ake ^ ame ^ ase;
	ci = abi ^ agi ^ aki ^ ami ^ asi;
	co = abo ^ ago ^ ako ^ amo ^ aso;
	cu = abu ^ agu ^ aku ^ amu ^ asu;
	da = cu ^ qsc_intutils_rotl64(ce, 1);
	de = ca ^ qsc_intutils_rotl64(ci, 1);
	di = ce ^ qsc_intutils_rotl64(co, 1);
	dz = ci ^ qsc_intutils_rotl64(cu, 1);
	du = co ^ qsc_intutils_rotl64(ca, 1);
	aba ^= da;
	ca = aba;
	age ^= de;
	ce = qsc_intutils_rotl64(age, 44);
	aki ^= di;
	ci = qsc_intutils_rotl64(aki, 43);
	amo ^= dz;
	co = qsc_intutils_rotl64(amo, 21);
	asu ^= du;
	cu = qsc_intutils_rotl64(asu, 14);
	eba = ca ^ ((!ce) & ci);
	eba ^= 0x000000000000008A;
	ebe = ce ^ ((!ci) & co);
	ebi = ci ^ ((!co) & cu);
	ebo = co ^ ((!cu) & ca);
	ebu = cu ^ ((!ca) & ce);
	abo ^= dz;
	ca = qsc_intutils_rotl64(abo, 28);
	agu ^= du;
	ce = qsc_intutils_rotl64(agu, 20);
	aka ^= da;
	ci = qsc_intutils_rotl64(aka, 3);
	ame ^= de;
	co = qsc_intutils_rotl64(ame, 45);
	asi ^= di;
	cu = qsc_intutils_rotl64(asi, 61);
	ega = ca ^ ((!ce) & ci);
	ege = ce ^ ((!ci) & co);
	egi = ci ^ ((!co) & cu);
	ego = co ^ ((!cu) & ca);
	egu = cu ^ ((!ca) & ce);
	abe ^= de;
	ca = qsc_intutils_rotl64(abe, 1);
	agi ^= di;
	ce = qsc_intutils_rotl64(agi, 6);
	ako ^= dz;
	ci = qsc_intutils_rotl64(ako, 25);
	amu ^= du;
	co = qsc_intutils_rotl64(amu, 8);
	asa ^= da;
	cu = qsc_intutils_rotl64(asa, 18);
	eka = ca ^ ((!ce) & ci);
	eke = ce ^ ((!ci) & co);
	eki = ci ^ ((!co) & cu);
	eko = co ^ ((!cu) & ca);
	eku = cu ^ ((!ca) & ce);
	abu ^= du;
	ca = qsc_intutils_rotl64(abu, 27);
	aga ^= da;
	ce = qsc_intutils_rotl64(aga, 36);
	ake ^= de;
	ci = qsc_intutils_rotl64(ake, 10);
	ami ^= di;
	co = qsc_intutils_rotl64(ami, 15);
	aso ^= dz;
	cu = qsc_intutils_rotl64(aso, 56);
	ema = ca ^ ((!ce) & ci);
	eme = ce ^ ((!ci) & co);
	emi = ci ^ ((!co) & cu);
	emo = co ^ ((!cu) & ca);
	emu = cu ^ ((!ca) & ce);
	abi ^= di;
	ca = qsc_intutils_rotl64(abi, 62);
	ago ^= dz;
	ce = qsc_intutils_rotl64(ago, 55);
	aku ^= du;
	ci = qsc_intutils_rotl64(aku, 39);
	ama ^= da;
	co = qsc_intutils_rotl64(ama, 41);
	ase ^= de;
	cu = qsc_intutils_rotl64(ase, 2);
	esa = ca ^ ((!ce) & ci);
	ese = ce ^ ((!ci) & co);
	esi = ci ^ ((!co) & cu);
	eso = co ^ ((!cu) & ca);
	esu = cu ^ ((!ca) & ce);
	/* round 10 */
	ca = eba ^ ega ^ eka ^ ema ^ esa;
	ce = ebe ^ ege ^ eke ^ eme ^ ese;
	ci = ebi ^ egi ^ eki ^ emi ^ esi;
	co = ebo ^ ego ^ eko ^ emo ^ eso;
	cu = ebu ^ egu ^ eku ^ emu ^ esu;
	da = cu ^ qsc_intutils_rotl64(ce, 1);
	de = ca ^ qsc_intutils_rotl64(ci, 1);
	di = ce ^ qsc_intutils_rotl64(co, 1);
	dz = ci ^ qsc_intutils_rotl64(cu, 1);
	du = co ^ qsc_intutils_rotl64(ca, 1);
	eba ^= da;
	ca = eba;
	ege ^= de;
	ce = qsc_intutils_rotl64(ege, 44);
	eki ^= di;
	ci = qsc_intutils_rotl64(eki, 43);
	emo ^= dz;
	co = qsc_intutils_rotl64(emo, 21);
	esu ^= du;
	cu = qsc_intutils_rotl64(esu, 14);
	aba = ca ^ ((!ce) & ci);
	aba ^= 0x0000000000000088;
	abe = ce ^ ((!ci) & co);
	abi = ci ^ ((!co) & cu);
	abo = co ^ ((!cu) & ca);
	abu = cu ^ ((!ca) & ce);
	ebo ^= dz;
	ca = qsc_intutils_rotl64(ebo, 28);
	egu ^= du;
	ce = qsc_intutils_rotl64(egu, 20);
	eka ^= da;
	ci = qsc_intutils_rotl64(eka, 3);
	eme ^= de;
	co = qsc_intutils_rotl64(eme, 45);
	esi ^= di;
	cu = qsc_intutils_rotl64(esi, 61);
	aga = ca ^ ((!ce) & ci);
	age = ce ^ ((!ci) & co);
	agi = ci ^ ((!co) & cu);
	ago = co ^ ((!cu) & ca);
	agu = cu ^ ((!ca) & ce);
	ebe ^= de;
	ca = qsc_intutils_rotl64(ebe, 1);
	egi ^= di;
	ce = qsc_intutils_rotl64(egi, 6);
	eko ^= dz;
	ci = qsc_intutils_rotl64(eko, 25);
	emu ^= du;
	co = qsc_intutils_rotl64(emu, 8);
	esa ^= da;
	cu = qsc_intutils_rotl64(esa, 18);
	aka = ca ^ ((!ce) & ci);
	ake = ce ^ ((!ci) & co);
	aki = ci ^ ((!co) & cu);
	ako = co ^ ((!cu) & ca);
	aku = cu ^ ((!ca) & ce);
	ebu ^= du;
	ca = qsc_intutils_rotl64(ebu, 27);
	ega ^= da;
	ce = qsc_intutils_rotl64(ega, 36);
	eke ^= de;
	ci = qsc_intutils_rotl64(eke, 10);
	emi ^= di;
	co = qsc_intutils_rotl64(emi, 15);
	eso ^= dz;
	cu = qsc_intutils_rotl64(eso, 56);
	ama = ca ^ ((!ce) & ci);
	ame = ce ^ ((!ci) & co);
	ami = ci ^ ((!co) & cu);
	amo = co ^ ((!cu) & ca);
	amu = cu ^ ((!ca) & ce);
	ebi ^= di;
	ca = qsc_intutils_rotl64(ebi, 62);
	ego ^= dz;
	ce = qsc_intutils_rotl64(ego, 55);
	eku ^= du;
	ci = qsc_intutils_rotl64(eku, 39);
	ema ^= da;
	co = qsc_intutils_rotl64(ema, 41);
	ese ^= de;
	cu = qsc_intutils_rotl64(ese, 2);
	asa = ca ^ ((!ce) & ci);
	ase = ce ^ ((!ci) & co);
	asi = ci ^ ((!co) & cu);
	aso = co ^ ((!cu) & ca);
	asu = cu ^ ((!ca) & ce);
	/* round 11 */
	ca = aba ^ aga ^ aka ^ ama ^ asa;
	ce = abe ^ age ^ ake ^ ame ^ ase;
	ci = abi ^ agi ^ aki ^ ami ^ asi;
	co = abo ^ ago ^ ako ^ amo ^ aso;
	cu = abu ^ agu ^ aku ^ amu ^ asu;
	da = cu ^ qsc_intutils_rotl64(ce, 1);
	de = ca ^ qsc_intutils_rotl64(ci, 1);
	di = ce ^ qsc_intutils_rotl64(co, 1);
	dz = ci ^ qsc_intutils_rotl64(cu, 1);
	du = co ^ qsc_intutils_rotl64(ca, 1);
	aba ^= da;
	ca = aba;
	age ^= de;
	ce = qsc_intutils_rotl64(age, 44);
	aki ^= di;
	ci = qsc_intutils_rotl64(aki, 43);
	amo ^= dz;
	co = qsc_intutils_rotl64(amo, 21);
	asu ^= du;
	cu = qsc_intutils_rotl64(asu, 14);
	eba = ca ^ ((!ce) & ci);
	eba ^= 0x0000000080008009;
	ebe = ce ^ ((!ci) & co);
	ebi = ci ^ ((!co) & cu);
	ebo = co ^ ((!cu) & ca);
	ebu = cu ^ ((!ca) & ce);
	abo ^= dz;
	ca = qsc_intutils_rotl64(abo, 28);
	agu ^= du;
	ce = qsc_intutils_rotl64(agu, 20);
	aka ^= da;
	ci = qsc_intutils_rotl64(aka, 3);
	ame ^= de;
	co = qsc_intutils_rotl64(ame, 45);
	asi ^= di;
	cu = qsc_intutils_rotl64(asi, 61);
	ega = ca ^ ((!ce) & ci);
	ege = ce ^ ((!ci) & co);
	egi = ci ^ ((!co) & cu);
	ego = co ^ ((!cu) & ca);
	egu = cu ^ ((!ca) & ce);
	abe ^= de;
	ca = qsc_intutils_rotl64(abe, 1);
	agi ^= di;
	ce = qsc_intutils_rotl64(agi, 6);
	ako ^= dz;
	ci = qsc_intutils_rotl64(ako, 25);
	amu ^= du;
	co = qsc_intutils_rotl64(amu, 8);
	asa ^= da;
	cu = qsc_intutils_rotl64(asa, 18);
	eka = ca ^ ((!ce) & ci);
	eke = ce ^ ((!ci) & co);
	eki = ci ^ ((!co) & cu);
	eko = co ^ ((!cu) & ca);
	eku = cu ^ ((!ca) & ce);
	abu ^= du;
	ca = qsc_intutils_rotl64(abu, 27);
	aga ^= da;
	ce = qsc_intutils_rotl64(aga, 36);
	ake ^= de;
	ci = qsc_intutils_rotl64(ake, 10);
	ami ^= di;
	co = qsc_intutils_rotl64(ami, 15);
	aso ^= dz;
	cu = qsc_intutils_rotl64(aso, 56);
	ema = ca ^ ((!ce) & ci);
	eme = ce ^ ((!ci) & co);
	emi = ci ^ ((!co) & cu);
	emo = co ^ ((!cu) & ca);
	emu = cu ^ ((!ca) & ce);
	abi ^= di;
	ca = qsc_intutils_rotl64(abi, 62);
	ago ^= dz;
	ce = qsc_intutils_rotl64(ago, 55);
	aku ^= du;
	ci = qsc_intutils_rotl64(aku, 39);
	ama ^= da;
	co = qsc_intutils_rotl64(ama, 41);
	ase ^= de;
	cu = qsc_intutils_rotl64(ase, 2);
	esa = ca ^ ((!ce) & ci);
	ese = ce ^ ((!ci) & co);
	esi = ci ^ ((!co) & cu);
	eso = co ^ ((!cu) & ca);
	esu = cu ^ ((!ca) & ce);
	/* round 12 */
	ca = eba ^ ega ^ eka ^ ema ^ esa;
	ce = ebe ^ ege ^ eke ^ eme ^ ese;
	ci = ebi ^ egi ^ eki ^ emi ^ esi;
	co = ebo ^ ego ^ eko ^ emo ^ eso;
	cu = ebu ^ egu ^ eku ^ emu ^ esu;
	da = cu ^ qsc_intutils_rotl64(ce, 1);
	de = ca ^ qsc_intutils_rotl64(ci, 1);
	di = ce ^ qsc_intutils_rotl64(co, 1);
	dz = ci ^ qsc_intutils_rotl64(cu, 1);
	du = co ^ qsc_intutils_rotl64(ca, 1);
	eba ^= da;
	ca = eba;
	ege ^= de;
	ce = qsc_intutils_rotl64(ege, 44);
	eki ^= di;
	ci = qsc_intutils_rotl64(eki, 43);
	emo ^= dz;
	co = qsc_intutils_rotl64(emo, 21);
	esu ^= du;
	cu = qsc_intutils_rotl64(esu, 14);
	aba = ca ^ ((!ce) & ci);
	aba ^= 0x000000008000000A;
	abe = ce ^ ((!ci) & co);
	abi = ci ^ ((!co) & cu);
	abo = co ^ ((!cu) & ca);
	abu = cu ^ ((!ca) & ce);
	ebo ^= dz;
	ca = qsc_intutils_rotl64(ebo, 28);
	egu ^= du;
	ce = qsc_intutils_rotl64(egu, 20);
	eka ^= da;
	ci = qsc_intutils_rotl64(eka, 3);
	eme ^= de;
	co = qsc_intutils_rotl64(eme, 45);
	esi ^= di;
	cu = qsc_intutils_rotl64(esi, 61);
	aga = ca ^ ((!ce) & ci);
	age = ce ^ ((!ci) & co);
	agi = ci ^ ((!co) & cu);
	ago = co ^ ((!cu) & ca);
	agu = cu ^ ((!ca) & ce);
	ebe ^= de;
	ca = qsc_intutils_rotl64(ebe, 1);
	egi ^= di;
	ce = qsc_intutils_rotl64(egi, 6);
	eko ^= dz;
	ci = qsc_intutils_rotl64(eko, 25);
	emu ^= du;
	co = qsc_intutils_rotl64(emu, 8);
	esa ^= da;
	cu = qsc_intutils_rotl64(esa, 18);
	aka = ca ^ ((!ce) & ci);
	ake = ce ^ ((!ci) & co);
	aki = ci ^ ((!co) & cu);
	ako = co ^ ((!cu) & ca);
	aku = cu ^ ((!ca) & ce);
	ebu ^= du;
	ca = qsc_intutils_rotl64(ebu, 27);
	ega ^= da;
	ce = qsc_intutils_rotl64(ega, 36);
	eke ^= de;
	ci = qsc_intutils_rotl64(eke, 10);
	emi ^= di;
	co = qsc_intutils_rotl64(emi, 15);
	eso ^= dz;
	cu = qsc_intutils_rotl64(eso, 56);
	ama = ca ^ ((!ce) & ci);
	ame = ce ^ ((!ci) & co);
	ami = ci ^ ((!co) & cu);
	amo = co ^ ((!cu) & ca);
	amu = cu ^ ((!ca) & ce);
	ebi ^= di;
	ca = qsc_intutils_rotl64(ebi, 62);
	ego ^= dz;
	ce = qsc_intutils_rotl64(ego, 55);
	eku ^= du;
	ci = qsc_intutils_rotl64(eku, 39);
	ema ^= da;
	co = qsc_intutils_rotl64(ema, 41);
	ese ^= de;
	cu = qsc_intutils_rotl64(ese, 2);
	asa = ca ^ ((!ce) & ci);
	ase = ce ^ ((!ci) & co);
	asi = ci ^ ((!co) & cu);
	aso = co ^ ((!cu) & ca);
	asu = cu ^ ((!ca) & ce);
	/* round 13 */
	ca = aba ^ aga ^ aka ^ ama ^ asa;
	ce = abe ^ age ^ ake ^ ame ^ ase;
	ci = abi ^ agi ^ aki ^ ami ^ asi;
	co = abo ^ ago ^ ako ^ amo ^ aso;
	cu = abu ^ agu ^ aku ^ amu ^ asu;
	da = cu ^ qsc_intutils_rotl64(ce, 1);
	de = ca ^ qsc_intutils_rotl64(ci, 1);
	di = ce ^ qsc_intutils_rotl64(co, 1);
	dz = ci ^ qsc_intutils_rotl64(cu, 1);
	du = co ^ qsc_intutils_rotl64(ca, 1);
	aba ^= da;
	ca = aba;
	age ^= de;
	ce = qsc_intutils_rotl64(age, 44);
	aki ^= di;
	ci = qsc_intutils_rotl64(aki, 43);
	amo ^= dz;
	co = qsc_intutils_rotl64(amo, 21);
	asu ^= du;
	cu = qsc_intutils_rotl64(asu, 14);
	eba = ca ^ ((!ce) & ci);
	eba ^= 0x000000008000808B;
	ebe = ce ^ ((!ci) & co);
	ebi = ci ^ ((!co) & cu);
	ebo = co ^ ((!cu) & ca);
	ebu = cu ^ ((!ca) & ce);
	abo ^= dz;
	ca = qsc_intutils_rotl64(abo, 28);
	agu ^= du;
	ce = qsc_intutils_rotl64(agu, 20);
	aka ^= da;
	ci = qsc_intutils_rotl64(aka, 3);
	ame ^= de;
	co = qsc_intutils_rotl64(ame, 45);
	asi ^= di;
	cu = qsc_intutils_rotl64(asi, 61);
	ega = ca ^ ((!ce) & ci);
	ege = ce ^ ((!ci) & co);
	egi = ci ^ ((!co) & cu);
	ego = co ^ ((!cu) & ca);
	egu = cu ^ ((!ca) & ce);
	abe ^= de;
	ca = qsc_intutils_rotl64(abe, 1);
	agi ^= di;
	ce = qsc_intutils_rotl64(agi, 6);
	ako ^= dz;
	ci = qsc_intutils_rotl64(ako, 25);
	amu ^= du;
	co = qsc_intutils_rotl64(amu, 8);
	asa ^= da;
	cu = qsc_intutils_rotl64(asa, 18);
	eka = ca ^ ((!ce) & ci);
	eke = ce ^ ((!ci) & co);
	eki = ci ^ ((!co) & cu);
	eko = co ^ ((!cu) & ca);
	eku = cu ^ ((!ca) & ce);
	abu ^= du;
	ca = qsc_intutils_rotl64(abu, 27);
	aga ^= da;
	ce = qsc_intutils_rotl64(aga, 36);
	ake ^= de;
	ci = qsc_intutils_rotl64(ake, 10);
	ami ^= di;
	co = qsc_intutils_rotl64(ami, 15);
	aso ^= dz;
	cu = qsc_intutils_rotl64(aso, 56);
	ema = ca ^ ((!ce) & ci);
	eme = ce ^ ((!ci) & co);
	emi = ci ^ ((!co) & cu);
	emo = co ^ ((!cu) & ca);
	emu = cu ^ ((!ca) & ce);
	abi ^= di;
	ca = qsc_intutils_rotl64(abi, 62);
	ago ^= dz;
	ce = qsc_intutils_rotl64(ago, 55);
	aku ^= du;
	ci = qsc_intutils_rotl64(aku, 39);
	ama ^= da;
	co = qsc_intutils_rotl64(ama, 41);
	ase ^= de;
	cu = qsc_intutils_rotl64(ase, 2);
	esa = ca ^ ((!ce) & ci);
	ese = ce ^ ((!ci) & co);
	esi = ci ^ ((!co) & cu);
	eso = co ^ ((!cu) & ca);
	esu = cu ^ ((!ca) & ce);
	/* round 14 */
	ca = eba ^ ega ^ eka ^ ema ^ esa;
	ce = ebe ^ ege ^ eke ^ eme ^ ese;
	ci = ebi ^ egi ^ eki ^ emi ^ esi;
	co = ebo ^ ego ^ eko ^ emo ^ eso;
	cu = ebu ^ egu ^ eku ^ emu ^ esu;
	da = cu ^ qsc_intutils_rotl64(ce, 1);
	de = ca ^ qsc_intutils_rotl64(ci, 1);
	di = ce ^ qsc_intutils_rotl64(co, 1);
	dz = ci ^ qsc_intutils_rotl64(cu, 1);
	du = co ^ qsc_intutils_rotl64(ca, 1);
	eba ^= da;
	ca = eba;
	ege ^= de;
	ce = qsc_intutils_rotl64(ege, 44);
	eki ^= di;
	ci = qsc_intutils_rotl64(eki, 43);
	emo ^= dz;
	co = qsc_intutils_rotl64(emo, 21);
	esu ^= du;
	cu = qsc_intutils_rotl64(esu, 14);
	aba = ca ^ ((!ce) & ci);
	aba ^= 0x800000000000008B;
	abe = ce ^ ((!ci) & co);
	abi = ci ^ ((!co) & cu);
	abo = co ^ ((!cu) & ca);
	abu = cu ^ ((!ca) & ce);
	ebo ^= dz;
	ca = qsc_intutils_rotl64(ebo, 28);
	egu ^= du;
	ce = qsc_intutils_rotl64(egu, 20);
	eka ^= da;
	ci = qsc_intutils_rotl64(eka, 3);
	eme ^= de;
	co = qsc_intutils_rotl64(eme, 45);
	esi ^= di;
	cu = qsc_intutils_rotl64(esi, 61);
	aga = ca ^ ((!ce) & ci);
	age = ce ^ ((!ci) & co);
	agi = ci ^ ((!co) & cu);
	ago = co ^ ((!cu) & ca);
	agu = cu ^ ((!ca) & ce);
	ebe ^= de;
	ca = qsc_intutils_rotl64(ebe, 1);
	egi ^= di;
	ce = qsc_intutils_rotl64(egi, 6);
	eko ^= dz;
	ci = qsc_intutils_rotl64(eko, 25);
	emu ^= du;
	co = qsc_intutils_rotl64(emu, 8);
	esa ^= da;
	cu = qsc_intutils_rotl64(esa, 18);
	aka = ca ^ ((!ce) & ci);
	ake = ce ^ ((!ci) & co);
	aki = ci ^ ((!co) & cu);
	ako = co ^ ((!cu) & ca);
	aku = cu ^ ((!ca) & ce);
	ebu ^= du;
	ca = qsc_intutils_rotl64(ebu, 27);
	ega ^= da;
	ce = qsc_intutils_rotl64(ega, 36);
	eke ^= de;
	ci = qsc_intutils_rotl64(eke, 10);
	emi ^= di;
	co = qsc_intutils_rotl64(emi, 15);
	eso ^= dz;
	cu = qsc_intutils_rotl64(eso, 56);
	ama = ca ^ ((!ce) & ci);
	ame = ce ^ ((!ci) & co);
	ami = ci ^ ((!co) & cu);
	amo = co ^ ((!cu) & ca);
	amu = cu ^ ((!ca) & ce);
	ebi ^= di;
	ca = qsc_intutils_rotl64(ebi, 62);
	ego ^= dz;
	ce = qsc_intutils_rotl64(ego, 55);
	eku ^= du;
	ci = qsc_intutils_rotl64(eku, 39);
	ema ^= da;
	co = qsc_intutils_rotl64(ema, 41);
	ese ^= de;
	cu = qsc_intutils_rotl64(ese, 2);
	asa = ca ^ ((!ce) & ci);
	ase = ce ^ ((!ci) & co);
	asi = ci ^ ((!co) & cu);
	aso = co ^ ((!cu) & ca);
	asu = cu ^ ((!ca) & ce);
	/* round 15 */
	ca = aba ^ aga ^ aka ^ ama ^ asa;
	ce = abe ^ age ^ ake ^ ame ^ ase;
	ci = abi ^ agi ^ aki ^ ami ^ asi;
	co = abo ^ ago ^ ako ^ amo ^ aso;
	cu = abu ^ agu ^ aku ^ amu ^ asu;
	da = cu ^ qsc_intutils_rotl64(ce, 1);
	de = ca ^ qsc_intutils_rotl64(ci, 1);
	di = ce ^ qsc_intutils_rotl64(co, 1);
	dz = ci ^ qsc_intutils_rotl64(cu, 1);
	du = co ^ qsc_intutils_rotl64(ca, 1);
	aba ^= da;
	ca = aba;
	age ^= de;
	ce = qsc_intutils_rotl64(age, 44);
	aki ^= di;
	ci = qsc_intutils_rotl64(aki, 43);
	amo ^= dz;
	co = qsc_intutils_rotl64(amo, 21);
	asu ^= du;
	cu = qsc_intutils_rotl64(asu, 14);
	eba = ca ^ ((!ce) & ci);
	eba ^= 0x8000000000008089;
	ebe = ce ^ ((!ci) & co);
	ebi = ci ^ ((!co) & cu);
	ebo = co ^ ((!cu) & ca);
	ebu = cu ^ ((!ca) & ce);
	abo ^= dz;
	ca = qsc_intutils_rotl64(abo, 28);
	agu ^= du;
	ce = qsc_intutils_rotl64(agu, 20);
	aka ^= da;
	ci = qsc_intutils_rotl64(aka, 3);
	ame ^= de;
	co = qsc_intutils_rotl64(ame, 45);
	asi ^= di;
	cu = qsc_intutils_rotl64(asi, 61);
	ega = ca ^ ((!ce) & ci);
	ege = ce ^ ((!ci) & co);
	egi = ci ^ ((!co) & cu);
	ego = co ^ ((!cu) & ca);
	egu = cu ^ ((!ca) & ce);
	abe ^= de;
	ca = qsc_intutils_rotl64(abe, 1);
	agi ^= di;
	ce = qsc_intutils_rotl64(agi, 6);
	ako ^= dz;
	ci = qsc_intutils_rotl64(ako, 25);
	amu ^= du;
	co = qsc_intutils_rotl64(amu, 8);
	asa ^= da;
	cu = qsc_intutils_rotl64(asa, 18);
	eka = ca ^ ((!ce) & ci);
	eke = ce ^ ((!ci) & co);
	eki = ci ^ ((!co) & cu);
	eko = co ^ ((!cu) & ca);
	eku = cu ^ ((!ca) & ce);
	abu ^= du;
	ca = qsc_intutils_rotl64(abu, 27);
	aga ^= da;
	ce = qsc_intutils_rotl64(aga, 36);
	ake ^= de;
	ci = qsc_intutils_rotl64(ake, 10);
	ami ^= di;
	co = qsc_intutils_rotl64(ami, 15);
	aso ^= dz;
	cu = qsc_intutils_rotl64(aso, 56);
	ema = ca ^ ((!ce) & ci);
	eme = ce ^ ((!ci) & co);
	emi = ci ^ ((!co) & cu);
	emo = co ^ ((!cu) & ca);
	emu = cu ^ ((!ca) & ce);
	abi ^= di;
	ca = qsc_intutils_rotl64(abi, 62);
	ago ^= dz;
	ce = qsc_intutils_rotl64(ago, 55);
	aku ^= du;
	ci = qsc_intutils_rotl64(aku, 39);
	ama ^= da;
	co = qsc_intutils_rotl64(ama, 41);
	ase ^= de;
	cu = qsc_intutils_rotl64(ase, 2);
	esa = ca ^ ((!ce) & ci);
	ese = ce ^ ((!ci) & co);
	esi = ci ^ ((!co) & cu);
	eso = co ^ ((!cu) & ca);
	esu = cu ^ ((!ca) & ce);
	/* round 16 */
	ca = eba ^ ega ^ eka ^ ema ^ esa;
	ce = ebe ^ ege ^ eke ^ eme ^ ese;
	ci = ebi ^ egi ^ eki ^ emi ^ esi;
	co = ebo ^ ego ^ eko ^ emo ^ eso;
	cu = ebu ^ egu ^ eku ^ emu ^ esu;
	da = cu ^ qsc_intutils_rotl64(ce, 1);
	de = ca ^ qsc_intutils_rotl64(ci, 1);
	di = ce ^ qsc_intutils_rotl64(co, 1);
	dz = ci ^ qsc_intutils_rotl64(cu, 1);
	du = co ^ qsc_intutils_rotl64(ca, 1);
	eba ^= da;
	ca = eba;
	ege ^= de;
	ce = qsc_intutils_rotl64(ege, 44);
	eki ^= di;
	ci = qsc_intutils_rotl64(eki, 43);
	emo ^= dz;
	co = qsc_intutils_rotl64(emo, 21);
	esu ^= du;
	cu = qsc_intutils_rotl64(esu, 14);
	aba = ca ^ ((!ce) & ci);
	aba ^= 0x8000000000008003;
	abe = ce ^ ((!ci) & co);
	abi = ci ^ ((!co) & cu);
	abo = co ^ ((!cu) & ca);
	abu = cu ^ ((!ca) & ce);
	ebo ^= dz;
	ca = qsc_intutils_rotl64(ebo, 28);
	egu ^= du;
	ce = qsc_intutils_rotl64(egu, 20);
	eka ^= da;
	ci = qsc_intutils_rotl64(eka, 3);
	eme ^= de;
	co = qsc_intutils_rotl64(eme, 45);
	esi ^= di;
	cu = qsc_intutils_rotl64(esi, 61);
	aga = ca ^ ((!ce) & ci);
	age = ce ^ ((!ci) & co);
	agi = ci ^ ((!co) & cu);
	ago = co ^ ((!cu) & ca);
	agu = cu ^ ((!ca) & ce);
	ebe ^= de;
	ca = qsc_intutils_rotl64(ebe, 1);
	egi ^= di;
	ce = qsc_intutils_rotl64(egi, 6);
	eko ^= dz;
	ci = qsc_intutils_rotl64(eko, 25);
	emu ^= du;
	co = qsc_intutils_rotl64(emu, 8);
	esa ^= da;
	cu = qsc_intutils_rotl64(esa, 18);
	aka = ca ^ ((!ce) & ci);
	ake = ce ^ ((!ci) & co);
	aki = ci ^ ((!co) & cu);
	ako = co ^ ((!cu) & ca);
	aku = cu ^ ((!ca) & ce);
	ebu ^= du;
	ca = qsc_intutils_rotl64(ebu, 27);
	ega ^= da;
	ce = qsc_intutils_rotl64(ega, 36);
	eke ^= de;
	ci = qsc_intutils_rotl64(eke, 10);
	emi ^= di;
	co = qsc_intutils_rotl64(emi, 15);
	eso ^= dz;
	cu = qsc_intutils_rotl64(eso, 56);
	ama = ca ^ ((!ce) & ci);
	ame = ce ^ ((!ci) & co);
	ami = ci ^ ((!co) & cu);
	amo = co ^ ((!cu) & ca);
	amu = cu ^ ((!ca) & ce);
	ebi ^= di;
	ca = qsc_intutils_rotl64(ebi, 62);
	ego ^= dz;
	ce = qsc_intutils_rotl64(ego, 55);
	eku ^= du;
	ci = qsc_intutils_rotl64(eku, 39);
	ema ^= da;
	co = qsc_intutils_rotl64(ema, 41);
	ese ^= de;
	cu = qsc_intutils_rotl64(ese, 2);
	asa = ca ^ ((!ce) & ci);
	ase = ce ^ ((!ci) & co);
	asi = ci ^ ((!co) & cu);
	aso = co ^ ((!cu) & ca);
	asu = cu ^ ((!ca) & ce);
	/* round 17 */
	ca = aba ^ aga ^ aka ^ ama ^ asa;
	ce = abe ^ age ^ ake ^ ame ^ ase;
	ci = abi ^ agi ^ aki ^ ami ^ asi;
	co = abo ^ ago ^ ako ^ amo ^ aso;
	cu = abu ^ agu ^ aku ^ amu ^ asu;
	da = cu ^ qsc_intutils_rotl64(ce, 1);
	de = ca ^ qsc_intutils_rotl64(ci, 1);
	di = ce ^ qsc_intutils_rotl64(co, 1);
	dz = ci ^ qsc_intutils_rotl64(cu, 1);
	du = co ^ qsc_intutils_rotl64(ca, 1);
	aba ^= da;
	ca = aba;
	age ^= de;
	ce = qsc_intutils_rotl64(age, 44);
	aki ^= di;
	ci = qsc_intutils_rotl64(aki, 43);
	amo ^= dz;
	co = qsc_intutils_rotl64(amo, 21);
	asu ^= du;
	cu = qsc_intutils_rotl64(asu, 14);
	eba = ca ^ ((!ce) & ci);
	eba ^= 0x8000000000008002;
	ebe = ce ^ ((!ci) & co);
	ebi = ci ^ ((!co) & cu);
	ebo = co ^ ((!cu) & ca);
	ebu = cu ^ ((!ca) & ce);
	abo ^= dz;
	ca = qsc_intutils_rotl64(abo, 28);
	agu ^= du;
	ce = qsc_intutils_rotl64(agu, 20);
	aka ^= da;
	ci = qsc_intutils_rotl64(aka, 3);
	ame ^= de;
	co = qsc_intutils_rotl64(ame, 45);
	asi ^= di;
	cu = qsc_intutils_rotl64(asi, 61);
	ega = ca ^ ((!ce) & ci);
	ege = ce ^ ((!ci) & co);
	egi = ci ^ ((!co) & cu);
	ego = co ^ ((!cu) & ca);
	egu = cu ^ ((!ca) & ce);
	abe ^= de;
	ca = qsc_intutils_rotl64(abe, 1);
	agi ^= di;
	ce = qsc_intutils_rotl64(agi, 6);
	ako ^= dz;
	ci = qsc_intutils_rotl64(ako, 25);
	amu ^= du;
	co = qsc_intutils_rotl64(amu, 8);
	asa ^= da;
	cu = qsc_intutils_rotl64(asa, 18);
	eka = ca ^ ((!ce) & ci);
	eke = ce ^ ((!ci) & co);
	eki = ci ^ ((!co) & cu);
	eko = co ^ ((!cu) & ca);
	eku = cu ^ ((!ca) & ce);
	abu ^= du;
	ca = qsc_intutils_rotl64(abu, 27);
	aga ^= da;
	ce = qsc_intutils_rotl64(aga, 36);
	ake ^= de;
	ci = qsc_intutils_rotl64(ake, 10);
	ami ^= di;
	co = qsc_intutils_rotl64(ami, 15);
	aso ^= dz;
	cu = qsc_intutils_rotl64(aso, 56);
	ema = ca ^ ((!ce) & ci);
	eme = ce ^ ((!ci) & co);
	emi = ci ^ ((!co) & cu);
	emo = co ^ ((!cu) & ca);
	emu = cu ^ ((!ca) & ce);
	abi ^= di;
	ca = qsc_intutils_rotl64(abi, 62);
	ago ^= dz;
	ce = qsc_intutils_rotl64(ago, 55);
	aku ^= du;
	ci = qsc_intutils_rotl64(aku, 39);
	ama ^= da;
	co = qsc_intutils_rotl64(ama, 41);
	ase ^= de;
	cu = qsc_intutils_rotl64(ase, 2);
	esa = ca ^ ((!ce) & ci);
	ese = ce ^ ((!ci) & co);
	esi = ci ^ ((!co) & cu);
	eso = co ^ ((!cu) & ca);
	esu = cu ^ ((!ca) & ce);
	/* round 18 */
	ca = eba ^ ega ^ eka ^ ema ^ esa;
	ce = ebe ^ ege ^ eke ^ eme ^ ese;
	ci = ebi ^ egi ^ eki ^ emi ^ esi;
	co = ebo ^ ego ^ eko ^ emo ^ eso;
	cu = ebu ^ egu ^ eku ^ emu ^ esu;
	da = cu ^ qsc_intutils_rotl64(ce, 1);
	de = ca ^ qsc_intutils_rotl64(ci, 1);
	di = ce ^ qsc_intutils_rotl64(co, 1);
	dz = ci ^ qsc_intutils_rotl64(cu, 1);
	du = co ^ qsc_intutils_rotl64(ca, 1);
	eba ^= da;
	ca = eba;
	ege ^= de;
	ce = qsc_intutils_rotl64(ege, 44);
	eki ^= di;
	ci = qsc_intutils_rotl64(eki, 43);
	emo ^= dz;
	co = qsc_intutils_rotl64(emo, 21);
	esu ^= du;
	cu = qsc_intutils_rotl64(esu, 14);
	aba = ca ^ ((!ce) & ci);
	aba ^= 0x8000000000000080;
	abe = ce ^ ((!ci) & co);
	abi = ci ^ ((!co) & cu);
	abo = co ^ ((!cu) & ca);
	abu = cu ^ ((!ca) & ce);
	ebo ^= dz;
	ca = qsc_intutils_rotl64(ebo, 28);
	egu ^= du;
	ce = qsc_intutils_rotl64(egu, 20);
	eka ^= da;
	ci = qsc_intutils_rotl64(eka, 3);
	eme ^= de;
	co = qsc_intutils_rotl64(eme, 45);
	esi ^= di;
	cu = qsc_intutils_rotl64(esi, 61);
	aga = ca ^ ((!ce) & ci);
	age = ce ^ ((!ci) & co);
	agi = ci ^ ((!co) & cu);
	ago = co ^ ((!cu) & ca);
	agu = cu ^ ((!ca) & ce);
	ebe ^= de;
	ca = qsc_intutils_rotl64(ebe, 1);
	egi ^= di;
	ce = qsc_intutils_rotl64(egi, 6);
	eko ^= dz;
	ci = qsc_intutils_rotl64(eko, 25);
	emu ^= du;
	co = qsc_intutils_rotl64(emu, 8);
	esa ^= da;
	cu = qsc_intutils_rotl64(esa, 18);
	aka = ca ^ ((!ce) & ci);
	ake = ce ^ ((!ci) & co);
	aki = ci ^ ((!co) & cu);
	ako = co ^ ((!cu) & ca);
	aku = cu ^ ((!ca) & ce);
	ebu ^= du;
	ca = qsc_intutils_rotl64(ebu, 27);
	ega ^= da;
	ce = qsc_intutils_rotl64(ega, 36);
	eke ^= de;
	ci = qsc_intutils_rotl64(eke, 10);
	emi ^= di;
	co = qsc_intutils_rotl64(emi, 15);
	eso ^= dz;
	cu = qsc_intutils_rotl64(eso, 56);
	ama = ca ^ ((!ce) & ci);
	ame = ce ^ ((!ci) & co);
	ami = ci ^ ((!co) & cu);
	amo = co ^ ((!cu) & ca);
	amu = cu ^ ((!ca) & ce);
	ebi ^= di;
	ca = qsc_intutils_rotl64(ebi, 62);
	ego ^= dz;
	ce = qsc_intutils_rotl64(ego, 55);
	eku ^= du;
	ci = qsc_intutils_rotl64(eku, 39);
	ema ^= da;
	co = qsc_intutils_rotl64(ema, 41);
	ese ^= de;
	cu = qsc_intutils_rotl64(ese, 2);
	asa = ca ^ ((!ce) & ci);
	ase = ce ^ ((!ci) & co);
	asi = ci ^ ((!co) & cu);
	aso = co ^ ((!cu) & ca);
	asu = cu ^ ((!ca) & ce);
	/* round 19 */
	ca = aba ^ aga ^ aka ^ ama ^ asa;
	ce = abe ^ age ^ ake ^ ame ^ ase;
	ci = abi ^ agi ^ aki ^ ami ^ asi;
	co = abo ^ ago ^ ako ^ amo ^ aso;
	cu = abu ^ agu ^ aku ^ amu ^ asu;
	da = cu ^ qsc_intutils_rotl64(ce, 1);
	de = ca ^ qsc_intutils_rotl64(ci, 1);
	di = ce ^ qsc_intutils_rotl64(co, 1);
	dz = ci ^ qsc_intutils_rotl64(cu, 1);
	du = co ^ qsc_intutils_rotl64(ca, 1);
	aba ^= da;
	ca = aba;
	age ^= de;
	ce = qsc_intutils_rotl64(age, 44);
	aki ^= di;
	ci = qsc_intutils_rotl64(aki, 43);
	amo ^= dz;
	co = qsc_intutils_rotl64(amo, 21);
	asu ^= du;
	cu = qsc_intutils_rotl64(asu, 14);
	eba = ca ^ ((!ce) & ci);
	eba ^= 0x000000000000800A;
	ebe = ce ^ ((!ci) & co);
	ebi = ci ^ ((!co) & cu);
	ebo = co ^ ((!cu) & ca);
	ebu = cu ^ ((!ca) & ce);
	abo ^= dz;
	ca = qsc_intutils_rotl64(abo, 28);
	agu ^= du;
	ce = qsc_intutils_rotl64(agu, 20);
	aka ^= da;
	ci = qsc_intutils_rotl64(aka, 3);
	ame ^= de;
	co = qsc_intutils_rotl64(ame, 45);
	asi ^= di;
	cu = qsc_intutils_rotl64(asi, 61);
	ega = ca ^ ((!ce) & ci);
	ege = ce ^ ((!ci) & co);
	egi = ci ^ ((!co) & cu);
	ego = co ^ ((!cu) & ca);
	egu = cu ^ ((!ca) & ce);
	abe ^= de;
	ca = qsc_intutils_rotl64(abe, 1);
	agi ^= di;
	ce = qsc_intutils_rotl64(agi, 6);
	ako ^= dz;
	ci = qsc_intutils_rotl64(ako, 25);
	amu ^= du;
	co = qsc_intutils_rotl64(amu, 8);
	asa ^= da;
	cu = qsc_intutils_rotl64(asa, 18);
	eka = ca ^ ((!ce) & ci);
	eke = ce ^ ((!ci) & co);
	eki = ci ^ ((!co) & cu);
	eko = co ^ ((!cu) & ca);
	eku = cu ^ ((!ca) & ce);
	abu ^= du;
	ca = qsc_intutils_rotl64(abu, 27);
	aga ^= da;
	ce = qsc_intutils_rotl64(aga, 36);
	ake ^= de;
	ci = qsc_intutils_rotl64(ake, 10);
	ami ^= di;
	co = qsc_intutils_rotl64(ami, 15);
	aso ^= dz;
	cu = qsc_intutils_rotl64(aso, 56);
	ema = ca ^ ((!ce) & ci);
	eme = ce ^ ((!ci) & co);
	emi = ci ^ ((!co) & cu);
	emo = co ^ ((!cu) & ca);
	emu = cu ^ ((!ca) & ce);
	abi ^= di;
	ca = qsc_intutils_rotl64(abi, 62);
	ago ^= dz;
	ce = qsc_intutils_rotl64(ago, 55);
	aku ^= du;
	ci = qsc_intutils_rotl64(aku, 39);
	ama ^= da;
	co = qsc_intutils_rotl64(ama, 41);
	ase ^= de;
	cu = qsc_intutils_rotl64(ase, 2);
	esa = ca ^ ((!ce) & ci);
	ese = ce ^ ((!ci) & co);
	esi = ci ^ ((!co) & cu);
	eso = co ^ ((!cu) & ca);
	esu = cu ^ ((!ca) & ce);
	/* round 20 */
	ca = eba ^ ega ^ eka ^ ema ^ esa;
	ce = ebe ^ ege ^ eke ^ eme ^ ese;
	ci = ebi ^ egi ^ eki ^ emi ^ esi;
	co = ebo ^ ego ^ eko ^ emo ^ eso;
	cu = ebu ^ egu ^ eku ^ emu ^ esu;
	da = cu ^ qsc_intutils_rotl64(ce, 1);
	de = ca ^ qsc_intutils_rotl64(ci, 1);
	di = ce ^ qsc_intutils_rotl64(co, 1);
	dz = ci ^ qsc_intutils_rotl64(cu, 1);
	du = co ^ qsc_intutils_rotl64(ca, 1);
	eba ^= da;
	ca = eba;
	ege ^= de;
	ce = qsc_intutils_rotl64(ege, 44);
	eki ^= di;
	ci = qsc_intutils_rotl64(eki, 43);
	emo ^= dz;
	co = qsc_intutils_rotl64(emo, 21);
	esu ^= du;
	cu = qsc_intutils_rotl64(esu, 14);
	aba = ca ^ ((!ce) & ci);
	aba ^= 0x800000008000000A;
	abe = ce ^ ((!ci) & co);
	abi = ci ^ ((!co) & cu);
	abo = co ^ ((!cu) & ca);
	abu = cu ^ ((!ca) & ce);
	ebo ^= dz;
	ca = qsc_intutils_rotl64(ebo, 28);
	egu ^= du;
	ce = qsc_intutils_rotl64(egu, 20);
	eka ^= da;
	ci = qsc_intutils_rotl64(eka, 3);
	eme ^= de;
	co = qsc_intutils_rotl64(eme, 45);
	esi ^= di;
	cu = qsc_intutils_rotl64(esi, 61);
	aga = ca ^ ((!ce) & ci);
	age = ce ^ ((!ci) & co);
	agi = ci ^ ((!co) & cu);
	ago = co ^ ((!cu) & ca);
	agu = cu ^ ((!ca) & ce);
	ebe ^= de;
	ca = qsc_intutils_rotl64(ebe, 1);
	egi ^= di;
	ce = qsc_intutils_rotl64(egi, 6);
	eko ^= dz;
	ci = qsc_intutils_rotl64(eko, 25);
	emu ^= du;
	co = qsc_intutils_rotl64(emu, 8);
	esa ^= da;
	cu = qsc_intutils_rotl64(esa, 18);
	aka = ca ^ ((!ce) & ci);
	ake = ce ^ ((!ci) & co);
	aki = ci ^ ((!co) & cu);
	ako = co ^ ((!cu) & ca);
	aku = cu ^ ((!ca) & ce);
	ebu ^= du;
	ca = qsc_intutils_rotl64(ebu, 27);
	ega ^= da;
	ce = qsc_intutils_rotl64(ega, 36);
	eke ^= de;
	ci = qsc_intutils_rotl64(eke, 10);
	emi ^= di;
	co = qsc_intutils_rotl64(emi, 15);
	eso ^= dz;
	cu = qsc_intutils_rotl64(eso, 56);
	ama = ca ^ ((!ce) & ci);
	ame = ce ^ ((!ci) & co);
	ami = ci ^ ((!co) & cu);
	amo = co ^ ((!cu) & ca);
	amu = cu ^ ((!ca) & ce);
	ebi ^= di;
	ca = qsc_intutils_rotl64(ebi, 62);
	ego ^= dz;
	ce = qsc_intutils_rotl64(ego, 55);
	eku ^= du;
	ci = qsc_intutils_rotl64(eku, 39);
	ema ^= da;
	co = qsc_intutils_rotl64(ema, 41);
	ese ^= de;
	cu = qsc_intutils_rotl64(ese, 2);
	asa = ca ^ ((!ce) & ci);
	ase = ce ^ ((!ci) & co);
	asi = ci ^ ((!co) & cu);
	aso = co ^ ((!cu) & ca);
	asu = cu ^ ((!ca) & ce);
	/* round 21 */
	ca = aba ^ aga ^ aka ^ ama ^ asa;
	ce = abe ^ age ^ ake ^ ame ^ ase;
	ci = abi ^ agi ^ aki ^ ami ^ asi;
	co = abo ^ ago ^ ako ^ amo ^ aso;
	cu = abu ^ agu ^ aku ^ amu ^ asu;
	da = cu ^ qsc_intutils_rotl64(ce, 1);
	de = ca ^ qsc_intutils_rotl64(ci, 1);
	di = ce ^ qsc_intutils_rotl64(co, 1);
	dz = ci ^ qsc_intutils_rotl64(cu, 1);
	du = co ^ qsc_intutils_rotl64(ca, 1);
	aba ^= da;
	ca = aba;
	age ^= de;
	ce = qsc_intutils_rotl64(age, 44);
	aki ^= di;
	ci = qsc_intutils_rotl64(aki, 43);
	amo ^= dz;
	co = qsc_intutils_rotl64(amo, 21);
	asu ^= du;
	cu = qsc_intutils_rotl64(asu, 14);
	eba = ca ^ ((!ce) & ci);
	eba ^= 0x8000000080008081;
	ebe = ce ^ ((!ci) & co);
	ebi = ci ^ ((!co) & cu);
	ebo = co ^ ((!cu) & ca);
	ebu = cu ^ ((!ca) & ce);
	abo ^= dz;
	ca = qsc_intutils_rotl64(abo, 28);
	agu ^= du;
	ce = qsc_intutils_rotl64(agu, 20);
	aka ^= da;
	ci = qsc_intutils_rotl64(aka, 3);
	ame ^= de;
	co = qsc_intutils_rotl64(ame, 45);
	asi ^= di;
	cu = qsc_intutils_rotl64(asi, 61);
	ega = ca ^ ((!ce) & ci);
	ege = ce ^ ((!ci) & co);
	egi = ci ^ ((!co) & cu);
	ego = co ^ ((!cu) & ca);
	egu = cu ^ ((!ca) & ce);
	abe ^= de;
	ca = qsc_intutils_rotl64(abe, 1);
	agi ^= di;
	ce = qsc_intutils_rotl64(agi, 6);
	ako ^= dz;
	ci = qsc_intutils_rotl64(ako, 25);
	amu ^= du;
	co = qsc_intutils_rotl64(amu, 8);
	asa ^= da;
	cu = qsc_intutils_rotl64(asa, 18);
	eka = ca ^ ((!ce) & ci);
	eke = ce ^ ((!ci) & co);
	eki = ci ^ ((!co) & cu);
	eko = co ^ ((!cu) & ca);
	eku = cu ^ ((!ca) & ce);
	abu ^= du;
	ca = qsc_intutils_rotl64(abu, 27);
	aga ^= da;
	ce = qsc_intutils_rotl64(aga, 36);
	ake ^= de;
	ci = qsc_intutils_rotl64(ake, 10);
	ami ^= di;
	co = qsc_intutils_rotl64(ami, 15);
	aso ^= dz;
	cu = qsc_intutils_rotl64(aso, 56);
	ema = ca ^ ((!ce) & ci);
	eme = ce ^ ((!ci) & co);
	emi = ci ^ ((!co) & cu);
	emo = co ^ ((!cu) & ca);
	emu = cu ^ ((!ca) & ce);
	abi ^= di;
	ca = qsc_intutils_rotl64(abi, 62);
	ago ^= dz;
	ce = qsc_intutils_rotl64(ago, 55);
	aku ^= du;
	ci = qsc_intutils_rotl64(aku, 39);
	ama ^= da;
	co = qsc_intutils_rotl64(ama, 41);
	ase ^= de;
	cu = qsc_intutils_rotl64(ase, 2);
	esa = ca ^ ((!ce) & ci);
	ese = ce ^ ((!ci) & co);
	esi = ci ^ ((!co) & cu);
	eso = co ^ ((!cu) & ca);
	esu = cu ^ ((!ca) & ce);
	/* round 22 */
	ca = eba ^ ega ^ eka ^ ema ^ esa;
	ce = ebe ^ ege ^ eke ^ eme ^ ese;
	ci = ebi ^ egi ^ eki ^ emi ^ esi;
	co = ebo ^ ego ^ eko ^ emo ^ eso;
	cu = ebu ^ egu ^ eku ^ emu ^ esu;
	da = cu ^ qsc_intutils_rotl64(ce, 1);
	de = ca ^ qsc_intutils_rotl64(ci, 1);
	di = ce ^ qsc_intutils_rotl64(co, 1);
	dz = ci ^ qsc_intutils_rotl64(cu, 1);
	du = co ^ qsc_intutils_rotl64(ca, 1);
	eba ^= da;
	ca = eba;
	ege ^= de;
	ce = qsc_intutils_rotl64(ege, 44);
	eki ^= di;
	ci = qsc_intutils_rotl64(eki, 43);
	emo ^= dz;
	co = qsc_intutils_rotl64(emo, 21);
	esu ^= du;
	cu = qsc_intutils_rotl64(esu, 14);
	aba = ca ^ ((!ce) & ci);
	aba ^= 0x8000000000008080;
	abe = ce ^ ((!ci) & co);
	abi = ci ^ ((!co) & cu);
	abo = co ^ ((!cu) & ca);
	abu = cu ^ ((!ca) & ce);
	ebo ^= dz;
	ca = qsc_intutils_rotl64(ebo, 28);
	egu ^= du;
	ce = qsc_intutils_rotl64(egu, 20);
	eka ^= da;
	ci = qsc_intutils_rotl64(eka, 3);
	eme ^= de;
	co = qsc_intutils_rotl64(eme, 45);
	esi ^= di;
	cu = qsc_intutils_rotl64(esi, 61);
	aga = ca ^ ((!ce) & ci);
	age = ce ^ ((!ci) & co);
	agi = ci ^ ((!co) & cu);
	ago = co ^ ((!cu) & ca);
	agu = cu ^ ((!ca) & ce);
	ebe ^= de;
	ca = qsc_intutils_rotl64(ebe, 1);
	egi ^= di;
	ce = qsc_intutils_rotl64(egi, 6);
	eko ^= dz;
	ci = qsc_intutils_rotl64(eko, 25);
	emu ^= du;
	co = qsc_intutils_rotl64(emu, 8);
	esa ^= da;
	cu = qsc_intutils_rotl64(esa, 18);
	aka = ca ^ ((!ce) & ci);
	ake = ce ^ ((!ci) & co);
	aki = ci ^ ((!co) & cu);
	ako = co ^ ((!cu) & ca);
	aku = cu ^ ((!ca) & ce);
	ebu ^= du;
	ca = qsc_intutils_rotl64(ebu, 27);
	ega ^= da;
	ce = qsc_intutils_rotl64(ega, 36);
	eke ^= de;
	ci = qsc_intutils_rotl64(eke, 10);
	emi ^= di;
	co = qsc_intutils_rotl64(emi, 15);
	eso ^= dz;
	cu = qsc_intutils_rotl64(eso, 56);
	ama = ca ^ ((!ce) & ci);
	ame = ce ^ ((!ci) & co);
	ami = ci ^ ((!co) & cu);
	amo = co ^ ((!cu) & ca);
	amu = cu ^ ((!ca) & ce);
	ebi ^= di;
	ca = qsc_intutils_rotl64(ebi, 62);
	ego ^= dz;
	ce = qsc_intutils_rotl64(ego, 55);
	eku ^= du;
	ci = qsc_intutils_rotl64(eku, 39);
	ema ^= da;
	co = qsc_intutils_rotl64(ema, 41);
	ese ^= de;
	cu = qsc_intutils_rotl64(ese, 2);
	asa = ca ^ ((!ce) & ci);
	ase = ce ^ ((!ci) & co);
	asi = ci ^ ((!co) & cu);
	aso = co ^ ((!cu) & ca);
	asu = cu ^ ((!ca) & ce);
	/* round 23 */
	ca = aba ^ aga ^ aka ^ ama ^ asa;
	ce = abe ^ age ^ ake ^ ame ^ ase;
	ci = abi ^ agi ^ aki ^ ami ^ asi;
	co = abo ^ ago ^ ako ^ amo ^ aso;
	cu = abu ^ agu ^ aku ^ amu ^ asu;
	da = cu ^ qsc_intutils_rotl64(ce, 1);
	de = ca ^ qsc_intutils_rotl64(ci, 1);
	di = ce ^ qsc_intutils_rotl64(co, 1);
	dz = ci ^ qsc_intutils_rotl64(cu, 1);
	du = co ^ qsc_intutils_rotl64(ca, 1);
	aba ^= da;
	ca = aba;
	age ^= de;
	ce = qsc_intutils_rotl64(age, 44);
	aki ^= di;
	ci = qsc_intutils_rotl64(aki, 43);
	amo ^= dz;
	co = qsc_intutils_rotl64(amo, 21);
	asu ^= du;
	cu = qsc_intutils_rotl64(asu, 14);
	eba = ca ^ ((!ce) & ci);
	eba ^= 0x0000000080000001;
	ebe = ce ^ ((!ci) & co);
	ebi = ci ^ ((!co) & cu);
	ebo = co ^ ((!cu) & ca);
	ebu = cu ^ ((!ca) & ce);
	abo ^= dz;
	ca = qsc_intutils_rotl64(abo, 28);
	agu ^= du;
	ce = qsc_intutils_rotl64(agu, 20);
	aka ^= da;
	ci = qsc_intutils_rotl64(aka, 3);
	ame ^= de;
	co = qsc_intutils_rotl64(ame, 45);
	asi ^= di;
	cu = qsc_intutils_rotl64(asi, 61);
	ega = ca ^ ((!ce) & ci);
	ege = ce ^ ((!ci) & co);
	egi = ci ^ ((!co) & cu);
	ego = co ^ ((!cu) & ca);
	egu = cu ^ ((!ca) & ce);
	abe ^= de;
	ca = qsc_intutils_rotl64(abe, 1);
	agi ^= di;
	ce = qsc_intutils_rotl64(agi, 6);
	ako ^= dz;
	ci = qsc_intutils_rotl64(ako, 25);
	amu ^= du;
	co = qsc_intutils_rotl64(amu, 8);
	asa ^= da;
	cu = qsc_intutils_rotl64(asa, 18);
	eka = ca ^ ((!ce) & ci);
	eke = ce ^ ((!ci) & co);
	eki = ci ^ ((!co) & cu);
	eko = co ^ ((!cu) & ca);
	eku = cu ^ ((!ca) & ce);
	abu ^= du;
	ca = qsc_intutils_rotl64(abu, 27);
	aga ^= da;
	ce = qsc_intutils_rotl64(aga, 36);
	ake ^= de;
	ci = qsc_intutils_rotl64(ake, 10);
	ami ^= di;
	co = qsc_intutils_rotl64(ami, 15);
	aso ^= dz;
	cu = qsc_intutils_rotl64(aso, 56);
	ema = ca ^ ((!ce) & ci);
	eme = ce ^ ((!ci) & co);
	emi = ci ^ ((!co) & cu);
	emo = co ^ ((!cu) & ca);
	emu = cu ^ ((!ca) & ce);
	abi ^= di;
	ca = qsc_intutils_rotl64(abi, 62);
	ago ^= dz;
	ce = qsc_intutils_rotl64(ago, 55);
	aku ^= du;
	ci = qsc_intutils_rotl64(aku, 39);
	ama ^= da;
	co = qsc_intutils_rotl64(ama, 41);
	ase ^= de;
	cu = qsc_intutils_rotl64(ase, 2);
	esa = ca ^ ((!ce) & ci);
	ese = ce ^ ((!ci) & co);
	esi = ci ^ ((!co) & cu);
	eso = co ^ ((!cu) & ca);
	esu = cu ^ ((!ca) & ce);
	/* round 24 */
	ca = eba ^ ega ^ eka ^ ema ^ esa;
	ce = ebe ^ ege ^ eke ^ eme ^ ese;
	ci = ebi ^ egi ^ eki ^ emi ^ esi;
	co = ebo ^ ego ^ eko ^ emo ^ eso;
	cu = ebu ^ egu ^ eku ^ emu ^ esu;
	da = cu ^ qsc_intutils_rotl64(ce, 1);
	de = ca ^ qsc_intutils_rotl64(ci, 1);
	di = ce ^ qsc_intutils_rotl64(co, 1);
	dz = ci ^ qsc_intutils_rotl64(cu, 1);
	du = co ^ qsc_intutils_rotl64(ca, 1);
	eba ^= da;
	ca = eba;
	ege ^= de;
	ce = qsc_intutils_rotl64(ege, 44);
	eki ^= di;
	ci = qsc_intutils_rotl64(eki, 43);
	emo ^= dz;
	co = qsc_intutils_rotl64(emo, 21);
	esu ^= du;
	cu = qsc_intutils_rotl64(esu, 14);
	aba = ca ^ ((!ce) & ci);
	aba ^= 0x8000000080008008;
	abe = ce ^ ((!ci) & co);
	abi = ci ^ ((!co) & cu);
	abo = co ^ ((!cu) & ca);
	abu = cu ^ ((!ca) & ce);
	ebo ^= dz;
	ca = qsc_intutils_rotl64(ebo, 28);
	egu ^= du;
	ce = qsc_intutils_rotl64(egu, 20);
	eka ^= da;
	ci = qsc_intutils_rotl64(eka, 3);
	eme ^= de;
	co = qsc_intutils_rotl64(eme, 45);
	esi ^= di;
	cu = qsc_intutils_rotl64(esi, 61);
	aga = ca ^ ((!ce) & ci);
	age = ce ^ ((!ci) & co);
	agi = ci ^ ((!co) & cu);
	ago = co ^ ((!cu) & ca);
	agu = cu ^ ((!ca) & ce);
	ebe ^= de;
	ca = qsc_intutils_rotl64(ebe, 1);
	egi ^= di;
	ce = qsc_intutils_rotl64(egi, 6);
	eko ^= dz;
	ci = qsc_intutils_rotl64(eko, 25);
	emu ^= du;
	co = qsc_intutils_rotl64(emu, 8);
	esa ^= da;
	cu = qsc_intutils_rotl64(esa, 18);
	aka = ca ^ ((!ce) & ci);
	ake = ce ^ ((!ci) & co);
	aki = ci ^ ((!co) & cu);
	ako = co ^ ((!cu) & ca);
	aku = cu ^ ((!ca) & ce);
	ebu ^= du;
	ca = qsc_intutils_rotl64(ebu, 27);
	ega ^= da;
	ce = qsc_intutils_rotl64(ega, 36);
	eke ^= de;
	ci = qsc_intutils_rotl64(eke, 10);
	emi ^= di;
	co = qsc_intutils_rotl64(emi, 15);
	eso ^= dz;
	cu = qsc_intutils_rotl64(eso, 56);
	ama = ca ^ ((!ce) & ci);
	ame = ce ^ ((!ci) & co);
	ami = ci ^ ((!co) & cu);
	amo = co ^ ((!cu) & ca);
	amu = cu ^ ((!ca) & ce);
	ebi ^= di;
	ca = qsc_intutils_rotl64(ebi, 62);
	ego ^= dz;
	ce = qsc_intutils_rotl64(ego, 55);
	eku ^= du;
	ci = qsc_intutils_rotl64(eku, 39);
	ema ^= da;
	co = qsc_intutils_rotl64(ema, 41);
	ese ^= de;
	cu = qsc_intutils_rotl64(ese, 2);
	asa = ca ^ ((!ce) & ci);
	ase = ce ^ ((!ci) & co);
	asi = ci ^ ((!co) & cu);
	aso = co ^ ((!cu) & ca);
	asu = cu ^ ((!ca) & ce);

	state[0] = aba;
	state[1] = abe;
	state[2] = abi;
	state[3] = abo;
	state[4] = abu;
	state[5] = aga;
	state[6] = age;
	state[7] = agi;
	state[8] = ago;
	state[9] = agu;
	state[10] = aka;
	state[11] = ake;
	state[12] = aki;
	state[13] = ako;
	state[14] = aku;
	state[15] = ama;
	state[16] = ame;
	state[17] = ami;
	state[18] = amo;
	state[19] = amu;
	state[20] = asa;
	state[21] = ase;
	state[22] = asi;
	state[23] = aso;
	state[24] = asu;
}

/**
* \brief The Keccak squeeze function.
*
* \warning Output array must be initialized to a multiple of the byte rate.
*
* \param ctx: [struct] A reference to the Keccak state; must be initialized
* \param output: The output byte array
* \param nblocks: The number of blocks to extract
* \param rate: The rate of absorption in bytes
* \param rounds: The number of permutation rounds, the default and maximum is 24
*/
fn qsc_keccak_squeezeblocks(ctx: &mut QscKeccakState, mut output: &mut [u8], mut nblocks: usize, rate: usize , rounds: usize) {
	while nblocks > 0 {
		qsc_keccak_permute(ctx, rounds);

		if QSC_SYSTEM_IS_LITTLE_ENDIAN {
			let byte_slice: &[u8] = cast_slice(&ctx.state);
			qsc_memutils_copy(output, byte_slice, rate);
		} else {
			for i in 0..(rate >> 3)	{
				qsc_intutils_le64to8(&mut output[(size_of::<u64>() * i)..], ctx.state[i]);
			}
		}
		output = &mut output[rate..];
		nblocks -= 1;
	}

}

/**
* \brief Initializes a Keccak state structure, must be called before message processing.
* Long form api: must be used in conjunction with the block-update and finalize functions.
*
* \param ctx: [struct] A reference to the Keccak state; must be initialized
*/
fn qsc_keccak_initialize_state(ctx: &mut QscKeccakState) {
	ctx.position = 0;
}

/**
* \brief Update Keccak state with message input.
*
* \warning The state must be initialized before calling
*
* \param ctx: [struct] A reference to the Keccak state; must be initialized
* \param rate: The rate of absorption in bytes
* \param message: [const] The input message byte array
* \param msglen: The number of message bytes to process
* \param rounds: The number of permutation rounds, the default and maximum is 24
*/
fn qsc_keccak_update(ctx: &mut QscKeccakState, rate: usize, mut message: &[u8], mut msglen: usize, rounds: usize) {
	if !message.is_empty() && msglen != 0 {
		if ctx.position != 0 && ctx.position + msglen >= rate {
			let rmdlen: usize = rate - ctx.position;

			if rmdlen != 0 {
				qsc_memutils_copy(&mut ctx.buffer[ctx.position..], message, rmdlen);
			}

			keccak_fast_absorb(&mut ctx.state, &ctx.buffer, rate);
			qsc_keccak_permute(ctx, rounds);
			ctx.position = 0;
			message = &message[rmdlen..];
			msglen -= rmdlen;
		}

		/* sequential loop through blocks */
		while msglen >= rate {
			keccak_fast_absorb(&mut ctx.state, message, rate);
			qsc_keccak_permute(ctx, rounds);
			message = &message[rate..];
			msglen -= rate;
		}

		/* store unaligned bytes */
		if msglen != 0 {
			qsc_memutils_copy(&mut ctx.buffer[ctx.position..], message, msglen);
			ctx.position = ctx.position + msglen;
		}
	}
}


/* SHA3 */

/**
* \brief Process a message with SHA3-256 and return the hash code in the output byte array.
* Short form api: processes the entire message and computes the hash code with a single call.
*
* \warning The output array must be at least 32 bytes in length.
*
* \param output:: The output byte array; receives the hash code
* \param message: [const] The message input byte array
* \param msglen: The number of message bytes to process
*/
pub fn qsc_sha3_compute256(output: &mut [u8], message: &[u8], msglen: usize) {
	let ctx = &mut QscKeccakState::default();
	let hash = &mut [0u8; QSC_KECCAK_256_RATE];

	let rate = QscKeccakRate::QscKeccakRate256 as usize;

	qsc_sha3_initialize(ctx);
	qsc_keccak_absorb(ctx, rate, message, msglen, QSC_KECCAK_SHA3_DOMAIN_ID, QSC_KECCAK_PERMUTATION_ROUNDS);
	qsc_keccak_squeezeblocks(ctx, hash, 1, rate, QSC_KECCAK_PERMUTATION_ROUNDS);
	qsc_memutils_copy(output, hash, QSC_SHA3_256_HASH_SIZE);
	qsc_keccak_dispose(ctx);
}

/**
* \brief Process a message with SHA3-512 and return the hash code in the output byte array.
* Short form api: processes the entire message and computes the hash code with a single call.
*
* \warning The output array must be at least 64 bytes in length.
*
* \param output: The output byte array; receives the hash code
* \param message: [const] The message input byte array
* \param msglen: The number of message bytes to process
*/
pub fn qsc_sha3_compute512(output: &mut [u8], message: &[u8], msglen: usize) {
	let ctx = &mut QscKeccakState::default();
	let hash = &mut [0u8; QSC_KECCAK_512_RATE];

	let rate = QscKeccakRate::QscKeccakRate512 as usize;

	qsc_sha3_initialize(ctx);
	qsc_keccak_absorb(ctx, rate, message, msglen, QSC_KECCAK_SHA3_DOMAIN_ID, QSC_KECCAK_PERMUTATION_ROUNDS);
	qsc_keccak_squeezeblocks(ctx, hash, 1, rate, QSC_KECCAK_PERMUTATION_ROUNDS);
	qsc_memutils_copy(output, hash, QSC_SHA3_512_HASH_SIZE);
	qsc_keccak_dispose(ctx);
}

/**
* \brief Finalize the message state and returns the hash value in output.
* Long form api: must be used in conjunction with the initialize and block-update functions.
* Absorb the last block of message and create the hash value.
* Produces a 32 byte output code using QSC_KECCAK_256_RATE, 64 bytes with QSC_KECCAK_512_RATE.
*
* \warning The output array must be sized correctly corresponding to the absorption rate ((200 - rate) / 2).
* Finalizes the message state, can not be used in consecutive calls.
* The state must be initialized before calling.
*
* \param ctx: [struct] A reference to the Keccak state; must be initialized
* \param rate: The rate of absorption in bytes
* \param output: The output byte array; receives the hash code
*/
pub fn qsc_sha3_finalize(ctx: &mut QscKeccakState, rate: usize, mut output: &mut [u8]) {

	let hlen = ((QSC_KECCAK_STATE_SIZE * size_of::<u64>()) - rate) / 2;
	qsc_memutils_clear(&mut ctx.buffer[ctx.position..]);

	ctx.buffer[ctx.position] = QSC_KECCAK_SHA3_DOMAIN_ID;
	ctx.buffer[rate - 1] |= 128;

	keccak_fast_absorb(&mut ctx.state, &ctx.buffer, rate);
	qsc_keccak_permute(ctx, QSC_KECCAK_PERMUTATION_ROUNDS);

	if QSC_SYSTEM_IS_LITTLE_ENDIAN {
		let byte_slice = cast_slice(&ctx.state);
		qsc_memutils_copy(output, byte_slice, hlen);
	} else {
		for i in 0..(hlen / size_of::<u64>()) {
			qsc_intutils_le64to8(output, ctx.state[i]);
			output = &mut output[(size_of::<u64>())..];
		}
	}

	qsc_keccak_dispose(ctx);
}

/**
* \brief Initialize the SHA3 state
* Long form api: Must be called before the update or finalize functions are called.
*
* \param ctx: [struct] A reference to the Keccak state
*/
pub fn qsc_sha3_initialize(ctx: &mut QscKeccakState) {
	qsc_keccak_initialize_state(ctx);
}

/**
* \brief Update SHA3 with message input.
* Long form api: must be used in conjunction with the initialize and finalize functions.
* Absorbs the input message into the state.
*
* \warning The state must be initialized before calling
*
* \param ctx: [struct] A reference to the Keccak state; must be initialized
* \param rate: The rate of absorption in bytes
* \param message: [const] The input message byte array
* \param msglen: The number of message bytes to process
*/
pub fn qsc_sha3_update(ctx: &mut QscKeccakState, rate: usize, message: &[u8], msglen: usize) {
	qsc_keccak_update(ctx, rate, message, msglen, QSC_KECCAK_PERMUTATION_ROUNDS);
}

/* SHAKE */

/**
* \brief Key a SHAKE-128 instance, and generate an array of pseudo-random bytes.
* Short form api: processes the key and generates the pseudo-random output with a single call.
*
* \warning The output array length must not be zero.
*
* \param output: The output byte array
* \param outlen: The number of output bytes to generate
* \param key: [const] The input key byte array
* \param keylen: The number of key bytes to process
*/
pub fn qsc_shake128_compute(mut output: &mut [u8], mut outlen: usize, key: &[u8], keylen: usize) {

	let nblocks = outlen / QSC_KECCAK_128_RATE;
	let mut ctx: QscKeccakState = Default::default();
	let mut hash = [0u8; QSC_KECCAK_128_RATE];

	let rate = QscKeccakRate::QscKeccakRate128 as usize;
	qsc_shake_initialize(&mut ctx, rate, key, keylen);
	qsc_shake_squeezeblocks(&mut ctx, rate, &mut output, nblocks);
	output = &mut output[(nblocks * QSC_KECCAK_128_RATE)..];
	outlen -= nblocks * QSC_KECCAK_128_RATE;

	if outlen != 0 {
		qsc_shake_squeezeblocks(&mut ctx, rate, &mut hash, 1);
		qsc_memutils_copy(&mut output, &hash, outlen);
	}

	qsc_keccak_dispose(&mut ctx);
}

/**
* \brief Key a SHAKE-256 instance, and generate an array of pseudo-random bytes.
* Short form api: processes the key and generates the pseudo-random output with a single call.
*
* \warning The output array length must not be zero.
*
* \param output: The output byte array
* \param outlen: The number of output bytes to generate
* \param key: [const] The input key byte array
* \param keylen: The number of key bytes to process
*/
pub fn qsc_shake256_compute(mut output: &mut [u8], mut outlen: usize, key: &[u8], keylen: usize) {

	let nblocks = outlen / QSC_KECCAK_256_RATE;
	let ctx = &mut QscKeccakState::default();
	let hash = &mut [0u8; QSC_KECCAK_256_RATE];

	let rate = QscKeccakRate::QscKeccakRate256 as usize;
	qsc_shake_initialize(ctx, rate, key, keylen);
	qsc_shake_squeezeblocks(ctx, rate, output, nblocks);
	output = &mut output[(nblocks * QSC_KECCAK_256_RATE)..];
	outlen -= nblocks * QSC_KECCAK_256_RATE;
	

	if outlen != 0 {
		qsc_shake_squeezeblocks(ctx, rate, hash, 1);
		qsc_memutils_copy(output, hash, outlen);
	}

	qsc_keccak_dispose(ctx);
}

/**
* \brief Key a SHAKE-512 instance, and generate an array of pseudo-random bytes.
* Short form api: processes the key and generates the pseudo-random output with a single call.
*
* \warning The output array length must not be zero.
*
* \param output: The output byte array
* \param outlen: The number of output bytes to generate
* \param key: [const] The input key byte array
* \param keylen: The number of key bytes to process
*/
pub fn qsc_shake512_compute(mut output: &mut [u8], mut outlen: usize, key: &[u8], keylen: usize) {

	let nblocks: usize = outlen / QSC_KECCAK_512_RATE;
	let mut ctx: QscKeccakState = Default::default();
	let mut hash = [0u8; QSC_KECCAK_512_RATE];

	let rate = QscKeccakRate::QscKeccakRate512 as usize;
	qsc_shake_initialize(&mut ctx, rate, key, keylen);
	qsc_shake_squeezeblocks(&mut ctx, rate, &mut output, nblocks);
	output = &mut output[(nblocks * QSC_KECCAK_512_RATE)..];
	outlen -= nblocks * QSC_KECCAK_512_RATE;

	if outlen != 0 {
		qsc_shake_squeezeblocks(&mut ctx, rate, &mut hash, 1);
		qsc_memutils_copy(&mut output, &hash, outlen);
	}

	qsc_keccak_dispose(&mut ctx);
}

/**
* \brief The SHAKE initialize function.
* Long form api: must be used in conjunction with the squeezeblocks function.
* Absorb and finalize an input key byte array.
*
* \param ctx: [struct] A reference to the Keccak state; must be initialized
* \param rate: The rate of absorption in bytes
* \param key: [const] The input key byte array
* \param keylen: The number of key bytes to process
*/
pub fn qsc_shake_initialize(ctx: &mut QscKeccakState, rate: usize, key: &[u8], keylen: usize) {
	qsc_keccak_initialize_state(ctx);
	qsc_keccak_absorb(ctx, rate, key, keylen, QSC_KECCAK_SHAKE_DOMAIN_ID, QSC_KECCAK_PERMUTATION_ROUNDS);
}

/**
* \brief The SHAKE squeeze function.
* Long form api: must be used in conjunction with the initialize function.
* Permutes and extracts the state to an output byte array.
*
* \warning Output array must be initialized to a multiple of the byte rate.
* The state must be initialized before calling.
*
* \param ctx: [struct] A reference to the Keccak state; must be initialized
* \param rate: The rate of absorption in bytes
* \param output: The output byte array
* \param nblocks: The number of blocks to extract
*/
pub fn qsc_shake_squeezeblocks(ctx: &mut QscKeccakState, rate: usize, output: &mut [u8], nblocks: usize) {
	qsc_keccak_squeezeblocks(ctx, output, nblocks, rate, QSC_KECCAK_PERMUTATION_ROUNDS);
}

/* cSHAKE */

/**
* \brief Key a cSHAKE-128 instance and generate pseudo-random output.
* Short form api: processes the key, name, and custom inputs and generates the pseudo-random output with a single call.
* Permutes and extracts the state to an output byte array..
*
* \param output: The output byte array
* \param outlen: The number of output bytes to generate
* \param key: [const] The input key byte array
* \param keylen: The number of key bytes to process
* \param name: [const] The function name string
* \param namelen: The byte length of the function name
* \param custom: [const] The customization string
* \param custlen: The byte length of the customization string
*/
pub fn qsc_cshake128_compute(mut output: &mut [u8], mut outlen: usize, key: &[u8], keylen: usize, name: &[u8], namelen: usize, custom: &[u8], custlen: usize) {

	let nblocks: usize = outlen / QSC_KECCAK_128_RATE;
	let mut ctx: QscKeccakState = Default::default();
	let mut hash = [0u8; QSC_KECCAK_128_RATE];

	let rate = QscKeccakRate::QscKeccakRate128 as usize;
	if custlen + namelen != 0 {
		qsc_cshake_initialize(&mut ctx, rate, key, keylen, name, namelen, custom, custlen);
	} else {
		qsc_shake_initialize(&mut ctx, rate, key, keylen);
	}

	qsc_cshake_squeezeblocks(&mut ctx, rate, &mut output, nblocks);
	output = &mut output[(nblocks * QSC_KECCAK_128_RATE)..];
	outlen -= nblocks * QSC_KECCAK_128_RATE;

	if outlen != 0 {
		qsc_cshake_squeezeblocks(&mut ctx, rate, &mut hash, 1);
		qsc_memutils_copy(output, &hash, outlen);
	}

	qsc_keccak_dispose(&mut ctx);
}

/**
* \brief Key a cSHAKE-256 instance and generate pseudo-random output.
* Short form api: processes the key, name, and custom inputs and generates the pseudo-random output with a single call.
* Permutes and extracts the state to an output byte array.
*
* \param output: The output byte array
* \param outlen: The number of output bytes to generate
* \param key: [const] The input key byte array
* \param keylen: The number of key bytes to process
* \param name: [const] The function name string
* \param namelen: The byte length of the function name
* \param custom: [const] The customization string
* \param custlen: The byte length of the customization string
*/
pub fn qsc_cshake256_compute(mut output: &mut [u8], mut outlen: usize, key: &[u8], keylen: usize, name: &[u8], namelen: usize, custom: &[u8], custlen: usize) {

	let nblocks: usize = outlen / QSC_KECCAK_256_RATE;
	let mut ctx: QscKeccakState = Default::default();
	let mut hash = [0u8; QSC_KECCAK_256_RATE];

	let rate = QscKeccakRate::QscKeccakRate256 as usize;
	if custlen + namelen != 0 {
		qsc_cshake_initialize(&mut ctx, rate, key, keylen, name, namelen, custom, custlen);
	} else {
		qsc_shake_initialize(&mut ctx, rate, key, keylen);
	}

	qsc_cshake_squeezeblocks(&mut ctx, rate, &mut output, nblocks);

	output = &mut output[(nblocks * QSC_KECCAK_256_RATE)..];
	outlen -= nblocks * QSC_KECCAK_256_RATE;

	if outlen != 0 {
		qsc_cshake_squeezeblocks(&mut ctx, rate, &mut hash, 1);
		qsc_memutils_copy(output, &hash, outlen);
	}

	qsc_keccak_dispose(&mut ctx);
}

/**
* \brief Key a cSHAKE-512 instance and generate pseudo-random output.
* Short form api: processes the key, name, and custom inputs and generates the pseudo-random output with a single call.
* Permutes and extracts the state to an output byte array.
*
* \param output: The output byte array
* \param outlen: The number of output bytes to generate
* \param key: [const] The input key byte array
* \param keylen: The number of key bytes to process
* \param name: [const] The function name string
* \param namelen: The byte length of the function name
* \param custom: [const] The customization string
* \param custlen: The byte length of the customization string
*/
pub fn qsc_cshake512_compute(mut output: &mut [u8], mut outlen: usize, key: &[u8], keylen: usize, name: &[u8], namelen: usize, custom: &[u8], custlen: usize) {

	let nblocks: usize = outlen / QSC_KECCAK_512_RATE;
	let ctx = &mut QscKeccakState::default();

	let hash = &mut [0u8; QSC_KECCAK_512_RATE];

	let rate = QscKeccakRate::QscKeccakRate512 as usize;
	if custlen + namelen != 0 {
		qsc_cshake_initialize(ctx, rate, key, keylen, name, namelen, custom, custlen);
	} else {
		qsc_shake_initialize(ctx, rate, key, keylen);
	}

	qsc_cshake_squeezeblocks(ctx, rate, output, nblocks);
	output = &mut output[(nblocks * QSC_KECCAK_512_RATE)..];
	outlen -= nblocks * QSC_KECCAK_512_RATE;

	if outlen != 0 {
		qsc_cshake_squeezeblocks(ctx, rate, hash, 1);
		qsc_memutils_copy(output, hash, outlen);
	}

	qsc_keccak_dispose(ctx);
}

/**
* \brief The cSHAKE initialize function.
* Long form api: must be used in conjunction with the squeezeblocks function.
* Initialize the name and customization strings into the state.
*
* \param ctx: [struct] A reference to the Keccak state; must be initialized
* \param rate: The rate of absorption in bytes
* \param key: [const] The input key byte array
* \param keylen: The number of key bytes to process
* \param name: [const] The function name string
* \param namelen: The byte length of the function name
* \param custom: [const] The customization string
* \param custlen: The byte length of the customization string
*/
pub fn qsc_cshake_initialize(ctx: &mut QscKeccakState, rate: usize, key: &[u8], keylen: usize, name: &[u8], namelen: usize, custom: &[u8], custlen: usize) {

	qsc_keccak_initialize_state(ctx);
	/* absorb the custom and name arrays */
	qsc_keccak_absorb_custom(ctx, rate, custom, custlen, name, namelen, QSC_KECCAK_PERMUTATION_ROUNDS);
	/* finalize the key */
	qsc_keccak_absorb(ctx, rate, key, keylen, QSC_KECCAK_CSHAKE_DOMAIN_ID, QSC_KECCAK_PERMUTATION_ROUNDS);
}

/**
* \brief The cSHAKE squeeze function.
* Long form api: must be used in conjunction with the initialize function.
* Permutes and extracts blocks of state to an output byte array.
*
* \warning Output array must be initialized to a multiple of the byte rate.
* The state must be initialized before calling.
*
* \param ctx: [struct] A reference to the Keccak state; must be initialized
* \param rate: The rate of absorption in bytes
* \param output: The output byte array
* \param nblocks: The number of blocks to extract
*/
pub fn qsc_cshake_squeezeblocks(ctx: &mut QscKeccakState, rate: usize, output: &mut [u8], nblocks: usize) {
	qsc_keccak_squeezeblocks(ctx, output, nblocks, rate, QSC_KECCAK_PERMUTATION_ROUNDS);
}

/**
* \brief The cSHAKE update function.
* Long form api: must be used in conjunction with the initialize and squeezeblocks functions.
* Finalize an input key directly into the state.
*
* \warning Finalizes the key state, should not be used in consecutive calls.
* The state must be initialized before calling.
*
* \param ctx: [struct] A reference to the Keccak state; must be initialized
* \param rate: The rate of absorption in bytes
* \param key: [const] The input key byte array
* \param keylen: The number of key bytes to process
*/
pub(crate) fn qsc_cshake_update(ctx: &mut QscKeccakState, rate: usize, mut key: &mut [u8], mut keylen: usize) {

	while keylen >= rate {
		keccak_fast_absorb(&mut ctx.state, key, keylen);
		qsc_keccak_permute(ctx, QSC_KECCAK_PERMUTATION_ROUNDS);
		keylen -= rate;
		key = &mut key[rate..];
	}

	if keylen != 0 {
		keccak_fast_absorb(&mut ctx.state, key, keylen);
		qsc_keccak_permute(ctx, QSC_KECCAK_PERMUTATION_ROUNDS);
	}
}

/* KMAC */

/**
* \brief Key a KMAC-128 instance and generate a MAC code.
* Short form api: processes the key and custom inputs and generates the MAC code with a single call.
* Key the MAC generator process a message and output the MAC code.
*
* \param output: The MAC code byte array
* \param outlen: The number of MAC code bytes to generate
* \param message: [const] The message input byte array
* \param msglen: The number of message bytes to process
* \param key: [const] The input key byte array
* \param keylen: The number of key bytes to process
* \param custom: [const] The customization string
* \param custlen: The byte length of the customization string
*/
pub fn qsc_kmac128_compute(mut output: &mut [u8], outlen: usize, mut message: &mut [u8], msglen: usize, mut key: &mut [u8], keylen: usize, mut custom: &mut [u8], custlen: usize) {

	let mut ctx: QscKeccakState = Default::default();

	let rate = QscKeccakRate::QscKeccakRate128 as usize;
	qsc_kmac_initialize(&mut ctx, rate, &mut key, keylen, &mut custom, custlen);
	qsc_kmac_update(&mut ctx, rate, &mut message, msglen);
	qsc_kmac_finalize(&mut ctx, rate, &mut output, outlen);
}

/**
* \brief Key a KMAC-256 instance and generate a MAC code.
* Short form api: processes the key and custom inputs and generates the MAC code with a single call.
* Key the MAC generator process a message and output the MAC code.
*
* \param output: The MAC code byte array
* \param outlen: The number of MAC code bytes to generate
* \param message: [const] The message input byte array
* \param msglen: The number of message bytes to process
* \param key: [const] The input key byte array
* \param keylen: The number of key bytes to process
* \param custom: [const] The customization string
* \param custlen: The byte length of the customization string
*/
pub fn qsc_kmac256_compute(output: &mut [u8], outlen: usize, message: &[u8], msglen: usize, key: &mut [u8], keylen: usize, custom: &mut [u8], custlen: usize) {
	let ctx = &mut QscKeccakState::default();

	let rate = QscKeccakRate::QscKeccakRate256 as usize;
	qsc_kmac_initialize(ctx, rate, key, keylen, custom, custlen);
	qsc_kmac_update(ctx, rate, message, msglen);
	qsc_kmac_finalize(ctx, rate, output, outlen);
}

/**
* \brief Key a KMAC-512 instance and generate a MAC code.
* Short form api: processes the key and custom inputs and generates the MAC code with a single call.
* Key the MAC generator process a message and output the MAC code.
*
* \param output: The MAC code byte array
* \param outlen: The number of MAC code bytes to generate
* \param message: [const] The message input byte array
* \param msglen: The number of message bytes to process
* \param key: [const] The input key byte array
* \param keylen: The number of key bytes to process
* \param custom: [const] The customization string
* \param custlen: The byte length of the customization string
*/
pub fn qsc_kmac512_compute(output: &mut [u8], outlen: usize, message: &[u8], msglen: usize, key: &mut [u8], keylen: usize, custom: &mut [u8], custlen: usize) {
	let ctx = &mut QscKeccakState::default();

	let rate = QscKeccakRate::QscKeccakRate512 as usize;
	qsc_kmac_initialize(ctx, rate, key, keylen, custom, custlen);
	qsc_kmac_update(ctx, rate, message, msglen);
	qsc_kmac_finalize(ctx, rate, output, outlen);
}

/**
* \brief The KMAC finalize function.
* Long form api: must be used in conjunction with the initialize and blockupdate functions.
* Final processing and calculation of the MAC code.
*
* \warning The state must be initialized before calling.
*
* \param ctx: [struct] A reference to the Keccak state; must be initialized
* \param rate: The rate of absorption in bytes
* \param output: The output byte array
* \param outlen: The number of bytes to extract
*/
pub fn qsc_kmac_finalize(ctx: &mut QscKeccakState, rate: usize, output: &mut [u8], outlen: usize) {
	qsc_keccak_finalize(ctx, rate, output, outlen, QSC_KECCAK_KMAC_DOMAIN_ID as usize, QSC_KECCAK_PERMUTATION_ROUNDS);
}

/**
* \brief Initialize a KMAC instance.
* Long form api: must be used in conjunction with the blockupdate and finalize functions.
* Key the MAC generator and initialize the internal state.
*
* \param ctx: [struct] A reference to the keccak state; must be initialized
* \param rate: The rate of absorption in bytes
* \param key: [const] The input key byte array
* \param keylen: The number of key bytes to process
* \param custom: [const] The customization string
* \param custlen: The byte length of the customization string
*/
pub fn qsc_kmac_initialize(ctx: &mut QscKeccakState, rate: usize, key: &mut [u8], keylen: usize, custom: &mut [u8], custlen: usize) {
	let name: [u8; 4] = [ 0x4B, 0x4D, 0x41, 0x43 ];

	qsc_keccak_absorb_key_custom(ctx, rate, key, keylen, custom, custlen, &name, 4, QSC_KECCAK_PERMUTATION_ROUNDS);
}

/**
* \brief The KMAC message update function.
* Long form api: must be used in conjunction with the initialize and finalize functions.
*
* \warning The state must be initialized before calling.
*
* \param ctx: [struct] A reference to the Keccak state; must be initialized
* \param rate: The rate of absorption in bytes
* \param message: [const] The message input byte array
* \param msglen: The number of message bytes to process
*/
pub fn qsc_kmac_update(ctx: &mut QscKeccakState, rate: usize, message: &[u8], msglen: usize) {
	qsc_keccak_update(ctx, rate, message, msglen, QSC_KECCAK_PERMUTATION_ROUNDS);
}