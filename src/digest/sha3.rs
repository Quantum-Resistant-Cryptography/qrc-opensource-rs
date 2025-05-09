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

use crate::{common::common::QRC_SYSTEM_IS_LITTLE_ENDIAN, tools::intutils::{qrc_intutils_be16to8, qrc_intutils_be8to64, qrc_intutils_clear64, qrc_intutils_clear8, qrc_intutils_copy64, qrc_intutils_copy8, qrc_intutils_le64to8, qrc_intutils_le8to64, qrc_intutils_min, qrc_intutils_rotl64, qrc_intutils_transform_64to8, qrc_intutils_transform_8to64, qrc_intutils_xor}};

use core::{mem::size_of, default::Default};

/*
* \def QRC_KECCAK_CSHAKE_DOMAIN_ID
* \brief The cSHAKE domain id
*/
pub const QRC_KECCAK_CSHAKE_DOMAIN_ID: u8 = 0x04;

/*
* \def QRC_KECCAK_KMAC_DOMAIN_ID
* \brief The KMAC domain id
*/
pub const QRC_KECCAK_KMAC_DOMAIN_ID: u8 = 0x04;

/*
* \def QRC_KECCAK_KPA_DOMAIN_ID
* \brief The KPA domain id
*/
pub const QRC_KECCAK_KPA_DOMAIN_ID: u8 = 0x41;

/*
* \def QRC_KECCAK_PERMUTATION_ROUNDS
* \brief The standard number of permutation rounds
*/
pub const QRC_KECCAK_PERMUTATION_ROUNDS: usize = 24;

/*
* \def QRC_KECCAK_PERMUTATION_MAX_ROUNDS
* \brief The maximum number of permutation rounds
*/
pub const QRC_KECCAK_PERMUTATION_MAX_ROUNDS: usize = 48;

/*
* \def QRC_KECCAK_PERMUTATION_MIN_ROUNDS
* \brief The minimum number of permutation rounds
*/
pub const QRC_KECCAK_PERMUTATION_MIN_ROUNDS: usize = 12;

/*
* \def QRC_KECCAK_SHA3_DOMAIN_ID
* \brief The SHA3 domain id
*/
pub const QRC_KECCAK_SHA3_DOMAIN_ID: u8 = 0x06;

/*
* \def QRC_KECCAK_SHAKE_DOMAIN_ID
* \brief The SHAKE domain id
*/
pub const QRC_KECCAK_SHAKE_DOMAIN_ID: u8 = 0x1F;

/*
* \def QRC_KECCAK_128_RATE
* \brief The KMAC-128 byte absorption rate
*/
pub const QRC_KECCAK_128_RATE: usize = 168;

/*
* \def QRC_KECCAK_256_RATE
* \brief The KMAC-256 byte absorption rate
*/
pub const QRC_KECCAK_256_RATE: usize = 136;

/*
\def SHAKE_256_RATE
* The SHAKE-256 byte absorption rate
*/
pub const QRC_SHAKE_256_RATE: usize = 136;

/*
* \def QRC_KECCAK_512_RATE
* \brief The KMAC-512 byte absorption rate
*/
pub const QRC_KECCAK_512_RATE: usize = 72;

/*
* \def QRC_KECCAK_STATE_SIZE
* \brief The Keccak SHA3 uint64 state array size
*/
pub const QRC_KECCAK_STATE_SIZE: usize = 25;

/*
\def SHAKE_512_RATE
* The SHAKE-512 byte absorption rate
*/
pub const QRC_SHAKE_512_RATE: usize = 72;

/*
\def SHAKE_STATE_SIZE
* The Keccak SHAKE uint64 state array size
*/
pub const QRC_SHAKE_STATE_SIZE: usize = 25;

/*
* \def QRC_KECCAK_STATE_BYTE_SIZE
* \brief The Keccak SHA3 state size in bytes
*/
pub const QRC_KECCAK_STATE_BYTE_SIZE: usize = 200;

/*
* \def QRC_KMAC_256_KEY_SIZE
* \brief The KMAC-256 key size in bytes
*/
pub const QRC_KMAC_256_KEY_SIZE: usize = 32;

/*
* \def QRC_KMAC_512_KEY_SIZE
* \brief The KMAC-512 key size in bytes
*/
pub const QRC_KMAC_512_KEY_SIZE: usize = 64;

/*
* \def QRC_SHA3_128_HASH_SIZE
* \brief The QRC_SHA3_128_HASH_SIZE hash size in bytes (16)
*/
pub const QRC_SHA3_128_HASH_SIZE: usize = 16;

/*
* \def QRC_SHA3_256_HASH_SIZE
* \brief The SHA-256 hash size in bytes (32)
*/
pub const QRC_SHA3_256_HASH_SIZE: usize = 32;

/*
* \def QRC_SHA3_512_HASH_SIZE
* \brief The SHA-512 hash size in bytes (64)
*/
pub const QRC_SHA3_512_HASH_SIZE: usize = 64;

/*
* \def QRC_SHAKE_256_KEY_SIZE
* \brief The SHAKE-256 key size in bytes
*/
pub const QRC_SHAKE_256_KEY_SIZE: usize = 32;

/*
* \def QRC_SHAKE512_KEY_SIZE
* \brief The SHAKE-512 key size in bytes
*/
pub const QRC_SHAKE512_KEY_SIZE: usize = 64;

/* common */

/*
* \struct qrc_keccak_state
* \brief The Keccak state array; state array must be initialized by the caller
*/
#[derive(PartialEq, Clone)]
pub struct QrcKeccakState {
	pub state: [u64; QRC_KECCAK_STATE_SIZE],			/*< The SHA3 state  */
	pub buffer: [u8; QRC_KECCAK_STATE_BYTE_SIZE],		/*< The message buffer  */
	pub position: usize,								/*< The buffer position  */
}
impl Default for QrcKeccakState {
    fn default() -> Self {
        Self {
			state: [Default::default(); QRC_KECCAK_STATE_SIZE],
            buffer: [Default::default(); QRC_KECCAK_STATE_BYTE_SIZE],
			position: Default::default(),
        }
    }
}

/*
* \enum qrc_keccak_rate
* \brief The Keccak rate; determines which security strength is used by the function, 128, 256, or 512-bit
*/
#[derive(Clone, Copy, PartialEq)]
pub enum QrcKeccakRate {
	QrcKeccakRateNone = 0,						/*< No bit rate was selected  */
	QrcKeccakRate128 = QRC_KECCAK_128_RATE as isize,		/*< The Keccak 128-bit rate  */
	QrcKeccakRate256 = QRC_KECCAK_256_RATE as isize,		/*< The Keccak 256-bit rate  */
	QrcKeccakRate512 = QRC_KECCAK_512_RATE as isize,		/*< The Keccak 512-bit rate  */
}

/*
* \brief Absorb an input message into the Keccak state
*
* \param ctx: [struct] A reference to the Keccak state; must be initialized
* \param rate: The rate of absorption in bytes
* \param message: [const] The input message byte array
* \param msglen: The number of message bytes to process
* \param domain: The function domain id
* \param rounds: The number of permutation rounds, the default is 24, maximum is 48
*/
pub fn qrc_keccak_absorb(ctx: &mut QrcKeccakState, rate: usize, mut message: &[u8], mut msglen: usize, domain: u8, rounds: usize) {
	if !message.is_empty() {
		let msg = &mut [0u8; QRC_KECCAK_STATE_BYTE_SIZE];

		while msglen >= rate {
			if QRC_SYSTEM_IS_LITTLE_ENDIAN {
				let mut state_slice = qrc_intutils_transform_64to8(&mut ctx.state);
				qrc_intutils_xor(&mut state_slice, message, rate);
				qrc_intutils_copy64(&mut ctx.state, &qrc_intutils_transform_8to64(&state_slice), QRC_KECCAK_STATE_SIZE);
			} else {
				for i in 0..(rate/size_of::<u64>()) {
					ctx.state[i] ^= qrc_intutils_le8to64(&message[(size_of::<u64>() * i)..]);
				}
			}

			qrc_keccak_permute(ctx, rounds, false);
			msglen -= rate;
			message = &message[rate..];
		}

		qrc_intutils_copy8(msg, message, msglen);
		msg[msglen] = domain;
		qrc_intutils_clear8(&mut msg[(msglen + 1)..], 200-(msglen + 1));
		msg[rate - 1] |= 128;

		if QRC_SYSTEM_IS_LITTLE_ENDIAN {
			let mut state_slice = qrc_intutils_transform_64to8(&mut ctx.state);
			qrc_intutils_xor(&mut state_slice, msg, rate);
			qrc_intutils_copy64(&mut ctx.state, &qrc_intutils_transform_8to64(&state_slice), QRC_KECCAK_STATE_SIZE);
		} else {
			for i in 0..(rate/8) {
				ctx.state[i] ^= qrc_intutils_le8to64(&msg[(8 * i)..]);
			}
		}
	}
}

/*
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
pub fn qrc_keccak_absorb_custom(ctx: &mut QrcKeccakState, rate: usize, custom: &[u8], custlen: usize, name: &[u8], namelen: usize, rounds: usize) {
	let pad = &mut [0u8; QRC_KECCAK_STATE_BYTE_SIZE];

	let mut oft: usize = keccak_left_encode(pad, rate);
	oft += keccak_left_encode(&mut pad[oft..], namelen * 8);

	if !name.is_empty() {
		for i in 0..namelen {
			if oft == rate {
				keccak_fast_absorb(&mut ctx.state, pad, rate);
				qrc_keccak_permute(ctx, rounds, false);
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
				qrc_keccak_permute(ctx, rounds, false);
				oft = 0;
			}

			pad[oft] = custom[i];
			oft = oft + 1;
		}
	}

	qrc_intutils_clear8(&mut pad[oft..], 200-oft);
	keccak_fast_absorb(&mut ctx.state, pad, rate);
	qrc_keccak_permute(ctx, rounds, false);
}

/*
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
pub fn qrc_keccak_absorb_key_custom(ctx: &mut QrcKeccakState, rate: usize, key: &[u8], keylen: usize, custom: &[u8], custlen: usize, name: &[u8], namelen: usize, rounds: usize) {
	let pad = &mut [0u8; QRC_KECCAK_STATE_BYTE_SIZE];

	qrc_intutils_clear64(&mut ctx.state, QRC_KECCAK_STATE_SIZE);
	qrc_intutils_clear8(&mut ctx.buffer, QRC_KECCAK_STATE_BYTE_SIZE);
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
				qrc_keccak_permute(ctx, rounds, false);
				oft = 0;
			}

			pad[oft] = custom[i];
			oft = oft + 1;
		}
	}

	qrc_intutils_clear8(&mut pad[oft..], 200-oft);
	keccak_fast_absorb(&mut ctx.state, pad, rate);
	qrc_keccak_permute(ctx, rounds, false);


	/* stage 2: key */

	qrc_intutils_clear8(pad, 200);

	oft = keccak_left_encode(pad, rate);
	oft += keccak_left_encode(&mut pad[oft..], keylen * 8);

	if !key.is_empty() {
		for i in 0..keylen {
			if oft == rate {
				keccak_fast_absorb(&mut ctx.state, pad, rate);
				qrc_keccak_permute(ctx, rounds, false);
				oft = 0;
			}

			pad[oft] = key[i];
			oft = oft + 1;
		}
	}

	qrc_intutils_clear8(&mut pad[oft..], 200-oft);
	keccak_fast_absorb(&mut ctx.state, pad, rate);
	qrc_keccak_permute(ctx, rounds, false);
}

/*
* \brief Dispose of the Keccak state.
*
* \warning The dispose function must be called when disposing of the function state.
* This function safely destroys the internal state.
*
* \param ctx: [struct] The Keccak state structure
*/
pub fn qrc_keccak_dispose(ctx: &mut QrcKeccakState) {
	qrc_intutils_clear64(&mut ctx.state, QRC_KECCAK_STATE_SIZE);
	qrc_intutils_clear8(&mut ctx.buffer, QRC_KECCAK_STATE_BYTE_SIZE);
	ctx.position = 0;
}

/*
* \brief Finalize the Keccak state
*
* \param ctx: [struct] The Keccak state structure
* \param rate: The rate of absorption in bytes
* \param output: The output byte array
* \param outlen: The number of output bytes to generate
* \param domain: The function domain id
* \param rounds: The number of permutation rounds, the default is 24, maximum is 48
*/
pub fn qrc_keccak_finalize(ctx: &mut QrcKeccakState, rate: usize, mut output: &mut [u8], mut outlen: usize, domain: usize, rounds: usize) {

	let buf = &mut [0u8; size_of::<usize>() + 1];
	let pad = &mut [0u8; QRC_KECCAK_STATE_BYTE_SIZE];

	qrc_intutils_copy8(pad, &ctx.buffer, ctx.position);
	let bitlen = keccak_right_encode(buf, outlen * 8);

	if ctx.position + bitlen >= rate {
		keccak_fast_absorb(&mut ctx.state, pad, ctx.position);
		qrc_keccak_permute(ctx, rounds, false);
		ctx.position = 0;
	}

	qrc_intutils_copy8(&mut pad[ctx.position..], buf, bitlen);

	pad[ctx.position + bitlen] = domain as u8;
	pad[rate - 1] |= 128;
	keccak_fast_absorb(&mut ctx.state, pad, rate);

	while outlen >= rate {
		qrc_keccak_squeezeblocks(ctx, pad, 1, rate, rounds);
		qrc_intutils_copy8(output, pad, rate);
		output = &mut output[rate..];
		outlen -= rate;
	}

	if outlen > 0 {
		qrc_keccak_squeezeblocks(ctx, pad, 1, rate, rounds);
		qrc_intutils_copy8(output, pad, outlen);
	}
	qrc_intutils_clear8(&mut ctx.buffer, QRC_KECCAK_STATE_BYTE_SIZE);
	ctx.position = 0;
}

/*
* \brief Absorb bytes into state incrementally
*
* \param ctx: The function state
* \param rate: The rate of absorption in bytes
* \param message: [const] The input message array
* \param msglen: The number of message bytes
*/
pub fn qrc_keccak_incremental_absorb(ctx: &mut QrcKeccakState, rate: usize, mut message: &[u8], mut msglen: usize) {
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

		ctx.state[(ctx.position - i) / 8] ^= qrc_intutils_le8to64(t);
	}

	if ctx.position >= rate - ctx.position && msglen >= rate - ctx.position {
		for i in 0..((rate - ctx.position) / 8) {
			ctx.state[(ctx.position / 8) + i] ^= qrc_intutils_le8to64(&message[(8 * i)..]);
		}

		message = &message[(rate - ctx.position)..];
		msglen -= rate - ctx.position;
		ctx.position = 0;
		qrc_keccak_permute_p1600c(&mut ctx.state, QRC_KECCAK_PERMUTATION_ROUNDS);
	}

	while msglen >= rate {
		for i in 0..(rate / 8) {
			ctx.state[i as usize] ^= qrc_intutils_le8to64(&message[(8 * i as usize)..]);
		}

		message = &message[rate..];
		msglen -= rate;
		qrc_keccak_permute_p1600c(&mut ctx.state, QRC_KECCAK_PERMUTATION_ROUNDS);
	}

	let mut i = 0;
	while i < msglen / 8 {
		ctx.state[(ctx.position / 8) + i] ^= qrc_intutils_le8to64(&message[(8 * i)..]);
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

		ctx.state[ctx.position / 8] ^= qrc_intutils_le8to64(t);
		ctx.position = ctx.position + msglen;
	}
}
pub fn qrc_keccak_incremental_block_absorb(ctx: &mut QrcKeccakState, rate: usize, mut message: &[u8], mut msglen: usize) {
    /* Recall that ok is the non-absorbed bytes xored into the state */
    while msglen + ctx.position >= rate {
        for i in 0..rate - ctx.position {
            /* Take the i'th byte from message
            xor with the ok + i'th byte of the state; little-endian */
            ctx.state[ctx.position + i >> 3] ^= (message[i] as u64) << (8 * ((ctx.position + i) & 0x07));
        }
        msglen -= rate - ctx.position;
        message = &message[rate - ctx.position..];
        ctx.position = 0;

        qrc_keccak_permute_p1600c(&mut ctx.state, QRC_KECCAK_PERMUTATION_ROUNDS);
    }
    for i in 0..msglen {
        ctx.state[(ctx.position + i) as usize >> 3] ^= (message[i] as u64) << (8 * ((ctx.position + i) & 0x07)) as u64;
    }
    ctx.position += msglen;
}

/*
* \brief Finalize state added incrementally
*
* \param ctx: The function state
* \param rate: The rate of absorption in bytes
* \param domain: The function domain id
*/
pub fn qrc_keccak_incremental_finalize(ctx: &mut QrcKeccakState, rate: usize, domain: u8) {
    let i = ctx.position >> 3;
    let j = ctx.position & 7;
    ctx.state[i] ^= (domain as u64) << (8 * j);
    ctx.state[(rate / 8) - 1] ^= 1 << 63;
    ctx.position = 0;
}

/*
* \brief Extract an array of bytes from the Keccak state
*
* \param ctx: The function state
* \param output: The output byte array
* \param outlen: The number of output bytes to generate
* \param rate: The rate of absorption in bytes
*/
pub fn qrc_keccak_incremental_squeeze(ctx: &mut QrcKeccakState, rate: usize, mut output: &mut [u8], mut outlen: usize) {
	let mut i: usize;
	let t = &mut [0u8; 8];

	if (ctx.position & 7) > 0 {
		qrc_intutils_le64to8(t, ctx.state[ctx.position / 8]);
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
			qrc_intutils_le64to8(&mut output[(8 * i)..], ctx.state[(ctx.position / 8) + i]);
		}

		output = &mut output[(rate - ctx.position)..];
		outlen -= rate - ctx.position;
		ctx.position = 0;
	}

	while outlen >= rate {
		qrc_keccak_permute_p1600c(&mut ctx.state, QRC_KECCAK_PERMUTATION_ROUNDS);

		for i in 0..rate / 8 {
			qrc_intutils_le64to8(&mut output[(8 * i)..], ctx.state[i]);
		}

		output = &mut output[rate..];
		outlen -= rate;
	}

	if outlen > 0 {
		if ctx.position == 0 {
			qrc_keccak_permute_p1600c(&mut ctx.state, QRC_KECCAK_PERMUTATION_ROUNDS);
		}

		let mut i = 0;
		while i < outlen / 8 {
			qrc_intutils_le64to8(&mut output[(8 * i)..], ctx.state[(ctx.position / 8) + i]);
			i += 1;
		}

		output = &mut output[(8 * i)..];
		outlen -= 8 * i;
		ctx.position += 8 * i;

		qrc_intutils_le64to8(t, ctx.state[ctx.position / 8]);

		for i in 0..outlen {
			output[i] = t[i];
		}

		ctx.position += outlen;
	}
}
pub fn qrc_keccak_incremental_block_squeeze(ctx: &mut QrcKeccakState, rate: usize, mut output: &mut [u8], mut outlen: usize) {
    let mut i = 0;
    /* First consume any bytes we still have sitting around */
    for _ in 0..qrc_intutils_min(outlen, ctx.position as usize) {
        /* There are ctx.position bytes left, so r - ctx.position is the first
        available byte. We consume from there, i.e., up to r. */
        output[i] = (ctx.state[(rate - ctx.position + i ) >> 3] >> (8 * ((rate - ctx.position + i) & 0x07))) as u8;
        i += 1;
    }
    output = &mut output[i..];
    outlen -= i;
    ctx.position -= i;

    /* Then squeeze the remaining necessary blocks */
    while outlen > 0 {
        qrc_keccak_permute_p1600c(&mut ctx.state, QRC_KECCAK_PERMUTATION_ROUNDS);
        
        let mut i = 0;
        for _ in 0..qrc_intutils_min(outlen, rate as usize) {
            output[i] = (ctx.state[i >> 3] >> (8 * (i & 0x07))) as u8;
            i += 1;
        }
        output = &mut output[i..];
        outlen -= i;
        ctx.position = rate - i;
    }
}

/*
* \brief The Keccak permute function.
* Internal function: Permutes the state array, can be used in external constructions.
*
* \param ctx: [struct] The function state; must be initialized
* \param rounds: The number of permutation rounds, the default and maximum is 24
*/
pub fn qrc_keccak_permute(ctx: &mut QrcKeccakState, rounds: usize, qrc_keccak_unrolled_permutation: bool) {
	if qrc_keccak_unrolled_permutation {
		qrc_keccak_permute_p1600u(&mut ctx.state)
	} else {
		qrc_keccak_permute_p1600c(&mut ctx.state, rounds);
	}
}

/*
* \brief The compact Keccak permute function.
* Internal function: Permutes the state array, can be used in external constructions.
*
* \param state: The state array; must be initialized
* \param rounds: The number of permutation rounds, the default and maximum is 24
*/
pub fn qrc_keccak_permute_p1600c(state: &mut [u64], rounds: usize) {
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
		let mut da = bcu ^ qrc_intutils_rotl64(bce, 1);
		let mut de = bca ^ qrc_intutils_rotl64(bci, 1);
		let mut di = bce ^ qrc_intutils_rotl64(bco, 1);
		let mut dz = bci ^ qrc_intutils_rotl64(bcu, 1);
		let mut du = bco ^ qrc_intutils_rotl64(bca, 1);

		aba ^= da;
		bca = aba;
		age ^= de;
		bce = qrc_intutils_rotl64(age, 44);
		aki ^= di;
		bci = qrc_intutils_rotl64(aki, 43);
		amo ^= dz;
		bco = qrc_intutils_rotl64(amo, 21);
		asu ^= du;
		bcu = qrc_intutils_rotl64(asu, 14);
		let mut eba = bca ^ ((!bce) & bci);
		eba ^= KECCAK_ROUND_CONSTANTS[i];
		let mut ebe = bce ^ ((!bci) & bco);
		let mut ebi = bci ^ ((!bco) & bcu);
		let mut ebo = bco ^ ((!bcu) & bca);
		let mut ebu = bcu ^ ((!bca) & bce);

		abo ^= dz;
		bca = qrc_intutils_rotl64(abo, 28);
		agu ^= du;
		bce = qrc_intutils_rotl64(agu, 20);
		aka ^= da;
		bci = qrc_intutils_rotl64(aka, 3);
		ame ^= de;
		bco = qrc_intutils_rotl64(ame, 45);
		asi ^= di;
		bcu = qrc_intutils_rotl64(asi, 61);
		let mut ega = bca ^ ((!bce) & bci);
		let mut ege = bce ^ ((!bci) & bco);
		let mut egi = bci ^ ((!bco) & bcu);
		let mut ego = bco ^ ((!bcu) & bca);
		let mut egu = bcu ^ ((!bca) & bce);

		abe ^= de;
		bca = qrc_intutils_rotl64(abe, 1);
		agi ^= di;
		bce = qrc_intutils_rotl64(agi, 6);
		ako ^= dz;
		bci = qrc_intutils_rotl64(ako, 25);
		amu ^= du;
		bco = qrc_intutils_rotl64(amu, 8);
		asa ^= da;
		bcu = qrc_intutils_rotl64(asa, 18);
		let mut eka = bca ^ ((!bce) & bci);
		let mut eke = bce ^ ((!bci) & bco);
		let mut eki = bci ^ ((!bco) & bcu);
		let mut eko = bco ^ ((!bcu) & bca);
		let mut eku = bcu ^ ((!bca) & bce);

		abu ^= du;
		bca = qrc_intutils_rotl64(abu, 27);
		aga ^= da;
		bce = qrc_intutils_rotl64(aga, 36);
		ake ^= de;
		bci = qrc_intutils_rotl64(ake, 10);
		ami ^= di;
		bco = qrc_intutils_rotl64(ami, 15);
		aso ^= dz;
		bcu = qrc_intutils_rotl64(aso, 56);
		let mut ema = bca ^ ((!bce) & bci);
		let mut eme = bce ^ ((!bci) & bco);
		let mut emi = bci ^ ((!bco) & bcu);
		let mut emo = bco ^ ((!bcu) & bca);
		let mut emu = bcu ^ ((!bca) & bce);

		abi ^= di;
		bca = qrc_intutils_rotl64(abi, 62);
		ago ^= dz;
		bce = qrc_intutils_rotl64(ago, 55);
		aku ^= du;
		bci = qrc_intutils_rotl64(aku, 39);
		ama ^= da;
		bco = qrc_intutils_rotl64(ama, 41);
		ase ^= de;
		bcu = qrc_intutils_rotl64(ase, 2);
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
		da = bcu ^ qrc_intutils_rotl64(bce, 1);
		de = bca ^ qrc_intutils_rotl64(bci, 1);
		di = bce ^ qrc_intutils_rotl64(bco, 1);
		dz = bci ^ qrc_intutils_rotl64(bcu, 1);
		du = bco ^ qrc_intutils_rotl64(bca, 1);

		eba ^= da;
		bca = eba;
		ege ^= de;
		bce = qrc_intutils_rotl64(ege, 44);
		eki ^= di;
		bci = qrc_intutils_rotl64(eki, 43);
		emo ^= dz;
		bco = qrc_intutils_rotl64(emo, 21);
		esu ^= du;
		bcu = qrc_intutils_rotl64(esu, 14);
		aba = bca ^ ((!bce) & bci);
		aba ^= KECCAK_ROUND_CONSTANTS[i + 1];
		abe = bce ^ ((!bci) & bco);
		abi = bci ^ ((!bco) & bcu);
		abo = bco ^ ((!bcu) & bca);
		abu = bcu ^ ((!bca) & bce);

		ebo ^= dz;
		bca = qrc_intutils_rotl64(ebo, 28);
		egu ^= du;
		bce = qrc_intutils_rotl64(egu, 20);
		eka ^= da;
		bci = qrc_intutils_rotl64(eka, 3);
		eme ^= de;
		bco = qrc_intutils_rotl64(eme, 45);
		esi ^= di;
		bcu = qrc_intutils_rotl64(esi, 61);
		aga = bca ^ ((!bce) & bci);
		age = bce ^ ((!bci) & bco);
		agi = bci ^ ((!bco) & bcu);
		ago = bco ^ ((!bcu) & bca);
		agu = bcu ^ ((!bca) & bce);

		ebe ^= de;
		bca = qrc_intutils_rotl64(ebe, 1);
		egi ^= di;
		bce = qrc_intutils_rotl64(egi, 6);
		eko ^= dz;
		bci = qrc_intutils_rotl64(eko, 25);
		emu ^= du;
		bco = qrc_intutils_rotl64(emu, 8);
		esa ^= da;
		bcu = qrc_intutils_rotl64(esa, 18);
		aka = bca ^ ((!bce) & bci);
		ake = bce ^ ((!bci) & bco);
		aki = bci ^ ((!bco) & bcu);
		ako = bco ^ ((!bcu) & bca);
		aku = bcu ^ ((!bca) & bce);

		ebu ^= du;
		bca = qrc_intutils_rotl64(ebu, 27);
		ega ^= da;
		bce = qrc_intutils_rotl64(ega, 36);
		eke ^= de;
		bci = qrc_intutils_rotl64(eke, 10);
		emi ^= di;
		bco = qrc_intutils_rotl64(emi, 15);
		eso ^= dz;
		bcu = qrc_intutils_rotl64(eso, 56);
		ama = bca ^ ((!bce) & bci);
		ame = bce ^ ((!bci) & bco);
		ami = bci ^ ((!bco) & bcu);
		amo = bco ^ ((!bcu) & bca);
		amu = bcu ^ ((!bca) & bce);

		ebi ^= di;
		bca = qrc_intutils_rotl64(ebi, 62);
		ego ^= dz;
		bce = qrc_intutils_rotl64(ego, 55);
		eku ^= du;
		bci = qrc_intutils_rotl64(eku, 39);
		ema ^= da;
		bco = qrc_intutils_rotl64(ema, 41);
		ese ^= de;
		bcu = qrc_intutils_rotl64(ese, 2);
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


/*
* \brief The unrolled Keccak permute function.
* Internal function: Permutes the state array, can be used in external constructions.
*
* \param state: The state array; must be initialized
*/
pub fn qrc_keccak_permute_p1600u(state: &mut [u64]) {
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
	let mut da = cu ^ qrc_intutils_rotl64(ce, 1);
	let mut de = ca ^ qrc_intutils_rotl64(ci, 1);
	let mut di = ce ^ qrc_intutils_rotl64(co, 1);
	let mut dz = ci ^ qrc_intutils_rotl64(cu, 1);
	let mut du = co ^ qrc_intutils_rotl64(ca, 1);
	aba ^= da;
	ca = aba;
	age ^= de;
	ce = qrc_intutils_rotl64(age, 44);
	aki ^= di;
	ci = qrc_intutils_rotl64(aki, 43);
	amo ^= dz;
	co = qrc_intutils_rotl64(amo, 21);
	asu ^= du;
	cu = qrc_intutils_rotl64(asu, 14);
	let mut eba = ca ^ ((!ce) & ci);
	eba ^= 0x0000000000000001;
	let mut ebe = ce ^ ((!ci) & co);
	let mut ebi = ci ^ ((!co) & cu);
	let mut ebo = co ^ ((!cu) & ca);
	let mut ebu = cu ^ ((!ca) & ce);
	abo ^= dz;
	ca = qrc_intutils_rotl64(abo, 28);
	agu ^= du;
	ce = qrc_intutils_rotl64(agu, 20);
	aka ^= da;
	ci = qrc_intutils_rotl64(aka, 3);
	ame ^= de;
	co = qrc_intutils_rotl64(ame, 45);
	asi ^= di;
	cu = qrc_intutils_rotl64(asi, 61);
	let mut ega = ca ^ ((!ce) & ci);
	let mut ege = ce ^ ((!ci) & co);
	let mut egi = ci ^ ((!co) & cu);
	let mut ego = co ^ ((!cu) & ca);
	let mut egu = cu ^ ((!ca) & ce);
	abe ^= de;
	ca = qrc_intutils_rotl64(abe, 1);
	agi ^= di;
	ce = qrc_intutils_rotl64(agi, 6);
	ako ^= dz;
	ci = qrc_intutils_rotl64(ako, 25);
	amu ^= du;
	co = qrc_intutils_rotl64(amu, 8);
	asa ^= da;
	cu = qrc_intutils_rotl64(asa, 18);
	let mut eka = ca ^ ((!ce) & ci);
	let mut eke = ce ^ ((!ci) & co);
	let mut eki = ci ^ ((!co) & cu);
	let mut eko = co ^ ((!cu) & ca);
	let mut eku = cu ^ ((!ca) & ce);
	abu ^= du;
	ca = qrc_intutils_rotl64(abu, 27);
	aga ^= da;
	ce = qrc_intutils_rotl64(aga, 36);
	ake ^= de;
	ci = qrc_intutils_rotl64(ake, 10);
	ami ^= di;
	co = qrc_intutils_rotl64(ami, 15);
	aso ^= dz;
	cu = qrc_intutils_rotl64(aso, 56);
	let mut ema = ca ^ ((!ce) & ci);
	let mut eme = ce ^ ((!ci) & co);
	let mut emi = ci ^ ((!co) & cu);
	let mut emo = co ^ ((!cu) & ca);
	let mut emu = cu ^ ((!ca) & ce);
	abi ^= di;
	ca = qrc_intutils_rotl64(abi, 62);
	ago ^= dz;
	ce = qrc_intutils_rotl64(ago, 55);
	aku ^= du;
	ci = qrc_intutils_rotl64(aku, 39);
	ama ^= da;
	co = qrc_intutils_rotl64(ama, 41);
	ase ^= de;
	cu = qrc_intutils_rotl64(ase, 2);
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
	da = cu ^ qrc_intutils_rotl64(ce, 1);
	de = ca ^ qrc_intutils_rotl64(ci, 1);
	di = ce ^ qrc_intutils_rotl64(co, 1);
	dz = ci ^ qrc_intutils_rotl64(cu, 1);
	du = co ^ qrc_intutils_rotl64(ca, 1);
	eba ^= da;
	ca = eba;
	ege ^= de;
	ce = qrc_intutils_rotl64(ege, 44);
	eki ^= di;
	ci = qrc_intutils_rotl64(eki, 43);
	emo ^= dz;
	co = qrc_intutils_rotl64(emo, 21);
	esu ^= du;
	cu = qrc_intutils_rotl64(esu, 14);
	aba = ca ^ ((!ce) & ci);
	aba ^= 0x0000000000008082;
	abe = ce ^ ((!ci) & co);
	abi = ci ^ ((!co) & cu);
	abo = co ^ ((!cu) & ca);
	abu = cu ^ ((!ca) & ce);
	ebo ^= dz;
	ca = qrc_intutils_rotl64(ebo, 28);
	egu ^= du;
	ce = qrc_intutils_rotl64(egu, 20);
	eka ^= da;
	ci = qrc_intutils_rotl64(eka, 3);
	eme ^= de;
	co = qrc_intutils_rotl64(eme, 45);
	esi ^= di;
	cu = qrc_intutils_rotl64(esi, 61);
	aga = ca ^ ((!ce) & ci);
	age = ce ^ ((!ci) & co);
	agi = ci ^ ((!co) & cu);
	ago = co ^ ((!cu) & ca);
	agu = cu ^ ((!ca) & ce);
	ebe ^= de;
	ca = qrc_intutils_rotl64(ebe, 1);
	egi ^= di;
	ce = qrc_intutils_rotl64(egi, 6);
	eko ^= dz;
	ci = qrc_intutils_rotl64(eko, 25);
	emu ^= du;
	co = qrc_intutils_rotl64(emu, 8);
	esa ^= da;
	cu = qrc_intutils_rotl64(esa, 18);
	aka = ca ^ ((!ce) & ci);
	ake = ce ^ ((!ci) & co);
	aki = ci ^ ((!co) & cu);
	ako = co ^ ((!cu) & ca);
	aku = cu ^ ((!ca) & ce);
	ebu ^= du;
	ca = qrc_intutils_rotl64(ebu, 27);
	ega ^= da;
	ce = qrc_intutils_rotl64(ega, 36);
	eke ^= de;
	ci = qrc_intutils_rotl64(eke, 10);
	emi ^= di;
	co = qrc_intutils_rotl64(emi, 15);
	eso ^= dz;
	cu = qrc_intutils_rotl64(eso, 56);
	ama = ca ^ ((!ce) & ci);
	ame = ce ^ ((!ci) & co);
	ami = ci ^ ((!co) & cu);
	amo = co ^ ((!cu) & ca);
	amu = cu ^ ((!ca) & ce);
	ebi ^= di;
	ca = qrc_intutils_rotl64(ebi, 62);
	ego ^= dz;
	ce = qrc_intutils_rotl64(ego, 55);
	eku ^= du;
	ci = qrc_intutils_rotl64(eku, 39);
	ema ^= da;
	co = qrc_intutils_rotl64(ema, 41);
	ese ^= de;
	cu = qrc_intutils_rotl64(ese, 2);
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
	da = cu ^ qrc_intutils_rotl64(ce, 1);
	de = ca ^ qrc_intutils_rotl64(ci, 1);
	di = ce ^ qrc_intutils_rotl64(co, 1);
	dz = ci ^ qrc_intutils_rotl64(cu, 1);
	du = co ^ qrc_intutils_rotl64(ca, 1);
	aba ^= da;
	ca = aba;
	age ^= de;
	ce = qrc_intutils_rotl64(age, 44);
	aki ^= di;
	ci = qrc_intutils_rotl64(aki, 43);
	amo ^= dz;
	co = qrc_intutils_rotl64(amo, 21);
	asu ^= du;
	cu = qrc_intutils_rotl64(asu, 14);
	eba = ca ^ ((!ce) & ci);
	eba ^= 0x800000000000808A;
	ebe = ce ^ ((!ci) & co);
	ebi = ci ^ ((!co) & cu);
	ebo = co ^ ((!cu) & ca);
	ebu = cu ^ ((!ca) & ce);
	abo ^= dz;
	ca = qrc_intutils_rotl64(abo, 28);
	agu ^= du;
	ce = qrc_intutils_rotl64(agu, 20);
	aka ^= da;
	ci = qrc_intutils_rotl64(aka, 3);
	ame ^= de;
	co = qrc_intutils_rotl64(ame, 45);
	asi ^= di;
	cu = qrc_intutils_rotl64(asi, 61);
	ega = ca ^ ((!ce) & ci);
	ege = ce ^ ((!ci) & co);
	egi = ci ^ ((!co) & cu);
	ego = co ^ ((!cu) & ca);
	egu = cu ^ ((!ca) & ce);
	abe ^= de;
	ca = qrc_intutils_rotl64(abe, 1);
	agi ^= di;
	ce = qrc_intutils_rotl64(agi, 6);
	ako ^= dz;
	ci = qrc_intutils_rotl64(ako, 25);
	amu ^= du;
	co = qrc_intutils_rotl64(amu, 8);
	asa ^= da;
	cu = qrc_intutils_rotl64(asa, 18);
	eka = ca ^ ((!ce) & ci);
	eke = ce ^ ((!ci) & co);
	eki = ci ^ ((!co) & cu);
	eko = co ^ ((!cu) & ca);
	eku = cu ^ ((!ca) & ce);
	abu ^= du;
	ca = qrc_intutils_rotl64(abu, 27);
	aga ^= da;
	ce = qrc_intutils_rotl64(aga, 36);
	ake ^= de;
	ci = qrc_intutils_rotl64(ake, 10);
	ami ^= di;
	co = qrc_intutils_rotl64(ami, 15);
	aso ^= dz;
	cu = qrc_intutils_rotl64(aso, 56);
	ema = ca ^ ((!ce) & ci);
	eme = ce ^ ((!ci) & co);
	emi = ci ^ ((!co) & cu);
	emo = co ^ ((!cu) & ca);
	emu = cu ^ ((!ca) & ce);
	abi ^= di;
	ca = qrc_intutils_rotl64(abi, 62);
	ago ^= dz;
	ce = qrc_intutils_rotl64(ago, 55);
	aku ^= du;
	ci = qrc_intutils_rotl64(aku, 39);
	ama ^= da;
	co = qrc_intutils_rotl64(ama, 41);
	ase ^= de;
	cu = qrc_intutils_rotl64(ase, 2);
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
	da = cu ^ qrc_intutils_rotl64(ce, 1);
	de = ca ^ qrc_intutils_rotl64(ci, 1);
	di = ce ^ qrc_intutils_rotl64(co, 1);
	dz = ci ^ qrc_intutils_rotl64(cu, 1);
	du = co ^ qrc_intutils_rotl64(ca, 1);
	eba ^= da;
	ca = eba;
	ege ^= de;
	ce = qrc_intutils_rotl64(ege, 44);
	eki ^= di;
	ci = qrc_intutils_rotl64(eki, 43);
	emo ^= dz;
	co = qrc_intutils_rotl64(emo, 21);
	esu ^= du;
	cu = qrc_intutils_rotl64(esu, 14);
	aba = ca ^ ((!ce) & ci);
	aba ^= 0x8000000080008000;
	abe = ce ^ ((!ci) & co);
	abi = ci ^ ((!co) & cu);
	abo = co ^ ((!cu) & ca);
	abu = cu ^ ((!ca) & ce);
	ebo ^= dz;
	ca = qrc_intutils_rotl64(ebo, 28);
	egu ^= du;
	ce = qrc_intutils_rotl64(egu, 20);
	eka ^= da;
	ci = qrc_intutils_rotl64(eka, 3);
	eme ^= de;
	co = qrc_intutils_rotl64(eme, 45);
	esi ^= di;
	cu = qrc_intutils_rotl64(esi, 61);
	aga = ca ^ ((!ce) & ci);
	age = ce ^ ((!ci) & co);
	agi = ci ^ ((!co) & cu);
	ago = co ^ ((!cu) & ca);
	agu = cu ^ ((!ca) & ce);
	ebe ^= de;
	ca = qrc_intutils_rotl64(ebe, 1);
	egi ^= di;
	ce = qrc_intutils_rotl64(egi, 6);
	eko ^= dz;
	ci = qrc_intutils_rotl64(eko, 25);
	emu ^= du;
	co = qrc_intutils_rotl64(emu, 8);
	esa ^= da;
	cu = qrc_intutils_rotl64(esa, 18);
	aka = ca ^ ((!ce) & ci);
	ake = ce ^ ((!ci) & co);
	aki = ci ^ ((!co) & cu);
	ako = co ^ ((!cu) & ca);
	aku = cu ^ ((!ca) & ce);
	ebu ^= du;
	ca = qrc_intutils_rotl64(ebu, 27);
	ega ^= da;
	ce = qrc_intutils_rotl64(ega, 36);
	eke ^= de;
	ci = qrc_intutils_rotl64(eke, 10);
	emi ^= di;
	co = qrc_intutils_rotl64(emi, 15);
	eso ^= dz;
	cu = qrc_intutils_rotl64(eso, 56);
	ama = ca ^ ((!ce) & ci);
	ame = ce ^ ((!ci) & co);
	ami = ci ^ ((!co) & cu);
	amo = co ^ ((!cu) & ca);
	amu = cu ^ ((!ca) & ce);
	ebi ^= di;
	ca = qrc_intutils_rotl64(ebi, 62);
	ego ^= dz;
	ce = qrc_intutils_rotl64(ego, 55);
	eku ^= du;
	ci = qrc_intutils_rotl64(eku, 39);
	ema ^= da;
	co = qrc_intutils_rotl64(ema, 41);
	ese ^= de;
	cu = qrc_intutils_rotl64(ese, 2);
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
	da = cu ^ qrc_intutils_rotl64(ce, 1);
	de = ca ^ qrc_intutils_rotl64(ci, 1);
	di = ce ^ qrc_intutils_rotl64(co, 1);
	dz = ci ^ qrc_intutils_rotl64(cu, 1);
	du = co ^ qrc_intutils_rotl64(ca, 1);
	aba ^= da;
	ca = aba;
	age ^= de;
	ce = qrc_intutils_rotl64(age, 44);
	aki ^= di;
	ci = qrc_intutils_rotl64(aki, 43);
	amo ^= dz;
	co = qrc_intutils_rotl64(amo, 21);
	asu ^= du;
	cu = qrc_intutils_rotl64(asu, 14);
	eba = ca ^ ((!ce) & ci);
	eba ^= 0x000000000000808B;
	ebe = ce ^ ((!ci) & co);
	ebi = ci ^ ((!co) & cu);
	ebo = co ^ ((!cu) & ca);
	ebu = cu ^ ((!ca) & ce);
	abo ^= dz;
	ca = qrc_intutils_rotl64(abo, 28);
	agu ^= du;
	ce = qrc_intutils_rotl64(agu, 20);
	aka ^= da;
	ci = qrc_intutils_rotl64(aka, 3);
	ame ^= de;
	co = qrc_intutils_rotl64(ame, 45);
	asi ^= di;
	cu = qrc_intutils_rotl64(asi, 61);
	ega = ca ^ ((!ce) & ci);
	ege = ce ^ ((!ci) & co);
	egi = ci ^ ((!co) & cu);
	ego = co ^ ((!cu) & ca);
	egu = cu ^ ((!ca) & ce);
	abe ^= de;
	ca = qrc_intutils_rotl64(abe, 1);
	agi ^= di;
	ce = qrc_intutils_rotl64(agi, 6);
	ako ^= dz;
	ci = qrc_intutils_rotl64(ako, 25);
	amu ^= du;
	co = qrc_intutils_rotl64(amu, 8);
	asa ^= da;
	cu = qrc_intutils_rotl64(asa, 18);
	eka = ca ^ ((!ce) & ci);
	eke = ce ^ ((!ci) & co);
	eki = ci ^ ((!co) & cu);
	eko = co ^ ((!cu) & ca);
	eku = cu ^ ((!ca) & ce);
	abu ^= du;
	ca = qrc_intutils_rotl64(abu, 27);
	aga ^= da;
	ce = qrc_intutils_rotl64(aga, 36);
	ake ^= de;
	ci = qrc_intutils_rotl64(ake, 10);
	ami ^= di;
	co = qrc_intutils_rotl64(ami, 15);
	aso ^= dz;
	cu = qrc_intutils_rotl64(aso, 56);
	ema = ca ^ ((!ce) & ci);
	eme = ce ^ ((!ci) & co);
	emi = ci ^ ((!co) & cu);
	emo = co ^ ((!cu) & ca);
	emu = cu ^ ((!ca) & ce);
	abi ^= di;
	ca = qrc_intutils_rotl64(abi, 62);
	ago ^= dz;
	ce = qrc_intutils_rotl64(ago, 55);
	aku ^= du;
	ci = qrc_intutils_rotl64(aku, 39);
	ama ^= da;
	co = qrc_intutils_rotl64(ama, 41);
	ase ^= de;
	cu = qrc_intutils_rotl64(ase, 2);
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
	da = cu ^ qrc_intutils_rotl64(ce, 1);
	de = ca ^ qrc_intutils_rotl64(ci, 1);
	di = ce ^ qrc_intutils_rotl64(co, 1);
	dz = ci ^ qrc_intutils_rotl64(cu, 1);
	du = co ^ qrc_intutils_rotl64(ca, 1);
	eba ^= da;
	ca = eba;
	ege ^= de;
	ce = qrc_intutils_rotl64(ege, 44);
	eki ^= di;
	ci = qrc_intutils_rotl64(eki, 43);
	emo ^= dz;
	co = qrc_intutils_rotl64(emo, 21);
	esu ^= du;
	cu = qrc_intutils_rotl64(esu, 14);
	aba = ca ^ ((!ce) & ci);
	aba ^= 0x0000000080000001;
	abe = ce ^ ((!ci) & co);
	abi = ci ^ ((!co) & cu);
	abo = co ^ ((!cu) & ca);
	abu = cu ^ ((!ca) & ce);
	ebo ^= dz;
	ca = qrc_intutils_rotl64(ebo, 28);
	egu ^= du;
	ce = qrc_intutils_rotl64(egu, 20);
	eka ^= da;
	ci = qrc_intutils_rotl64(eka, 3);
	eme ^= de;
	co = qrc_intutils_rotl64(eme, 45);
	esi ^= di;
	cu = qrc_intutils_rotl64(esi, 61);
	aga = ca ^ ((!ce) & ci);
	age = ce ^ ((!ci) & co);
	agi = ci ^ ((!co) & cu);
	ago = co ^ ((!cu) & ca);
	agu = cu ^ ((!ca) & ce);
	ebe ^= de;
	ca = qrc_intutils_rotl64(ebe, 1);
	egi ^= di;
	ce = qrc_intutils_rotl64(egi, 6);
	eko ^= dz;
	ci = qrc_intutils_rotl64(eko, 25);
	emu ^= du;
	co = qrc_intutils_rotl64(emu, 8);
	esa ^= da;
	cu = qrc_intutils_rotl64(esa, 18);
	aka = ca ^ ((!ce) & ci);
	ake = ce ^ ((!ci) & co);
	aki = ci ^ ((!co) & cu);
	ako = co ^ ((!cu) & ca);
	aku = cu ^ ((!ca) & ce);
	ebu ^= du;
	ca = qrc_intutils_rotl64(ebu, 27);
	ega ^= da;
	ce = qrc_intutils_rotl64(ega, 36);
	eke ^= de;
	ci = qrc_intutils_rotl64(eke, 10);
	emi ^= di;
	co = qrc_intutils_rotl64(emi, 15);
	eso ^= dz;
	cu = qrc_intutils_rotl64(eso, 56);
	ama = ca ^ ((!ce) & ci);
	ame = ce ^ ((!ci) & co);
	ami = ci ^ ((!co) & cu);
	amo = co ^ ((!cu) & ca);
	amu = cu ^ ((!ca) & ce);
	ebi ^= di;
	ca = qrc_intutils_rotl64(ebi, 62);
	ego ^= dz;
	ce = qrc_intutils_rotl64(ego, 55);
	eku ^= du;
	ci = qrc_intutils_rotl64(eku, 39);
	ema ^= da;
	co = qrc_intutils_rotl64(ema, 41);
	ese ^= de;
	cu = qrc_intutils_rotl64(ese, 2);
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
	da = cu ^ qrc_intutils_rotl64(ce, 1);
	de = ca ^ qrc_intutils_rotl64(ci, 1);
	di = ce ^ qrc_intutils_rotl64(co, 1);
	dz = ci ^ qrc_intutils_rotl64(cu, 1);
	du = co ^ qrc_intutils_rotl64(ca, 1);
	aba ^= da;
	ca = aba;
	age ^= de;
	ce = qrc_intutils_rotl64(age, 44);
	aki ^= di;
	ci = qrc_intutils_rotl64(aki, 43);
	amo ^= dz;
	co = qrc_intutils_rotl64(amo, 21);
	asu ^= du;
	cu = qrc_intutils_rotl64(asu, 14);
	eba = ca ^ ((!ce) & ci);
	eba ^= 0x8000000080008081;
	ebe = ce ^ ((!ci) & co);
	ebi = ci ^ ((!co) & cu);
	ebo = co ^ ((!cu) & ca);
	ebu = cu ^ ((!ca) & ce);
	abo ^= dz;
	ca = qrc_intutils_rotl64(abo, 28);
	agu ^= du;
	ce = qrc_intutils_rotl64(agu, 20);
	aka ^= da;
	ci = qrc_intutils_rotl64(aka, 3);
	ame ^= de;
	co = qrc_intutils_rotl64(ame, 45);
	asi ^= di;
	cu = qrc_intutils_rotl64(asi, 61);
	ega = ca ^ ((!ce) & ci);
	ege = ce ^ ((!ci) & co);
	egi = ci ^ ((!co) & cu);
	ego = co ^ ((!cu) & ca);
	egu = cu ^ ((!ca) & ce);
	abe ^= de;
	ca = qrc_intutils_rotl64(abe, 1);
	agi ^= di;
	ce = qrc_intutils_rotl64(agi, 6);
	ako ^= dz;
	ci = qrc_intutils_rotl64(ako, 25);
	amu ^= du;
	co = qrc_intutils_rotl64(amu, 8);
	asa ^= da;
	cu = qrc_intutils_rotl64(asa, 18);
	eka = ca ^ ((!ce) & ci);
	eke = ce ^ ((!ci) & co);
	eki = ci ^ ((!co) & cu);
	eko = co ^ ((!cu) & ca);
	eku = cu ^ ((!ca) & ce);
	abu ^= du;
	ca = qrc_intutils_rotl64(abu, 27);
	aga ^= da;
	ce = qrc_intutils_rotl64(aga, 36);
	ake ^= de;
	ci = qrc_intutils_rotl64(ake, 10);
	ami ^= di;
	co = qrc_intutils_rotl64(ami, 15);
	aso ^= dz;
	cu = qrc_intutils_rotl64(aso, 56);
	ema = ca ^ ((!ce) & ci);
	eme = ce ^ ((!ci) & co);
	emi = ci ^ ((!co) & cu);
	emo = co ^ ((!cu) & ca);
	emu = cu ^ ((!ca) & ce);
	abi ^= di;
	ca = qrc_intutils_rotl64(abi, 62);
	ago ^= dz;
	ce = qrc_intutils_rotl64(ago, 55);
	aku ^= du;
	ci = qrc_intutils_rotl64(aku, 39);
	ama ^= da;
	co = qrc_intutils_rotl64(ama, 41);
	ase ^= de;
	cu = qrc_intutils_rotl64(ase, 2);
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
	da = cu ^ qrc_intutils_rotl64(ce, 1);
	de = ca ^ qrc_intutils_rotl64(ci, 1);
	di = ce ^ qrc_intutils_rotl64(co, 1);
	dz = ci ^ qrc_intutils_rotl64(cu, 1);
	du = co ^ qrc_intutils_rotl64(ca, 1);
	eba ^= da;
	ca = eba;
	ege ^= de;
	ce = qrc_intutils_rotl64(ege, 44);
	eki ^= di;
	ci = qrc_intutils_rotl64(eki, 43);
	emo ^= dz;
	co = qrc_intutils_rotl64(emo, 21);
	esu ^= du;
	cu = qrc_intutils_rotl64(esu, 14);
	aba = ca ^ ((!ce) & ci);
	aba ^= 0x8000000000008009;
	abe = ce ^ ((!ci) & co);
	abi = ci ^ ((!co) & cu);
	abo = co ^ ((!cu) & ca);
	abu = cu ^ ((!ca) & ce);
	ebo ^= dz;
	ca = qrc_intutils_rotl64(ebo, 28);
	egu ^= du;
	ce = qrc_intutils_rotl64(egu, 20);
	eka ^= da;
	ci = qrc_intutils_rotl64(eka, 3);
	eme ^= de;
	co = qrc_intutils_rotl64(eme, 45);
	esi ^= di;
	cu = qrc_intutils_rotl64(esi, 61);
	aga = ca ^ ((!ce) & ci);
	age = ce ^ ((!ci) & co);
	agi = ci ^ ((!co) & cu);
	ago = co ^ ((!cu) & ca);
	agu = cu ^ ((!ca) & ce);
	ebe ^= de;
	ca = qrc_intutils_rotl64(ebe, 1);
	egi ^= di;
	ce = qrc_intutils_rotl64(egi, 6);
	eko ^= dz;
	ci = qrc_intutils_rotl64(eko, 25);
	emu ^= du;
	co = qrc_intutils_rotl64(emu, 8);
	esa ^= da;
	cu = qrc_intutils_rotl64(esa, 18);
	aka = ca ^ ((!ce) & ci);
	ake = ce ^ ((!ci) & co);
	aki = ci ^ ((!co) & cu);
	ako = co ^ ((!cu) & ca);
	aku = cu ^ ((!ca) & ce);
	ebu ^= du;
	ca = qrc_intutils_rotl64(ebu, 27);
	ega ^= da;
	ce = qrc_intutils_rotl64(ega, 36);
	eke ^= de;
	ci = qrc_intutils_rotl64(eke, 10);
	emi ^= di;
	co = qrc_intutils_rotl64(emi, 15);
	eso ^= dz;
	cu = qrc_intutils_rotl64(eso, 56);
	ama = ca ^ ((!ce) & ci);
	ame = ce ^ ((!ci) & co);
	ami = ci ^ ((!co) & cu);
	amo = co ^ ((!cu) & ca);
	amu = cu ^ ((!ca) & ce);
	ebi ^= di;
	ca = qrc_intutils_rotl64(ebi, 62);
	ego ^= dz;
	ce = qrc_intutils_rotl64(ego, 55);
	eku ^= du;
	ci = qrc_intutils_rotl64(eku, 39);
	ema ^= da;
	co = qrc_intutils_rotl64(ema, 41);
	ese ^= de;
	cu = qrc_intutils_rotl64(ese, 2);
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
	da = cu ^ qrc_intutils_rotl64(ce, 1);
	de = ca ^ qrc_intutils_rotl64(ci, 1);
	di = ce ^ qrc_intutils_rotl64(co, 1);
	dz = ci ^ qrc_intutils_rotl64(cu, 1);
	du = co ^ qrc_intutils_rotl64(ca, 1);
	aba ^= da;
	ca = aba;
	age ^= de;
	ce = qrc_intutils_rotl64(age, 44);
	aki ^= di;
	ci = qrc_intutils_rotl64(aki, 43);
	amo ^= dz;
	co = qrc_intutils_rotl64(amo, 21);
	asu ^= du;
	cu = qrc_intutils_rotl64(asu, 14);
	eba = ca ^ ((!ce) & ci);
	eba ^= 0x000000000000008A;
	ebe = ce ^ ((!ci) & co);
	ebi = ci ^ ((!co) & cu);
	ebo = co ^ ((!cu) & ca);
	ebu = cu ^ ((!ca) & ce);
	abo ^= dz;
	ca = qrc_intutils_rotl64(abo, 28);
	agu ^= du;
	ce = qrc_intutils_rotl64(agu, 20);
	aka ^= da;
	ci = qrc_intutils_rotl64(aka, 3);
	ame ^= de;
	co = qrc_intutils_rotl64(ame, 45);
	asi ^= di;
	cu = qrc_intutils_rotl64(asi, 61);
	ega = ca ^ ((!ce) & ci);
	ege = ce ^ ((!ci) & co);
	egi = ci ^ ((!co) & cu);
	ego = co ^ ((!cu) & ca);
	egu = cu ^ ((!ca) & ce);
	abe ^= de;
	ca = qrc_intutils_rotl64(abe, 1);
	agi ^= di;
	ce = qrc_intutils_rotl64(agi, 6);
	ako ^= dz;
	ci = qrc_intutils_rotl64(ako, 25);
	amu ^= du;
	co = qrc_intutils_rotl64(amu, 8);
	asa ^= da;
	cu = qrc_intutils_rotl64(asa, 18);
	eka = ca ^ ((!ce) & ci);
	eke = ce ^ ((!ci) & co);
	eki = ci ^ ((!co) & cu);
	eko = co ^ ((!cu) & ca);
	eku = cu ^ ((!ca) & ce);
	abu ^= du;
	ca = qrc_intutils_rotl64(abu, 27);
	aga ^= da;
	ce = qrc_intutils_rotl64(aga, 36);
	ake ^= de;
	ci = qrc_intutils_rotl64(ake, 10);
	ami ^= di;
	co = qrc_intutils_rotl64(ami, 15);
	aso ^= dz;
	cu = qrc_intutils_rotl64(aso, 56);
	ema = ca ^ ((!ce) & ci);
	eme = ce ^ ((!ci) & co);
	emi = ci ^ ((!co) & cu);
	emo = co ^ ((!cu) & ca);
	emu = cu ^ ((!ca) & ce);
	abi ^= di;
	ca = qrc_intutils_rotl64(abi, 62);
	ago ^= dz;
	ce = qrc_intutils_rotl64(ago, 55);
	aku ^= du;
	ci = qrc_intutils_rotl64(aku, 39);
	ama ^= da;
	co = qrc_intutils_rotl64(ama, 41);
	ase ^= de;
	cu = qrc_intutils_rotl64(ase, 2);
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
	da = cu ^ qrc_intutils_rotl64(ce, 1);
	de = ca ^ qrc_intutils_rotl64(ci, 1);
	di = ce ^ qrc_intutils_rotl64(co, 1);
	dz = ci ^ qrc_intutils_rotl64(cu, 1);
	du = co ^ qrc_intutils_rotl64(ca, 1);
	eba ^= da;
	ca = eba;
	ege ^= de;
	ce = qrc_intutils_rotl64(ege, 44);
	eki ^= di;
	ci = qrc_intutils_rotl64(eki, 43);
	emo ^= dz;
	co = qrc_intutils_rotl64(emo, 21);
	esu ^= du;
	cu = qrc_intutils_rotl64(esu, 14);
	aba = ca ^ ((!ce) & ci);
	aba ^= 0x0000000000000088;
	abe = ce ^ ((!ci) & co);
	abi = ci ^ ((!co) & cu);
	abo = co ^ ((!cu) & ca);
	abu = cu ^ ((!ca) & ce);
	ebo ^= dz;
	ca = qrc_intutils_rotl64(ebo, 28);
	egu ^= du;
	ce = qrc_intutils_rotl64(egu, 20);
	eka ^= da;
	ci = qrc_intutils_rotl64(eka, 3);
	eme ^= de;
	co = qrc_intutils_rotl64(eme, 45);
	esi ^= di;
	cu = qrc_intutils_rotl64(esi, 61);
	aga = ca ^ ((!ce) & ci);
	age = ce ^ ((!ci) & co);
	agi = ci ^ ((!co) & cu);
	ago = co ^ ((!cu) & ca);
	agu = cu ^ ((!ca) & ce);
	ebe ^= de;
	ca = qrc_intutils_rotl64(ebe, 1);
	egi ^= di;
	ce = qrc_intutils_rotl64(egi, 6);
	eko ^= dz;
	ci = qrc_intutils_rotl64(eko, 25);
	emu ^= du;
	co = qrc_intutils_rotl64(emu, 8);
	esa ^= da;
	cu = qrc_intutils_rotl64(esa, 18);
	aka = ca ^ ((!ce) & ci);
	ake = ce ^ ((!ci) & co);
	aki = ci ^ ((!co) & cu);
	ako = co ^ ((!cu) & ca);
	aku = cu ^ ((!ca) & ce);
	ebu ^= du;
	ca = qrc_intutils_rotl64(ebu, 27);
	ega ^= da;
	ce = qrc_intutils_rotl64(ega, 36);
	eke ^= de;
	ci = qrc_intutils_rotl64(eke, 10);
	emi ^= di;
	co = qrc_intutils_rotl64(emi, 15);
	eso ^= dz;
	cu = qrc_intutils_rotl64(eso, 56);
	ama = ca ^ ((!ce) & ci);
	ame = ce ^ ((!ci) & co);
	ami = ci ^ ((!co) & cu);
	amo = co ^ ((!cu) & ca);
	amu = cu ^ ((!ca) & ce);
	ebi ^= di;
	ca = qrc_intutils_rotl64(ebi, 62);
	ego ^= dz;
	ce = qrc_intutils_rotl64(ego, 55);
	eku ^= du;
	ci = qrc_intutils_rotl64(eku, 39);
	ema ^= da;
	co = qrc_intutils_rotl64(ema, 41);
	ese ^= de;
	cu = qrc_intutils_rotl64(ese, 2);
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
	da = cu ^ qrc_intutils_rotl64(ce, 1);
	de = ca ^ qrc_intutils_rotl64(ci, 1);
	di = ce ^ qrc_intutils_rotl64(co, 1);
	dz = ci ^ qrc_intutils_rotl64(cu, 1);
	du = co ^ qrc_intutils_rotl64(ca, 1);
	aba ^= da;
	ca = aba;
	age ^= de;
	ce = qrc_intutils_rotl64(age, 44);
	aki ^= di;
	ci = qrc_intutils_rotl64(aki, 43);
	amo ^= dz;
	co = qrc_intutils_rotl64(amo, 21);
	asu ^= du;
	cu = qrc_intutils_rotl64(asu, 14);
	eba = ca ^ ((!ce) & ci);
	eba ^= 0x0000000080008009;
	ebe = ce ^ ((!ci) & co);
	ebi = ci ^ ((!co) & cu);
	ebo = co ^ ((!cu) & ca);
	ebu = cu ^ ((!ca) & ce);
	abo ^= dz;
	ca = qrc_intutils_rotl64(abo, 28);
	agu ^= du;
	ce = qrc_intutils_rotl64(agu, 20);
	aka ^= da;
	ci = qrc_intutils_rotl64(aka, 3);
	ame ^= de;
	co = qrc_intutils_rotl64(ame, 45);
	asi ^= di;
	cu = qrc_intutils_rotl64(asi, 61);
	ega = ca ^ ((!ce) & ci);
	ege = ce ^ ((!ci) & co);
	egi = ci ^ ((!co) & cu);
	ego = co ^ ((!cu) & ca);
	egu = cu ^ ((!ca) & ce);
	abe ^= de;
	ca = qrc_intutils_rotl64(abe, 1);
	agi ^= di;
	ce = qrc_intutils_rotl64(agi, 6);
	ako ^= dz;
	ci = qrc_intutils_rotl64(ako, 25);
	amu ^= du;
	co = qrc_intutils_rotl64(amu, 8);
	asa ^= da;
	cu = qrc_intutils_rotl64(asa, 18);
	eka = ca ^ ((!ce) & ci);
	eke = ce ^ ((!ci) & co);
	eki = ci ^ ((!co) & cu);
	eko = co ^ ((!cu) & ca);
	eku = cu ^ ((!ca) & ce);
	abu ^= du;
	ca = qrc_intutils_rotl64(abu, 27);
	aga ^= da;
	ce = qrc_intutils_rotl64(aga, 36);
	ake ^= de;
	ci = qrc_intutils_rotl64(ake, 10);
	ami ^= di;
	co = qrc_intutils_rotl64(ami, 15);
	aso ^= dz;
	cu = qrc_intutils_rotl64(aso, 56);
	ema = ca ^ ((!ce) & ci);
	eme = ce ^ ((!ci) & co);
	emi = ci ^ ((!co) & cu);
	emo = co ^ ((!cu) & ca);
	emu = cu ^ ((!ca) & ce);
	abi ^= di;
	ca = qrc_intutils_rotl64(abi, 62);
	ago ^= dz;
	ce = qrc_intutils_rotl64(ago, 55);
	aku ^= du;
	ci = qrc_intutils_rotl64(aku, 39);
	ama ^= da;
	co = qrc_intutils_rotl64(ama, 41);
	ase ^= de;
	cu = qrc_intutils_rotl64(ase, 2);
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
	da = cu ^ qrc_intutils_rotl64(ce, 1);
	de = ca ^ qrc_intutils_rotl64(ci, 1);
	di = ce ^ qrc_intutils_rotl64(co, 1);
	dz = ci ^ qrc_intutils_rotl64(cu, 1);
	du = co ^ qrc_intutils_rotl64(ca, 1);
	eba ^= da;
	ca = eba;
	ege ^= de;
	ce = qrc_intutils_rotl64(ege, 44);
	eki ^= di;
	ci = qrc_intutils_rotl64(eki, 43);
	emo ^= dz;
	co = qrc_intutils_rotl64(emo, 21);
	esu ^= du;
	cu = qrc_intutils_rotl64(esu, 14);
	aba = ca ^ ((!ce) & ci);
	aba ^= 0x000000008000000A;
	abe = ce ^ ((!ci) & co);
	abi = ci ^ ((!co) & cu);
	abo = co ^ ((!cu) & ca);
	abu = cu ^ ((!ca) & ce);
	ebo ^= dz;
	ca = qrc_intutils_rotl64(ebo, 28);
	egu ^= du;
	ce = qrc_intutils_rotl64(egu, 20);
	eka ^= da;
	ci = qrc_intutils_rotl64(eka, 3);
	eme ^= de;
	co = qrc_intutils_rotl64(eme, 45);
	esi ^= di;
	cu = qrc_intutils_rotl64(esi, 61);
	aga = ca ^ ((!ce) & ci);
	age = ce ^ ((!ci) & co);
	agi = ci ^ ((!co) & cu);
	ago = co ^ ((!cu) & ca);
	agu = cu ^ ((!ca) & ce);
	ebe ^= de;
	ca = qrc_intutils_rotl64(ebe, 1);
	egi ^= di;
	ce = qrc_intutils_rotl64(egi, 6);
	eko ^= dz;
	ci = qrc_intutils_rotl64(eko, 25);
	emu ^= du;
	co = qrc_intutils_rotl64(emu, 8);
	esa ^= da;
	cu = qrc_intutils_rotl64(esa, 18);
	aka = ca ^ ((!ce) & ci);
	ake = ce ^ ((!ci) & co);
	aki = ci ^ ((!co) & cu);
	ako = co ^ ((!cu) & ca);
	aku = cu ^ ((!ca) & ce);
	ebu ^= du;
	ca = qrc_intutils_rotl64(ebu, 27);
	ega ^= da;
	ce = qrc_intutils_rotl64(ega, 36);
	eke ^= de;
	ci = qrc_intutils_rotl64(eke, 10);
	emi ^= di;
	co = qrc_intutils_rotl64(emi, 15);
	eso ^= dz;
	cu = qrc_intutils_rotl64(eso, 56);
	ama = ca ^ ((!ce) & ci);
	ame = ce ^ ((!ci) & co);
	ami = ci ^ ((!co) & cu);
	amo = co ^ ((!cu) & ca);
	amu = cu ^ ((!ca) & ce);
	ebi ^= di;
	ca = qrc_intutils_rotl64(ebi, 62);
	ego ^= dz;
	ce = qrc_intutils_rotl64(ego, 55);
	eku ^= du;
	ci = qrc_intutils_rotl64(eku, 39);
	ema ^= da;
	co = qrc_intutils_rotl64(ema, 41);
	ese ^= de;
	cu = qrc_intutils_rotl64(ese, 2);
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
	da = cu ^ qrc_intutils_rotl64(ce, 1);
	de = ca ^ qrc_intutils_rotl64(ci, 1);
	di = ce ^ qrc_intutils_rotl64(co, 1);
	dz = ci ^ qrc_intutils_rotl64(cu, 1);
	du = co ^ qrc_intutils_rotl64(ca, 1);
	aba ^= da;
	ca = aba;
	age ^= de;
	ce = qrc_intutils_rotl64(age, 44);
	aki ^= di;
	ci = qrc_intutils_rotl64(aki, 43);
	amo ^= dz;
	co = qrc_intutils_rotl64(amo, 21);
	asu ^= du;
	cu = qrc_intutils_rotl64(asu, 14);
	eba = ca ^ ((!ce) & ci);
	eba ^= 0x000000008000808B;
	ebe = ce ^ ((!ci) & co);
	ebi = ci ^ ((!co) & cu);
	ebo = co ^ ((!cu) & ca);
	ebu = cu ^ ((!ca) & ce);
	abo ^= dz;
	ca = qrc_intutils_rotl64(abo, 28);
	agu ^= du;
	ce = qrc_intutils_rotl64(agu, 20);
	aka ^= da;
	ci = qrc_intutils_rotl64(aka, 3);
	ame ^= de;
	co = qrc_intutils_rotl64(ame, 45);
	asi ^= di;
	cu = qrc_intutils_rotl64(asi, 61);
	ega = ca ^ ((!ce) & ci);
	ege = ce ^ ((!ci) & co);
	egi = ci ^ ((!co) & cu);
	ego = co ^ ((!cu) & ca);
	egu = cu ^ ((!ca) & ce);
	abe ^= de;
	ca = qrc_intutils_rotl64(abe, 1);
	agi ^= di;
	ce = qrc_intutils_rotl64(agi, 6);
	ako ^= dz;
	ci = qrc_intutils_rotl64(ako, 25);
	amu ^= du;
	co = qrc_intutils_rotl64(amu, 8);
	asa ^= da;
	cu = qrc_intutils_rotl64(asa, 18);
	eka = ca ^ ((!ce) & ci);
	eke = ce ^ ((!ci) & co);
	eki = ci ^ ((!co) & cu);
	eko = co ^ ((!cu) & ca);
	eku = cu ^ ((!ca) & ce);
	abu ^= du;
	ca = qrc_intutils_rotl64(abu, 27);
	aga ^= da;
	ce = qrc_intutils_rotl64(aga, 36);
	ake ^= de;
	ci = qrc_intutils_rotl64(ake, 10);
	ami ^= di;
	co = qrc_intutils_rotl64(ami, 15);
	aso ^= dz;
	cu = qrc_intutils_rotl64(aso, 56);
	ema = ca ^ ((!ce) & ci);
	eme = ce ^ ((!ci) & co);
	emi = ci ^ ((!co) & cu);
	emo = co ^ ((!cu) & ca);
	emu = cu ^ ((!ca) & ce);
	abi ^= di;
	ca = qrc_intutils_rotl64(abi, 62);
	ago ^= dz;
	ce = qrc_intutils_rotl64(ago, 55);
	aku ^= du;
	ci = qrc_intutils_rotl64(aku, 39);
	ama ^= da;
	co = qrc_intutils_rotl64(ama, 41);
	ase ^= de;
	cu = qrc_intutils_rotl64(ase, 2);
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
	da = cu ^ qrc_intutils_rotl64(ce, 1);
	de = ca ^ qrc_intutils_rotl64(ci, 1);
	di = ce ^ qrc_intutils_rotl64(co, 1);
	dz = ci ^ qrc_intutils_rotl64(cu, 1);
	du = co ^ qrc_intutils_rotl64(ca, 1);
	eba ^= da;
	ca = eba;
	ege ^= de;
	ce = qrc_intutils_rotl64(ege, 44);
	eki ^= di;
	ci = qrc_intutils_rotl64(eki, 43);
	emo ^= dz;
	co = qrc_intutils_rotl64(emo, 21);
	esu ^= du;
	cu = qrc_intutils_rotl64(esu, 14);
	aba = ca ^ ((!ce) & ci);
	aba ^= 0x800000000000008B;
	abe = ce ^ ((!ci) & co);
	abi = ci ^ ((!co) & cu);
	abo = co ^ ((!cu) & ca);
	abu = cu ^ ((!ca) & ce);
	ebo ^= dz;
	ca = qrc_intutils_rotl64(ebo, 28);
	egu ^= du;
	ce = qrc_intutils_rotl64(egu, 20);
	eka ^= da;
	ci = qrc_intutils_rotl64(eka, 3);
	eme ^= de;
	co = qrc_intutils_rotl64(eme, 45);
	esi ^= di;
	cu = qrc_intutils_rotl64(esi, 61);
	aga = ca ^ ((!ce) & ci);
	age = ce ^ ((!ci) & co);
	agi = ci ^ ((!co) & cu);
	ago = co ^ ((!cu) & ca);
	agu = cu ^ ((!ca) & ce);
	ebe ^= de;
	ca = qrc_intutils_rotl64(ebe, 1);
	egi ^= di;
	ce = qrc_intutils_rotl64(egi, 6);
	eko ^= dz;
	ci = qrc_intutils_rotl64(eko, 25);
	emu ^= du;
	co = qrc_intutils_rotl64(emu, 8);
	esa ^= da;
	cu = qrc_intutils_rotl64(esa, 18);
	aka = ca ^ ((!ce) & ci);
	ake = ce ^ ((!ci) & co);
	aki = ci ^ ((!co) & cu);
	ako = co ^ ((!cu) & ca);
	aku = cu ^ ((!ca) & ce);
	ebu ^= du;
	ca = qrc_intutils_rotl64(ebu, 27);
	ega ^= da;
	ce = qrc_intutils_rotl64(ega, 36);
	eke ^= de;
	ci = qrc_intutils_rotl64(eke, 10);
	emi ^= di;
	co = qrc_intutils_rotl64(emi, 15);
	eso ^= dz;
	cu = qrc_intutils_rotl64(eso, 56);
	ama = ca ^ ((!ce) & ci);
	ame = ce ^ ((!ci) & co);
	ami = ci ^ ((!co) & cu);
	amo = co ^ ((!cu) & ca);
	amu = cu ^ ((!ca) & ce);
	ebi ^= di;
	ca = qrc_intutils_rotl64(ebi, 62);
	ego ^= dz;
	ce = qrc_intutils_rotl64(ego, 55);
	eku ^= du;
	ci = qrc_intutils_rotl64(eku, 39);
	ema ^= da;
	co = qrc_intutils_rotl64(ema, 41);
	ese ^= de;
	cu = qrc_intutils_rotl64(ese, 2);
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
	da = cu ^ qrc_intutils_rotl64(ce, 1);
	de = ca ^ qrc_intutils_rotl64(ci, 1);
	di = ce ^ qrc_intutils_rotl64(co, 1);
	dz = ci ^ qrc_intutils_rotl64(cu, 1);
	du = co ^ qrc_intutils_rotl64(ca, 1);
	aba ^= da;
	ca = aba;
	age ^= de;
	ce = qrc_intutils_rotl64(age, 44);
	aki ^= di;
	ci = qrc_intutils_rotl64(aki, 43);
	amo ^= dz;
	co = qrc_intutils_rotl64(amo, 21);
	asu ^= du;
	cu = qrc_intutils_rotl64(asu, 14);
	eba = ca ^ ((!ce) & ci);
	eba ^= 0x8000000000008089;
	ebe = ce ^ ((!ci) & co);
	ebi = ci ^ ((!co) & cu);
	ebo = co ^ ((!cu) & ca);
	ebu = cu ^ ((!ca) & ce);
	abo ^= dz;
	ca = qrc_intutils_rotl64(abo, 28);
	agu ^= du;
	ce = qrc_intutils_rotl64(agu, 20);
	aka ^= da;
	ci = qrc_intutils_rotl64(aka, 3);
	ame ^= de;
	co = qrc_intutils_rotl64(ame, 45);
	asi ^= di;
	cu = qrc_intutils_rotl64(asi, 61);
	ega = ca ^ ((!ce) & ci);
	ege = ce ^ ((!ci) & co);
	egi = ci ^ ((!co) & cu);
	ego = co ^ ((!cu) & ca);
	egu = cu ^ ((!ca) & ce);
	abe ^= de;
	ca = qrc_intutils_rotl64(abe, 1);
	agi ^= di;
	ce = qrc_intutils_rotl64(agi, 6);
	ako ^= dz;
	ci = qrc_intutils_rotl64(ako, 25);
	amu ^= du;
	co = qrc_intutils_rotl64(amu, 8);
	asa ^= da;
	cu = qrc_intutils_rotl64(asa, 18);
	eka = ca ^ ((!ce) & ci);
	eke = ce ^ ((!ci) & co);
	eki = ci ^ ((!co) & cu);
	eko = co ^ ((!cu) & ca);
	eku = cu ^ ((!ca) & ce);
	abu ^= du;
	ca = qrc_intutils_rotl64(abu, 27);
	aga ^= da;
	ce = qrc_intutils_rotl64(aga, 36);
	ake ^= de;
	ci = qrc_intutils_rotl64(ake, 10);
	ami ^= di;
	co = qrc_intutils_rotl64(ami, 15);
	aso ^= dz;
	cu = qrc_intutils_rotl64(aso, 56);
	ema = ca ^ ((!ce) & ci);
	eme = ce ^ ((!ci) & co);
	emi = ci ^ ((!co) & cu);
	emo = co ^ ((!cu) & ca);
	emu = cu ^ ((!ca) & ce);
	abi ^= di;
	ca = qrc_intutils_rotl64(abi, 62);
	ago ^= dz;
	ce = qrc_intutils_rotl64(ago, 55);
	aku ^= du;
	ci = qrc_intutils_rotl64(aku, 39);
	ama ^= da;
	co = qrc_intutils_rotl64(ama, 41);
	ase ^= de;
	cu = qrc_intutils_rotl64(ase, 2);
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
	da = cu ^ qrc_intutils_rotl64(ce, 1);
	de = ca ^ qrc_intutils_rotl64(ci, 1);
	di = ce ^ qrc_intutils_rotl64(co, 1);
	dz = ci ^ qrc_intutils_rotl64(cu, 1);
	du = co ^ qrc_intutils_rotl64(ca, 1);
	eba ^= da;
	ca = eba;
	ege ^= de;
	ce = qrc_intutils_rotl64(ege, 44);
	eki ^= di;
	ci = qrc_intutils_rotl64(eki, 43);
	emo ^= dz;
	co = qrc_intutils_rotl64(emo, 21);
	esu ^= du;
	cu = qrc_intutils_rotl64(esu, 14);
	aba = ca ^ ((!ce) & ci);
	aba ^= 0x8000000000008003;
	abe = ce ^ ((!ci) & co);
	abi = ci ^ ((!co) & cu);
	abo = co ^ ((!cu) & ca);
	abu = cu ^ ((!ca) & ce);
	ebo ^= dz;
	ca = qrc_intutils_rotl64(ebo, 28);
	egu ^= du;
	ce = qrc_intutils_rotl64(egu, 20);
	eka ^= da;
	ci = qrc_intutils_rotl64(eka, 3);
	eme ^= de;
	co = qrc_intutils_rotl64(eme, 45);
	esi ^= di;
	cu = qrc_intutils_rotl64(esi, 61);
	aga = ca ^ ((!ce) & ci);
	age = ce ^ ((!ci) & co);
	agi = ci ^ ((!co) & cu);
	ago = co ^ ((!cu) & ca);
	agu = cu ^ ((!ca) & ce);
	ebe ^= de;
	ca = qrc_intutils_rotl64(ebe, 1);
	egi ^= di;
	ce = qrc_intutils_rotl64(egi, 6);
	eko ^= dz;
	ci = qrc_intutils_rotl64(eko, 25);
	emu ^= du;
	co = qrc_intutils_rotl64(emu, 8);
	esa ^= da;
	cu = qrc_intutils_rotl64(esa, 18);
	aka = ca ^ ((!ce) & ci);
	ake = ce ^ ((!ci) & co);
	aki = ci ^ ((!co) & cu);
	ako = co ^ ((!cu) & ca);
	aku = cu ^ ((!ca) & ce);
	ebu ^= du;
	ca = qrc_intutils_rotl64(ebu, 27);
	ega ^= da;
	ce = qrc_intutils_rotl64(ega, 36);
	eke ^= de;
	ci = qrc_intutils_rotl64(eke, 10);
	emi ^= di;
	co = qrc_intutils_rotl64(emi, 15);
	eso ^= dz;
	cu = qrc_intutils_rotl64(eso, 56);
	ama = ca ^ ((!ce) & ci);
	ame = ce ^ ((!ci) & co);
	ami = ci ^ ((!co) & cu);
	amo = co ^ ((!cu) & ca);
	amu = cu ^ ((!ca) & ce);
	ebi ^= di;
	ca = qrc_intutils_rotl64(ebi, 62);
	ego ^= dz;
	ce = qrc_intutils_rotl64(ego, 55);
	eku ^= du;
	ci = qrc_intutils_rotl64(eku, 39);
	ema ^= da;
	co = qrc_intutils_rotl64(ema, 41);
	ese ^= de;
	cu = qrc_intutils_rotl64(ese, 2);
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
	da = cu ^ qrc_intutils_rotl64(ce, 1);
	de = ca ^ qrc_intutils_rotl64(ci, 1);
	di = ce ^ qrc_intutils_rotl64(co, 1);
	dz = ci ^ qrc_intutils_rotl64(cu, 1);
	du = co ^ qrc_intutils_rotl64(ca, 1);
	aba ^= da;
	ca = aba;
	age ^= de;
	ce = qrc_intutils_rotl64(age, 44);
	aki ^= di;
	ci = qrc_intutils_rotl64(aki, 43);
	amo ^= dz;
	co = qrc_intutils_rotl64(amo, 21);
	asu ^= du;
	cu = qrc_intutils_rotl64(asu, 14);
	eba = ca ^ ((!ce) & ci);
	eba ^= 0x8000000000008002;
	ebe = ce ^ ((!ci) & co);
	ebi = ci ^ ((!co) & cu);
	ebo = co ^ ((!cu) & ca);
	ebu = cu ^ ((!ca) & ce);
	abo ^= dz;
	ca = qrc_intutils_rotl64(abo, 28);
	agu ^= du;
	ce = qrc_intutils_rotl64(agu, 20);
	aka ^= da;
	ci = qrc_intutils_rotl64(aka, 3);
	ame ^= de;
	co = qrc_intutils_rotl64(ame, 45);
	asi ^= di;
	cu = qrc_intutils_rotl64(asi, 61);
	ega = ca ^ ((!ce) & ci);
	ege = ce ^ ((!ci) & co);
	egi = ci ^ ((!co) & cu);
	ego = co ^ ((!cu) & ca);
	egu = cu ^ ((!ca) & ce);
	abe ^= de;
	ca = qrc_intutils_rotl64(abe, 1);
	agi ^= di;
	ce = qrc_intutils_rotl64(agi, 6);
	ako ^= dz;
	ci = qrc_intutils_rotl64(ako, 25);
	amu ^= du;
	co = qrc_intutils_rotl64(amu, 8);
	asa ^= da;
	cu = qrc_intutils_rotl64(asa, 18);
	eka = ca ^ ((!ce) & ci);
	eke = ce ^ ((!ci) & co);
	eki = ci ^ ((!co) & cu);
	eko = co ^ ((!cu) & ca);
	eku = cu ^ ((!ca) & ce);
	abu ^= du;
	ca = qrc_intutils_rotl64(abu, 27);
	aga ^= da;
	ce = qrc_intutils_rotl64(aga, 36);
	ake ^= de;
	ci = qrc_intutils_rotl64(ake, 10);
	ami ^= di;
	co = qrc_intutils_rotl64(ami, 15);
	aso ^= dz;
	cu = qrc_intutils_rotl64(aso, 56);
	ema = ca ^ ((!ce) & ci);
	eme = ce ^ ((!ci) & co);
	emi = ci ^ ((!co) & cu);
	emo = co ^ ((!cu) & ca);
	emu = cu ^ ((!ca) & ce);
	abi ^= di;
	ca = qrc_intutils_rotl64(abi, 62);
	ago ^= dz;
	ce = qrc_intutils_rotl64(ago, 55);
	aku ^= du;
	ci = qrc_intutils_rotl64(aku, 39);
	ama ^= da;
	co = qrc_intutils_rotl64(ama, 41);
	ase ^= de;
	cu = qrc_intutils_rotl64(ase, 2);
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
	da = cu ^ qrc_intutils_rotl64(ce, 1);
	de = ca ^ qrc_intutils_rotl64(ci, 1);
	di = ce ^ qrc_intutils_rotl64(co, 1);
	dz = ci ^ qrc_intutils_rotl64(cu, 1);
	du = co ^ qrc_intutils_rotl64(ca, 1);
	eba ^= da;
	ca = eba;
	ege ^= de;
	ce = qrc_intutils_rotl64(ege, 44);
	eki ^= di;
	ci = qrc_intutils_rotl64(eki, 43);
	emo ^= dz;
	co = qrc_intutils_rotl64(emo, 21);
	esu ^= du;
	cu = qrc_intutils_rotl64(esu, 14);
	aba = ca ^ ((!ce) & ci);
	aba ^= 0x8000000000000080;
	abe = ce ^ ((!ci) & co);
	abi = ci ^ ((!co) & cu);
	abo = co ^ ((!cu) & ca);
	abu = cu ^ ((!ca) & ce);
	ebo ^= dz;
	ca = qrc_intutils_rotl64(ebo, 28);
	egu ^= du;
	ce = qrc_intutils_rotl64(egu, 20);
	eka ^= da;
	ci = qrc_intutils_rotl64(eka, 3);
	eme ^= de;
	co = qrc_intutils_rotl64(eme, 45);
	esi ^= di;
	cu = qrc_intutils_rotl64(esi, 61);
	aga = ca ^ ((!ce) & ci);
	age = ce ^ ((!ci) & co);
	agi = ci ^ ((!co) & cu);
	ago = co ^ ((!cu) & ca);
	agu = cu ^ ((!ca) & ce);
	ebe ^= de;
	ca = qrc_intutils_rotl64(ebe, 1);
	egi ^= di;
	ce = qrc_intutils_rotl64(egi, 6);
	eko ^= dz;
	ci = qrc_intutils_rotl64(eko, 25);
	emu ^= du;
	co = qrc_intutils_rotl64(emu, 8);
	esa ^= da;
	cu = qrc_intutils_rotl64(esa, 18);
	aka = ca ^ ((!ce) & ci);
	ake = ce ^ ((!ci) & co);
	aki = ci ^ ((!co) & cu);
	ako = co ^ ((!cu) & ca);
	aku = cu ^ ((!ca) & ce);
	ebu ^= du;
	ca = qrc_intutils_rotl64(ebu, 27);
	ega ^= da;
	ce = qrc_intutils_rotl64(ega, 36);
	eke ^= de;
	ci = qrc_intutils_rotl64(eke, 10);
	emi ^= di;
	co = qrc_intutils_rotl64(emi, 15);
	eso ^= dz;
	cu = qrc_intutils_rotl64(eso, 56);
	ama = ca ^ ((!ce) & ci);
	ame = ce ^ ((!ci) & co);
	ami = ci ^ ((!co) & cu);
	amo = co ^ ((!cu) & ca);
	amu = cu ^ ((!ca) & ce);
	ebi ^= di;
	ca = qrc_intutils_rotl64(ebi, 62);
	ego ^= dz;
	ce = qrc_intutils_rotl64(ego, 55);
	eku ^= du;
	ci = qrc_intutils_rotl64(eku, 39);
	ema ^= da;
	co = qrc_intutils_rotl64(ema, 41);
	ese ^= de;
	cu = qrc_intutils_rotl64(ese, 2);
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
	da = cu ^ qrc_intutils_rotl64(ce, 1);
	de = ca ^ qrc_intutils_rotl64(ci, 1);
	di = ce ^ qrc_intutils_rotl64(co, 1);
	dz = ci ^ qrc_intutils_rotl64(cu, 1);
	du = co ^ qrc_intutils_rotl64(ca, 1);
	aba ^= da;
	ca = aba;
	age ^= de;
	ce = qrc_intutils_rotl64(age, 44);
	aki ^= di;
	ci = qrc_intutils_rotl64(aki, 43);
	amo ^= dz;
	co = qrc_intutils_rotl64(amo, 21);
	asu ^= du;
	cu = qrc_intutils_rotl64(asu, 14);
	eba = ca ^ ((!ce) & ci);
	eba ^= 0x000000000000800A;
	ebe = ce ^ ((!ci) & co);
	ebi = ci ^ ((!co) & cu);
	ebo = co ^ ((!cu) & ca);
	ebu = cu ^ ((!ca) & ce);
	abo ^= dz;
	ca = qrc_intutils_rotl64(abo, 28);
	agu ^= du;
	ce = qrc_intutils_rotl64(agu, 20);
	aka ^= da;
	ci = qrc_intutils_rotl64(aka, 3);
	ame ^= de;
	co = qrc_intutils_rotl64(ame, 45);
	asi ^= di;
	cu = qrc_intutils_rotl64(asi, 61);
	ega = ca ^ ((!ce) & ci);
	ege = ce ^ ((!ci) & co);
	egi = ci ^ ((!co) & cu);
	ego = co ^ ((!cu) & ca);
	egu = cu ^ ((!ca) & ce);
	abe ^= de;
	ca = qrc_intutils_rotl64(abe, 1);
	agi ^= di;
	ce = qrc_intutils_rotl64(agi, 6);
	ako ^= dz;
	ci = qrc_intutils_rotl64(ako, 25);
	amu ^= du;
	co = qrc_intutils_rotl64(amu, 8);
	asa ^= da;
	cu = qrc_intutils_rotl64(asa, 18);
	eka = ca ^ ((!ce) & ci);
	eke = ce ^ ((!ci) & co);
	eki = ci ^ ((!co) & cu);
	eko = co ^ ((!cu) & ca);
	eku = cu ^ ((!ca) & ce);
	abu ^= du;
	ca = qrc_intutils_rotl64(abu, 27);
	aga ^= da;
	ce = qrc_intutils_rotl64(aga, 36);
	ake ^= de;
	ci = qrc_intutils_rotl64(ake, 10);
	ami ^= di;
	co = qrc_intutils_rotl64(ami, 15);
	aso ^= dz;
	cu = qrc_intutils_rotl64(aso, 56);
	ema = ca ^ ((!ce) & ci);
	eme = ce ^ ((!ci) & co);
	emi = ci ^ ((!co) & cu);
	emo = co ^ ((!cu) & ca);
	emu = cu ^ ((!ca) & ce);
	abi ^= di;
	ca = qrc_intutils_rotl64(abi, 62);
	ago ^= dz;
	ce = qrc_intutils_rotl64(ago, 55);
	aku ^= du;
	ci = qrc_intutils_rotl64(aku, 39);
	ama ^= da;
	co = qrc_intutils_rotl64(ama, 41);
	ase ^= de;
	cu = qrc_intutils_rotl64(ase, 2);
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
	da = cu ^ qrc_intutils_rotl64(ce, 1);
	de = ca ^ qrc_intutils_rotl64(ci, 1);
	di = ce ^ qrc_intutils_rotl64(co, 1);
	dz = ci ^ qrc_intutils_rotl64(cu, 1);
	du = co ^ qrc_intutils_rotl64(ca, 1);
	eba ^= da;
	ca = eba;
	ege ^= de;
	ce = qrc_intutils_rotl64(ege, 44);
	eki ^= di;
	ci = qrc_intutils_rotl64(eki, 43);
	emo ^= dz;
	co = qrc_intutils_rotl64(emo, 21);
	esu ^= du;
	cu = qrc_intutils_rotl64(esu, 14);
	aba = ca ^ ((!ce) & ci);
	aba ^= 0x800000008000000A;
	abe = ce ^ ((!ci) & co);
	abi = ci ^ ((!co) & cu);
	abo = co ^ ((!cu) & ca);
	abu = cu ^ ((!ca) & ce);
	ebo ^= dz;
	ca = qrc_intutils_rotl64(ebo, 28);
	egu ^= du;
	ce = qrc_intutils_rotl64(egu, 20);
	eka ^= da;
	ci = qrc_intutils_rotl64(eka, 3);
	eme ^= de;
	co = qrc_intutils_rotl64(eme, 45);
	esi ^= di;
	cu = qrc_intutils_rotl64(esi, 61);
	aga = ca ^ ((!ce) & ci);
	age = ce ^ ((!ci) & co);
	agi = ci ^ ((!co) & cu);
	ago = co ^ ((!cu) & ca);
	agu = cu ^ ((!ca) & ce);
	ebe ^= de;
	ca = qrc_intutils_rotl64(ebe, 1);
	egi ^= di;
	ce = qrc_intutils_rotl64(egi, 6);
	eko ^= dz;
	ci = qrc_intutils_rotl64(eko, 25);
	emu ^= du;
	co = qrc_intutils_rotl64(emu, 8);
	esa ^= da;
	cu = qrc_intutils_rotl64(esa, 18);
	aka = ca ^ ((!ce) & ci);
	ake = ce ^ ((!ci) & co);
	aki = ci ^ ((!co) & cu);
	ako = co ^ ((!cu) & ca);
	aku = cu ^ ((!ca) & ce);
	ebu ^= du;
	ca = qrc_intutils_rotl64(ebu, 27);
	ega ^= da;
	ce = qrc_intutils_rotl64(ega, 36);
	eke ^= de;
	ci = qrc_intutils_rotl64(eke, 10);
	emi ^= di;
	co = qrc_intutils_rotl64(emi, 15);
	eso ^= dz;
	cu = qrc_intutils_rotl64(eso, 56);
	ama = ca ^ ((!ce) & ci);
	ame = ce ^ ((!ci) & co);
	ami = ci ^ ((!co) & cu);
	amo = co ^ ((!cu) & ca);
	amu = cu ^ ((!ca) & ce);
	ebi ^= di;
	ca = qrc_intutils_rotl64(ebi, 62);
	ego ^= dz;
	ce = qrc_intutils_rotl64(ego, 55);
	eku ^= du;
	ci = qrc_intutils_rotl64(eku, 39);
	ema ^= da;
	co = qrc_intutils_rotl64(ema, 41);
	ese ^= de;
	cu = qrc_intutils_rotl64(ese, 2);
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
	da = cu ^ qrc_intutils_rotl64(ce, 1);
	de = ca ^ qrc_intutils_rotl64(ci, 1);
	di = ce ^ qrc_intutils_rotl64(co, 1);
	dz = ci ^ qrc_intutils_rotl64(cu, 1);
	du = co ^ qrc_intutils_rotl64(ca, 1);
	aba ^= da;
	ca = aba;
	age ^= de;
	ce = qrc_intutils_rotl64(age, 44);
	aki ^= di;
	ci = qrc_intutils_rotl64(aki, 43);
	amo ^= dz;
	co = qrc_intutils_rotl64(amo, 21);
	asu ^= du;
	cu = qrc_intutils_rotl64(asu, 14);
	eba = ca ^ ((!ce) & ci);
	eba ^= 0x8000000080008081;
	ebe = ce ^ ((!ci) & co);
	ebi = ci ^ ((!co) & cu);
	ebo = co ^ ((!cu) & ca);
	ebu = cu ^ ((!ca) & ce);
	abo ^= dz;
	ca = qrc_intutils_rotl64(abo, 28);
	agu ^= du;
	ce = qrc_intutils_rotl64(agu, 20);
	aka ^= da;
	ci = qrc_intutils_rotl64(aka, 3);
	ame ^= de;
	co = qrc_intutils_rotl64(ame, 45);
	asi ^= di;
	cu = qrc_intutils_rotl64(asi, 61);
	ega = ca ^ ((!ce) & ci);
	ege = ce ^ ((!ci) & co);
	egi = ci ^ ((!co) & cu);
	ego = co ^ ((!cu) & ca);
	egu = cu ^ ((!ca) & ce);
	abe ^= de;
	ca = qrc_intutils_rotl64(abe, 1);
	agi ^= di;
	ce = qrc_intutils_rotl64(agi, 6);
	ako ^= dz;
	ci = qrc_intutils_rotl64(ako, 25);
	amu ^= du;
	co = qrc_intutils_rotl64(amu, 8);
	asa ^= da;
	cu = qrc_intutils_rotl64(asa, 18);
	eka = ca ^ ((!ce) & ci);
	eke = ce ^ ((!ci) & co);
	eki = ci ^ ((!co) & cu);
	eko = co ^ ((!cu) & ca);
	eku = cu ^ ((!ca) & ce);
	abu ^= du;
	ca = qrc_intutils_rotl64(abu, 27);
	aga ^= da;
	ce = qrc_intutils_rotl64(aga, 36);
	ake ^= de;
	ci = qrc_intutils_rotl64(ake, 10);
	ami ^= di;
	co = qrc_intutils_rotl64(ami, 15);
	aso ^= dz;
	cu = qrc_intutils_rotl64(aso, 56);
	ema = ca ^ ((!ce) & ci);
	eme = ce ^ ((!ci) & co);
	emi = ci ^ ((!co) & cu);
	emo = co ^ ((!cu) & ca);
	emu = cu ^ ((!ca) & ce);
	abi ^= di;
	ca = qrc_intutils_rotl64(abi, 62);
	ago ^= dz;
	ce = qrc_intutils_rotl64(ago, 55);
	aku ^= du;
	ci = qrc_intutils_rotl64(aku, 39);
	ama ^= da;
	co = qrc_intutils_rotl64(ama, 41);
	ase ^= de;
	cu = qrc_intutils_rotl64(ase, 2);
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
	da = cu ^ qrc_intutils_rotl64(ce, 1);
	de = ca ^ qrc_intutils_rotl64(ci, 1);
	di = ce ^ qrc_intutils_rotl64(co, 1);
	dz = ci ^ qrc_intutils_rotl64(cu, 1);
	du = co ^ qrc_intutils_rotl64(ca, 1);
	eba ^= da;
	ca = eba;
	ege ^= de;
	ce = qrc_intutils_rotl64(ege, 44);
	eki ^= di;
	ci = qrc_intutils_rotl64(eki, 43);
	emo ^= dz;
	co = qrc_intutils_rotl64(emo, 21);
	esu ^= du;
	cu = qrc_intutils_rotl64(esu, 14);
	aba = ca ^ ((!ce) & ci);
	aba ^= 0x8000000000008080;
	abe = ce ^ ((!ci) & co);
	abi = ci ^ ((!co) & cu);
	abo = co ^ ((!cu) & ca);
	abu = cu ^ ((!ca) & ce);
	ebo ^= dz;
	ca = qrc_intutils_rotl64(ebo, 28);
	egu ^= du;
	ce = qrc_intutils_rotl64(egu, 20);
	eka ^= da;
	ci = qrc_intutils_rotl64(eka, 3);
	eme ^= de;
	co = qrc_intutils_rotl64(eme, 45);
	esi ^= di;
	cu = qrc_intutils_rotl64(esi, 61);
	aga = ca ^ ((!ce) & ci);
	age = ce ^ ((!ci) & co);
	agi = ci ^ ((!co) & cu);
	ago = co ^ ((!cu) & ca);
	agu = cu ^ ((!ca) & ce);
	ebe ^= de;
	ca = qrc_intutils_rotl64(ebe, 1);
	egi ^= di;
	ce = qrc_intutils_rotl64(egi, 6);
	eko ^= dz;
	ci = qrc_intutils_rotl64(eko, 25);
	emu ^= du;
	co = qrc_intutils_rotl64(emu, 8);
	esa ^= da;
	cu = qrc_intutils_rotl64(esa, 18);
	aka = ca ^ ((!ce) & ci);
	ake = ce ^ ((!ci) & co);
	aki = ci ^ ((!co) & cu);
	ako = co ^ ((!cu) & ca);
	aku = cu ^ ((!ca) & ce);
	ebu ^= du;
	ca = qrc_intutils_rotl64(ebu, 27);
	ega ^= da;
	ce = qrc_intutils_rotl64(ega, 36);
	eke ^= de;
	ci = qrc_intutils_rotl64(eke, 10);
	emi ^= di;
	co = qrc_intutils_rotl64(emi, 15);
	eso ^= dz;
	cu = qrc_intutils_rotl64(eso, 56);
	ama = ca ^ ((!ce) & ci);
	ame = ce ^ ((!ci) & co);
	ami = ci ^ ((!co) & cu);
	amo = co ^ ((!cu) & ca);
	amu = cu ^ ((!ca) & ce);
	ebi ^= di;
	ca = qrc_intutils_rotl64(ebi, 62);
	ego ^= dz;
	ce = qrc_intutils_rotl64(ego, 55);
	eku ^= du;
	ci = qrc_intutils_rotl64(eku, 39);
	ema ^= da;
	co = qrc_intutils_rotl64(ema, 41);
	ese ^= de;
	cu = qrc_intutils_rotl64(ese, 2);
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
	da = cu ^ qrc_intutils_rotl64(ce, 1);
	de = ca ^ qrc_intutils_rotl64(ci, 1);
	di = ce ^ qrc_intutils_rotl64(co, 1);
	dz = ci ^ qrc_intutils_rotl64(cu, 1);
	du = co ^ qrc_intutils_rotl64(ca, 1);
	aba ^= da;
	ca = aba;
	age ^= de;
	ce = qrc_intutils_rotl64(age, 44);
	aki ^= di;
	ci = qrc_intutils_rotl64(aki, 43);
	amo ^= dz;
	co = qrc_intutils_rotl64(amo, 21);
	asu ^= du;
	cu = qrc_intutils_rotl64(asu, 14);
	eba = ca ^ ((!ce) & ci);
	eba ^= 0x0000000080000001;
	ebe = ce ^ ((!ci) & co);
	ebi = ci ^ ((!co) & cu);
	ebo = co ^ ((!cu) & ca);
	ebu = cu ^ ((!ca) & ce);
	abo ^= dz;
	ca = qrc_intutils_rotl64(abo, 28);
	agu ^= du;
	ce = qrc_intutils_rotl64(agu, 20);
	aka ^= da;
	ci = qrc_intutils_rotl64(aka, 3);
	ame ^= de;
	co = qrc_intutils_rotl64(ame, 45);
	asi ^= di;
	cu = qrc_intutils_rotl64(asi, 61);
	ega = ca ^ ((!ce) & ci);
	ege = ce ^ ((!ci) & co);
	egi = ci ^ ((!co) & cu);
	ego = co ^ ((!cu) & ca);
	egu = cu ^ ((!ca) & ce);
	abe ^= de;
	ca = qrc_intutils_rotl64(abe, 1);
	agi ^= di;
	ce = qrc_intutils_rotl64(agi, 6);
	ako ^= dz;
	ci = qrc_intutils_rotl64(ako, 25);
	amu ^= du;
	co = qrc_intutils_rotl64(amu, 8);
	asa ^= da;
	cu = qrc_intutils_rotl64(asa, 18);
	eka = ca ^ ((!ce) & ci);
	eke = ce ^ ((!ci) & co);
	eki = ci ^ ((!co) & cu);
	eko = co ^ ((!cu) & ca);
	eku = cu ^ ((!ca) & ce);
	abu ^= du;
	ca = qrc_intutils_rotl64(abu, 27);
	aga ^= da;
	ce = qrc_intutils_rotl64(aga, 36);
	ake ^= de;
	ci = qrc_intutils_rotl64(ake, 10);
	ami ^= di;
	co = qrc_intutils_rotl64(ami, 15);
	aso ^= dz;
	cu = qrc_intutils_rotl64(aso, 56);
	ema = ca ^ ((!ce) & ci);
	eme = ce ^ ((!ci) & co);
	emi = ci ^ ((!co) & cu);
	emo = co ^ ((!cu) & ca);
	emu = cu ^ ((!ca) & ce);
	abi ^= di;
	ca = qrc_intutils_rotl64(abi, 62);
	ago ^= dz;
	ce = qrc_intutils_rotl64(ago, 55);
	aku ^= du;
	ci = qrc_intutils_rotl64(aku, 39);
	ama ^= da;
	co = qrc_intutils_rotl64(ama, 41);
	ase ^= de;
	cu = qrc_intutils_rotl64(ase, 2);
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
	da = cu ^ qrc_intutils_rotl64(ce, 1);
	de = ca ^ qrc_intutils_rotl64(ci, 1);
	di = ce ^ qrc_intutils_rotl64(co, 1);
	dz = ci ^ qrc_intutils_rotl64(cu, 1);
	du = co ^ qrc_intutils_rotl64(ca, 1);
	eba ^= da;
	ca = eba;
	ege ^= de;
	ce = qrc_intutils_rotl64(ege, 44);
	eki ^= di;
	ci = qrc_intutils_rotl64(eki, 43);
	emo ^= dz;
	co = qrc_intutils_rotl64(emo, 21);
	esu ^= du;
	cu = qrc_intutils_rotl64(esu, 14);
	aba = ca ^ ((!ce) & ci);
	aba ^= 0x8000000080008008;
	abe = ce ^ ((!ci) & co);
	abi = ci ^ ((!co) & cu);
	abo = co ^ ((!cu) & ca);
	abu = cu ^ ((!ca) & ce);
	ebo ^= dz;
	ca = qrc_intutils_rotl64(ebo, 28);
	egu ^= du;
	ce = qrc_intutils_rotl64(egu, 20);
	eka ^= da;
	ci = qrc_intutils_rotl64(eka, 3);
	eme ^= de;
	co = qrc_intutils_rotl64(eme, 45);
	esi ^= di;
	cu = qrc_intutils_rotl64(esi, 61);
	aga = ca ^ ((!ce) & ci);
	age = ce ^ ((!ci) & co);
	agi = ci ^ ((!co) & cu);
	ago = co ^ ((!cu) & ca);
	agu = cu ^ ((!ca) & ce);
	ebe ^= de;
	ca = qrc_intutils_rotl64(ebe, 1);
	egi ^= di;
	ce = qrc_intutils_rotl64(egi, 6);
	eko ^= dz;
	ci = qrc_intutils_rotl64(eko, 25);
	emu ^= du;
	co = qrc_intutils_rotl64(emu, 8);
	esa ^= da;
	cu = qrc_intutils_rotl64(esa, 18);
	aka = ca ^ ((!ce) & ci);
	ake = ce ^ ((!ci) & co);
	aki = ci ^ ((!co) & cu);
	ako = co ^ ((!cu) & ca);
	aku = cu ^ ((!ca) & ce);
	ebu ^= du;
	ca = qrc_intutils_rotl64(ebu, 27);
	ega ^= da;
	ce = qrc_intutils_rotl64(ega, 36);
	eke ^= de;
	ci = qrc_intutils_rotl64(eke, 10);
	emi ^= di;
	co = qrc_intutils_rotl64(emi, 15);
	eso ^= dz;
	cu = qrc_intutils_rotl64(eso, 56);
	ama = ca ^ ((!ce) & ci);
	ame = ce ^ ((!ci) & co);
	ami = ci ^ ((!co) & cu);
	amo = co ^ ((!cu) & ca);
	amu = cu ^ ((!ca) & ce);
	ebi ^= di;
	ca = qrc_intutils_rotl64(ebi, 62);
	ego ^= dz;
	ce = qrc_intutils_rotl64(ego, 55);
	eku ^= du;
	ci = qrc_intutils_rotl64(eku, 39);
	ema ^= da;
	co = qrc_intutils_rotl64(ema, 41);
	ese ^= de;
	cu = qrc_intutils_rotl64(ese, 2);
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

/*
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
pub fn qrc_keccak_squeezeblocks(ctx: &mut QrcKeccakState, mut output: &mut [u8], mut nblocks: usize, rate: usize , rounds: usize) {
	while nblocks > 0 {
		qrc_keccak_permute(ctx, rounds, false);

		if QRC_SYSTEM_IS_LITTLE_ENDIAN {
			qrc_intutils_copy8(output, &qrc_intutils_transform_64to8(&ctx.state), rate);
		} else {
			for i in 0..(rate >> 3)	{
				qrc_intutils_le64to8(&mut output[(size_of::<u64>() * i)..], ctx.state[i]);
			}
		}
		output = &mut output[rate..];
		nblocks -= 1;
	}

}

/*
* \brief Initializes a Keccak state structure, must be called before message processing.
* Long form api: must be used in conjunction with the block-update and finalize functions.
*
* \param ctx: [struct] A reference to the Keccak state; must be initialized
*/
pub fn qrc_keccak_initialize_state(ctx: &mut QrcKeccakState) {
	qrc_intutils_clear64(&mut ctx.state, QRC_KECCAK_STATE_SIZE);
	qrc_intutils_clear8(&mut ctx.buffer, QRC_KECCAK_STATE_BYTE_SIZE);
	ctx.position = 0;
}

/*
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
pub fn qrc_keccak_update(ctx: &mut QrcKeccakState, rate: usize, mut message: &[u8], mut msglen: usize, rounds: usize) {
	if !message.is_empty() && msglen != 0 {
		if ctx.position != 0 && ctx.position + msglen >= rate {
			let rmdlen: usize = rate - ctx.position;

			if rmdlen != 0 {
				qrc_intutils_copy8(&mut ctx.buffer[ctx.position..], message, rmdlen);
			}

			keccak_fast_absorb(&mut ctx.state, &ctx.buffer, rate);
			qrc_keccak_permute(ctx, rounds, false);
			ctx.position = 0;
			message = &message[rmdlen..];
			msglen -= rmdlen;
		}

		/* sequential loop through blocks */
		while msglen >= rate {
			keccak_fast_absorb(&mut ctx.state, message, rate);
			qrc_keccak_permute(ctx, rounds, false);
			message = &message[rate..];
			msglen -= rate;
		}

		/* store unaligned bytes */
		if msglen != 0 {
			qrc_intutils_copy8(&mut ctx.buffer[ctx.position..], message, msglen);
			ctx.position = ctx.position + msglen;
		}
	}
}
/* SHA3 */

/*
* \brief Process a message with SHA3-128 and return the hash code in the output byte array.
* Short form api: processes the entire message and computes the hash code with a single call.
*
* \warning The output array must be at least 16 bytes in length.
*
* \param output:: The output byte array; receives the hash code
* \param message: [const] The message input byte array
* \param msglen: The number of message bytes to process
*/
pub fn qrc_sha3_compute128(output: &mut [u8], message: &[u8], msglen: usize) {

	let ctx = &mut QrcKeccakState::default();
	let hash = &mut [0u8; QRC_KECCAK_128_RATE];

	let rate = QrcKeccakRate::QrcKeccakRate128 as usize;

	qrc_sha3_initialize(ctx);
	qrc_keccak_absorb(ctx, rate, message, msglen, QRC_KECCAK_SHA3_DOMAIN_ID, QRC_KECCAK_PERMUTATION_ROUNDS);
	qrc_keccak_squeezeblocks(ctx, hash, 1, rate, QRC_KECCAK_PERMUTATION_ROUNDS);
	qrc_intutils_copy8(output, hash, QRC_SHA3_128_HASH_SIZE);
	qrc_keccak_dispose(ctx);
}

/*
* \brief Process a message with SHA3-256 and return the hash code in the output byte array.
* Short form api: processes the entire message and computes the hash code with a single call.
*
* \warning The output array must be at least 32 bytes in length.
*
* \param output:: The output byte array; receives the hash code
* \param message: [const] The message input byte array
* \param msglen: The number of message bytes to process
*/
pub fn qrc_sha3_compute256(output: &mut [u8], message: &[u8], msglen: usize) {
	let ctx = &mut QrcKeccakState::default();
	let hash = &mut [0u8; QRC_KECCAK_256_RATE];

	let rate = QrcKeccakRate::QrcKeccakRate256 as usize;

	qrc_sha3_initialize(ctx);
	qrc_keccak_absorb(ctx, rate, message, msglen, QRC_KECCAK_SHA3_DOMAIN_ID, QRC_KECCAK_PERMUTATION_ROUNDS);
	qrc_keccak_squeezeblocks(ctx, hash, 1, rate, QRC_KECCAK_PERMUTATION_ROUNDS);
	qrc_intutils_copy8(output, hash, QRC_SHA3_256_HASH_SIZE);
	qrc_keccak_dispose(ctx);
}

/*
* \brief Process a message with SHA3-512 and return the hash code in the output byte array.
* Short form api: processes the entire message and computes the hash code with a single call.
*
* \warning The output array must be at least 64 bytes in length.
*
* \param output: The output byte array; receives the hash code
* \param message: [const] The message input byte array
* \param msglen: The number of message bytes to process
*/
pub fn qrc_sha3_compute512(output: &mut [u8], message: &[u8], msglen: usize) {
	let ctx = &mut QrcKeccakState::default();
	let hash = &mut [0u8; QRC_KECCAK_512_RATE];

	let rate = QrcKeccakRate::QrcKeccakRate512 as usize;

	qrc_sha3_initialize(ctx);
	qrc_keccak_absorb(ctx, rate, message, msglen, QRC_KECCAK_SHA3_DOMAIN_ID, QRC_KECCAK_PERMUTATION_ROUNDS);
	qrc_keccak_squeezeblocks(ctx, hash, 1, rate, QRC_KECCAK_PERMUTATION_ROUNDS);
	qrc_intutils_copy8(output, hash, QRC_SHA3_512_HASH_SIZE);
	qrc_keccak_dispose(ctx);
}

/*
* \brief Finalize the message state and returns the hash value in output.
* Long form api: must be used in conjunction with the initialize and block-update functions.
* Absorb the last block of message and create the hash value.
* Produces a 32 byte output code using QRC_KECCAK_256_RATE, 64 bytes with QRC_KECCAK_512_RATE.
*
* \warning The output array must be sized correctly corresponding to the absorption rate ((200 - rate) / 2).
* Finalizes the message state, can not be used in consecutive calls.
* The state must be initialized before calling.
*
* \param ctx: [struct] A reference to the Keccak state; must be initialized
* \param rate: The rate of absorption in bytes
* \param output: The output byte array; receives the hash code
*/
pub fn qrc_sha3_finalize(ctx: &mut QrcKeccakState, rate: usize, mut output: &mut [u8]) {

	let hlen = ((QRC_KECCAK_STATE_SIZE * size_of::<u64>()) - rate) / 2;
	qrc_intutils_clear8(&mut ctx.buffer[ctx.position..], QRC_KECCAK_STATE_BYTE_SIZE-ctx.position);

	ctx.buffer[ctx.position] = QRC_KECCAK_SHA3_DOMAIN_ID;
	ctx.buffer[rate - 1] |= 128;

	keccak_fast_absorb(&mut ctx.state, &ctx.buffer, rate);
	qrc_keccak_permute(ctx, QRC_KECCAK_PERMUTATION_ROUNDS, false);

	if QRC_SYSTEM_IS_LITTLE_ENDIAN {
		qrc_intutils_copy8(output, &qrc_intutils_transform_64to8(&ctx.state), hlen);
	} else {
		for i in 0..(hlen / size_of::<u64>()) {
			qrc_intutils_le64to8(output, ctx.state[i]);
			output = &mut output[(size_of::<u64>())..];
		}
	}

	qrc_keccak_dispose(ctx);
}

/*
* \brief Initialize the SHA3 state
* Long form api: Must be called before the update or finalize functions are called.
*
* \param ctx: [struct] A reference to the Keccak state
*/
pub fn qrc_sha3_initialize(ctx: &mut QrcKeccakState) {
	qrc_keccak_initialize_state(ctx);
}

/*
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
pub fn qrc_sha3_update(ctx: &mut QrcKeccakState, rate: usize, message: &[u8], msglen: usize) {
	qrc_keccak_update(ctx, rate, message, msglen, QRC_KECCAK_PERMUTATION_ROUNDS);
}

/* SHAKE */

/*
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
pub fn qrc_shake128_compute(mut output: &mut [u8], mut outlen: usize, key: &[u8], keylen: usize) {
	let nblocks = outlen / QRC_KECCAK_128_RATE;
	let mut ctx: QrcKeccakState = Default::default();
	let mut hash = [0u8; QRC_KECCAK_128_RATE];

	let rate = QrcKeccakRate::QrcKeccakRate128 as usize;
	qrc_shake_initialize(&mut ctx, rate, key, keylen);
	qrc_shake_squeezeblocks(&mut ctx, rate, &mut output, nblocks);
	output = &mut output[(nblocks * QRC_KECCAK_128_RATE)..];
	outlen -= nblocks * QRC_KECCAK_128_RATE;

	if outlen != 0 {
		qrc_shake_squeezeblocks(&mut ctx, rate, &mut hash, 1);
		qrc_intutils_copy8(&mut output, &hash, outlen);
	}

	qrc_keccak_dispose(&mut ctx);
}

/*
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
pub fn qrc_shake256_compute(mut output: &mut [u8], mut outlen: usize, key: &[u8], keylen: usize) {
	let nblocks = outlen / QRC_KECCAK_256_RATE;
	let ctx = &mut QrcKeccakState::default();
	let hash = &mut [0u8; QRC_KECCAK_256_RATE];

	let rate = QrcKeccakRate::QrcKeccakRate256 as usize;
	qrc_shake_initialize(ctx, rate, key, keylen);
	qrc_shake_squeezeblocks(ctx, rate, output, nblocks);
	output = &mut output[(nblocks * QRC_KECCAK_256_RATE)..];
	outlen -= nblocks * QRC_KECCAK_256_RATE;
	

	if outlen != 0 {
		qrc_shake_squeezeblocks(ctx, rate, hash, 1);
		qrc_intutils_copy8(output, hash, outlen);
	}

	qrc_keccak_dispose(ctx);
}

/*
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
pub fn qrc_shake512_compute(mut output: &mut [u8], mut outlen: usize, key: &[u8], keylen: usize) {
	let nblocks: usize = outlen / QRC_KECCAK_512_RATE;
	let mut ctx: QrcKeccakState = Default::default();
	let mut hash = [0u8; QRC_KECCAK_512_RATE];

	let rate = QrcKeccakRate::QrcKeccakRate512 as usize;
	qrc_shake_initialize(&mut ctx, rate, key, keylen);
	qrc_shake_squeezeblocks(&mut ctx, rate, &mut output, nblocks);
	output = &mut output[(nblocks * QRC_KECCAK_512_RATE)..];
	outlen -= nblocks * QRC_KECCAK_512_RATE;

	if outlen != 0 {
		qrc_shake_squeezeblocks(&mut ctx, rate, &mut hash, 1);
		qrc_intutils_copy8(&mut output, &hash, outlen);
	}

	qrc_keccak_dispose(&mut ctx);
}

/*
* \brief The SHAKE initialize function.
* Long form api: must be used in conjunction with the squeezeblocks function.
* Absorb and finalize an input key byte array.
*
* \param ctx: [struct] A reference to the Keccak state; must be initialized
* \param rate: The rate of absorption in bytes
* \param key: [const] The input key byte array
* \param keylen: The number of key bytes to process
*/
pub fn qrc_shake_initialize(ctx: &mut QrcKeccakState, rate: usize, key: &[u8], keylen: usize) {
	qrc_keccak_initialize_state(ctx);
	qrc_keccak_absorb(ctx, rate, key, keylen, QRC_KECCAK_SHAKE_DOMAIN_ID, QRC_KECCAK_PERMUTATION_ROUNDS);
}
/*
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
pub fn qrc_shake_squeezeblocks(ctx: &mut QrcKeccakState, rate: usize, output: &mut [u8], nblocks: usize) {
	qrc_keccak_squeezeblocks(ctx, output, nblocks, rate, QRC_KECCAK_PERMUTATION_ROUNDS);
}
/* cSHAKE */

/*
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
pub fn qrc_cshake128_compute(mut output: &mut [u8], mut outlen: usize, key: &[u8], keylen: usize, name: &[u8], namelen: usize, custom: &[u8], custlen: usize) {
	let nblocks: usize = outlen / QRC_KECCAK_128_RATE;
	let mut ctx: QrcKeccakState = Default::default();
	let mut hash = [0u8; QRC_KECCAK_128_RATE];

	let rate = QrcKeccakRate::QrcKeccakRate128 as usize;
	if custlen + namelen != 0 {
		qrc_cshake_initialize(&mut ctx, rate, key, keylen, name, namelen, custom, custlen);
	} else {
		qrc_shake_initialize(&mut ctx, rate, key, keylen);
	}

	qrc_cshake_squeezeblocks(&mut ctx, rate, &mut output, nblocks);
	output = &mut output[(nblocks * QRC_KECCAK_128_RATE)..];
	outlen -= nblocks * QRC_KECCAK_128_RATE;

	if outlen != 0 {
		qrc_cshake_squeezeblocks(&mut ctx, rate, &mut hash, 1);
		qrc_intutils_copy8(output, &hash, outlen);
	}

	qrc_keccak_dispose(&mut ctx);
}

/*
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
pub fn qrc_cshake256_compute(mut output: &mut [u8], mut outlen: usize, key: &[u8], keylen: usize, name: &[u8], namelen: usize, custom: &[u8], custlen: usize) {
	let nblocks: usize = outlen / QRC_KECCAK_256_RATE;
	let mut ctx: QrcKeccakState = Default::default();
	let mut hash = [0u8; QRC_KECCAK_256_RATE];

	let rate = QrcKeccakRate::QrcKeccakRate256 as usize;
	if custlen + namelen != 0 {
		qrc_cshake_initialize(&mut ctx, rate, key, keylen, name, namelen, custom, custlen);
	} else {
		qrc_shake_initialize(&mut ctx, rate, key, keylen);
	}

	qrc_cshake_squeezeblocks(&mut ctx, rate, &mut output, nblocks);

	output = &mut output[(nblocks * QRC_KECCAK_256_RATE)..];
	outlen -= nblocks * QRC_KECCAK_256_RATE;

	if outlen != 0 {
		qrc_cshake_squeezeblocks(&mut ctx, rate, &mut hash, 1);
		qrc_intutils_copy8(output, &hash, outlen);
	}

	qrc_keccak_dispose(&mut ctx);
}

/*
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
pub fn qrc_cshake512_compute(mut output: &mut [u8], mut outlen: usize, key: &[u8], keylen: usize, name: &[u8], namelen: usize, custom: &[u8], custlen: usize) {
	let nblocks: usize = outlen / QRC_KECCAK_512_RATE;
	let ctx = &mut QrcKeccakState::default();

	let hash = &mut [0u8; QRC_KECCAK_512_RATE];

	let rate = QrcKeccakRate::QrcKeccakRate512 as usize;
	if custlen + namelen != 0 {
		qrc_cshake_initialize(ctx, rate, key, keylen, name, namelen, custom, custlen);
	} else {
		qrc_shake_initialize(ctx, rate, key, keylen);
	}

	qrc_cshake_squeezeblocks(ctx, rate, output, nblocks);
	output = &mut output[(nblocks * QRC_KECCAK_512_RATE)..];
	outlen -= nblocks * QRC_KECCAK_512_RATE;

	if outlen != 0 {
		qrc_cshake_squeezeblocks(ctx, rate, hash, 1);
		qrc_intutils_copy8(output, hash, outlen);
	}

	qrc_keccak_dispose(ctx);
}
/*
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
pub fn qrc_cshake_initialize(ctx: &mut QrcKeccakState, rate: usize, key: &[u8], keylen: usize, name: &[u8], namelen: usize, custom: &[u8], custlen: usize) {
	qrc_keccak_initialize_state(ctx);
	/* absorb the custom and name arrays */
	qrc_keccak_absorb_custom(ctx, rate, custom, custlen, name, namelen, QRC_KECCAK_PERMUTATION_ROUNDS);
	/* finalize the key */
	qrc_keccak_absorb(ctx, rate, key, keylen, QRC_KECCAK_CSHAKE_DOMAIN_ID, QRC_KECCAK_PERMUTATION_ROUNDS);
}
/*
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
pub fn qrc_cshake_squeezeblocks(ctx: &mut QrcKeccakState, rate: usize, output: &mut [u8], nblocks: usize) {
	qrc_keccak_squeezeblocks(ctx, output, nblocks, rate, QRC_KECCAK_PERMUTATION_ROUNDS);
}
/*
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
pub fn qrc_cshake_update(ctx: &mut QrcKeccakState, rate: usize, mut key: &mut [u8], mut keylen: usize) {
	while keylen >= rate {
		keccak_fast_absorb(&mut ctx.state, key, keylen);
		qrc_keccak_permute(ctx, QRC_KECCAK_PERMUTATION_ROUNDS, false);
		keylen -= rate;
		key = &mut key[rate..];
	}

	if keylen != 0 {
		keccak_fast_absorb(&mut ctx.state, key, keylen);
		qrc_keccak_permute(ctx, QRC_KECCAK_PERMUTATION_ROUNDS, false);
	}
}

/* KMAC */

/*
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
pub fn qrc_kmac128_compute(mut output: &mut [u8], outlen: usize, mut message: &mut [u8], msglen: usize, mut key: &mut [u8], keylen: usize, mut custom: &mut [u8], custlen: usize) {
	let mut ctx: QrcKeccakState = Default::default();

	let rate = QrcKeccakRate::QrcKeccakRate128 as usize;
	qrc_kmac_initialize(&mut ctx, rate, &mut key, keylen, &mut custom, custlen);
	qrc_kmac_update(&mut ctx, rate, &mut message, msglen);
	qrc_kmac_finalize(&mut ctx, rate, &mut output, outlen);
}

/*
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
pub fn qrc_kmac256_compute(output: &mut [u8], outlen: usize, message: &[u8], msglen: usize, key: &mut [u8], keylen: usize, custom: &mut [u8], custlen: usize) {
	let ctx = &mut QrcKeccakState::default();

	let rate = QrcKeccakRate::QrcKeccakRate256 as usize;
	qrc_kmac_initialize(ctx, rate, key, keylen, custom, custlen);
	qrc_kmac_update(ctx, rate, message, msglen);
	qrc_kmac_finalize(ctx, rate, output, outlen);
}

/*
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
pub fn qrc_kmac512_compute(output: &mut [u8], outlen: usize, message: &[u8], msglen: usize, key: &mut [u8], keylen: usize, custom: &mut [u8], custlen: usize) {
	let ctx = &mut QrcKeccakState::default();

	let rate = QrcKeccakRate::QrcKeccakRate512 as usize;
	qrc_kmac_initialize(ctx, rate, key, keylen, custom, custlen);
	qrc_kmac_update(ctx, rate, message, msglen);
	qrc_kmac_finalize(ctx, rate, output, outlen);
}

/*
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
pub fn qrc_kmac_finalize(ctx: &mut QrcKeccakState, rate: usize, output: &mut [u8], outlen: usize) {
	qrc_keccak_finalize(ctx, rate, output, outlen, QRC_KECCAK_KMAC_DOMAIN_ID as usize, QRC_KECCAK_PERMUTATION_ROUNDS);
}

/*
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
pub fn qrc_kmac_initialize(ctx: &mut QrcKeccakState, rate: usize, key: &mut [u8], keylen: usize, custom: &mut [u8], custlen: usize) {
	let name: [u8; 4] = [ 0x4B, 0x4D, 0x41, 0x43 ];

	qrc_keccak_absorb_key_custom(ctx, rate, key, keylen, custom, custlen, &name, 4, QRC_KECCAK_PERMUTATION_ROUNDS);
}

/*
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
pub fn qrc_kmac_update(ctx: &mut QrcKeccakState, rate: usize, message: &[u8], msglen: usize) {
	qrc_keccak_update(ctx, rate, message, msglen, QRC_KECCAK_PERMUTATION_ROUNDS);
}

/* KPA - Keccak-based Parallel Authentication */

/*
* \def QRC_KPA_128_KEY_SIZE
* \brief The KPA-128 key size in bytes
*/
pub const QRC_KPA_128_KEY_SIZE: usize = 16;

/*
* \def QRC_KPA_256_KEY_SIZE
* \brief The KPA-256 key size in bytes
*/
pub const QRC_KPA_256_KEY_SIZE: usize = 32;

/*
* \def QRC_KPA_512_KEY_SIZE
* \brief The KPA-512 key size in bytes
*/
pub const QRC_KPA_512_KEY_SIZE: usize = 64;

/*
* \def QRC_KPA_ROUNDS
* \brief The number of Keccak rounds used by a KPA permutation
*/
pub const QRC_KPA_ROUNDS: usize = 12;

/*
* \def QRC_KPA_PARALLELISM
* \brief The KPA degree of parallelization
*/
pub const QRC_KPA_PARALLELISM: usize = 8;

/*
* \struct qrc_kpa_state
* \brief The KPA state array; state array must be initialized by the caller
*/
#[derive(PartialEq, Clone)]
pub struct QrcKpaState {
	pub state: [[u64; QRC_KECCAK_STATE_SIZE]; QRC_KPA_PARALLELISM],			/*< The long state array  */
	pub buffer: [u8; QRC_KPA_PARALLELISM * QRC_KECCAK_STATE_BYTE_SIZE],		/*< The message buffer  */
	pub position: usize,								/*< The buffer position  */
	pub processed: usize,								/*< The number of message bytes processed  */
	pub rate: QrcKeccakRate,							/*< The absorption rate  */
}
impl Default for QrcKpaState {
    fn default() -> Self {
        Self {
			state: [[Default::default(); QRC_KECCAK_STATE_SIZE]; QRC_KPA_PARALLELISM],
            buffer: [Default::default(); QRC_KPA_PARALLELISM * QRC_KECCAK_STATE_BYTE_SIZE],
			position: Default::default(),
			processed: Default::default(),
			rate: QrcKeccakRate::QrcKeccakRateNone,
        }
    }
}

/*
* \brief The KPA finalize function.
* Long form api: must be used in conjunction with the initialize and blockupdate functions.
* Final processing and calculation of the MAC code.
*
* \warning The state must be initialized before calling.
*
* \param ctx: [struct] A reference to the Keccak state; must be initialized
* \param output: The output byte array
* \param outlen: The number of bytes to extract
*/
pub fn qrc_kpa_finalize(ctx: &mut QrcKpaState, mut output: &mut [u8], mut outlen: usize) {
	let hashlen = if ctx.rate == QrcKeccakRate::QrcKeccakRate512 {
	KPA_LEAF_HASH512 } else if ctx.rate == QrcKeccakRate::QrcKeccakRate256 {
	KPA_LEAF_HASH256 } else { KPA_LEAF_HASH128 };
	let rate = ctx.rate as usize;

	let fbuf = &mut [0u8; QRC_KPA_PARALLELISM * KPA_LEAF_HASH512];
	let pstate = &mut [0u64; QRC_KECCAK_STATE_SIZE];
	let prcb = &mut [0u8; 2 * size_of::<u64>()];


	/* clear unused buffer */
	if ctx.position != 0 {
		qrc_intutils_clear8(&mut ctx.buffer[ctx.position..], (QRC_KPA_PARALLELISM * QRC_KECCAK_STATE_BYTE_SIZE)-ctx.position);
		let ctx_message = &ctx.buffer.clone();
		kpa_fast_absorbx8(ctx, ctx_message);
		kpa_permutex8(ctx);
	}

	/* set processed counter to final position */
	ctx.processed += ctx.position;

	/* collect leaf node hashes */
	for i in 0..QRC_KPA_PARALLELISM {
		/* copy each of the leaf hashes to the buffer */
		qrc_intutils_copy8(&mut fbuf[i * hashlen..], &qrc_intutils_transform_64to8(&ctx.state[i]), hashlen);
	}

	/* absorb the leaves into the root state and permute */
	kpa_absorb_leaves(pstate, rate, fbuf, QRC_KPA_PARALLELISM * hashlen);

	/* clear buffer */
	qrc_intutils_clear8(&mut ctx.buffer, QRC_KPA_PARALLELISM * QRC_KECCAK_STATE_BYTE_SIZE);

	/* add total processed bytes and output length to padding string */
	let mut bitlen = keccak_right_encode(prcb, outlen * 8);
	bitlen += keccak_right_encode(&mut prcb[bitlen..], ctx.processed * 8);
	/* copy to buffer */
	qrc_intutils_copy8(&mut ctx.buffer, prcb, bitlen);

	/* add the domain id */
	ctx.buffer[bitlen] = QRC_KECCAK_KPA_DOMAIN_ID;
	/* clamp the last byte */
	ctx.buffer[rate - 1] |= 128;

	/* absorb the buffer into parent state */
	keccak_fast_absorb(pstate, &ctx.buffer, rate);

	/* squeeze blocks to produce the output hash */
	while outlen >= rate {
		kpa_squeezeblocks(pstate, &mut ctx.buffer, 1, rate);
		qrc_intutils_copy8(output, &ctx.buffer, rate);
		output = &mut output[rate..];
		outlen -= rate;
	}

	/* add unaligned hash bytes */
	if outlen > 0 {
		kpa_squeezeblocks(pstate, &mut ctx.buffer, 1, rate);
		qrc_intutils_copy8(output, &ctx.buffer, outlen);
	}

	/* reset the buffer and counters */
	qrc_intutils_clear8(&mut ctx.buffer, QRC_KPA_PARALLELISM * QRC_KECCAK_STATE_BYTE_SIZE);
	ctx.position = 0;
	ctx.processed = 0;
}

/*
* \brief Initialize a KPA instance.
* Long form api: must be used in conjunction with the blockupdate and finalize functions.
* Key the MAC generator and initialize the internal state.
*
* \param ctx: [struct] A reference to the Keccak state; must be initialized
* \param key: [const] The input key byte array
* \param keylen: The number of key bytes to process
* \param custom: [const] The customization string
* \param custlen: The byte length of the customization string
*/
pub fn qrc_kpa_initialize(ctx: &mut QrcKpaState, key: &[u8], keylen: usize, custom: &[u8], custlen: usize) {
	let tmps = &mut [0u64; QRC_KECCAK_STATE_SIZE];
	let pad = &mut [0u8; QRC_KECCAK_STATE_BYTE_SIZE];
	let algb = &mut [0x00, 0x00, 0x4B, 0x42, 0x41, 0xAD, 0x31, 0x32];

	/* set state values */
	ctx.position = 0;
	ctx.processed = 0;
	ctx.rate = if keylen == QRC_KPA_128_KEY_SIZE {
	QrcKeccakRate::QrcKeccakRate128 } else if keylen == QRC_KPA_256_KEY_SIZE {
	QrcKeccakRate::QrcKeccakRate256 } else if keylen == QRC_KPA_512_KEY_SIZE { 
	QrcKeccakRate::QrcKeccakRate512 } else { QrcKeccakRate::QrcKeccakRateNone };
	let rate = ctx.rate as usize;


	for i in 0..QRC_KPA_PARALLELISM {
		qrc_intutils_clear64(&mut ctx.state[i], QRC_KECCAK_STATE_SIZE);
	}
	qrc_intutils_clear8(&mut ctx.buffer, QRC_KPA_PARALLELISM * QRC_KECCAK_STATE_BYTE_SIZE);

	/* stage 1: add customization to state */
	if custlen != 0 {
		let mut oft = keccak_left_encode(pad, rate);
		oft += keccak_left_encode(&mut pad[oft..], custlen * 8);

		for i in 0..custlen {
			if oft == rate {
				keccak_fast_absorb(tmps, pad, rate);
				qrc_keccak_permute_p1600c(tmps, QRC_KPA_ROUNDS);
				oft = 0;
			}

			pad[oft] = custom[i];
			oft += 1;
		}

		if oft != 0 {
			/* absorb custom and name, and permute state */
			qrc_intutils_clear8(&mut pad[oft..], 200-oft);
			keccak_fast_absorb(tmps, pad, rate);
			qrc_keccak_permute_p1600c(tmps, QRC_KPA_ROUNDS);
		}
	}

	/* stage 2: add key to state  */

	if keylen != 0 {
		qrc_intutils_clear8(pad, 200);
		let mut oft = keccak_left_encode(pad, rate);
		oft += keccak_left_encode(&mut pad[oft..], keylen * 8);

		for i in 0..keylen {
			if oft == rate {
				keccak_fast_absorb(tmps, pad, rate);
				qrc_keccak_permute_p1600c(tmps, QRC_KPA_ROUNDS);
				oft = 0;
			}

			pad[oft] = key[i];
			oft += 1;
		}

		if oft != 0 {
			/* absorb the key and permute the state */
			qrc_intutils_clear8(&mut pad[oft..], 200-oft);
			keccak_fast_absorb(tmps, pad, rate);
			qrc_keccak_permute_p1600c(tmps, QRC_KPA_ROUNDS);
		}
	}

	/* stage 3: copy state to leaf nodes, and add leaf-unique name string */
	for i in 0..QRC_KPA_PARALLELISM {
		/* store the state index to the algorithm name */
		qrc_intutils_be16to8(algb, i as u16 + 1);
		/* copy the name to a 64-bit integer */
		let algn = qrc_intutils_be8to64(algb);
		/* copy the state to each leaf node */
		qrc_intutils_copy64(&mut ctx.state[i], tmps, QRC_KECCAK_STATE_SIZE);
		/* absorb the leafs unique index name */
		ctx.state[i][0] ^= algn;
	}

	/* permute leaf nodes */
	kpa_permutex8(ctx);
}

/*
* \brief The KPA message update function.
* Long form api: must be used in conjunction with the initialize and finalize functions.
*
* \warning The state must be initialized before calling.
*
* \param ctx: [struct] A reference to the Keccak state; must be initialized
* \param message: [const] The message input byte array
* \param msglen: The number of message bytes to process
*/
pub fn qrc_kpa_update(ctx: &mut QrcKpaState, mut message: &[u8], mut msglen: usize) {
	let blklen = ctx.rate as usize * QRC_KPA_PARALLELISM;

	if msglen != 0 {
		if ctx.position != 0 && (ctx.position + msglen >= blklen) {
			let rmdlen = blklen - ctx.position;

			if rmdlen != 0 {
				qrc_intutils_copy8(&mut ctx.buffer[ctx.position..], message, rmdlen);
			}
			let ctx_message = &ctx.buffer.clone();
			kpa_fast_absorbx8(ctx, ctx_message);
			kpa_permutex8(ctx);
			ctx.processed += ctx.rate as usize * QRC_KPA_PARALLELISM;
			ctx.position = 0;
			message = &message[rmdlen..];
			msglen -= rmdlen;
		}

		/* sequential loop through blocks */
		while msglen >= blklen {
			kpa_fast_absorbx8(ctx, message);
			kpa_permutex8(ctx);
			ctx.processed += ctx.rate as usize * QRC_KPA_PARALLELISM;
			message = &message[blklen..];
			msglen -= blklen;
		}

		/* store unaligned bytes */
		if msglen != 0 {
			qrc_intutils_copy8(&mut ctx.buffer[ctx.position..], message, msglen);
			ctx.position += msglen;
		}
	}
}

/*
* \brief Dispose of the KPA state.
*
* \warning The dispose function must be called when disposing of the function state.
* This function safely destroys the internal state.
*
* \param ctx: [struct] The Keccak state structure
*/
pub fn qrc_kpa_dispose(ctx: &mut QrcKpaState) {
	for i in 0..QRC_KPA_PARALLELISM {
		qrc_intutils_clear64(&mut ctx.state[i], QRC_KECCAK_STATE_SIZE);
	}
	qrc_intutils_clear8(&mut ctx.buffer, QRC_KPA_PARALLELISM * QRC_KECCAK_STATE_BYTE_SIZE);
	ctx.position = 0;
	ctx.processed = 0;
	ctx.rate = QrcKeccakRate::QrcKeccakRateNone;
}

const KPA_LEAF_HASH128: usize = 16;
const KPA_LEAF_HASH256: usize = 32;
const KPA_LEAF_HASH512: usize = 64;

/* keccak round constants */
const KECCAK_ROUND_CONSTANTS: [u64; QRC_KECCAK_PERMUTATION_MAX_ROUNDS] =
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
	if QRC_SYSTEM_IS_LITTLE_ENDIAN {	
		let mut state_slice = qrc_intutils_transform_64to8(state);
		qrc_intutils_xor(&mut state_slice, message, msglen);
		qrc_intutils_copy64(state, &qrc_intutils_transform_8to64(&state_slice), QRC_KECCAK_STATE_SIZE);
	} else {
		for i in 0..(msglen/size_of::<u64>()) {
			state[i] ^= qrc_intutils_le8to64(&message[(size_of::<u64>() * i)..]);
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

/* KPA */

fn kpa_absorb_leaves(state: &mut [u64], rate: usize, mut input: &[u8], mut inplen: usize) {
	while inplen >= rate {
		if QRC_SYSTEM_IS_LITTLE_ENDIAN {
			let mut state_slice = qrc_intutils_transform_64to8(state);
			qrc_intutils_xor(&mut state_slice, input, rate);
			qrc_intutils_copy64(state, &qrc_intutils_transform_8to64(&state_slice), QRC_KECCAK_STATE_SIZE);
		} else {
				for i in 0..rate / size_of::<u64>() {
					state[i] ^= qrc_intutils_le8to64(&input[size_of::<u64>() * i..]);
				}
		}
		qrc_keccak_permute_p1600c(state, QRC_KPA_ROUNDS);
		inplen -= rate;
		input = &input[rate..];
	}

	if inplen != 0 {
		if QRC_SYSTEM_IS_LITTLE_ENDIAN {
			let mut state_slice = qrc_intutils_transform_64to8(state);
			qrc_intutils_xor(&mut state_slice, input, inplen);
			qrc_intutils_copy64(state, &qrc_intutils_transform_8to64(&state_slice), QRC_KECCAK_STATE_SIZE);
		} else {
			for i in 0..inplen / size_of::<u64>() {
				state[i] ^= qrc_intutils_le8to64(&input[(size_of::<u64>() * i)..]);
			}
		}

		qrc_keccak_permute_p1600c(state, QRC_KPA_ROUNDS);
	}
}

fn kpa_fast_absorbx8(ctx: &mut QrcKpaState, message: &[u8]) {
	let rate = ctx.rate as usize;
	for i in 0..QRC_KPA_PARALLELISM {
		if QRC_SYSTEM_IS_LITTLE_ENDIAN {
			let mut state_slice = qrc_intutils_transform_64to8(&mut ctx.state[i]);
			qrc_intutils_xor(&mut state_slice, &message[i * rate..], rate);
			qrc_intutils_copy64(&mut ctx.state[i], &qrc_intutils_transform_8to64(&state_slice), QRC_KECCAK_STATE_SIZE);
		} else {
			for j in 0..rate as usize / size_of::<u64>()	{
				ctx.state[i][j] ^= qrc_intutils_le8to64(&message[(i * rate) + (j * size_of::<u64>())..]);
			}
		}
	}
}

fn kpa_permutex8(ctx: &mut QrcKpaState) {
	for i in 0..QRC_KPA_PARALLELISM {
		qrc_keccak_permute_p1600c(&mut ctx.state[i], QRC_KPA_ROUNDS);
	}
}

fn kpa_squeezeblocks(state: &mut [u64], mut output: &mut [u8], mut nblocks: usize, rate: usize) {
	while nblocks > 0 {
		qrc_keccak_permute_p1600c(state, QRC_KPA_ROUNDS);

		if QRC_SYSTEM_IS_LITTLE_ENDIAN {
			qrc_intutils_copy8(output, &qrc_intutils_transform_64to8(&state), rate);
		} else {
			for i in 0..(rate >> 3) {
				qrc_intutils_le64to8(&mut output[size_of::<u64>() * i..], state[i]);
			}
		}
		output = &mut output[rate..];
		nblocks -= 1;
	}
}