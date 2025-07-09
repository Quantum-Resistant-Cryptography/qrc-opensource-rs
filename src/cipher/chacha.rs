/* The AGPL version 3 License (AGPLv3)
* 
* Copyright (c) 2021 Digital Freedom Defence Inc.
* This file is part of the QSC Cryptographic library
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
*
*
*
* Copyright (c) Original-2021 John G. Underhill <john.underhill@mailfence.com>
* Copyright (c) 2022-Present QRC Eurosmart SA <opensource-support@qrcrypto.ch>
*
* The following code is a derivative work of the code from the QSC Cryptographic library in C, 
* which is licensed AGPLv3. This code therefore is also licensed under the terms of 
* the GNU Affero General Public License, version 3. The AGPL version 3 License (AGPLv3). */

use crate::tools::intutils::{qrc_intutils_clear32, qrc_intutils_copy8, qrc_intutils_le32to8, qrc_intutils_le8to32, qrc_intutils_rotl32, qrc_intutils_xor};

use core::default::Default;

#[cfg(feature = "no_std")]
use alloc::vec::Vec;

/*
* \def QRC_CHACHA_BLOCK_SIZE
* \brief The internal block size
*/
pub const QRC_CHACHA_BLOCK_SIZE: usize = 64;

/*
* \def QRC_CHACHA_KEY128_SIZE
* \brief The size of the 128-bit secret key array in bytes
*/
pub const QRC_CHACHA_KEY128_SIZE: usize = 16;

/*
* \def QRC_CHACHA_KEY256_SIZE
* \brief The size of the 256-bit secret key array in bytes
*/
pub const QRC_CHACHA_KEY256_SIZE: usize = 32;

/*
* \def QRC_CHACHA_NONCE_SIZE
* \brief The size of the nonce array in bytes
*/
pub const QRC_CHACHA_NONCE_SIZE: usize = 8;

/*
* \def QRC_CHACHA_ROUND_COUNT
* \brief The number of mixing rounds used by ChaCha
*/
pub const QRC_CHACHA_ROUND_COUNT: usize = 20;

/*
* \struct qrc_chacha_state
* \brief Internal: contains the qrc_chacha_state state
*/
#[derive(Clone)]
pub struct QrcChachaState {
	pub state: [u32; 16],	/*< The internal state array */
}
impl Default for QrcChachaState{
    fn default() -> Self {
        Self {
            state: [Default::default(); 16],
        }
    }
}

/* 
* \struct qrc_chacha_keyparams
* \brief The key parameters structure containing key, and nonce arrays and lengths.
* Use this structure to load an input cipher-key and nonce using the qrc_chacha_initialize function.
* Keys must be random and secret, and align to the corresponding key size of the cipher implemented.
* The key must be QRC_CHACHA_KEY128_SIZE or QRC_CHACHA_KEY256_SIZE in length.
* The nonce is always QRC_CHACHA_NONCE_SIZE in length.
*/
#[derive(Clone)]
pub struct QrcChachaKeyparams {
	pub key: Vec<u8>,	/*< The input cipher key */
	pub keylen: usize,		/*< The length in bytes of the cipher key */
	pub nonce: Vec<u8>,		/*< The nonce or initialization vector */
}
impl Default for QrcChachaKeyparams{
    fn default() -> Self {
        Self {
            key: Default::default(),
			keylen: Default::default(),
			nonce: Default::default(),
        }
    }
}

/*
* \brief Dispose of the ChaCha cipher state.
*
* \warning The dispose function must be called when disposing of the cipher.
* This function destroys internal arrays and data
*
* \param ctx: [struct] The cipher state structure
*/
pub fn qrc_chacha_dispose(ctx: &mut QrcChachaState) {
	qrc_intutils_clear32(&mut ctx.state, 16);
}

/*
* \brief Initialize the state with the secret key and nonce.
*
* \warning The key array must be either 16 or 32 bytes in length
* \warning The nonce array must be 8 bytes bytes in length
*
* \param ctx: [struct] The cipher state structure
* \param keyparams: [const][struct] The secret key and nonce structure
*/
pub fn qrc_chacha_initialize(ctx: &mut QrcChachaState, keyparams: QrcChachaKeyparams) {
	if keyparams.keylen == 32 {
		ctx.state[0] = 0x61707865;
		ctx.state[1] = 0x3320646E;
		ctx.state[2] = 0x79622D32;
		ctx.state[3] = 0x6B206574;
		ctx.state[4] = qrc_intutils_le8to32(&keyparams.key);
		ctx.state[5] = qrc_intutils_le8to32(&keyparams.key[4..]);
		ctx.state[6] = qrc_intutils_le8to32(&keyparams.key[8..]);
		ctx.state[7] = qrc_intutils_le8to32(&keyparams.key[12..]);
		ctx.state[8] = qrc_intutils_le8to32(&keyparams.key[16..]);
		ctx.state[9] = qrc_intutils_le8to32(&keyparams.key[20..]);
		ctx.state[10] = qrc_intutils_le8to32(&keyparams.key[24..]);
		ctx.state[11] = qrc_intutils_le8to32(&keyparams.key[28..]);
		ctx.state[12] = 0;
		ctx.state[13] = 0;
		ctx.state[14] = qrc_intutils_le8to32(&keyparams.nonce);
		ctx.state[15] = qrc_intutils_le8to32(&keyparams.nonce[4..]);
	} else {
		ctx.state[0] = 0x61707865;
		ctx.state[1] = 0x3120646E;
		ctx.state[2] = 0x79622D36;
		ctx.state[3] = 0x6B206574;
		ctx.state[4] = qrc_intutils_le8to32(&keyparams.key[0..]);
		ctx.state[5] = qrc_intutils_le8to32(&keyparams.key[4..]);
		ctx.state[6] = qrc_intutils_le8to32(&keyparams.key[8..]);
		ctx.state[7] = qrc_intutils_le8to32(&keyparams.key[12..]);
		ctx.state[8] = qrc_intutils_le8to32(&keyparams.key[0..]);
		ctx.state[9] = qrc_intutils_le8to32(&keyparams.key[4..]);
		ctx.state[10] = qrc_intutils_le8to32(&keyparams.key[8..]);
		ctx.state[11] = qrc_intutils_le8to32(&keyparams.key[12..]);
		ctx.state[12] = 0;
		ctx.state[13] = 0;
		ctx.state[14] = qrc_intutils_le8to32(&keyparams.nonce);
		ctx.state[15] = qrc_intutils_le8to32(&keyparams.nonce[4..]);
	}
}

/*
* \brief Transform a length of input text.
*
* \param ctx: [struct] The cipher state structure
* \param output: A pointer to the output byte array
* \param input: [const] A pointer to the input byte array
* \param length: The number of bytes to process
*/
pub fn qrc_chacha_transform(ctx: &mut QrcChachaState, output: &mut [u8], input: &[u8], mut length: usize) {
	let mut oft = 0;

	if length != 0 {
		while length >= QRC_CHACHA_BLOCK_SIZE {
			chacha_permute_p512c(ctx.clone(), &mut output[oft..]);
			chacha_increment(ctx);
			qrc_intutils_xor(&mut output[oft..], &input[oft..], QRC_CHACHA_BLOCK_SIZE);
			oft += QRC_CHACHA_BLOCK_SIZE;
			length -= QRC_CHACHA_BLOCK_SIZE;
		}

		if length != 0	{
			let tmp = &mut [0u8; QRC_CHACHA_BLOCK_SIZE];
			chacha_permute_p512c(ctx.clone(), tmp);
			chacha_increment(ctx);
			qrc_intutils_copy8(&mut output[oft..], tmp, length);

			for i in oft..oft + length {
				output[i] ^= input[i];
			}
		}
	}
}

//const CHACHA_STATE_SIZE: usize = 16;

fn chacha_increment(ctx: &mut QrcChachaState) {
	ctx.state[12] = ctx.state[12].wrapping_add(1);

	if ctx.state[12] == 0 {
		ctx.state[13] =  ctx.state[13].wrapping_add(1);
	}
}

fn chacha_permute_p512c(ctx: QrcChachaState, output: &mut [u8]) {
	let mut x0 = ctx.state[0];
	let mut x1 = ctx.state[1];
	let mut x2 = ctx.state[2];
	let mut x3 = ctx.state[3];
	let mut x4 = ctx.state[4];
	let mut x5 = ctx.state[5];
	let mut x6 = ctx.state[6];
	let mut x7 = ctx.state[7];
	let mut x8 = ctx.state[8];
	let mut x9 = ctx.state[9];
	let mut x10 = ctx.state[10];
	let mut x11 = ctx.state[11];
	let mut x12 = ctx.state[12];
	let mut x13 = ctx.state[13];
	let mut x14 = ctx.state[14];
	let mut x15 = ctx.state[15];
	let mut ctr = QRC_CHACHA_ROUND_COUNT;

	while ctr != 0 {
		x0 = x0.wrapping_add(x4);
		x12 = qrc_intutils_rotl32(x12 ^ x0, 16);
		x8 = x8.wrapping_add(x12);
		x4 = qrc_intutils_rotl32(x4 ^ x8, 12);
		x0 = x0.wrapping_add(x4);
		x12 = qrc_intutils_rotl32(x12 ^ x0, 8);
		x8 = x8.wrapping_add(x12);
		x4 = qrc_intutils_rotl32(x4 ^ x8, 7);
		x1 = x1.wrapping_add(x5);
		x13 = qrc_intutils_rotl32(x13 ^ x1, 16);
		x9 = x9.wrapping_add(x13);
		x5 = qrc_intutils_rotl32(x5 ^ x9, 12);
		x1 = x1.wrapping_add(x5);
		x13 = qrc_intutils_rotl32(x13 ^ x1, 8);
		x9 = x9.wrapping_add(x13);
		x5 = qrc_intutils_rotl32(x5 ^ x9, 7);
		x2 = x2.wrapping_add(x6);
		x14 = qrc_intutils_rotl32(x14 ^ x2, 16);
		x10 = x10.wrapping_add(x14);
		x6 = qrc_intutils_rotl32(x6 ^ x10, 12);
		x2 = x2.wrapping_add(x6);
		x14 = qrc_intutils_rotl32(x14 ^ x2, 8);
		x10 = x10.wrapping_add(x14);
		x6 = qrc_intutils_rotl32(x6 ^ x10, 7);
		x3 = x3.wrapping_add(x7);
		x15 = qrc_intutils_rotl32(x15 ^ x3, 16);
		x11 = x11.wrapping_add(x15);
		x7 = qrc_intutils_rotl32(x7 ^ x11, 12);
		x3 = x3.wrapping_add(x7);
		x15 = qrc_intutils_rotl32(x15 ^ x3, 8);
		x11 = x11.wrapping_add(x15);
		x7 = qrc_intutils_rotl32(x7 ^ x11, 7);
		x0 = x0.wrapping_add(x5);
		x15 = qrc_intutils_rotl32(x15 ^ x0, 16);
		x10 = x10.wrapping_add(x15);
		x5 = qrc_intutils_rotl32(x5 ^ x10, 12);
		x0 = x0.wrapping_add(x5);
		x15 = qrc_intutils_rotl32(x15 ^ x0, 8);
		x10 = x10.wrapping_add(x15);
		x5 = qrc_intutils_rotl32(x5 ^ x10, 7);
		x1 = x1.wrapping_add(x6);
		x12 = qrc_intutils_rotl32(x12 ^ x1, 16);
		x11 = x11.wrapping_add(x12);
		x6 = qrc_intutils_rotl32(x6 ^ x11, 12);
		x1 = x1.wrapping_add(x6);
		x12 = qrc_intutils_rotl32(x12 ^ x1, 8);
		x11 = x11.wrapping_add(x12);
		x6 = qrc_intutils_rotl32(x6 ^ x11, 7);
		x2 = x2.wrapping_add(x7);
		x13 = qrc_intutils_rotl32(x13 ^ x2, 16);
		x8 = x8.wrapping_add(x13);
		x7 = qrc_intutils_rotl32(x7 ^ x8, 12);
		x2 = x2.wrapping_add(x7);
		x13 = qrc_intutils_rotl32(x13 ^ x2, 8);
		x8 = x8.wrapping_add(x13);
		x7 = qrc_intutils_rotl32(x7 ^ x8, 7);
		x3 = x3.wrapping_add(x4);
		x14 = qrc_intutils_rotl32(x14 ^ x3, 16);
		x9 = x9.wrapping_add(x14);
		x4 = qrc_intutils_rotl32(x4 ^ x9, 12);
		x3 = x3.wrapping_add(x4);
		x14 = qrc_intutils_rotl32(x14 ^ x3, 8);
		x9 = x9.wrapping_add(x14);
		x4 = qrc_intutils_rotl32(x4 ^ x9, 7);
		ctr -= 2;
	}

	qrc_intutils_le32to8(output, x0.wrapping_add(ctx.state[0]));
	qrc_intutils_le32to8(&mut output[4..], x1.wrapping_add(ctx.state[1]));
	qrc_intutils_le32to8(&mut output[8..], x2.wrapping_add(ctx.state[2]));
	qrc_intutils_le32to8(&mut output[12..], x3.wrapping_add(ctx.state[3]));
	qrc_intutils_le32to8(&mut output[16..], x4.wrapping_add(ctx.state[4]));
	qrc_intutils_le32to8(&mut output[20..], x5.wrapping_add(ctx.state[5]));
	qrc_intutils_le32to8(&mut output[24..], x6.wrapping_add(ctx.state[6]));
	qrc_intutils_le32to8(&mut output[28..], x7.wrapping_add(ctx.state[7]));
	qrc_intutils_le32to8(&mut output[32..], x8.wrapping_add(ctx.state[8]));
	qrc_intutils_le32to8(&mut output[36..], x9.wrapping_add(ctx.state[9]));
	qrc_intutils_le32to8(&mut output[40..], x10.wrapping_add(ctx.state[10]));
	qrc_intutils_le32to8(&mut output[44..], x11.wrapping_add(ctx.state[11]));
	qrc_intutils_le32to8(&mut output[48..], x12.wrapping_add(ctx.state[12]));
	qrc_intutils_le32to8(&mut output[52..], x13.wrapping_add(ctx.state[13]));
	qrc_intutils_le32to8(&mut output[56..], x14.wrapping_add(ctx.state[14]));
	qrc_intutils_le32to8(&mut output[60..], x15.wrapping_add(ctx.state[15]));
}