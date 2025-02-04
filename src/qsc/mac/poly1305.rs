/* The AGPL version 3 License (AGPLv3)
*
* Copyright (c) 2024 DFD & QRC Eurosmart SA
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
*/

/**
* \file poly1305.h
* \brief Poly1305 function definitions \n
* Contains the public api and documentation for the Poly1305 implementation.
*
* Poly1305 Examples \n
* \code
	fn poly1305() {
		let key = &mut [0u8; 32];
		let mac = &mut [0u8; 16];
		let msg = &mut [0u8; 34];

		/* compact api */
		qsc_poly1305_compute(mac, msg, 34, key); 

		/* long-form api */
		let ctx = &mut QscPoly1305State::default();
		qsc_poly1305_initialize(ctx, key);
		for i in (0..32).step_by(QSC_POLY1305_BLOCK_SIZE) {
			qsc_poly1305_blockupdate(ctx, msg[i..]);
		}
		qsc_poly1305_update(ctx, msg[32..], 2);
		qsc_poly1305_finalize(ctx, mac);
	}
* \endcode
* \remarks
* For usage examples, see poly1305_test.h
*/

use crate::qsc::tools::intutils::{
        qsc_intutils_le8to32,
        qsc_intutils_le32to8,
		qsc_intutils_clear8,
        qsc_intutils_clear32,
};

/*
* \def QSC_POLY1305_BLOCK_SIZE
* \brief The natural block size of the message input in bytes
*/
const QSC_POLY1305_BLOCK_SIZE: usize = 16;

/* 
* \struct qsc_poly1305_state
* \brief Contains the Poly1305 internal state
*/
struct QscPoly1305State {
	pub h: [u32; 5],							/*< The h parameter */
	pub k: [u32; 4],							/*< The k parameter */
	pub r: [u32; 5],							/*< The r parameter */
	pub s: [u32; 4],							/*< The s parameter */
	pub buf: [u8; QSC_POLY1305_BLOCK_SIZE],	    /*< The buffer parameter */
	pub fnl: usize,								/*< The fnl size */
	pub rmd: usize,								/*< The rmd size */
}
impl Default for QscPoly1305State {
    fn default() -> Self {
        Self {
            h: [Default::default(); 5],
            k: [Default::default(); 4],
			r: [Default::default(); 5],
            s: [Default::default(); 4],
			buf: [Default::default(); QSC_POLY1305_BLOCK_SIZE],
            fnl: Default::default(),
            rmd: Default::default(),
        }
    }
}

/**
* \brief Update the poly1305 generator with a single block of message input.
* Absorbs block sized lengths of input message into the state.
*
* \warning Message length must be a single 16 byte message block. \n
*
* \param ctx: [struct] The function state; must be initialized
* \param message: [const] The input message byte array
*/
fn qsc_poly1305_blockupdate(ctx: &mut QscPoly1305State, message: &[u8]) {
	let hibit = if ctx.fnl != 0 { 0 } else { 1 << 24 };

	let t0 = qsc_intutils_le8to32(message) as u64;
	let t1 = qsc_intutils_le8to32(&message[4..]) as u64;
	let t2 = qsc_intutils_le8to32(&message[8..]) as u64;
	let t3 = qsc_intutils_le8to32(&message[12..]) as u64;

	ctx.h[0] += (t0 & 0x3FFFFFF) as u32;
	ctx.h[1] += ((((t1 << 32) | t0) >> 26) & 0x3FFFFFF) as u32;
	ctx.h[2] += ((((t2 << 32) | t1) >> 20) & 0x3FFFFFF) as u32;
	ctx.h[3] += ((((t3 << 32) | t2) >> 14) & 0x3FFFFFF) as u32;
	ctx.h[4] += (t3 >> 8) as u32 | hibit;

	let tp0 = (ctx.h[0] as u64 * ctx.r[0] as u64) + (ctx.h[1] as u64 * ctx.s[3] as u64) + (ctx.h[2] as u64 * ctx.s[2] as u64) + (ctx.h[3] as u64 * ctx.s[1] as u64) + (ctx.h[4] as u64 * ctx.s[0] as u64);
	let mut tp1 = (ctx.h[0] as u64 * ctx.r[1] as u64) + (ctx.h[1] as u64 * ctx.r[0] as u64) + (ctx.h[2] as u64 * ctx.s[3] as u64) + (ctx.h[3] as u64 * ctx.s[2] as u64) + (ctx.h[4] as u64 * ctx.s[1] as u64);
	let mut tp2 = (ctx.h[0] as u64 * ctx.r[2] as u64) + (ctx.h[1] as u64 * ctx.r[1] as u64) + (ctx.h[2] as u64 * ctx.r[0] as u64) + (ctx.h[3] as u64 * ctx.s[3] as u64) + (ctx.h[4] as u64 * ctx.s[2] as u64);
	let mut tp3 = (ctx.h[0] as u64 * ctx.r[3] as u64) + (ctx.h[1] as u64 * ctx.r[2] as u64) + (ctx.h[2] as u64 * ctx.r[1] as u64) + (ctx.h[3] as u64 * ctx.r[0] as u64) + (ctx.h[4] as u64 * ctx.s[3] as u64);
	let mut tp4 = (ctx.h[0] as u64 * ctx.r[4] as u64) + (ctx.h[1] as u64 * ctx.r[3] as u64) + (ctx.h[2] as u64 * ctx.r[2] as u64) + (ctx.h[3] as u64 * ctx.r[1] as u64) + (ctx.h[4] as u64 * ctx.r[0] as u64);

	ctx.h[0] = (tp0 & 0x3FFFFFF) as u32;
	let mut b = tp0 >> 26;
	tp1 += b;
	ctx.h[1] = (tp1 & 0x3FFFFFF) as u32;
	b = tp1 >> 26;
	tp2 += b;
	ctx.h[2] = (tp2 & 0x3FFFFFF) as u32;
	b = tp2 >> 26;
	tp3 += b;
	ctx.h[3] = (tp3 & 0x3FFFFFF) as u32;
	b = tp3 >> 26;
	tp4 += b;
	ctx.h[4] = (tp4 & 0x3FFFFFF) as u32;
	b = tp4 >> 26;
	ctx.h[0] += (b * 5) as u32;
}

/**
* \brief Compute the MAC code and return the result in the mac byte array.
*
* \warning The output array must be at least 16 bytes in length.
*
* \param output: The output byte array; receives the MAC code
* \param message: [const] The message input byte array
* \param msglen: The number of message bytes to process
* \param key: [const] The 32 byte key array
*/
#[allow(dead_code)]
fn qsc_poly1305_compute(output: &mut [u8], message: &[u8], msglen: usize, key: &[u8]) {
	let ctx = &mut QscPoly1305State::default();

	qsc_poly1305_initialize(ctx, key);
	qsc_poly1305_update(ctx, message, msglen);
	qsc_poly1305_finalize(ctx, output);
}

/**
* \brief Finalize the message state and returns the MAC code.
* Absorb the last block of message and create the MAC array. \n
*
* \param ctx: [struct] The function state; must be initialized
* \param mac: The MAC byte array; receives the MAC code
*/
fn qsc_poly1305_finalize(ctx: &mut QscPoly1305State, output: &mut [u8]) {
	if ctx.rmd != 0	{
		ctx.buf[ctx.rmd] = 1;

		for i in (ctx.rmd + 1)..QSC_POLY1305_BLOCK_SIZE {
			ctx.buf[i] = 0;
		}

		ctx.fnl = 1;
		let buf = &ctx.buf.to_owned();
		qsc_poly1305_blockupdate(ctx, buf);
	}

	let mut b = ctx.h[0] >> 26;
	ctx.h[0] = ctx.h[0] & 0x3FFFFFF;
	ctx.h[1] += b;
	b = ctx.h[1] >> 26;
	ctx.h[1] = ctx.h[1] & 0x3FFFFFF;
	ctx.h[2] += b;
	b = ctx.h[2] >> 26;
	ctx.h[2] = ctx.h[2] & 0x3FFFFFF;
	ctx.h[3] += b;
	b = ctx.h[3] >> 26;
	ctx.h[3] = ctx.h[3] & 0x3FFFFFF;
	ctx.h[4] += b;
	b = ctx.h[4] >> 26;
	ctx.h[4] = ctx.h[4] & 0x3FFFFFF;
	ctx.h[0] += b * 5;

	let mut g0 = ctx.h[0] + 5;
	b = g0 >> 26;
	g0 &= 0x3FFFFFF;
	let mut g1 = ctx.h[1] + b;
	b = g1 >> 26;
	g1 &= 0x3FFFFFF;
	let mut g2 = ctx.h[2] + b;
	b = g2 >> 26;
	g2 &= 0x3FFFFFF;
	let mut g3 = ctx.h[3] + b;
	b = g3 >> 26;
	g3 &= 0x3FFFFFF;
	let g4 = ctx.h[4].wrapping_add(b).wrapping_sub(1 << 26);

	b = (g4 >> 31) - 1;
	let nb = !b;
	ctx.h[0] = (ctx.h[0] & nb) | (g0 & b);
	ctx.h[1] = (ctx.h[1] & nb) | (g1 & b);
	ctx.h[2] = (ctx.h[2] & nb) | (g2 & b);
	ctx.h[3] = (ctx.h[3] & nb) | (g3 & b);
	ctx.h[4] = (ctx.h[4] & nb) | (g4 & b);
	
	/* jgu: checked */
	/*lint -save -e647 */
	let f0 = (ctx.h[0] as u64 | (ctx.h[1] << 26) as u64).wrapping_add(ctx.k[0] as u64);
	let mut f1 = ((ctx.h[1] >> 6) as u64 | (ctx.h[2] << 20) as u64).wrapping_add(ctx.k[1] as u64);
	let mut f2 = ((ctx.h[2] >> 12) as u64 | (ctx.h[3] << 14) as u64).wrapping_add(ctx.k[2] as u64);
	let mut f3 = ((ctx.h[3] >> 18) as u64 | (ctx.h[4] << 8) as u64).wrapping_add(ctx.k[3] as u64);
	/*lint -restore */

	f1 += f0 >> 32;
	f2 += f1 >> 32;
	f3 += f2 >> 32;

	qsc_intutils_le32to8(&mut output[0..], f0 as u32);
	qsc_intutils_le32to8(&mut output[4..], f1 as u32);
	qsc_intutils_le32to8(&mut output[8..], f2 as u32);
	qsc_intutils_le32to8(&mut output[12..], f3 as u32);

	qsc_poly1305_reset(ctx);
}

/**
* \brief Initialize the state with the secret key.
*
* \param ctx: [struct] The function state
* \param key: [const] The secret key byte array
*/
fn qsc_poly1305_initialize(ctx: &mut QscPoly1305State, key: &[u8]) {
	ctx.r[0] = (qsc_intutils_le8to32(&key[0..])) & 0x3FFFFFF;
	ctx.r[1] = (qsc_intutils_le8to32(&key[3..]) >> 2) & 0x3FFFF03;
	ctx.r[2] = (qsc_intutils_le8to32(&key[6..]) >> 4) & 0x3FFC0FF;
	ctx.r[3] = (qsc_intutils_le8to32(&key[9..]) >> 6) & 0x3F03FFF;
	ctx.r[4] = (qsc_intutils_le8to32(&key[12..]) >> 8) & 0x00FFFFF;
	ctx.s[0] = ctx.r[1] * 5;
	ctx.s[1] = ctx.r[2] * 5;
	ctx.s[2] = ctx.r[3] * 5;
	ctx.s[3] = ctx.r[4] * 5;
	ctx.h[0] = 0;
	ctx.h[1] = 0;
	ctx.h[2] = 0;
	ctx.h[3] = 0;
	ctx.h[4] = 0;
	ctx.k[0] = qsc_intutils_le8to32(&key[16..]);
	ctx.k[1] = qsc_intutils_le8to32(&key[20..]);
	ctx.k[2] = qsc_intutils_le8to32(&key[24..]);
	ctx.k[3] = qsc_intutils_le8to32(&key[28..]);
	ctx.fnl = 0;
	ctx.rmd = 0;
}

/**
* \brief Reset the state values to zero.
*
* \param ctx The function state
*/
fn qsc_poly1305_reset(ctx: &mut QscPoly1305State) {
	qsc_intutils_clear32(&mut ctx.h, 5);
	qsc_intutils_clear32(&mut ctx.k, 4);
	qsc_intutils_clear32(&mut ctx.r, 5);
	qsc_intutils_clear32(&mut ctx.s, 4);
	qsc_intutils_clear8(&mut ctx.buf, QSC_POLY1305_BLOCK_SIZE);
	ctx.rmd = 0;
	ctx.fnl = 0;
}

/**
* \brief Update the poly1305 generator with a length of message input.
* Absorbs the input message into the state.
*
* \param ctx: [struct] The function state; must be initialized
* \param message: [const] The input message byte array
* \param msglen: The number of input message bytes to process
*/
fn qsc_poly1305_update(ctx: &mut QscPoly1305State, mut message: &[u8], mut msglen: usize) {
	if ctx.rmd != 0	{
		let mut rmd = QSC_POLY1305_BLOCK_SIZE - ctx.rmd;

		if rmd > msglen	{
			rmd = msglen;
		}

		for i in 0..rmd {
			ctx.buf[ctx.rmd + i] = message[i];
		}

		msglen -= rmd;
		message = &message[rmd..];
		ctx.rmd += rmd;

		if ctx.rmd == QSC_POLY1305_BLOCK_SIZE {
			let buf = &ctx.buf.to_owned();
			qsc_poly1305_blockupdate(ctx, buf);
			ctx.rmd = 0;
		}
	}

	while msglen >= QSC_POLY1305_BLOCK_SIZE {
		qsc_poly1305_blockupdate(ctx, message);
		message = &message[QSC_POLY1305_BLOCK_SIZE..];
		msglen -= QSC_POLY1305_BLOCK_SIZE;
	}

	if msglen != 0{
		for i in 0..msglen {
			ctx.buf[ctx.rmd + i] = message[i];
		}

		ctx.rmd += msglen;
	}
}