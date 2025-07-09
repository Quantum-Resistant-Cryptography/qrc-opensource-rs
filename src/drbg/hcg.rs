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

use crate::{digest::sha2::{qrc_hmac512_blockfinalize, qrc_hmac512_initialize, QrcHmac512State, QRC_HMAC_512_RATE}, provider::rcrng::qrc_rcrng_generate, tools::intutils::{qrc_intutils_be8increment, qrc_intutils_clear8, qrc_intutils_copy8, qrc_intutils_min}};

use core::default::Default;

#[cfg(feature = "no_std")]
use alloc::vec;


/* QRC-HCG-SHA51201*/
pub const QRC_DEFAULT_INFO: [u8; 17] = [ 0x51, 0x53, 0x43, 0x2D, 0x48, 0x43, 0x47, 0x2D, 0x53, 0x48, 0x41, 0x32, 0x35, 0x31, 0x32, 0x00, 0x01 ];

/*
* \def QRC_HCG_CACHE_SIZE
* \brief The HCG cache size size
*/
pub const QRC_HCG_CACHE_SIZE: usize = 64;

/*
* \def QRC_HCG_MAX_INFO_SIZE
* \brief The HCG info size
*/
pub const QRC_HCG_MAX_INFO_SIZE: usize = 56;

/*
* \def QRC_HCG_NONCE_SIZE
* \brief The HCG nonce size
*/
pub const QRC_HCG_NONCE_SIZE: usize = 8;

/*
* \def QRC_HCG_RESEED_THRESHHOLD
* \brief The HCG re-seed size
*/
pub const QRC_HCG_RESEED_THRESHHOLD: usize = 1024000;

/*
* \def QRC_HCG_SEED_SIZE
* \brief The HCG seed size
*/
pub const QRC_HCG_SEED_SIZE: usize = 64;

/*
* \struct qrc_hcg_state
* \brief The HCG state structure
*/
pub struct QrcHcgState {
	pub hstate: QrcHmac512State,				/*< The hmac state  */
	pub cache: [u8; QRC_HCG_CACHE_SIZE],		/*< The cache buffer  */
	pub info: [u8; QRC_HCG_MAX_INFO_SIZE],	/*< The info string  */
	pub nonce: [u8; QRC_HCG_NONCE_SIZE],		/*< The nonce array  */
	pub bctr: usize,							/*< The bytes counter  */
	pub cpos: usize,							/*< The cache position  */
	pub crmd: usize,							/*< The cache remainder  */
	pub pres: bool,								/*< The predictive resistance flag  */
}
impl Default for QrcHcgState {
    fn default() -> Self {
        Self {
            hstate: QrcHmac512State::default(),
            cache: [Default::default(); QRC_HCG_CACHE_SIZE],
            info: [Default::default(); QRC_HCG_MAX_INFO_SIZE],
            nonce: [Default::default(); QRC_HCG_NONCE_SIZE],
			bctr: Default::default(),
            cpos: Default::default(),
			crmd: Default::default(),
            pres: Default::default(),
        }
    }
}

/*
* \brief Dispose of the HCG DRBG state
*
* \warning The dispose function must be called when disposing of the cipher.
* This function destroys the internal state of the cipher.
*
* \param ctx: [struct] The HCG state structure
*/
pub fn qrc_hcg_dispose(ctx: &mut QrcHcgState) {
    qrc_intutils_clear8(&mut ctx.cache, QRC_HCG_CACHE_SIZE);
    ctx.bctr = 0;
    ctx.cpos = 0;
    ctx.crmd = 0;
    ctx.pres = false;
}

/*
* \brief Initialize the pseudo-random provider state with a seed and optional personalization string
*
* \param ctx: [struct] The hcg state structure
* \param seed: [const] The random seed, 32 bytes of seed instantiates the 256-bit generator, 64 bytes the 512-bit generator
* \param seedlen: The length of the input seed
* \param info: [const] The optional personalization string
* \param infolen: The length of the personalization string
* \param pres: Enable periodic random injection; enables non deterministic pseudo-random generation
*/
pub fn qrc_hcg_initialize(ctx: &mut QrcHcgState, seed: &[u8], seedlen: usize, info: &[u8], infolen: usize, predictive_resistance: bool) {
	qrc_intutils_clear8(&mut ctx.cache, QRC_HCG_CACHE_SIZE);
	qrc_intutils_clear8(&mut ctx.nonce, QRC_HCG_NONCE_SIZE);
	ctx.bctr = 0;
	ctx.cpos = 0;
	ctx.pres = predictive_resistance;

	qrc_hmac512_initialize(&mut ctx.hstate, seed, seedlen);

	/* copy from the info string to state */
	if infolen != 0 {
		let rmdlen = qrc_intutils_min(QRC_HCG_MAX_INFO_SIZE, infolen);
		qrc_intutils_copy8(&mut ctx.info, info, rmdlen);
	} else {
		qrc_intutils_copy8(&mut ctx.info, &QRC_DEFAULT_INFO, 17);
	}

    let mut prand = vec![0u8; 0];
    let mut prand_len = 0;
	if ctx.pres {
		/* add a random seed to hmac state */
		prand = vec![0u8; QRC_HMAC_512_RATE];
        prand_len = QRC_HMAC_512_RATE;
		qrc_rcrng_generate(&mut prand, prand_len);
	}

	/* pre-load the state cache */
	qrc_hmac512_blockfinalize(&mut ctx.hstate, &mut ctx.cache, &prand, prand_len);

	/* cache the first block */
	hcg_fill_buffer(ctx);
}

/*
* \brief Generate pseudo-random bytes using the random provider.
*
* \warning Initialize must first be called before this function can be used.
*
* \param ctx: [struct] The HCG state structure
* \param output: The pseudo-random output array
* \param outlen: The requested number of bytes to generate
* \return The number of bytes generated
*/
pub fn qrc_hcg_generate(ctx: &mut QrcHcgState, output: &mut [u8], mut outlen: usize) {
	if ctx.crmd < outlen {
		let mut outpos = 0;
		/* copy remaining bytes from the cache */
		if ctx.crmd != 0 {
			/* empty the state buffer */
			qrc_intutils_copy8(output, &ctx.cache[ctx.cpos..], ctx.crmd);
			outpos += ctx.crmd;
			outlen -= ctx.crmd;
		}

		/* loop through the remainder */
		while outlen != 0 {
			/* fill the buffer */
			hcg_fill_buffer(ctx);

			/* copy to output */
			let rmdlen = qrc_intutils_min(ctx.crmd, outlen);
			qrc_intutils_copy8(&mut output[outpos..], &ctx.cache, rmdlen);

			outlen -= rmdlen;
			outpos += rmdlen;
			ctx.crmd -= rmdlen;
			ctx.cpos += rmdlen;
		}
	} else {
		/* copy from the state buffer to output */
		let rmdlen = qrc_intutils_min(ctx.crmd, outlen);
		qrc_intutils_copy8(output, &ctx.cache[ctx.cpos..], rmdlen);
		ctx.crmd -= rmdlen;
		ctx.cpos += rmdlen;
	}

	/* reseed check */
	csg_auto_reseed(ctx);
}

/*
* \brief Update the random provider with new keying material
*
* \warning Initialize must first be called before this function can be used.
*
* \param ctx: [struct] The HCG state structure
* \param seed: [const] The random update seed
* \param seedlen: The length of the update seed
*/
pub fn qrc_hcg_update(ctx: &mut QrcHcgState, seed: &[u8], seedlen: usize) {

	let hblk = &mut [0u8; QRC_HMAC_512_RATE];

	/* copy the existing cache */
	qrc_intutils_copy8(hblk, &ctx.cache, QRC_HCG_CACHE_SIZE);
	/* copy the new seed */
	qrc_intutils_copy8(&mut hblk[QRC_HCG_CACHE_SIZE..], seed, seedlen);

	/* reset the hmac key */
	qrc_hmac512_initialize(&mut ctx.hstate, hblk, QRC_HMAC_512_RATE);
}

fn hcg_fill_buffer(ctx: &mut QrcHcgState) {
	/* similar mechanism to hkdf, but with a larger counter and set info size */

	let hblk = &mut [0u8; QRC_HMAC_512_RATE];

	/* copy the cache */
	qrc_intutils_copy8(hblk, &ctx.cache, QRC_HCG_CACHE_SIZE);

	/* increment and copy the counter */
	qrc_intutils_be8increment(&mut ctx.nonce, QRC_HCG_NONCE_SIZE);
	qrc_intutils_copy8(&mut hblk[QRC_HCG_CACHE_SIZE..], &ctx.nonce, QRC_HCG_NONCE_SIZE);

	/* copy the info */
	qrc_intutils_copy8(&mut hblk[QRC_HCG_CACHE_SIZE + QRC_HCG_NONCE_SIZE..], &ctx.info, QRC_HCG_MAX_INFO_SIZE);

	/* finalize and cache the block */
	qrc_hmac512_blockfinalize(&mut ctx.hstate, &mut ctx.cache, hblk, QRC_HMAC_512_RATE);

	/* reset cache counters */
	ctx.crmd = QRC_HCG_CACHE_SIZE;
	ctx.cpos = 0;
}

fn csg_auto_reseed(ctx: &mut QrcHcgState) {
	if ctx.pres && ctx.bctr >= QRC_HCG_RESEED_THRESHHOLD {
		/* add a random seed to input seed and info */
		let prand = &mut [0u8; QRC_HMAC_512_RATE];
		qrc_rcrng_generate(prand, QRC_HMAC_512_RATE);

		/* update hmac */
		qrc_hcg_update(ctx, prand, QRC_HMAC_512_RATE);

		/* re-fill the buffer and reset counter */
		hcg_fill_buffer(ctx);
		ctx.bctr = 0;
	}
}