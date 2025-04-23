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

use crate::{digest::sha3::{qrc_cshake_initialize, qrc_cshake_squeezeblocks, qrc_cshake_update, qrc_keccak_dispose, QrcKeccakRate, QrcKeccakState, QRC_KECCAK_256_RATE, QRC_KECCAK_512_RATE, QRC_KECCAK_STATE_SIZE}, provider::rcrng::qrc_rcrng_generate, tools::intutils::{qrc_intutils_clear64, qrc_intutils_clear8, qrc_intutils_copy8, qrc_intutils_min}};

use core::{mem::size_of, default::Default};


/*
* \def QRC_CSG_256_SEED_SIZE
* \brief The CSG-256 seed size
*/
pub const QRC_CSG_256_SEED_SIZE: usize = 32;

/*
* \def QRC_CSG_512_SEED_SIZE
* \brief The CSG-512 seed size
*/
pub const QRC_CSG_512_SEED_SIZE: usize = 64;

/*
* \def QRC_CSG_RESEED_THRESHHOLD
* \brief The CSG re-seed threshold interval
*/
pub const QRC_CSG_RESEED_THRESHHOLD: usize = 1024000;


/*
* \struct qrc_csg_state
* \brief The CSG state structure
*/
#[derive(PartialEq)]
pub struct QrcCsgState {
    pub kstate: QrcKeccakState,             /*< The Keccak state  */
    pub cache: [u8; QRC_KECCAK_256_RATE],   /*< The cache buffer */
    pub bctr: usize,                        /*< The bytes counter  */
    pub cpos: usize,                        /*< The cache position  */
    pub crmd: usize,                        /*< The cache remainder  */
    pub rate: usize,                        /*< The absorption rate  */
    pub pres: bool                          /*< The predictive resistance flag  */
}
impl Default for QrcCsgState {
    fn default() -> Self {
        Self {
            kstate: QrcKeccakState::default(),
            cache: [Default::default(); QRC_KECCAK_256_RATE],
			bctr: Default::default(),
            cpos: Default::default(),
			crmd: Default::default(),
            rate: Default::default(),
            pres: Default::default(),
        }
    }
}

/*
* \brief Dispose of the DRBG state
*
* \warning The dispose function must be called when disposing of the cipher.
* This function destroys the internal state of the cipher.
*
* \param ctx: [struct] The DRBG state structure
*/
pub fn qrc_csg_dispose(ctx: &mut QrcCsgState) {
    qrc_keccak_dispose(&mut ctx.kstate);
    qrc_intutils_clear8(&mut ctx.cache, QRC_KECCAK_256_RATE);

    ctx.bctr = 0;
    ctx.cpos = 0;
    ctx.crmd = 0;
    ctx.rate = 0;
    ctx.pres = false;
}

/*
* \brief Initialize the pseudo-random provider state with a seed and optional personalization string
*
* \param ctx: [struct] The function state
* \param seed: [const] The random seed, 32 bytes of seed instantiates the 256-bit generator, 64 bytes the 512-bit generator
* \param seedlen: The length of the input seed
* \param info: [const] The optional personalization string
* \param infolen: The length of the personalization string
* \param predres: Enable periodic random injection; enables non deterministic pseudo-random generation
*/
pub fn qrc_csg_initialize(ctx: &mut QrcCsgState, seed: &[u8], seedlen: usize, info: &[u8], infolen: usize, predres: bool) {
	if seedlen == QRC_CSG_512_SEED_SIZE	{
		ctx.rate = QRC_KECCAK_512_RATE;
	} else {
		ctx.rate = QRC_KECCAK_256_RATE;
	}

	qrc_intutils_clear8(&mut ctx.cache, QRC_KECCAK_256_RATE);
    
	ctx.bctr = 0;
	ctx.cpos = 0;
	ctx.pres = predres;

	qrc_intutils_clear64(&mut ctx.kstate.state, QRC_KECCAK_STATE_SIZE / size_of::<u64>());

	if ctx.rate == QRC_KECCAK_512_RATE {
        let rate = QrcKeccakRate::QrcKeccakRate512 as usize;
		if ctx.pres	{
			/* add a random seed to input seed and info */
			let prand = &mut [0u8; QRC_CSG_512_SEED_SIZE];
			qrc_rcrng_generate(prand, QRC_CSG_512_SEED_SIZE);
			qrc_cshake_initialize(&mut ctx.kstate, rate, seed, seedlen, info, infolen, prand, QRC_CSG_512_SEED_SIZE);
		} else {
			/* initialize with the seed and info */
			qrc_cshake_initialize(&mut ctx.kstate, rate, seed, seedlen, info, infolen, &[], 0);
		}
	} else {
        let rate = QrcKeccakRate::QrcKeccakRate256 as usize;
		if ctx.pres {
			let prand = &mut [0u8; QRC_CSG_256_SEED_SIZE];
			qrc_rcrng_generate(prand, QRC_CSG_256_SEED_SIZE);
			qrc_cshake_initialize(&mut ctx.kstate, rate, seed, seedlen, info, infolen, prand, QRC_CSG_256_SEED_SIZE);
		}
		else
		{
			qrc_cshake_initialize(&mut ctx.kstate, rate, seed, seedlen, info, infolen, &[], 0);
		}
	}

	/* cache the first block */
	csg_fill_buffer(ctx);
}
/*
* \brief Generate pseudo-random bytes using the random provider.
*
* \warning Initialize must first be called before this function can be used.
*
* \param ctx: [struct] The function state
* \param output: The pseudo-random output array
* \param outlen: The requested number of bytes to generate
* \return The number of bytes generated
*/
pub fn qrc_csg_generate(ctx: &mut QrcCsgState, output: &mut [u8], mut outlen: usize) {

	ctx.bctr += outlen;

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
		loop {
            if outlen == 0 {
                break
            }

			/* fill the buffer */
			csg_fill_buffer(ctx);

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

	/* clear used bytes */
	if ctx.crmd != 0 {
		qrc_intutils_clear8(&mut ctx.cache, QRC_KECCAK_256_RATE);
	}

	/* reseed check */
	csg_auto_reseed(ctx);
}
/*
* \brief Update the random provider with new keying material
*
* \warning Initialize must first be called before this function can be used.
*
* \param ctx: [struct] The function state
* \param seed: [const] The random update seed
* \param seedlen: The length of the update seed
*/
pub fn qrc_csg_update(ctx: &mut QrcCsgState, seed: &mut [u8], seedlen: usize) {
	/* absorb and permute */

	if ctx.rate == QRC_KECCAK_512_RATE	{
		qrc_cshake_update(&mut ctx.kstate, QrcKeccakRate::QrcKeccakRate512 as usize, seed, seedlen);
	} else {
		qrc_cshake_update(&mut ctx.kstate, QrcKeccakRate::QrcKeccakRate256 as usize, seed, seedlen);
	}

	/* re-fill the buffer */
	csg_fill_buffer(ctx);
}


fn csg_fill_buffer(ctx: &mut QrcCsgState) {
	/* cache the block */
	if ctx.rate == QRC_KECCAK_512_RATE {
		qrc_cshake_squeezeblocks(&mut ctx.kstate, QrcKeccakRate::QrcKeccakRate512 as usize, &mut ctx.cache, 1);
	} else {
		qrc_cshake_squeezeblocks(&mut ctx.kstate, QrcKeccakRate::QrcKeccakRate256 as usize, &mut ctx.cache, 1);
	}

	/* reset cache counters */
	ctx.crmd = ctx.rate;
	ctx.cpos = 0;
}

fn csg_auto_reseed(ctx: &mut QrcCsgState) {
	if ctx.pres && ctx.bctr >= QRC_CSG_RESEED_THRESHHOLD {
		if ctx.rate == QRC_KECCAK_512_RATE {
			/* add a random seed to input seed and info */
			let prand = &mut [0u8; QRC_CSG_512_SEED_SIZE];
			qrc_rcrng_generate(prand, QRC_CSG_512_SEED_SIZE);

			qrc_cshake_update(&mut ctx.kstate, QrcKeccakRate::QrcKeccakRate512 as usize, prand, QRC_CSG_512_SEED_SIZE);
		} else {
			/* add a random seed to input seed and info */
			let prand = &mut [0u8; QRC_CSG_256_SEED_SIZE];
			qrc_rcrng_generate(prand, QRC_CSG_256_SEED_SIZE);

			qrc_cshake_update(&mut ctx.kstate, QrcKeccakRate::QrcKeccakRate256 as usize, prand, QRC_CSG_256_SEED_SIZE);
		}

		/* re-fill the buffer and reset counter */
		csg_fill_buffer(ctx);
		ctx.bctr = 0;
	}
}