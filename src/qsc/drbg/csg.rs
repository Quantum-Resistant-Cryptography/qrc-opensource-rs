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
* \file csg.h
* \brief Contains the public api and documentation for the CSG pseudo-random bytes generator
*
* Usage Example \n
*
* Initialize the DRBG and generate output \n
* \code
	fn csg() {
		let ctx = &mut QscSecrandState::default();
		let seed = &mut [0u8; 32];
		let info = &mut [0u8; 32];
		
		qsc_csg_initialize(&mut ctx.hstate, seed, 32, info, 32, true);
		qsc_csg_generate(&mut ctx.hstate, &mut ctx.cache, QSC_SECRAND_CACHE_SIZE);
	}
* \endcode
*
* \remarks
* \par
* CSG uses the Keccak cSHAKE XOF function to produce pseudo-random bytes from a seeded custom SHAKE generator. \n
* If a 32-byte key is used, the implementation uses the cSHAKE-256 implementation for pseudo-random generation, if a 64-byte key is used, the generator uses cSHAKE-512. \n
* An optional predictive resistance feature, enabled through the initialize function, injects random bytes into the generator at initialization and 1MB intervals,
* creating a non-deterministic pseudo-random output. \n
* Pseudo random bytes are cached internally, and the generator can be initialized and then reused without requiring re-initialization in an online configuration. \n
* The generator can be updated with new seed material, which is absorbed into the Keccak state.
*
* For additional usage examples, see csg_test.h. \n
*
* NIST: SHA3 Fips202 http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
* NIST: SP800-185 http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pd
* NIST: SHA3 Keccak Submission http://keccak.noekeon.org/Keccak-submission-3.pdf
* NIST: SHA3 Keccak Slides http://csrc.nist.gov/groups/ST/hash/sha-3/documents/Keccak-slides-at-NIST.pdf
* NIST: SHA3 Third-Round Report http://nvlpubs.nist.gov/nistpubs/ir/2012/NIST.IR.7896.pdf
* Team Keccak: Specifications summary https://keccak.team/keccak_specs_summary.html
*/


use crate::qsc::{
	tools::{
		memutils::{
			qsc_memutils_copy,
			qsc_memutils_clear,
		},
		intutils::{qsc_intutils_min, qsc_intutils_clear8, qsc_intutils_clear64},
	},
	digest::sha3::{QscKeccakState, QscKeccakRate, QSC_KECCAK_512_RATE, QSC_KECCAK_256_RATE, QSC_KECCAK_STATE_SIZE, qsc_cshake_initialize, qsc_cshake_squeezeblocks, qsc_cshake_update, qsc_keccak_dispose},
	provider::rcrng::qsc_rcrng_generate
};

use std::mem::size_of;

/*
* \def QSC_CSG_256_SEED_SIZE
* \brief The CSG-256 seed size
*/
const QSC_CSG_256_SEED_SIZE: usize = 32;

/*
* \def QSC_CSG_512_SEED_SIZE
* \brief The CSG-512 seed size
*/
const QSC_CSG_512_SEED_SIZE: usize = 64;

/*
* \def QSC_CSG_RESEED_THRESHHOLD
* \brief The CSG re-seed threshold interval
*/
const QSC_CSG_RESEED_THRESHHOLD: usize = 1024000;

/*
* \struct qsc_csg_state
* \brief The CSG state structure
*/
#[derive(PartialEq, Debug)]
pub struct QscCsgState {
    pub kstate: QscKeccakState,             /*< The Keccak state  */
    pub cache: [u8; QSC_KECCAK_256_RATE],   /*< The cache buffer */
    pub bctr: usize,                        /*< The bytes counter  */
    pub cpos: usize,                        /*< The cache position  */
    pub crmd: usize,                        /*< The cache remainder  */
    pub rate: usize,                        /*< The absorption rate  */
    pub pres: bool                          /*< The predictive resistance flag  */
}

impl Default for QscCsgState {
    fn default() -> Self {
        Self {
            kstate: QscKeccakState::default(),
            cache: [Default::default(); QSC_KECCAK_256_RATE],
			bctr: Default::default(),
            cpos: Default::default(),
			crmd: Default::default(),
            rate: Default::default(),
            pres: Default::default(),
        }
    }
}

fn csg_fill_buffer(ctx: &mut QscCsgState) {
	/* cache the block */
	if ctx.rate == QSC_KECCAK_512_RATE {
		qsc_cshake_squeezeblocks(&mut ctx.kstate, QscKeccakRate::QscKeccakRate512 as usize, &mut ctx.cache, 1);
	} else {
		qsc_cshake_squeezeblocks(&mut ctx.kstate, QscKeccakRate::QscKeccakRate256 as usize, &mut ctx.cache, 1);
	}

	/* reset cache counters */
	ctx.crmd = ctx.rate;
	ctx.cpos = 0;
}

fn csg_auto_reseed(ctx: &mut QscCsgState) {
	if ctx.pres && ctx.bctr >= QSC_CSG_RESEED_THRESHHOLD {
		if ctx.rate == QSC_KECCAK_512_RATE {
			/* add a random seed to input seed and info */
			let prand = &mut [0u8; QSC_CSG_512_SEED_SIZE];
			qsc_rcrng_generate(prand, QSC_CSG_512_SEED_SIZE);

			qsc_cshake_update(&mut ctx.kstate, QscKeccakRate::QscKeccakRate512 as usize, prand, QSC_CSG_512_SEED_SIZE);
		} else {
			/* add a random seed to input seed and info */
			let prand = &mut [0u8; QSC_CSG_256_SEED_SIZE];
			qsc_rcrng_generate(prand, QSC_CSG_256_SEED_SIZE);

			qsc_cshake_update(&mut ctx.kstate, QscKeccakRate::QscKeccakRate256 as usize, prand, QSC_CSG_256_SEED_SIZE);
		}

		/* re-fill the buffer and reset counter */
		csg_fill_buffer(ctx);
		ctx.bctr = 0;
	}
}

/**
* \brief Dispose of the DRBG state
*
* \warning The dispose function must be called when disposing of the cipher.
* This function destroys the internal state of the cipher.
*
* \param ctx: [struct] The DRBG state structure
*/
pub fn qsc_csg_dispose(ctx: &mut QscCsgState) {
    qsc_keccak_dispose(&mut ctx.kstate);
    qsc_memutils_clear(&mut ctx.cache);

    ctx.bctr = 0;
    ctx.cpos = 0;
    ctx.crmd = 0;
    ctx.rate = 0;
    ctx.pres = false;
}

/**
* \brief Initialize the pseudo-random provider state with a seed and optional personalization string
*
* \param ctx: [struct] The function state
* \param seed: [const] The random seed, 32 bytes of seed instantiates the 256-bit generator, 64 bytes the 512-bit generator
* \param seedlen: The length of the input seed
* \param info: [const] The optional personalization string
* \param infolen: The length of the personalization string
* \param predres: Enable periodic random injection; enables non deterministic pseudo-random generation
*/
pub fn qsc_csg_initialize(ctx: &mut QscCsgState, seed: &[u8], seedlen: usize, info: &[u8], infolen: usize, predres: bool) {
	if seedlen == QSC_CSG_512_SEED_SIZE	{
		ctx.rate = QSC_KECCAK_512_RATE;
	} else {
		ctx.rate = QSC_KECCAK_256_RATE;
	}

	qsc_intutils_clear8(&mut ctx.cache, QSC_KECCAK_256_RATE);
    
	ctx.bctr = 0;
	ctx.cpos = 0;
	ctx.pres = predres;

	qsc_intutils_clear64(&mut ctx.kstate.state, QSC_KECCAK_STATE_SIZE / size_of::<u64>());

	if ctx.rate == QSC_KECCAK_512_RATE {
        let rate = QscKeccakRate::QscKeccakRate512 as usize;
		if ctx.pres	{
			/* add a random seed to input seed and info */
			let prand = &mut [0u8; QSC_CSG_512_SEED_SIZE];
			qsc_rcrng_generate(prand, QSC_CSG_512_SEED_SIZE);
			qsc_cshake_initialize(&mut ctx.kstate, rate, seed, seedlen, info, infolen, prand, QSC_CSG_512_SEED_SIZE);
		} else {
			/* initialize with the seed and info */
			qsc_cshake_initialize(&mut ctx.kstate, rate, seed, seedlen, info, infolen, &[], 0);
		}
	} else {
        let rate = QscKeccakRate::QscKeccakRate256 as usize;
		if ctx.pres {
			let prand = &mut [0u8; QSC_CSG_256_SEED_SIZE];
			qsc_rcrng_generate(prand, QSC_CSG_256_SEED_SIZE);
			qsc_cshake_initialize(&mut ctx.kstate, rate, seed, seedlen, info, infolen, prand, QSC_CSG_256_SEED_SIZE);
		}
		else
		{
			qsc_cshake_initialize(&mut ctx.kstate, rate, seed, seedlen, info, infolen, &[], 0);
		}
	}

	/* cache the first block */
	csg_fill_buffer(ctx);
}

/**
* \brief Generate pseudo-random bytes using the random provider.
*
* \warning Initialize must first be called before this function can be used.
*
* \param ctx: [struct] The function state
* \param output: The pseudo-random output array
* \param outlen: The requested number of bytes to generate
* \return The number of bytes generated
*/
pub fn qsc_csg_generate(ctx: &mut QscCsgState, output: &mut [u8], mut outlen: usize) {

	ctx.bctr += outlen;

	if ctx.crmd < outlen {
		let mut outpos = 0;

		/* copy remaining bytes from the cache */
		if ctx.crmd != 0 {
			/* empty the state buffer */
			qsc_memutils_copy(output, &ctx.cache[ctx.cpos..], ctx.crmd);
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
			let rmdlen = qsc_intutils_min(ctx.crmd, outlen);
			qsc_memutils_copy(&mut output[outpos..], &ctx.cache, rmdlen);

			outlen -= rmdlen;
			outpos += rmdlen;
			ctx.crmd -= rmdlen;
			ctx.cpos += rmdlen;
		}
	} else {
		/* copy from the state buffer to output */
		let rmdlen = qsc_intutils_min(ctx.crmd, outlen);
		qsc_memutils_copy(output, &ctx.cache[ctx.cpos..], rmdlen);
		ctx.crmd -= rmdlen;
		ctx.cpos += rmdlen;
	}

	/* clear used bytes */
	if ctx.crmd != 0 {
		qsc_memutils_clear(&mut ctx.cache);
	}

	/* reseed check */
	csg_auto_reseed(ctx);
}