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
* \file scb.h
* \brief An implementation of the SHAKE Cost Based key derivation function: SCB
*
* Usage Example \n
*
* Initialize the DRBG and generate output \n
* \code
	fn scb() {
		let ctx = &mut QscScbState::default();
		let info = &mut [0u8; 64];

		qsc_scb_initialize(ctx, &QRCS_APPLICATION_SALT, QRCS_CRYPTO_SALT_SIZE, info, 64, 10, 10);
		qsc_scb_generate(ctx, info, 64);
		qsc_scb_dispose(ctx);
	}
* \endcode
*
* \remarks
* \par
* CSG uses the Keccak cSHAKE XOF function to produce pseudo-random bytes from a seeded custom SHAKE generator. \n
* If a 32-byte key is used, the implementation uses the cSHAKE-256 implementation for pseudo-random generation, if a 64-byte key is used, the generator uses cSHAKE-512. \n
* The CPU cost feature is an iteration count in the cost mechanism, it determines the number of times both the state absorption and memory expansion functions execute.
* The Memory cost, is the maximum number of megabytes the internal cache is expanded to, during execution of the cost mechanism. \n
* The maximum values of Memory and CPU cost should be determined based on the estimated capability of an adversary, 
* if set too high, the application will become unsuable, if set too low, it may fall within their computational capabilities. \n
* The recommended low-threshold parameters are c:500, m:100. \n
* The generator can be updated with new seed material, which is absorbed into the Keccak state.
*
* For additional usage examples, see scb_test.h. \n
*
* NIST: SHA3 Fips202 http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
* NIST: SP800-185 http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pd
* NIST: SHA3 Keccak Submission http://keccak.noekeon.org/Keccak-submission-3.pdf
* NIST: SHA3 Keccak Slides http://csrc.nist.gov/groups/ST/hash/sha-3/documents/Keccak-slides-at-NIST.pdf
* NIST: SHA3 Third-Round Report http://nvlpubs.nist.gov/nistpubs/ir/2012/NIST.IR.7896.pdf
* Team Keccak: Specifications summary https://keccak.team/keccak_specs_summary.html
*/

use crate::qsc::{
	tools::memutils::qsc_memutils_copy,
	digest::sha3::{
		QscKeccakState,
		QscKeccakRate,
		QSC_KECCAK_STATE_BYTE_SIZE,
		QSC_KECCAK_SHAKE_DOMAIN_ID,
		QSC_KECCAK_PERMUTATION_ROUNDS,
		qsc_shake_squeezeblocks,
		qsc_keccak_absorb,
		qsc_keccak_dispose,
		qsc_cshake_initialize,
	},
};

/*
* \def QSC_SCB512_SEED_SIZE
* \brief The SCB-512 seed size
*/
pub const QSC_SCB_512_SEED_SIZE: usize = 64;

/*
* \def QSC_SCB_CACHE_MINIMUM
* \brief The minimum internal cache allocation in bytes
*/
pub const QSC_SCB_CACHE_MINIMUM: usize = 200;

/*
* \def QSC_SCB_CACHE_MULTIPLIER
* \brief The internal cache allocation multiplier base
*/
pub const QSC_SCB_CACHE_MULTIPLIER: usize = 1000000;

/*
* \struct qsc_scb_state
* \brief The CSG state structure
*/
#[derive(PartialEq)]
pub struct QscScbState {
    pub kstate: QscKeccakState,          /*< The Keccak state  */
    pub cache: Vec<u8>,                     /*< The cache buffer */
    pub clen: usize,                        /*< The cache size */
    pub cpuc: usize,                        /*< The cpu cost  */
    pub memc: usize,                        /*< The memory cost  */
    pub rate: QscKeccakRate,               /*< The absorption rate  */
}

impl Default for QscScbState {
    fn default() -> Self {
        Self {
            kstate: QscKeccakState::default(),
            cache: Default::default(), 
			clen: Default::default(),
            cpuc: Default::default(),
			memc: Default::default(),
            rate: QscKeccakRate::QscKeccakRateNone
        }
    }
}


pub const QSC_SCB_NAME_SIZE: usize = 8;

pub const SCB_NAME: &str = "SCB v1.a";

pub fn scb_extract(ctx: &mut QscScbState, output: &mut [u8], outlen: usize, check: bool) {
	if outlen > 0 {
		let ctxrate = ctx.rate as usize;
		let blkcnt = outlen / ctxrate;

		/* extract the bytes from shake */
		if check {
			qsc_shake_squeezeblocks(&mut ctx.kstate, ctxrate, output, blkcnt);
		} else {
			qsc_shake_squeezeblocks(&mut ctx.kstate, ctxrate, &mut ctx.cache, blkcnt);
		}

		

		if ctxrate * blkcnt < outlen {
			let tmpb = &mut [0u8; QSC_KECCAK_STATE_BYTE_SIZE];
			let fnlblk = outlen - (ctxrate * blkcnt);

			qsc_shake_squeezeblocks(&mut ctx.kstate, ctxrate, tmpb, 1);
			if check {
				qsc_memutils_copy(&mut output[(ctxrate * blkcnt)..], tmpb, fnlblk);
			} else {
				qsc_memutils_copy(&mut ctx.cache[(ctxrate * blkcnt)..], tmpb, fnlblk);
			}
		}
	}
}

pub fn scb_expand(ctx: &mut QscScbState) {
	for _ in 0..ctx.cpuc {
		/* fill the cache */
		let clen = ctx.clen;
		let temp = &mut vec![];
		scb_extract(ctx, temp, clen, false);
		/* absorb the cache */
		qsc_keccak_absorb(&mut ctx.kstate, ctx.rate as usize, &ctx.cache, ctx.clen, QSC_KECCAK_SHAKE_DOMAIN_ID, QSC_KECCAK_PERMUTATION_ROUNDS);

		/* incrementally increase the cache size up to memory cost */
		if ctx.clen < ctx.memc * QSC_SCB_CACHE_MULTIPLIER {
			/* calculate the incremental block size */
			let alclen = (ctx.memc * QSC_SCB_CACHE_MULTIPLIER) / ctx.cpuc;

			ctx.cache.extend_from_slice(&vec![0u8; alclen]);
			ctx.clen += alclen;
		}
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
pub fn qsc_scb_dispose(ctx: &mut QscScbState) {
	qsc_keccak_dispose(&mut ctx.kstate);

	ctx.cache = vec![];
	ctx.clen = 0;
	ctx.cpuc = 0;
	ctx.memc = 0;
	ctx.rate = QscKeccakRate::QscKeccakRateNone;
}

/**
* \brief Initialize the pseudo-random provider state with a seed and optional personalization string
*
* \param ctx: [struct] The function state
* \param seed: [const] The random seed, 32 bytes of seed instantiates the 256-bit generator, 64 bytes the 512-bit generator
* \param seedlen: The length of the input seed
* \param info: [const] The optional personalization string
* \param infolen: The length of the personalization string
* \param cpucost: The number of iterations the internal cost mechanism is executed
* \param memcost: The memory cost is the maximum number of megabytes that can be used by the internal cost mechanism
*/
pub fn qsc_scb_initialize(ctx: &mut QscScbState, seed: &[u8], seedlen: usize, info: &[u8], infolen: usize, cpucost: usize, memcost: usize) {

	/* set the state parameters */
	ctx.clen = QSC_SCB_CACHE_MINIMUM;
	ctx.cache = vec![0u8; QSC_SCB_CACHE_MINIMUM];
	ctx.cpuc = cpucost;
	ctx.memc = memcost;

	if seedlen >= QSC_SCB_512_SEED_SIZE	{
		ctx.rate = QscKeccakRate::QscKeccakRate512;
	} else {
		ctx.rate = QscKeccakRate::QscKeccakRate256;
	}

	/* intialize shake */
	qsc_cshake_initialize(&mut ctx.kstate, ctx.rate as usize, seed, seedlen, SCB_NAME.as_bytes(), QSC_SCB_NAME_SIZE, info, infolen);
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
pub fn qsc_scb_generate(ctx: &mut QscScbState, output: &mut [u8], outlen: usize){
	/* run the cost mechanism */
	scb_expand(ctx);
	/* cost-expand and extract the bytes */
	scb_extract(ctx, output, outlen, true);
}