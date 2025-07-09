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

use crate::{digest::sha3::{qrc_cshake_initialize, qrc_keccak_absorb, qrc_keccak_dispose, qrc_shake_squeezeblocks, QrcKeccakRate, QrcKeccakState, QRC_KECCAK_PERMUTATION_ROUNDS, QRC_KECCAK_SHAKE_DOMAIN_ID, QRC_KECCAK_STATE_BYTE_SIZE}, tools::intutils::qrc_intutils_copy8};

use core::default::Default;

#[cfg(feature = "no_std")]
use alloc::{vec, vec::Vec};


/*
* \def QRC_SCB_256_HASH_SIZE
* \brief The SCB-256 hash size
*/
pub const QRC_SCB_256_HASH_SIZE: usize = 32;

/*
* \def QRC_SCB512_HASH_SIZE
* \brief The SCB-512 hash size
*/
pub const QRC_SCB_512_HASH_SIZE: usize = 64;

/*
* \def QRC_SCB256_SEED_SIZE
* \brief The SCB-256 seed size
*/
pub const QRC_SCB_256_SEED_SIZE: usize = 32;

/*
* \def QRC_SCB512_SEED_SIZE
* \brief The SCB-512 seed size
*/
pub const QRC_SCB_512_SEED_SIZE: usize = 64;

/*
* \def QRC_SCB_CACHE_MINIMUM
* \brief The minimum internal cache allocation in bytes
*/
pub const QRC_SCB_CACHE_MINIMUM: usize = 200;

/*
* \def QRC_SCB_CACHE_MULTIPLIER
* \brief The internal cache allocation multiplier base
*/
pub const QRC_SCB_CACHE_MULTIPLIER: usize = 1000000;

/*
* \struct qrc_scb_state
* \brief The CSG state structure
*/
#[derive(PartialEq)]
pub struct QrcScbState {
    pub kstate: QrcKeccakState,          /*< The Keccak state  */
    pub cache: Vec<u8>,                     /*< The cache buffer */
    pub clen: usize,                        /*< The cache size */
    pub cpuc: usize,                        /*< The cpu cost  */
    pub memc: usize,                        /*< The memory cost  */
    pub rate: QrcKeccakRate,               /*< The absorption rate  */
}

impl Default for QrcScbState {
    fn default() -> Self {
        Self {
            kstate: QrcKeccakState::default(),
            cache: Default::default(), 
			clen: Default::default(),
            cpuc: Default::default(),
			memc: Default::default(),
            rate: QrcKeccakRate::QrcKeccakRateNone
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
pub fn qrc_scb_dispose(ctx: &mut QrcScbState) {
	qrc_keccak_dispose(&mut ctx.kstate);

	ctx.cache = vec![];
	ctx.clen = 0;
	ctx.cpuc = 0;
	ctx.memc = 0;
	ctx.rate = QrcKeccakRate::QrcKeccakRateNone;
}

/*
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
pub fn qrc_scb_initialize(ctx: &mut QrcScbState, seed: &[u8], seedlen: usize, info: &[u8], infolen: usize, cpucost: usize, memcost: usize) {

	/* set the state parameters */
	ctx.clen = QRC_SCB_CACHE_MINIMUM;
	ctx.cache = vec![0u8; QRC_SCB_CACHE_MINIMUM];
	ctx.cpuc = cpucost;
	ctx.memc = memcost;

	if seedlen >= QRC_SCB_512_SEED_SIZE	{
		ctx.rate = QrcKeccakRate::QrcKeccakRate512;
	} else {
		ctx.rate = QrcKeccakRate::QrcKeccakRate256;
	}

	/* intialize shake */
	qrc_cshake_initialize(&mut ctx.kstate, ctx.rate as usize, seed, seedlen, SCB_NAME.as_bytes(), QRC_SCB_NAME_SIZE, info, infolen);
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
pub fn qrc_scb_generate(ctx: &mut QrcScbState, output: &mut [u8], outlen: usize){
	/* run the cost mechanism */
	scb_expand(ctx);
	/* cost-expand and extract the bytes */
	scb_extract(ctx, output, outlen, true);
}

const QRC_SCB_NAME_SIZE: usize = 8;

const SCB_NAME: &str = "SCB v1.a";

fn scb_extract(ctx: &mut QrcScbState, output: &mut [u8], outlen: usize, check: bool) {
	if outlen > 0 {
		let ctxrate = ctx.rate as usize;
		let blkcnt = outlen / ctxrate;

		/* extract the bytes from shake */
		if check {
			qrc_shake_squeezeblocks(&mut ctx.kstate, ctxrate, output, blkcnt);
		} else {
			qrc_shake_squeezeblocks(&mut ctx.kstate, ctxrate, &mut ctx.cache, blkcnt);
		}

		

		if ctxrate * blkcnt < outlen {
			let tmpb = &mut [0u8; QRC_KECCAK_STATE_BYTE_SIZE];
			let fnlblk = outlen - (ctxrate * blkcnt);

			qrc_shake_squeezeblocks(&mut ctx.kstate, ctxrate, tmpb, 1);
			if check {
				qrc_intutils_copy8(&mut output[(ctxrate * blkcnt)..], tmpb, fnlblk);
			} else {
				qrc_intutils_copy8(&mut ctx.cache[(ctxrate * blkcnt)..], tmpb, fnlblk);
			}
		}
	}
}

fn scb_expand(ctx: &mut QrcScbState) {
	for _ in 0..ctx.cpuc {
		/* fill the cache */
		let clen = ctx.clen;
		let temp = &mut vec![];
		scb_extract(ctx, temp, clen, false);
		/* absorb the cache */
		qrc_keccak_absorb(&mut ctx.kstate, ctx.rate as usize, &ctx.cache, ctx.clen, QRC_KECCAK_SHAKE_DOMAIN_ID, QRC_KECCAK_PERMUTATION_ROUNDS);

		/* incrementally increase the cache size up to memory cost */
		if ctx.clen < ctx.memc * QRC_SCB_CACHE_MULTIPLIER {
			/* calculate the incremental block size */
			let alclen = (ctx.memc * QRC_SCB_CACHE_MULTIPLIER) / ctx.cpuc;

			ctx.cache.extend_from_slice(&vec![0u8; alclen]);
			ctx.clen += alclen;
		}
	}
}