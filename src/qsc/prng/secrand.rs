/* The AGPL version 3 License (AGPLv3)
*
* Copyright (c) 2024 DFD & QRC Eurosmart SA
* This file is part of the QSC Cryptographic library
*
* This program is free software : you can redistribute it and / or modify
* it under the terms of the GNU Affero General public License as pub(crate)lished by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
* See the GNU Affero General public License for more details.
*
* You should have received a copy of the GNU Affero General public License
* along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

/*
* \file secrand.h
* \brief An implementation of an secure pseudo-random generator.
* Must be pre-keyed using the secrand_initialize function.
*/

use crate::qsc::{
	drbg::csg::{
		QscCsgState,
		qsc_csg_initialize,
		qsc_csg_generate,
		qsc_csg_dispose,
	},
	tools::memutils::{qsc_memutils_clear, qsc_memutils_copy},
};

use bytemuck::cast_slice_mut;

/*
* \def QSC_SECRAND_CACHE_SIZE
* \brief The internal cache size of the generator
*/
const QSC_SECRAND_CACHE_SIZE: usize = 0x400;

/*
* \struct qsc_secrand_state
* \brief The internal secrand state array
*/
#[derive(PartialEq, Debug)]
pub(crate) struct QscSecrandState {
    pub(crate) hstate: QscCsgState,                  /*< The CSG state */
    pub(crate) cache: [u8; QSC_SECRAND_CACHE_SIZE],    /*< The cache buffer */
    pub(crate) cpos: usize,                            /*< The cache position */
    pub(crate) init: bool                              /*< The initialized flag */
}
impl Default for QscSecrandState {
    fn default() -> Self {
        Self {
			hstate: QscCsgState::default(),
            cache: [Default::default(); QSC_SECRAND_CACHE_SIZE],
			cpos: Default::default(),
            init: Default::default(),
        }
    }
}

/**
* \brief Clear the buffer and destroy the internal state
*/
pub(crate) fn qsc_secrand_destroy(secrand_state: &mut QscSecrandState) {
	if secrand_state.init == true {
		qsc_memutils_clear(&mut secrand_state.cache);
		qsc_csg_dispose(&mut secrand_state.hstate);
		secrand_state.cpos = 0;
		secrand_state.init = false;
	}
}

/**
* \brief Initialize the random generator with a seed and optional customization array
*
* \param seed: The primary seed, must be 32 or 64 bytes in length
* \param seedlen: The byte length of the seed
* \param custom: The optional customization parameter (can be NULL)
* \param custlen: The length of the customization array
*/
pub(crate) fn qsc_secrand_initialize(secrand_state: &mut QscSecrandState, seed: &[u8], seedlen: usize, custom: &[u8], custlen: usize) {
	/* initialize the underlying generator */
	qsc_csg_initialize(&mut secrand_state.hstate, seed, seedlen, custom, custlen, true);

	/* pre-fill the cache */
	qsc_csg_generate(&mut secrand_state.hstate, &mut secrand_state.cache, QSC_SECRAND_CACHE_SIZE);
	secrand_state.cpos = 0;
	secrand_state.init = true;
}

/**
* \brief Generate an array of pseudo-random bytes
*
* \param output: The destination array
* \param length: The number of bytes to generate
*/
pub(crate) fn qsc_secrand_generate(secrand_state: &mut QscSecrandState, output: &mut [u8], mut length: usize) -> bool {

	let buflen = QSC_SECRAND_CACHE_SIZE - secrand_state.cpos;
	let mut res = false;

	if secrand_state.init != true {
		qsc_memutils_clear(output);
		length = 0;
	}

	if length != 0 {
		if length > buflen {
			let mut poft = 0;

			if buflen > 0 {
				qsc_memutils_copy(output, &secrand_state.cache[secrand_state.cpos..], buflen);
				length -= buflen;
				poft += buflen;
				secrand_state.cpos = QSC_SECRAND_CACHE_SIZE;
			}

			while length >= QSC_SECRAND_CACHE_SIZE {
				qsc_csg_generate(&mut secrand_state.hstate, &mut secrand_state.cache, QSC_SECRAND_CACHE_SIZE);
				qsc_memutils_copy(&mut output[poft..], &secrand_state.cache, QSC_SECRAND_CACHE_SIZE);
				length -= QSC_SECRAND_CACHE_SIZE;
				poft += QSC_SECRAND_CACHE_SIZE;
			}

			if length != 0 {
				qsc_csg_generate(&mut secrand_state.hstate, &mut secrand_state.cache, QSC_SECRAND_CACHE_SIZE);
				qsc_memutils_copy(&mut output[poft..], &secrand_state.cache, length);
				secrand_state.cpos = length;
			}
		} else {
			qsc_memutils_copy(output, &secrand_state.cache[secrand_state.cpos..], length);
			secrand_state.cpos += length;
		}

		res = true;
	}

	if secrand_state.cpos != 0 {
		let byte_slice = cast_slice_mut(&mut secrand_state.cache);
		qsc_memutils_clear(byte_slice);
	}

	return res;
}
