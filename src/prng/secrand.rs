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

use crate::drbg::csg::{qrc_csg_dispose, qrc_csg_generate, qrc_csg_initialize, QrcCsgState};
use crate::tools::intutils::{qrc_intutils_be8to16, qrc_intutils_be8to16i, qrc_intutils_be8to32, qrc_intutils_be8to32i, qrc_intutils_be8to64, qrc_intutils_be8to64i, qrc_intutils_clear8, qrc_intutils_clear8all, qrc_intutils_copy8};

use core::{mem::size_of, default::Default, u16, u32, u64, i16, i32, i64};

#[cfg(feature = "no_std")]
use alloc::borrow::ToOwned;


const INT16_MAX: i16 = i16::MAX;
const UINT16_MAX: u16 = u16::MAX;

const INT32_MAX: i32 = i32::MAX;
const UINT32_MAX: u32 = u32::MAX;

const INT64_MAX: i64 = i64::MAX;
const UINT64_MAX: u64 = u64::MAX;

/*
* \def QRC_SECRAND_CACHE_SIZE
* \brief The internal cache size of the generator
*/
pub const QRC_SECRAND_CACHE_SIZE: usize = 0x400;

/* 
* \struct qrc_secrand_state
* \brief The internal secrand state array
*/
#[derive(PartialEq)]
pub struct QrcSecrandState {
    pub hstate: QrcCsgState,                  /*< The CSG state */
    pub cache: [u8; QRC_SECRAND_CACHE_SIZE],    /*< The cache buffer */
    pub cpos: usize,                            /*< The cache position */
    pub init: bool                              /*< The initialized flag */
}
impl Default for QrcSecrandState {
    fn default() -> Self {
        Self {
			hstate: QrcCsgState::default(),
            cache: [Default::default(); QRC_SECRAND_CACHE_SIZE],
			cpos: Default::default(),
            init: Default::default(),
        }
    }
}

/*
* \brief Generate a signed 8-bit random integer
*
* \return Returns an signed 8-bit random integer
*/
pub fn qrc_secrand_next_char(state: &mut QrcSecrandState) -> i8 {
	let smp = &mut [0u8; size_of::<i8>()];
	qrc_secrand_generate(state, smp, size_of::<i8>());

	return smp[0] as i8;
}

/*
* \brief Generate a unsigned 8-bit random integer
*
* \return Returns an unsigned 8-bit random integer
*/
pub fn qrc_secrand_next_uchar(state: &mut QrcSecrandState) -> u8 {
	let smp = &mut [0u8; size_of::<u8>()];
	qrc_secrand_generate(state, smp, size_of::<u8>());

	return smp[0];
}

/*
* \brief Generate a random double integer
*
* \return Returns a random double integer
*/
pub fn qrc_secrand_next_double(state: &mut QrcSecrandState) -> f64 {
	let smp = &mut [0u8; size_of::<f64>()];

	qrc_secrand_generate(state, smp, size_of::<f64>());
	return f64::from_ne_bytes(smp.to_owned());
}

/*
* \brief Generate a signed 16-bit random integer
*
* \return Returns a signed 16-bit random integer
*/
pub fn qrc_secrand_next_int16(state: &mut QrcSecrandState) -> i16 {
	let smp = &mut [0u8; size_of::<i16>()];

	qrc_secrand_generate(state, smp, size_of::<i16>());
	return qrc_intutils_be8to16i(smp);
}


/*
* \brief Generate a signed 16-bit random integer of a maximum value
*
* \param maximum: The maximum value of the integer
* \return Returns a signed 16-bit random integer
*/
pub fn qrc_secrand_next_int16_max(state: &mut QrcSecrandState, maximum: i16) -> i16 {
	let smpmax = (INT16_MAX - (INT16_MAX % maximum)) as i16;

	let mut x = 0;
	let mut ret = 0;

	while x >= smpmax || ret < 0 {
		x = qrc_secrand_next_int16(state);
		ret = x % maximum;
	}

	return ret;
}

/*
* \brief Generate a signed 16-bit random integer of a maximum and minimum value
*
* \param maximum: The maximum value of the integer
* \param minimum: The minimum value of the integer
* \return Returns a signed 16-bit random integer
*/
pub fn qrc_secrand_next_int16_maxmin(state: &mut QrcSecrandState, maximum: i16, minimum: i16) -> i16 {
	let smpthr = maximum - minimum + 1;
	let smpmax = (INT16_MAX - (INT16_MAX % smpthr)) as i16;

	let mut x = 0;
	let mut ret = 0;

	while x >= smpmax || ret < 0 {
		x = qrc_secrand_next_int16(state);
		ret = x % smpthr;
	}

	return minimum + ret;
}

/*
* \brief Generate a unsigned 16-bit random integer
*
* \return Returns a unsigned 16-bit random integer
*/
pub fn qrc_secrand_next_uint16(state: &mut QrcSecrandState) -> u16 {
	let smp = &mut [0u8; size_of::<u16>()];

	qrc_secrand_generate(state, smp, size_of::<u16>());
	return qrc_intutils_be8to16(smp);
}

/*
* \brief Generate a unsigned 16-bit random integer of a maximum value
*
* \param maximum: The maximum value of the integer
* \return Returns a unsigned 16-bit random integer
*/
pub fn qrc_secrand_next_uint16_max(state: &mut QrcSecrandState, maximum: u16) -> u16 {
	let smpmax = (UINT16_MAX - (UINT16_MAX % maximum)) as u16;

	let mut x = 0;
	let mut ret = 0;

	while x >= smpmax || ret == 0 {
		x = qrc_secrand_next_uint16(state);
		ret = x % maximum;
	}

	return ret;
}

/*
* \brief Generate a unsigned 16-bit random integer of a maximum and minimum value
*
* \param maximum: The maximum value of the integer
* \param minimum: The minimum value of the integer
* \return Returns a unsigned 16-bit random integer
*/
pub fn qrc_secrand_next_uint16_maxmin(state: &mut QrcSecrandState, maximum: u16, minimum: u16) -> u16 {
	let smpthr = maximum - minimum + 1;
	let smpmax = UINT16_MAX - (UINT16_MAX % smpthr) as u16;

	let mut x = 0;
	let mut ret = 0;

	while x >= smpmax || ret == 0 {
		x = qrc_secrand_next_uint16(state);
		ret = x % smpthr;
	}

	return minimum + ret;
}

/*
* \brief Generate a signed 32-bit random integer
*
* \return Returns a signed 32-bit random integer
*/
pub fn qrc_secrand_next_int32(state: &mut QrcSecrandState) -> i32 {
	let smp = &mut [0u8; size_of::<i32>()];
	
	qrc_secrand_generate(state, smp, size_of::<i32>());
	return qrc_intutils_be8to32i(smp);
}

/*
* \brief Generate a signed 32-bit random integer of a maximum value
*
* \param maximum: The maximum value of the integer
* \return Returns a signed 32-bit random integer
*/
pub fn qrc_secrand_next_int32_max(state: &mut QrcSecrandState, maximum: i32) -> i32 {
	let smpmax = INT32_MAX - (INT32_MAX % maximum);

	let mut x = 0;
	let mut ret = 0;

	while x >= smpmax || ret < 0 {
		x = qrc_secrand_next_int32(state);
		ret = x % maximum;
	}

	return ret;
}

/*
* \brief Generate a signed 32-bit random integer of a maximum and minimum value
*
* \param maximum: The maximum value of the integer
* \param minimum: The minimum value of the integer
* \return Returns a signed 32-bit random integer
*/
pub fn qrc_secrand_next_int32_maxmin(state: &mut QrcSecrandState, maximum: i32, minimum: i32) -> i32 {
	let smpthr = maximum - minimum + 1;
	let smpmax = INT32_MAX - (INT32_MAX % smpthr);

	let mut x = 0;
	let mut ret = 0;

	while x >= smpmax || ret < 0 {
		x = qrc_secrand_next_int32(state);
		ret = x % smpthr;
	}

	return minimum + ret;
}

/*
* \brief Generate a unsigned 32-bit random integer
*
* \return Returns a unsigned 32-bit random integer
*/
pub fn qrc_secrand_next_uint32(state: &mut QrcSecrandState) -> u32{
	let smp = &mut [0u8; size_of::<u32>()];

	qrc_secrand_generate(state, smp, size_of::<u32>());
	return qrc_intutils_be8to32(smp);
}

/*
* \brief Generate a unsigned 32-bit random integer of a maximum value
*
* \param maximum: The maximum value of the integer
* \return Returns a unsigned 32-bit random integer
*/
pub fn qrc_secrand_next_uint32_max(state: &mut QrcSecrandState, maximum: u32) -> u32 {
	let smpmax = UINT32_MAX - (UINT32_MAX % maximum);

	let mut x = 0;
	let mut ret = 0;

	while x >= smpmax || ret == 0 {
		x = qrc_secrand_next_uint32(state);
		ret = x % maximum;
	}

	return ret;
}

/*
* \brief Generate a unsigned 32-bit random integer of a maximum and minimum value
*
* \param maximum: The maximum value of the integer
* \param minimum: The minimum value of the integer
* \return Returns a unsigned 32-bit random integer
*/
pub fn qrc_secrand_next_uint32_maxmin(state: &mut QrcSecrandState, maximum: u32, minimum: u32) -> u32 {
	let smpthr = maximum - minimum + 1;
	let smpmax = UINT32_MAX - (UINT32_MAX % smpthr);

	let mut x = 0;
	let mut ret = 0;

	while x >= smpmax || ret == 0	{
		x = qrc_secrand_next_uint32(state);
		ret = x % smpthr;
	}

	return minimum + ret;
}

/*
* \brief Generate a signed 64-bit random integer
*
* \return Returns a signed 64-bit random integer
*/
pub fn qrc_secrand_next_int64(state: &mut QrcSecrandState) -> i64 {
	let smp = &mut [0u8; size_of::<i64>()];

	qrc_secrand_generate(state, smp, size_of::<i64>());
	return qrc_intutils_be8to64i(smp);
}

/*
* \brief Generate a signed 64-bit random integer of a maximum value
*
* \param maximum: The maximum value of the integer
* \return Returns a signed 64-bit random integer
*/
pub fn qrc_secrand_next_int64_max(state: &mut QrcSecrandState, maximum: i64) -> i64{
	let smpmax = INT64_MAX - (INT64_MAX % maximum);

	let mut x = 0;
	let mut ret = 0;

	while x >= smpmax || ret < 0 {
		x = qrc_secrand_next_int64(state);
		ret = x % maximum;
	}

	return ret;
}

/*
* \brief Generate a signed 64-bit random integer of a maximum and minimum value
*
* \param maximum: The maximum value of the integer
* \param minimum: The minimum value of the integer
* \return Returns a signed 64-bit random integer
*/
pub fn qrc_secrand_next_int64_maxmin(state: &mut QrcSecrandState, maximum: i64, minimum: i64) -> i64 {
	let smpthr = maximum - minimum + 1;
	let smpmax = INT64_MAX - (INT64_MAX % smpthr);

	let mut x = 0;
	let mut ret = 0;

	while x >= smpmax || ret < 0 {
		x = qrc_secrand_next_int64(state);
		ret = x % smpthr;
	}

	return minimum + ret;
}

/*
* \brief Generate a unsigned 64-bit random integer
*
* \return Returns a unsigned 64-bit random integer
*/
pub fn qrc_secrand_next_uint64(state: &mut QrcSecrandState) -> u64 {
	let smp = &mut [0u8; size_of::<u64>()];

	qrc_secrand_generate(state, smp, size_of::<u64>());
	return qrc_intutils_be8to64(smp);
}
/*
* \brief Generate a unsigned 64-bit random integer of a maximum value
*
* \param maximum: The maximum value of the integer
* \return Returns a unsigned 64-bit random integer
*/
pub fn qrc_secrand_next_uint64_max(state: &mut QrcSecrandState, maximum: u64) -> u64 {
	let smpmax = UINT64_MAX - (UINT64_MAX % maximum);

	let mut x = 04;
	let mut ret = 0;

	while x >= smpmax || ret == 0 {
		x = qrc_secrand_next_uint64(state);
		ret = x % maximum;
	}

	return ret;
}

/*
* \brief Generate a unsigned 64-bit random integer of a maximum and minimum value
*
* \param maximum: The maximum value of the integer
* \param minimum: The minimum value of the integer
* \return Returns a unsigned 64-bit random integer
*/
pub fn qrc_secrand_next_uint64_maxmin(state: &mut QrcSecrandState, maximum: u64, minimum: u64) -> u64 {
	let smpthr = maximum - minimum + 1;
	let smpmax = UINT64_MAX - (UINT64_MAX % smpthr);

	let mut x = 0;
	let mut ret = 0;

	while x >= smpmax || ret == 0 {
		x = qrc_secrand_next_uint64(state);
		ret = x % smpthr;
	}

	return minimum + ret;
}

/*
* \brief Clear the buffer and destroy the internal state
*/
pub fn qrc_secrand_destroy(secrand_state: &mut QrcSecrandState) {
	if secrand_state.init {
		qrc_intutils_clear8(&mut secrand_state.cache, QRC_SECRAND_CACHE_SIZE);
		qrc_csg_dispose(&mut secrand_state.hstate);
		secrand_state.cpos = 0;
		secrand_state.init = false;
	}
}

/*
* \brief Initialize the random generator with a seed and optional customization array
*
* \param seed: The primary seed, must be 32 or 64 bytes in length
* \param seedlen: The byte length of the seed
* \param custom: The optional customization parameter (can be NULL)
* \param custlen: The length of the customization array
*/
pub fn qrc_secrand_initialize(secrand_state: &mut QrcSecrandState, seed: &[u8], seedlen: usize, custom: &[u8], custlen: usize) {
	/* initialize the underlying generator */
	qrc_csg_initialize(&mut secrand_state.hstate, seed, seedlen, custom, custlen, true);

	/* pre-fill the cache */
	qrc_csg_generate(&mut secrand_state.hstate, &mut secrand_state.cache, QRC_SECRAND_CACHE_SIZE);
	secrand_state.cpos = 0;
	secrand_state.init = true;
}

/*
* \brief Generate an array of pseudo-random bytes
*
* \param output: The destination array
* \param length: The number of bytes to generate
*/
pub fn qrc_secrand_generate(secrand_state: &mut QrcSecrandState, output: &mut [u8], mut length: usize) -> bool {

	let buflen = QRC_SECRAND_CACHE_SIZE - secrand_state.cpos;
	let mut res = false;

	if !secrand_state.init {
		qrc_intutils_clear8all(output);
		length = 0;
	}

	if length != 0 {
		if length > buflen {
			let mut poft = 0;

			if buflen > 0 {
				qrc_intutils_copy8(output, &secrand_state.cache[secrand_state.cpos..], buflen);
				length -= buflen;
				poft += buflen;
				secrand_state.cpos = QRC_SECRAND_CACHE_SIZE;
			}

			while length >= QRC_SECRAND_CACHE_SIZE {
				qrc_csg_generate(&mut secrand_state.hstate, &mut secrand_state.cache, QRC_SECRAND_CACHE_SIZE);
				qrc_intutils_copy8(&mut output[poft..], &secrand_state.cache, QRC_SECRAND_CACHE_SIZE);
				length -= QRC_SECRAND_CACHE_SIZE;
				poft += QRC_SECRAND_CACHE_SIZE;
			}

			if length != 0 {
				qrc_csg_generate(&mut secrand_state.hstate, &mut secrand_state.cache, QRC_SECRAND_CACHE_SIZE);
				qrc_intutils_copy8(&mut output[poft..], &secrand_state.cache, length);
				secrand_state.cpos = length;
			}
		} else {
			qrc_intutils_copy8(output, &secrand_state.cache[secrand_state.cpos..], length);
			secrand_state.cpos += length;
		}

		res = true;
	}

	if secrand_state.cpos != 0 {
		qrc_intutils_clear8(&mut secrand_state.cache, QRC_SECRAND_CACHE_SIZE);
	}

	return res;
}