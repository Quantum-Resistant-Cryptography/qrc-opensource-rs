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

/*
* \file intutils.h
* \brief This file contains common integer functions
*/

use std::mem::size_of;

/**
* \brief Increment an 8-bit integer array as a segmented big-endian integer
*
* \param output: The destination integer 8-bit array
* \param outlen: The length of the output counter array
*/
pub fn qsc_intutils_be8increment(output: &mut [u8], outlen: usize) {
    let mut i = outlen;

    if outlen > 0 {
        loop {
            i -= 1;
            if output[i] == 255 {
				output[i] = 0;
			} else {
				output[i] += 1;
			}
            if i == 0 || output[i] != 0 {
                break;
            }
        }
    }
}

/**
* \brief Constant-time conditional move function
* b=1 means move, b=0 means don't move
*
* \param dest: The return array
* \param source: [const] The source array
* \param length: The number of bytes to move
* \param cond: The condition
*/
pub fn qsc_intutils_cmov(dest: &mut [u8], source: &[u8], length: usize, mut cond: u8) {
    cond = (!cond).wrapping_add(1);

    for i in 0..length {
        dest[i] ^= (dest[i] ^ source[i]) & cond;
    }
}

/**
* \brief Convert an 8-bit integer array to a 32-bit big-endian integer
*
* \param input: [const] The source integer 8-bit array
* \return Returns the 32-bit big endian integer
*/
pub fn qsc_intutils_be8to32(input: &[u8]) -> u32 {
	return ((input[3] as u32) | ((input[2] as u32) << 8) | ((input[1] as u32) << 16) | ((input[0] as u32) << 24)) as u32;
}

/**
* \brief Convert an 8-bit integer array to a 64-bit big-endian integer
*
* \param input: [const] The source integer 8-bit array
* \return Returns the 64-bit big endian integer
*/
pub fn qsc_intutils_be8to64(input: &[u8]) -> u64 {
	return ((input[7] as u64) | ((input[6] as u64) << 8) | ((input[5] as u64) << 16) | ((input[4] as u64) << 24) | ((input[3] as u64) << 32) | ((input[2] as u64) << 40) | ((input[1] as u64) << 48) | ((input[0] as u64) << 56)) as u64;
}

/**
* \brief Convert a 32-bit integer to a big-endian 8-bit integer array
*
* \param output: The destination 8-bit integer array
* \param value: The 32-bit integer
*/
pub fn qsc_intutils_be32to8(output: &mut [u8], value: u32) {
	output[3] = value as u8 & 0xFF;
	output[2] = (value >> 8) as u8 & 0xFF;
	output[1] = (value >> 16) as u8 & 0xFF;
	output[0] = (value >> 24) as u8 & 0xFF;
}

/**
* \brief Convert a 64-bit integer to a big-endian 8-bit integer array
*
* \param output: The destination 8-bit integer array
* \param value: The 64-bit integer
*/
pub fn qsc_intutils_be64to8(output: &mut [u8], value: u64) {
	output[7] = value as u8 & 0xFF;
	output[6] = (value >> 8) as u8 & 0xFF;
	output[5] = (value >> 16) as u8 & 0xFF;
	output[4] = (value >> 24) as u8 & 0xFF;
	output[3] = (value >> 32) as u8 & 0xFF;
	output[2] = (value >> 40) as u8 & 0xFF;
	output[1] = (value >> 48) as u8 & 0xFF;
	output[0] = (value >> 56) as u8 & 0xFF;
}

/**
* \brief Set an an 8-bit integer array to zeroes
*
* \param a: The array to zeroize
* \param count: The number of 8-bit integers to zeroize
*/
pub fn qsc_intutils_clear8(a: &mut [u8], count: usize) {
	for i in 0..count {
		a[i] = 0;
	}
}

/**
* \brief Set an an 32-bit integer array to zeroes
*
* \param a: The array to zeroize
* \param count: the number of 32-bit integers to zeroize
*/
pub fn qsc_intutils_clear32(a: &mut [u32], count: usize) {
	for i in 0..count {
		a[i] = 0;
	}
}

/**
* \brief Set an an 64-bit integer array to zeroes
*
* \param a: The array to zeroize
* \param count: The number of 64-bit integers to zeroize
*/
pub fn qsc_intutils_clear64(a: &mut [u64], count: usize) {
	for i in 0..count {
		a[i] = 0;
	}
}

/**
* \brief Convert an array to a hex string
*
* \param input: [const] The array input
* \param hexstr: The hexadecimal string output; must be 2x the size of input array
* \param length: The length of the input array
*/
pub fn qsc_intutils_bin_to_hex(input: &[u8], hexstr: &mut String) {
	const ENCODING_TABLE: [u8; 16] = [
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
    ];

    for &byte in input {
        hexstr.push(ENCODING_TABLE[(byte >> 4) as usize] as char);
        hexstr.push(ENCODING_TABLE[(byte & 0x0F) as usize] as char);
    }
}

/**
* \brief Increment an 8-bit integer array as a segmented little-endian integer
*
* \param output: The source integer 8-bit array
* \param outlen: The length of the output counter array
*/
pub fn qsc_intutils_le8increment(output: &mut [u8], outlen: usize) {
	for i in 0..outlen {
		if output[i] == 255 {
			output[i] = 0;
		} else {
			output[i] += 1;
		}

		if output[i] != 0 {
			break;
		}
	}
}

/**
* \brief Convert an 8-bit integer array to a 16-bit little-endian integer
*
* \param input: [const] The source integer 8-bit array
* \return Returns the 16-bit little endian integer
*/
pub fn qsc_intutils_le8to16(input: &[u8]) -> u16 {
	return (input[0] as u16 | ((input[1] as u16) << 8)) as u16;
}

/**
* \brief Convert an 8-bit integer array to a 32-bit little-endian integer
*
* \param input: [const] The source integer 8-bit array
* \return Returns the 32-bit little endian integer
*/
pub fn qsc_intutils_le8to32(input: &[u8]) -> u32 {
	return (input[0] as u32 | ((input[1] as u32) << 8) | ((input[2] as u32) << 16) | ((input[3] as u32) << 24)) as u32;
}

/**
* \brief Convert an 8-bit integer array to a 64-bit little-endian integer
*
* \param input: [const] The source integer 8-bit array
* \return Returns the 64-bit little endian integer
*/
pub fn qsc_intutils_le8to64(input: &[u8]) -> u64 {
	return ((input[0] as u64) | ((input[1] as u64) << 8) | ((input[2] as u64) << 16) | ((input[3] as u64) << 24) | ((input[4] as u64) << 32) | ((input[5] as u64) << 40) | ((input[6] as u64) << 48) | ((input[7] as u64) << 56)) as u64;
}

/**
* \brief Convert a 16-bit integer to a little-endian 8-bit integer array
*
* \param output: The 8-bit integer array
* \param value: The 16-bit integer
*/
pub fn qsc_intutils_le16to8(output: &mut [u8], value: u16) {
	output[0] = value as u8 & 0xFF;
	output[1] = (value >> 8) as u8 & 0xFF;
}

/**
* \brief Convert a 32-bit integer to a little-endian 8-bit integer array
*
* \param output: The 8-bit integer array
* \param value: The 32-bit integer
*/
pub fn qsc_intutils_le32to8(output: &mut [u8], value: u32) {
	output[0] = value as u8 & 0xFF;
	output[1] = (value >> 8) as u8 & 0xFF;
	output[2] = (value >> 16) as u8 & 0xFF;
	output[3] = (value >> 24) as u8 & 0xFF;
}

/**
* \brief Convert a 64-bit integer to a little-endian 8-bit integer array
*
* \param output: The 8-bit integer array
* \param value: The 64-bit integer
*/
pub fn qsc_intutils_le64to8(output: &mut [u8], value: u64) {
	output[0] = value as u8 & 0xFF;
	output[1] = (value >> 8) as u8 & 0xFF;
	output[2] = (value >> 16) as u8 & 0xFF;
	output[3] = (value >> 24) as u8 & 0xFF;
	output[4] = (value >> 32) as u8 & 0xFF;
	output[5] = (value >> 40) as u8 & 0xFF;
	output[6] = (value >> 48) as u8 & 0xFF;
	output[7] = (value >> 56) as u8 & 0xFF;
}

/**
* \brief Compares two byte 8-bit integers for equality
*
* \param a: [const] The first array to compare
* \param b: [const] The second array to compare
* \param length: The number of bytes to compare
* \return Returns true for equal values
*/
pub fn qsc_intutils_are_equal8(a: &[u8], b: &[u8], length: usize) ->  bool {
    let mut status: bool = true;
	for i in 0..length {
		if a[i] != b[i]	{
			status = false;
			break;
		}
	}

	return status;
}

/**
* \brief Return the smaller of two integers
*
* \param a: The first 32-bit integer
* \param b: The second 32-bit integer
* \return Returns the smaller integer
*/
pub fn qsc_intutils_min(a: usize, b: usize) -> usize {
	return if a < b { a } else { b };
}

/**
* \brief Rotate an unsigned 64-bit integer to the left
*
* \param value: The value to rotate
* \param shift: The bit shift register
* \return Returns the rotated integer
*/
pub fn qsc_intutils_rotl64(value: u64, shift: usize) -> u64 {
	return (value << shift) | (value >> ((size_of::<u64>() * 8) - shift));
}


pub fn qsc_intutils_verify(a: &[u8], b: &[u8], length: usize) -> i32 {
	let mut d: u16 = 0;

	for i in 0..length {
		d |= (a[i] ^ b[i]) as u16;
	}

	return (1 & ((d as i32 - 1) >> 8)) - 1;
}