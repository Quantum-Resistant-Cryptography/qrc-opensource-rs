#![allow(dead_code)]
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

/*
* \file intutils
* \brief This file contains common integer functions
*/


use crate::{
    common::common::{QRC_MAX_MEMORY_CLEAR, QRC_SYSTEM_IS_LITTLE_ENDIAN},
    tools::memutils::{
        qrc_memutils_clear8, qrc_memutils_clear8i, qrc_memutils_clear16, qrc_memutils_clear16i,
        qrc_memutils_clear32, qrc_memutils_clear32i, qrc_memutils_clear64, qrc_memutils_clear64i,
    },
};

use core::mem::size_of;

#[cfg(feature = "std")]
use crate::tools::memutils::qrc_memutils_clear_string;

#[cfg(feature = "no_std")]
use alloc::{vec, vec::Vec, borrow::ToOwned};



/*
* \brief Compares two byte 8-bit integers for equality
*
* \param a: [const] The first array to compare
* \param b: [const] The second array to compare
* \param length: The number of bytes to compare
* \return Returns true for equal values
*/
pub fn qrc_intutils_are_equal8(a: &[u8], b: &[u8], length: usize) -> bool {
    let mut status: bool = true;
    for i in 0..length {
        if a[i] != b[i] {
            status = false;
            break;
        }
    }

    return status;
}

/*
* \brief Convert an 8-bit integer array to a 16-bit big-endian integer
*
* \param input: [const] The source integer 8-bit array
* \return Returns the 16-bit big endian integer
*/
pub fn qrc_intutils_be8to16(input: &[u8]) -> u16 {
    return ((input[1] as u16) | ((input[0] as u16) << 8)) as u16;
}
pub fn qrc_intutils_be8to16i(input: &[u8]) -> i16 {
    return ((input[1] as i16) | ((input[0] as i16) << 8)) as i16;
}

/*
* \brief Convert an 8-bit integer array to a 32-bit big-endian integer
*
* \param input: [const] The source integer 8-bit array
* \return Returns the 32-bit big endian integer
*/
pub fn qrc_intutils_be8to32(input: &[u8]) -> u32 {
    return ((input[3] as u32)
        | ((input[2] as u32) << 8)
        | ((input[1] as u32) << 16)
        | ((input[0] as u32) << 24)) as u32;
}
pub fn qrc_intutils_be8to32i(input: &[u8]) -> i32 {
    return ((input[3] as i32)
        | ((input[2] as i32) << 8)
        | ((input[1] as i32) << 16)
        | ((input[0] as i32) << 24)) as i32;
}

/*
* \brief Convert an 8-bit integer array to a 64-bit big-endian integer
*
* \param input: [const] The source integer 8-bit array
* \return Returns the 64-bit big endian integer
*/
pub fn qrc_intutils_be8to64(input: &[u8]) -> u64 {
    return ((input[7] as u64)
        | ((input[6] as u64) << 8)
        | ((input[5] as u64) << 16)
        | ((input[4] as u64) << 24)
        | ((input[3] as u64) << 32)
        | ((input[2] as u64) << 40)
        | ((input[1] as u64) << 48)
        | ((input[0] as u64) << 56)) as u64;
}
pub fn qrc_intutils_be8to64i(input: &[u8]) -> i64 {
    return ((input[7] as i64)
        | ((input[6] as i64) << 8)
        | ((input[5] as i64) << 16)
        | ((input[4] as i64) << 24)
        | ((input[3] as i64) << 32)
        | ((input[2] as i64) << 40)
        | ((input[1] as i64) << 48)
        | ((input[0] as i64) << 56)) as i64;
}

/*
* \brief Convert a 16-bit integer to a big-endian 8-bit integer array
*
* \param output: The destination 8-bit integer array
* \param value: The 16-bit integer
*/
pub fn qrc_intutils_be16to8(output: &mut [u8], value: u16) {
    output[1] = value as u8 & 0xFF;
    output[0] = (value >> 8) as u8 & 0xFF;
}

/*
* \brief Convert a 32-bit integer to a big-endian 8-bit integer array
*
* \param output: The destination 8-bit integer array
* \param value: The 32-bit integer
*/
pub fn qrc_intutils_be32to8(output: &mut [u8], value: u32) {
    output[3] = value as u8 & 0xFF;
    output[2] = (value >> 8) as u8 & 0xFF;
    output[1] = (value >> 16) as u8 & 0xFF;
    output[0] = (value >> 24) as u8 & 0xFF;
}

/*
* \brief Convert a 64-bit integer to a big-endian 8-bit integer array
*
* \param output: The destination 8-bit integer array
* \param value: The 64-bit integer
*/
pub fn qrc_intutils_be64to8(output: &mut [u8], value: u64) {
    output[7] = value as u8 & 0xFF;
    output[6] = (value >> 8) as u8 & 0xFF;
    output[5] = (value >> 16) as u8 & 0xFF;
    output[4] = (value >> 24) as u8 & 0xFF;
    output[3] = (value >> 32) as u8 & 0xFF;
    output[2] = (value >> 40) as u8 & 0xFF;
    output[1] = (value >> 48) as u8 & 0xFF;
    output[0] = (value >> 56) as u8 & 0xFF;
}

/*
* \brief Increment an 8-bit integer array as a segmented big-endian integer
*
* \param output: The destination integer 8-bit array
* \param outlen: The length of the output counter array
*/
pub fn qrc_intutils_be8increment(output: &mut [u8], outlen: usize) {
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

/*
* \brief Set an an 8-bit integer array to zeroes
*
* \param a: The array to zeroize
* \param count: The number of 8-bit integers to zeroize
*/
pub fn qrc_intutils_clear8(a: &mut [u8], count: usize) {
    if QRC_MAX_MEMORY_CLEAR {
        qrc_memutils_clear8(a);
    } else {
        for i in 0..count {
            a[i] = 0;
        }
    }
}
pub fn qrc_intutils_clear8i(a: &mut [i8], count: usize) {
    if QRC_MAX_MEMORY_CLEAR {
        qrc_memutils_clear8i(a);
    } else {
        for i in 0..count {
            a[i] = 0;
        }
    }
}
pub fn qrc_intutils_clear8all(a: &mut [u8]) {
    if QRC_MAX_MEMORY_CLEAR {
        qrc_memutils_clear8(a);
    } else {
        a.fill(0);
    }
}

/*
* \brief Set an an 8-bit integer array to zeroes
*
* \param a: The array to zeroize
* \param count: The number of 8-bit integers to zeroize
*/
pub fn qrc_intutils_clear16(a: &mut [u16], count: usize) {
    if QRC_MAX_MEMORY_CLEAR {
        qrc_memutils_clear16(a);
    } else {
        for i in 0..count {
            a[i] = 0;
        }
    }
}
pub fn qrc_intutils_clear16i(a: &mut [i16], count: usize) {
    if QRC_MAX_MEMORY_CLEAR {
        qrc_memutils_clear16i(a);
    } else {
        for i in 0..count {
            a[i] = 0;
        }
    }
}

/*
* \brief Set an an 32-bit integer array to zeroes
*
* \param a: The array to zeroize
* \param count: the number of 32-bit integers to zeroize
*/
pub fn qrc_intutils_clear32(a: &mut [u32], count: usize) {
    if QRC_MAX_MEMORY_CLEAR {
        qrc_memutils_clear32(a);
    } else {
        for i in 0..count {
            a[i] = 0;
        }
    }
}
pub fn qrc_intutils_clear32i(a: &mut [i32], count: usize) {
    if QRC_MAX_MEMORY_CLEAR {
        qrc_memutils_clear32i(a);
    } else {
        for i in 0..count {
            a[i] = 0;
        }
    }
}

/*
* \brief Set an an 64-bit integer array to zeroes
*
* \param a: The array to zeroize
* \param count: The number of 64-bit integers to zeroize
*/
pub fn qrc_intutils_clear64(a: &mut [u64], count: usize) {
    if QRC_MAX_MEMORY_CLEAR {
        qrc_memutils_clear64(a);
    } else {
        for i in 0..count {
            a[i] = 0;
        }
    }
}
pub fn qrc_intutils_clear64i(a: &mut [i64], count: usize) {
    if QRC_MAX_MEMORY_CLEAR {
        qrc_memutils_clear64i(a);
    } else {
        for i in 0..count {
            a[i] = 0;
        }
    }
}
pub fn qrc_intutils_clear64all(a: &mut [u64]) {
    if QRC_MAX_MEMORY_CLEAR {
        qrc_memutils_clear64(a);
    } else {
        a.fill(0);
    }
}

#[cfg(not(feature = "no_std"))]
pub fn qrc_intutils_clear_string(output: &mut String) {
    if QRC_MAX_MEMORY_CLEAR {
        qrc_memutils_clear_string(output);
    } else {
        output.clear();
    }
}

/*
* \brief Constant-time conditional move function
* b=1 means move, b=0 means don't move
*
* \param dest: The return array
* \param source: [const] The source array
* \param length: The number of bytes to move
* \param cond: The condition
*/
pub fn qrc_intutils_cmov(dest: &mut [u8], source: &[u8], length: usize, mut cond: u8) {
    cond = (!cond).wrapping_add(1);

    for i in 0..length {
        dest[i] ^= (dest[i] ^ source[i]) & cond;
    }
}

/*
* \brief Expand an integer mask in constant time
*
* \param x: The N bit word
* \return: A N bit expanded word
*/
pub fn qrc_intutils_expand_mask(x: usize) -> usize {
    let mut r = x;

    for i in 1..64 {
        r |= r >> i;
    }

    r &= 1;
    r = !(r - 1);

    return r;
}

/*
* \brief Check if an integer is greater or equal to a second integer
*
* \param x: The base integer
* \param y: The comparison integer
* \return: Returns true if the base integer is greater or equal to the comparison integer
*/
pub fn qrc_intutils_are_equal(x: usize, y: usize) -> bool {
    return (x ^ y) == 0;
}

/*
* \brief Check if an integer (x) is greater or equal to a second integer (y)
*
* \param x: The base integer
* \param y: The comparison integer
* \return: Returns true if the base integer is greater or equal to the comparison integer
*/
pub fn qrc_intutils_is_gte(x: usize, y: usize) -> bool {
    return x >= y;
}

/*
* \brief Convert a hex string to an array
*
* \param hexstr: [const] The hexadecimal string
* \param output: The array output
* \param length: The length of the output array
*/
pub fn qrc_intutils_hex_to_bin(hexstr: &str, mut output: &mut [u8]) {
    const HASHMAP: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ];

    if !hexstr.is_empty() {
        qrc_intutils_clear8all(&mut output);

        let input_bytes = hexstr.as_bytes();
        for i in (0..input_bytes.len()).step_by(2) {
            let idx0 = (input_bytes[i + 0] & 0x1F) ^ 0x10;
            let idx1 = (input_bytes[i + 1] & 0x1F) ^ 0x10;
            output[i / 2] = (HASHMAP[idx0 as usize] << 4) | HASHMAP[idx1 as usize];
        }
    }
}

/*
* \brief Convert an array to a hex string
*
* \param input: [const] The array input
* \param hexstr: The hexadecimal string output; must be 2x the size of input array
* \param length: The length of the input array
*/
#[cfg(feature = "std")]
pub fn qrc_intutils_bin_to_hex(input: &[u8], hexstr: &mut String) {
    const ENCODING_TABLE: [u8; 16] = [
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65,
        0x66,
    ];

    for &byte in input {
        hexstr.push(ENCODING_TABLE[(byte >> 4) as usize] as char);
        hexstr.push(ENCODING_TABLE[(byte & 0x0F) as usize] as char);
    }
}

/*
* \brief Increment an 8-bit integer array as a segmented little-endian integer
*
* \param output: The source integer 8-bit array
* \param outlen: The length of the output counter array
*/
pub fn qrc_intutils_le8increment(output: &mut [u8], outlen: usize) {
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

/*
* \brief Convert an 8-bit integer array to a 16-bit little-endian integer
*
* \param input: [const] The source integer 8-bit array
* \return Returns the 16-bit little endian integer
*/
pub fn qrc_intutils_le8to16(input: &[u8]) -> u16 {
    return (input[0] as u16 | ((input[1] as u16) << 8)) as u16;
}

/*
* \brief Convert an 8-bit integer array to a 32-bit little-endian integer
*
* \param input: [const] The source integer 8-bit array
* \return Returns the 32-bit little endian integer
*/
pub fn qrc_intutils_le8to32(input: &[u8]) -> u32 {
    return (input[0] as u32
        | ((input[1] as u32) << 8)
        | ((input[2] as u32) << 16)
        | ((input[3] as u32) << 24)) as u32;
}

/*
* \brief Convert an 8-bit integer array to a 64-bit little-endian integer
*
* \param input: [const] The source integer 8-bit array
* \return Returns the 64-bit little endian integer
*/
pub fn qrc_intutils_le8to64(input: &[u8]) -> u64 {
    return ((input[0] as u64)
        | ((input[1] as u64) << 8)
        | ((input[2] as u64) << 16)
        | ((input[3] as u64) << 24)
        | ((input[4] as u64) << 32)
        | ((input[5] as u64) << 40)
        | ((input[6] as u64) << 48)
        | ((input[7] as u64) << 56)) as u64;
}

/*
* \brief Convert a 16-bit integer to a little-endian 8-bit integer array
*
* \param output: The 8-bit integer array
* \param value: The 16-bit integer
*/
pub fn qrc_intutils_le16to8(output: &mut [u8], value: u16) {
    output[0] = value as u8 & 0xFF;
    output[1] = (value >> 8) as u8 & 0xFF;
}

/*
* \brief Convert a 32-bit integer to a little-endian 8-bit integer array
*
* \param output: The 8-bit integer array
* \param value: The 32-bit integer
*/
pub fn qrc_intutils_le32to8(output: &mut [u8], value: u32) {
    output[0] = value as u8 & 0xFF;
    output[1] = (value >> 8) as u8 & 0xFF;
    output[2] = (value >> 16) as u8 & 0xFF;
    output[3] = (value >> 24) as u8 & 0xFF;
}

/*
* \brief Convert a 64-bit integer to a little-endian 8-bit integer array
*
* \param output: The 8-bit integer array
* \param value: The 64-bit integer
*/
pub fn qrc_intutils_le64to8(output: &mut [u8], value: u64) {
    output[0] = value as u8 & 0xFF;
    output[1] = (value >> 8) as u8 & 0xFF;
    output[2] = (value >> 16) as u8 & 0xFF;
    output[3] = (value >> 24) as u8 & 0xFF;
    output[4] = (value >> 32) as u8 & 0xFF;
    output[5] = (value >> 40) as u8 & 0xFF;
    output[6] = (value >> 48) as u8 & 0xFF;
    output[7] = (value >> 56) as u8 & 0xFF;
}

/*
* \brief Return the larger of two integers
*
* \param a: The first 32-bit integer
* \param b: The second 32-bit integer
* \return Returns the larger integer
*/
pub fn qrc_intutils_max(a: usize, b: usize) -> usize {
    return if a > b { a } else { b };
}

/*
* \brief Return the smaller of two integers
*
* \param a: The first 32-bit integer
* \param b: The second 32-bit integer
* \return Returns the smaller integer
*/
pub fn qrc_intutils_min(a: usize, b: usize) -> usize {
    return if a < b { a } else { b };
}

/*
* \brief Rotate an unsigned 32-bit integer to the left
*
* \param value: The value to rotate
* \param shift: The bit shift register
* \return Returns the rotated integer
*/
pub fn qrc_intutils_rotl32(value: u32, shift: usize) -> u32 {
    return (value << shift) | (value >> ((size_of::<u32>() * 8) - shift));
}

/*
* \brief Rotate an unsigned 64-bit integer to the left
*
* \param value: The value to rotate
* \param shift: The bit shift register
* \return Returns the rotated integer
*/
pub fn qrc_intutils_rotl64(value: u64, shift: usize) -> u64 {
    return (value << shift) | (value >> ((size_of::<u64>() * 8) - shift));
}

/*
* \brief Rotate an unsigned 32-bit integer to the right
*
* \param value: The value to rotate
* \param shift: The bit shift register
* \return Returns the rotated integer
*/
pub fn qrc_intutils_rotr32(value: u32, shift: usize) -> u32 {
    return (value >> shift) | (value << ((size_of::<u32>() * 8) - shift));
}

/*
* \brief Rotate an unsigned 64-bit integer to the right
*
* \param value: The value to rotate
* \param shift: The bit shift register
* \return Returns the rotated integer
*/
pub fn qrc_intutils_rotr64(value: u64, shift: usize) -> u64 {
    return (value >> shift) | (value << ((size_of::<u64>() * 8) - shift) as u64);
}

/*
* \brief Constant time comparison of two arrays of unsigned 8-bit integers
*
* \param a: [const] The first 8-bit integer array
* \param b: [const] The second 8-bit integer array
* \param length: The number of bytes to check
* \return Returns zero if the arrays are equivalent
*/
pub fn qrc_intutils_verify(a: &[u8], b: &[u8], length: usize) -> i32 {
    let mut d: u16 = 0;

    for i in 0..length {
        d |= (a[i] ^ b[i]) as u16;
    }

    return (1 & ((d as i32 - 1) >> 8)) - 1;
}


pub fn qrc_intutils_transform_itou_8(i8_slice: &[i8]) -> Vec<u8> {
    let u8_vec: Vec<u8> = i8_slice.iter().map(|&x| x as u8).collect();
    return u8_vec;
}
pub fn qrc_intutils_transform_utoi_8(u8_slice: &[u8]) -> Vec<i8> {
    let i8_vec: Vec<i8> = u8_slice.iter().map(|&x| x as i8).collect();
    return i8_vec;
}
pub fn qrc_intutils_transform_itou_16(i16_slice: &[i16]) -> Vec<u16> {
    let u16_vec: Vec<u16> = i16_slice.iter().map(|&x| x as u16).collect();
    return u16_vec;
}
pub fn qrc_intutils_transform_utoi_16(u16_slice: &[u16]) -> Vec<i16> {
    let i16_vec: Vec<i16> = u16_slice.iter().map(|&x| x as i16).collect();
    return i16_vec;
}
pub fn qrc_intutils_transform_itou_32(i32_slice: &[i32]) -> Vec<u32> {
    let u32_vec: Vec<u32> = i32_slice.iter().map(|&x| x as u32).collect();
    return u32_vec;
}
pub fn qrc_intutils_transform_utoi_32(u32_slice: &[u32]) -> Vec<i32> {
    let i32_vec: Vec<i32> = u32_slice.iter().map(|&x| x as i32).collect();
    return i32_vec;
}
pub fn qrc_intutils_transform_itou_64(i64_slice: &[i64]) -> Vec<u64> {
    let u64_vec: Vec<u64> = i64_slice.iter().map(|&x| x as u64).collect();
    return u64_vec;
}
pub fn qrc_intutils_transform_utoi_64(u64_slice: &[u64]) -> Vec<i64> {
    let i64_vec: Vec<i64> = u64_slice.iter().map(|&x| x as i64).collect();
    return i64_vec;
}


pub fn qrc_intutils_transform_8to16(z: &[u8]) -> Vec<u16> {
    let modifier = 2;
    let len = z.len();
    let padded_len = (len + modifier - 1) / modifier * modifier;

    let mut a = z.to_vec();
    if len < padded_len {
        a.resize(padded_len, 0);
    }

    let mut result = Vec::with_capacity(padded_len / modifier);
    for chunk in a.chunks_exact(modifier) {
        if QRC_SYSTEM_IS_LITTLE_ENDIAN {
            result.push(u16::from_le_bytes(chunk.try_into().unwrap()));
        } else {
            result.push(u16::from_be_bytes(chunk.try_into().unwrap()));
        }
    }

    return result;
}
pub fn qrc_intutils_transform_8to32(z: &[u8]) -> Vec<u32> {
    let modifier = 4;
    let len = z.len();
    let padded_len = (len + modifier - 1) / modifier * modifier;

    let mut a = z.to_vec();
    if len < padded_len {
        a.resize(padded_len, 0);
    }

    let mut result = Vec::with_capacity(padded_len / modifier);
    for chunk in a.chunks_exact(modifier) {
        if QRC_SYSTEM_IS_LITTLE_ENDIAN {
            result.push(u32::from_le_bytes(chunk.try_into().unwrap()));
        } else {
            result.push(u32::from_be_bytes(chunk.try_into().unwrap()));
        }
    }

    return result;
}
pub fn qrc_intutils_transform_8to64(z: &[u8]) -> Vec<u64> {
    let modifier = 8;
    let len = z.len();
    let padded_len = (len + modifier - 1) / modifier * modifier;

    let mut a = z.to_vec();
    if len < padded_len {
        a.resize(padded_len, 0);
    }

    let mut result = Vec::with_capacity(padded_len / modifier);
    for chunk in a.chunks_exact(modifier) {
        if QRC_SYSTEM_IS_LITTLE_ENDIAN {
            result.push(u64::from_le_bytes(chunk.try_into().unwrap()));
        } else {
            result.push(u64::from_be_bytes(chunk.try_into().unwrap()));
        }
    }

    return result;
}

pub fn qrc_intutils_transform_16to8(a: &[u16]) -> Vec<u8> {
    let mut result = vec![0u8; a.len() * 2];
    let mut i = 0;
    for &b in a {
        let out = &mut [0u8; 2];
        qrc_intutils_le16to8(out, b);
        for c in out.to_owned() {
            result[i] = c;
            i += 1;
        }
    }
    return result;
}
pub fn qrc_intutils_transform_32to8(a: &[u32]) -> Vec<u8> {
    let mut result = vec![0u8; a.len() * 4];
    let mut i = 0;
    for &b in a {
        let out = &mut [0u8; 4];
        qrc_intutils_le32to8(out, b);
        for c in out.to_owned() {
            result[i] = c;
            i += 1;
        }
    }
    return result;
}
pub fn qrc_intutils_transform_64to8(a: &[u64]) -> Vec<u8> {
    let mut result = vec![0u8; a.len() * 8];
    let mut i = 0;
    for &b in a {
        let out = &mut [0u8; 8];
        qrc_intutils_le64to8(out, b);
        for c in out.to_owned() {
            result[i] = c;
            i += 1;
        }
    }
    return result;
}

/*
* \brief Copy a integer array
*
* \param output: A pointer to the destination array
* \param input: A pointer to the source array
* \param length: The number of bytes to copy
*/
pub fn qrc_intutils_copy8(output: &mut [u8], input: &[u8], length: usize) {
    if length != 0 {
        for i in 0..length {
            let bytes = input[i].to_ne_bytes();
            output[i] = u8::from_ne_bytes(bytes);
        }
    }
}
pub fn qrc_intutils_copy8i(output: &mut [i8], input: &[i8], length: usize) {
    if length != 0 {
        for i in 0..length {
            let bytes = input[i].to_ne_bytes();
            output[i] = i8::from_ne_bytes(bytes);
        }
    }
}
pub fn qrc_intutils_copy16(output: &mut [u16], input: &[u16], length: usize) {
    if length != 0 {
        for i in 0..length {
            let bytes = input[i].to_ne_bytes();
            output[i] = u16::from_ne_bytes(bytes);
        }
    }
}
pub fn qrc_intutils_copy16i(output: &mut [i16], input: &[i16], length: usize) {
    if length != 0 {
        for i in 0..length {
            let bytes = input[i].to_ne_bytes();
            output[i] = i16::from_ne_bytes(bytes);
        }
    }
}
pub fn qrc_intutils_copy32(output: &mut [u32], input: &[u32], length: usize) {
    if length != 0 {
        for i in 0..length {
            let bytes = input[i].to_ne_bytes();
            output[i] = u32::from_ne_bytes(bytes);
        }
    }
}
pub fn qrc_intutils_copy32i(output: &mut [i32], input: &[i32], length: usize) {
    if length != 0 {
        for i in 0..length {
            let bytes = input[i].to_ne_bytes();
            output[i] = i32::from_ne_bytes(bytes);
        }
    }
}
pub fn qrc_intutils_copy64(output: &mut [u64], input: &[u64], length: usize) {
    if length != 0 {
        for i in 0..length {
            let bytes = input[i].to_ne_bytes();
            output[i] = u64::from_ne_bytes(bytes);
        }
    }
}

/*
* \brief Set a integer array to a value
*
* \param output: A pointer to the destination array
* \param value: The value to set each byte
* \param length: The number of bytes to change
*/
pub fn qrc_intutils_setvalue(output: &mut [u8], value: u8, length: usize) {
    if length != 0 {
        for i in 0..length {
            output[i] = value;
        }
    }
}

/*
* \brief Bitwise XOR two integer array
*
* \param output: A pointer to the destination array
* \param input: A pointer to the source array
* \param length: The number of bytes to XOR
*/
pub fn qrc_intutils_xor(output: &mut [u8], input: &[u8], length: usize) {
    if length != 0 {
        for i in 0..qrc_intutils_min(qrc_intutils_min(output.len(), input.len()), length) {
            output[i] ^= input[i];
        }
    }
}

/*
* \brief Bitwise XOR a integer array with a byte value
*
* \param output: A pointer to the destination array
* \param value: A byte value
* \param length: The number of bytes to XOR
*/
pub fn qrc_intutil_xorv(output: &mut [u8], value: u8, length: usize) {
    if length != 0 {
        for i in 0..length {
            output[i] ^= value;
        }
    }
}
