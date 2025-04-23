#![allow(dead_code)]
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

use zeroize::Zeroize;

/*
* \file memutils
* \brief Contains common memory related functions implemented using SIMD instructions
*/

/*
* \brief Erase a block of memory
*
* \param output: A pointer to the memory block to erase
* \param length: The number of bytes to erase
*/
#[cfg(not(feature = "no_std"))]
pub fn qrc_memutils_clear_string(output: &mut String) {
    output.zeroize();
}

pub fn qrc_memutils_clear8(output: &mut [u8]) {
    output.zeroize();
}
pub fn qrc_memutils_clear8i(output: &mut [i8]) {
    output.zeroize();
}
pub fn qrc_memutils_clear16(output: &mut [u16]) {
    output.zeroize();
}
pub fn qrc_memutils_clear16i(output: &mut [i16]) {
    output.zeroize();
}
pub fn qrc_memutils_clear32(output: &mut [u32]) {
    output.zeroize();
}
pub fn qrc_memutils_clear32i(output: &mut [i32]) {
    output.zeroize();
}
pub fn qrc_memutils_clear64(output: &mut [u64]) {
    output.zeroize();
}
pub fn qrc_memutils_clear64i(output: &mut [i64]) {
    output.zeroize();
}
