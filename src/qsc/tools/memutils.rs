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
* \file memutils.h
* \brief Contains common memory related functions
*/

use crate::qsc::tools::{
	intutils::qsc_intutils_min,
	stringutils::qsc_stringutils_string_size,
};

use std::mem::swap;

/**
* \brief Erase a block of memory
*
* \param output: A pointer to the memory block to erase
*/
pub fn qsc_memutils_clear(output: &mut [u8]) {
	output.fill(0);
}

pub fn qsc_memutils_clear_string(output: &mut String) {
    swap(output, &mut String::with_capacity(qsc_stringutils_string_size(output)));
}
 
pub fn qsc_memutils_copy(output: &mut [u8], input: &[u8], length: usize) {
	if length != 0 {
		for i in 0..length {
			output[i] = input[i];
		}
	}
}

pub fn qsc_memutils_xor(output: &mut [u8], input: &[u8], length: usize) {
	if length != 0 {
		for i in 0..qsc_intutils_min(qsc_intutils_min(output.len(), input.len()), length) {
			output[i] ^= input[i];
		}
	}
}