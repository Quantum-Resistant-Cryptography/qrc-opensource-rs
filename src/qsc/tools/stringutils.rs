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
* \file stringutils.h
* \brief String utilities; common string support functions
*/

use crate::qsc::tools::memutils::qsc_memutils_clear_string;

/**
* \brief Clear a string of data
*
* \param source: The string to clear
*/
pub(crate) fn qsc_stringutils_clear_string(source: &mut String) {
	if !source.is_empty() {
		if qsc_stringutils_string_size(source) != 0 {
			qsc_memutils_clear_string(source);
		}
	}
}

pub(crate) fn qsc_stringutils_string_size(source: &str) -> usize {

	let mut res = 0;

	if !source.is_empty() {
		res = source.len();
	}

	return res;
}