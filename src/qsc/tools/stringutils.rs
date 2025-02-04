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
* \file stringutils.h
* \brief String utilities; common string support functions
*/

use crate::qsc::tools::{
	memutils::qsc_memutils_clear_string,
	intutils::qsc_intutils_min,
};

use unicode_segmentation::UnicodeSegmentation;



pub const QSC_STRING_MAX_LEN: usize = 4096;

/**
* \brief Clear a string of data
*
* \param source: The string to clear
*/
pub fn qsc_stringutils_clear_string(source: &mut String) {
	if !source.is_empty() {
		if qsc_stringutils_string_size(source) != 0 {
			qsc_memutils_clear_string(source);
		}
	}
}

/**
* \brief Concatenate two strings
*
* \param dest: The destination dest
* \param dstlen: The size of the destination dest
* \param source: [const] The source string to copy
* \return Returns the size of the string
*/
pub fn qsc_stringutils_concat_strings(dest: &mut String, dstlen: usize, source: &str) -> usize {

	let mut res = 0;

	if !source.is_empty() {
		let dlen = qsc_stringutils_string_size(dest);
		let slen = qsc_stringutils_string_size(source);

		if slen > 0 && slen <= dstlen - dlen {
			dest.push_str(&source[..dstlen.min(qsc_stringutils_string_size(source))]);
		}


		if !qsc_stringutils_string_size(dest) == dstlen {
			res = qsc_stringutils_string_size(dest);
		}
	}
	

	return res;
}

/**
* \brief Copy a source string to a destination string
*
* \param dest: The destination string to copy to
* \param dstlen: The size of the destination dest
* \param source: [const] The string to copy from
* \return Returns the size of the string
*/
pub fn qsc_stringutils_copy_string(dest: &mut String, dstlen: usize, source: &str) -> usize {
	let mut res = 0;

	if !source.is_empty() {
		let slen = qsc_stringutils_string_size(source);
		if slen > 0 {
			qsc_stringutils_clear_string(dest);
			dest.push_str(&source[..dstlen.min(qsc_stringutils_string_size(source))]);
		}

		if !qsc_stringutils_string_size(dest) == dstlen {
			res = qsc_stringutils_string_size(dest);
		}
	}

	return res;
}

pub fn qsc_stringutils_find_string(source: &str, token: &str) -> i32 {
	let mut pos = -1;

	if !source.is_empty() && !token.is_empty() {
		if let Some(position) = source.find(token) {
			pos = position as i32;
		}
	}

	return pos;
}

pub fn qsc_stringutils_is_numeric(source: &str) -> bool {
	let mut res = false;
	if qsc_stringutils_string_size(source) != 0 {
		res = true;
		for c in source.chars() {
			if c < '0' as char || c > '9' as char {
				res = false;
			}
		}
	}
    return res
}

pub fn qsc_stringutils_split_strings(dest1: &mut String, dest2: &mut String, destlen: usize, source: &str, token: &str) {
	let pos = qsc_stringutils_find_string(source, token);
	if pos > 0 {
		let toklen = qsc_stringutils_string_size(token);

		let mut pstr = source;
		let mut plen = pos as usize + toklen;

		if destlen >= plen {
			qsc_stringutils_copy_string(dest1, plen, &pstr[..plen]);
			plen += 1;
			pstr = pstr.get(plen..).unwrap();
			plen = qsc_stringutils_string_size(pstr);

			if destlen >= plen	{
				qsc_stringutils_copy_string(dest2, plen, pstr);
			}
		}
	}
}


pub fn qsc_stringutils_reverse_sub_string(source: &str, token: &str) -> String {
	let mut sub = String::with_capacity(qsc_stringutils_string_size(source));

	if qsc_stringutils_string_size(source) != 0 && qsc_stringutils_string_size(token) != 0 {
		if let Some(pch) = source.rfind(token.chars().next().unwrap()) {
			let pos = pch + 1;
			sub = source[pos..].to_string();

		}
	}

	return sub;
}

pub fn qsc_stringutils_string_contains(source: &str, token: &str) -> bool {

	let mut res = false;

	if !source.is_empty() && !token.is_empty() {
		res = qsc_stringutils_find_string(source, token) >= 0;
	}

	return res;
}


pub fn qsc_stringutils_string_to_int(source: &str) -> i32 {
    let mut res = 0;

    for c in source.chars() {
        if c == '\0' || c < '0' as char || c > '9' as char {
            break;
        }
        res = res * 10 + (c as i32) - ('0' as i32);
    }

    res
}

pub fn qsc_stringutils_string_size(source: &str) -> usize {

	let mut res = 0;

	if !source.is_empty() {
		res = source.len();
	}

	return res;
}

pub fn qsc_stringutils_to_uppercase(source: &mut String, maxlen: usize) {
	if qsc_stringutils_string_size(source) != 0 {
		let tmp = &source[..];

		let uppercased = tmp.to_uppercase();
		let actual_length = uppercased.graphemes(true).count();
	
		let trimmed: String = uppercased
			.graphemes(true)
			.take(qsc_intutils_min(qsc_intutils_min(QSC_STRING_MAX_LEN, actual_length), maxlen))
			.collect();

		qsc_memutils_clear_string(source);
		source.push_str(&trimmed[..]);
	}
}