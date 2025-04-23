#![allow(dead_code)]
#![cfg(feature = "std")]
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

use crate::tools::intutils::{qrc_intutils_clear_string, qrc_intutils_min};
use unicode_segmentation::UnicodeSegmentation;

/*
* \file stringutils
* \brief String utilities; common string support functions
*/

/*
* \brief Clear a string of data
*
* \param source: The string to clear
*/
pub fn qrc_stringutils_clear_string(source: &mut String) {
    if !source.is_empty() {
        if qrc_stringutils_string_size(source) != 0 {
            qrc_intutils_clear_string(source);
        }
    }
}

/*
* \brief Concatenate two strings
*
* \param dest: The destination dest
* \param dstlen: The size of the destination dest
* \param source: [const] The source string to copy
* \return Returns the size of the string
*/
pub fn qrc_stringutils_concat_strings(dest: &mut String, dstlen: usize, source: &str) -> usize {
    let mut res = 0;

    if !source.is_empty() {
        let dlen = qrc_stringutils_string_size(dest);
        let slen = qrc_stringutils_string_size(source);

        if slen > 0 && slen <= dstlen - dlen {
            dest.push_str(&source[..dstlen.min(qrc_stringutils_string_size(source))]);
        }

        if !qrc_stringutils_string_size(dest) == dstlen {
            res = qrc_stringutils_string_size(dest);
        }
    }

    return res;
}

/*
* \brief Copy a source string to a destination string
*
* \param dest: The destination string to copy to
* \param dstlen: The size of the destination dest
* \param source: [const] The string to copy from
* \return Returns the size of the string
*/
pub fn qrc_stringutils_copy_string(dest: &mut String, dstlen: usize, source: &str) -> usize {
    let mut res = 0;

    if !source.is_empty() {
        let slen = qrc_stringutils_string_size(source);
        if slen > 0 {
            qrc_stringutils_clear_string(dest);
            dest.push_str(&source[..dstlen.min(qrc_stringutils_string_size(source))]);
        }

        if !qrc_stringutils_string_size(dest) == dstlen {
            res = qrc_stringutils_string_size(dest);
        }
    }

    return res;
}

/*
* \brief Find a substrings position within a string
*
* \param source: [const] The string to check for the substring
* \param token: [const] The substring to search for
* \return Returns the character position within the string, or QRC_STRINGUTILS_TOKEN_NOT_FOUND if the string is not found
*/
pub fn qrc_stringutils_find_string(source: &str, token: &str) -> i32 {
    let mut pos = -1;

    if !source.is_empty() && !token.is_empty() {
        if let Some(position) = source.find(token) {
            pos = position as i32;
        }
    }

    return pos;
}

/*
* \brief Check that a string contains only numeric ASCII characters
*
* \param source: [const] The string to check for numeric characters
* \param srclen: The number of characters to check
* \return Returns true if the string is numeric
*/
pub fn qrc_stringutils_is_numeric(source: &str) -> bool {
    let mut res = false;
    if qrc_stringutils_string_size(source) != 0 {
        res = true;
        for c in source.chars() {
            if c < '0' as char || c > '9' as char {
                res = false;
            }
        }
    }
    return res;
}

/*
* \brief Test if the string contains a substring
*
* \param source: [const] The string to check for the substring
* \param token: [const] The substring to search for
* \return Returns true if the substring is found
*/
pub fn qrc_stringutils_string_contains(source: &str, token: &str) -> bool {
    let mut res = false;

    if !source.is_empty() && !token.is_empty() {
        res = qrc_stringutils_find_string(source, token) >= 0;
    }

    return res;
}

/*
* \brief Split a string into two substrings
*
* \param dest1: The first destination string
* \param dest2: The second destination string
* \param destlen: The destination strings length
* \param [const] source: The source string
* \param [const] token: The search token
*/
pub fn qrc_stringutils_split_strings(
    dest1: &mut String,
    dest2: &mut String,
    destlen: usize,
    source: &str,
    token: &str,
) {
    let pos = qrc_stringutils_find_string(source, token);
    if pos > 0 {
        let toklen = qrc_stringutils_string_size(token);

        let mut pstr = source;
        let mut plen = pos as usize + toklen;

        if destlen >= plen {
            qrc_stringutils_copy_string(dest1, plen, &pstr[..plen]);
            plen += 1;
            pstr = pstr.get(plen..).unwrap();
            plen = qrc_stringutils_string_size(pstr);

            if destlen >= plen {
                qrc_stringutils_copy_string(dest2, plen, pstr);
            }
        }
    }
}

/*
* \brief Find a substring within a string
*
* \warning The string returned must be deleted by the caller
*
* \param source: [const] The string to check for the substring
* \param token: [const] The token separator
* \return Returns the substring, or NULL if not found
*/
pub fn qrc_stringutils_reverse_sub_string(source: &str, token: &str) -> String {
    let mut sub = String::with_capacity(qrc_stringutils_string_size(source));

    if qrc_stringutils_string_size(source) != 0 && qrc_stringutils_string_size(token) != 0 {
        if let Some(pch) = source.rfind(token.chars().next().unwrap()) {
            let pos = pch + 1;
            sub = source[pos..].to_string();
        }
    }

    return sub;
}
/*
* \brief Convert a string to a 32-bit integer
*
* \param source: [const] The string to convert to an integer
* \return Returns the converted integer
*/
pub fn qrc_stringutils_string_to_int(source: &str) -> i32 {
    let mut res = 0;

    for c in source.chars() {
        if c == '\0' || c < '0' as char || c > '9' as char {
            break;
        }
        res = res * 10 + (c as i32) - ('0' as i32);
    }

    res
}

/*
* \brief Get the character length of a string
*
* \param source: [const] The source string pointer
* \return Returns the size of the string
*/
pub fn qrc_stringutils_string_size(source: &str) -> usize {
    let mut res = 0;

    if !source.is_empty() {
        res = source.len();
    }

    return res;
}

/*
* \brief Convert a string to all upper-case characters
*
* \param source: The string to convert to upper-case
*/
pub fn qrc_stringutils_to_uppercase(source: &mut String, maxlen: usize) {
    if qrc_stringutils_string_size(source) != 0 {
        let tmp = &source[..];

        let uppercased = tmp.to_uppercase();
        let actual_length = uppercased.graphemes(true).count();

        let trimmed: String = uppercased
            .graphemes(true)
            .take(qrc_intutils_min(
                qrc_intutils_min(QRC_STRING_MAX_LEN, actual_length),
                maxlen,
            ))
            .collect();

        qrc_intutils_clear_string(source);
        source.push_str(&trimmed[..]);
    }
}

const QRC_STRING_MAX_LEN: usize = 4096;
