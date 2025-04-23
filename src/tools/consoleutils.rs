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

use crate::{
    common::common::QRC_SYSTEM_OS_WINDOWS,
    tools::{
        intutils::qrc_intutils_clear8all,
        stringutils::{qrc_stringutils_clear_string, qrc_stringutils_string_size},
    },
};

use crossterm::{
    cursor::Show,
    execute,
    style::{Color, SetForegroundColor},
    terminal::{SetSize, SetTitle},
};
use rpassword::read_password;
use std::io::{BufRead, Write, stdin, stdout};

/*
* \file consoleutils
* \brief Console support functions
*/

/*
* \brief Color a line of console text
*
* \param message: [const] The message string
* \param color: The color of the text
*/
pub fn qrc_consoleutils_print_colour(input: &str, colour: usize) {
    let mut stdout = stdout();
    let mut col = Color::Reset;
    match colour {
        0 => col = Color::DarkRed,
        1 => col = Color::DarkGreen,
        2 => col = Color::DarkBlue,
        3 => col = Color::Red,
        4 => {
            col = Color::Rgb {
                r: (11),
                g: (66),
                b: (11),
            }
        }
        5 => col = Color::Blue,
        6 => col = Color::Magenta,
        7 => col = Color::DarkMagenta,
        _ => {}
    }
    execute!(stdout, SetForegroundColor(col)).unwrap();
    qrc_consoleutils_print_safe(input);
    execute!(stdout, SetForegroundColor(Color::Reset)).unwrap();
}

/*
* \brief A blocking wait that returns a single character from console input
*
* \return Returns the character detected
*/
pub fn qrc_consoleutils_get_char() -> char {
    stdout().flush().unwrap();
    let line = &mut String::with_capacity(1);
    stdin().lock().read_line(line).unwrap();

    if QRC_SYSTEM_OS_WINDOWS {
        if line.ends_with('\n') {
            line.pop();
        }
    }

    if qrc_stringutils_string_size(line) != 2 {
        return "z".trim().chars().next().unwrap();
    }

    qrc_consoleutils_print_line("");

    return line.trim().chars().next().unwrap();
}

/*
* \brief Get a string of characters from the console
*
* \param line: The string of text received
* \param maxlen: The maximum text length
*
* \return Returns the number of characters in the line
*/
pub fn qrc_consoleutils_get_line(line: &mut String, maxlen: usize) -> usize {
    stdout().flush().unwrap();

    let line_console = &mut String::with_capacity(maxlen);
    stdin().lock().read_line(line_console).unwrap();

    if qrc_stringutils_string_size(line_console) > maxlen {
        line_console.truncate(maxlen);
    }

    qrc_stringutils_clear_string(line);
    line.push_str(&line_console.trim().to_string()[..]);

    qrc_consoleutils_print_line("");

    return qrc_stringutils_string_size(line);
}

/*
* \brief Pause the console until user input is detected
*
* \return Returns the number of character
*/
pub fn qrc_consoleutils_get_wait() -> () {
    stdout().flush().unwrap();
    let line = &mut String::with_capacity(1);
    stdin().lock().read_line(line).unwrap();
}

/*
* \brief Convert a hexadecimal character string to a character byte array
*
* \param hexstr: [const] The string to convert
* \param output: The character output array
* \param length: The number of characters to convert
*/
pub fn qrc_consoleutils_hex_to_bin(hexstr: &str, mut output: &mut [u8]) {
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
* \brief Find a set of characters in a line of console text.
*
* \param line: [const] The string of text received
* \param token: [const] The string to search for
*/
pub fn qrc_consoleutils_bin_to_hex(input: &[u8]) -> String {
    const HEX_TABLE: &[u8; 16] = b"0123456789ABCDEF";

    let mut output = Vec::with_capacity(input.len() * 2);

    for byte in input {
        output.push(HEX_TABLE[(byte.to_owned() as usize & 0xF0) >> 4]); // High nibble
        output.push(HEX_TABLE[byte.to_owned() as usize & 0x0F]); // Low nibble
    }

    String::from_utf8(output).expect("Invalid UTF-8")
}

/*
* \brief Gets a password masked on the console screen
*
* \param output: The output character array
* \param outlen: The maximum size of the output array
* \return Returns the size of the password
*/
pub fn qrc_consoleutils_masked_password(output: &mut String, maxlen: usize) -> usize {
    stdout().flush().unwrap();

    let password = read_password();

    match password {
        Ok(mut pass) => {
            if qrc_stringutils_string_size(&pass) > maxlen {
                pass.truncate(maxlen);
            }

            qrc_stringutils_clear_string(output);
            output.push_str(&pass.trim().to_string()[..]);

            qrc_consoleutils_print_line("");

            return qrc_stringutils_string_size(output);
        }
        _ => return 0,
    }
}

/*
* \brief Print an array of characters to the console
*
* \param input: [const] The character array to print
*/
pub fn qrc_consoleutils_print_safe(input: &str) {
    if !input.is_empty() && qrc_stringutils_string_size(input) > 0 {
        print!("{}", input);
    }
}

/*
* \brief Print an array of characters to the console with a line break
*
* \param input: [const] The character array to print
*/
pub fn qrc_consoleutils_print_line(input: &str) {
    if !input.is_empty() {
        qrc_consoleutils_print_safe(input);
    }
    qrc_consoleutils_print_safe("\n");
}

/*
* \brief Set the initial size of the console window
*
* \param width: The window width
* \param height: The window height
*/
pub fn qrc_consoleutils_set_window_size(width: u16, height: u16) {
    execute!(stdout(), SetSize(width, height)).unwrap();
}

/*
* \brief Set the window title string
*
* \param title: [const] The title string
*/
pub fn qrc_consoleutils_set_window_title(title: &str) {
    execute!(stdout(), SetTitle(title)).unwrap();
}

/*
* \brief Enable virtual terminal mode
*/
pub fn qrc_consoleutils_set_virtual_terminal() {
    let mut stdout = stdout();
    execute!(stdout, Show).unwrap();
}
