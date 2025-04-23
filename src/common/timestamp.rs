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

use crate::tools::intutils::qrc_intutils_clear8;

#[cfg(feature = "std")]
use chrono::{Local, prelude::DateTime, Datelike, Timelike};

/*
* \file timestamp
* \brief Time-stamp function definitions
*/

/*
* \def QRC_TIMESTAMP_STRING_SIZE
* \brief The size of the time-stamp string
*/
pub const QRC_TIMESTAMP_STRING_SIZE: usize = 20;

/*
* \brief Get the calendar date and time from the current locale.
* Time-stamp string format is YYYY-MM-DD HH-MM-SS.
*
* \param output: The output time and date string
*/
#[cfg(not(feature = "no_std"))]
pub fn qrc_timestamp_current_datetime(output: &mut [u8; QRC_TIMESTAMP_STRING_SIZE]) {
	qrc_intutils_clear8(output, QRC_TIMESTAMP_STRING_SIZE);
    let time: DateTime<Local> = Local::now();
    qrc_timestamp_time_struct_to_string(output, time);
}
#[cfg(feature = "no_std")]
pub fn qrc_timestamp_current_datetime(output: &mut [u8; QRC_TIMESTAMP_STRING_SIZE]) {
	qrc_intutils_clear8(output, QRC_TIMESTAMP_STRING_SIZE);
}

/*
* \brief Convert a time structure to a date and time string.
* Time-stamp string format is YYYY-MM-DD HH-MM-SS.
*
* \param output: The output time and date string
* \param tstruct: [const] The populated time structure
*/
#[cfg(not(feature = "no_std"))]
pub fn qrc_timestamp_time_struct_to_string(output: &mut [u8; QRC_TIMESTAMP_STRING_SIZE], time: DateTime<Local>) {
    let formatted_time = format!(
        "{:04}-{:02}-{:02}-{:02}-{:02}-{:02}\0",
        time.year(),
        time.month(),
        time.day(),
        time.hour(),
        time.minute(),
        time.second()
    );

    for i in 0..QRC_TIMESTAMP_STRING_SIZE {
        output[i] = formatted_time.as_bytes()[i];
    }
}