/* The AGPL version 3 License (AGPLv3)
*
* Copyright (c) 2024 DFD & QRC Eurosmart SA
* This file is part of the QSC Cryptographic library
*
* This program is free software : you can redistribute it and / or modify
* it under the terms of the GNU Affero General public License as published by
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

Derived from John G. Underhill's AGPL QSC library in C
*/

use crate::tools::intutils::qrc_intutils_min;

#[cfg(feature = "std")]
use rand::{RngCore, rngs::OsRng};

#[cfg(feature = "no_std")]
use alloc::vec;

/*
* \def QRC_OSRNG_SEED_MAX
* \brief The maximum seed size that can be extracted from a single generate call
*/
const QRC_OSRNG_SEED_MAX: usize = 1024000;

/**
* \brief Get an array of random bytes from the RDRAND entropy provider.
*
* \param output: Pointer to the output byte array
* \param length: The number of bytes to copy
* \return Returns true for success
*/
#[cfg(feature = "std")]
pub fn qrc_osrng_generate(output: &mut [u8], length: usize) -> bool {
    let key = &mut vec![0u8; qrc_intutils_min(length, QRC_OSRNG_SEED_MAX)];

    if OsRng.try_fill_bytes(key).is_err() {
        return false;
    };

    for i in 0..qrc_intutils_min(length, QRC_OSRNG_SEED_MAX) {
        output[i] = key[i];
    }

    return true;
}
#[cfg(feature = "no_std")]
pub fn qrc_osrng_generate(output: &mut [u8], length: usize) -> bool {
    let key = &mut vec![0u8; qrc_intutils_min(length, QRC_OSRNG_SEED_MAX)];
    for i in 0..qrc_intutils_min(length, QRC_OSRNG_SEED_MAX) {
        output[i] = key[i];
    }
    return true;
}
