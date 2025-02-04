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

use crate::qsc::tools::intutils::qsc_intutils_min;
use rand::{Rng, thread_rng};

/*
* \def QSC_TRNG_SEED_MAX
* \brief The maximum seed size that can be extracted from a single generate call
*/
pub const QSC_TRNG_SEED_MAX: usize = 1024000;

/**
* \brief Get an array of pseudo-random bytes from the system entropy provider.
*
* \param output: Pointer to the output byte array
* \param length: The number of bytes to copy
* \return Returns true for success
*/
pub fn qsc_trng_generate(output: &mut [u8], length: usize) -> bool {
    let mut res = true;

    let mut rng = thread_rng();

    for i in 0..qsc_intutils_min(length, QSC_TRNG_SEED_MAX) {
        output[i] = rng.gen();
    }

    if output.is_empty() {
        res = false;
    }

    return res
}
