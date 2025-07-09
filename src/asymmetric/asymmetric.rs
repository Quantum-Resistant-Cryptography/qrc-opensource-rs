/* The AGPL version 3 License (AGPLv3)
* 
* Copyright (c) 2025 QRC Eurosmart SA.
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
*
*
*
* Copyright (c) 2025-Present QRC Eurosmart SA <opensource-support@qrcrypto.ch> */


use crate::{
    prng::{
        nistrng::{QrctestNistAes256State, qrc_nistrng_prng_generate},
        secrand::{QrcSecrandState, qrc_secrand_generate},
    },
    provider::rcrng::qrc_rcrng_generate,
};

use core::default::Default;

pub struct AsymmetricRandState {
    pub secrand_state: QrcSecrandState,
    pub nist_test_state: QrctestNistAes256State,
}
impl Default for AsymmetricRandState {
    fn default() -> Self {
        Self {
            secrand_state: QrcSecrandState::default(),
            nist_test_state: QrctestNistAes256State::default(),
        }
    }
}

pub fn qrc_asymmetric_secrand_generate(
    asymmetric_state: &mut AsymmetricRandState,
    output: &mut [u8],
    length: usize,
) -> bool {
    return qrc_secrand_generate(&mut asymmetric_state.secrand_state, output, length);
}

pub fn qrc_asymmetric_nistrng_generate(
    asymmetric_state: &mut AsymmetricRandState,
    output: &mut [u8],
    length: usize,
) -> bool {
    return qrc_nistrng_prng_generate(&mut asymmetric_state.nist_test_state, output, length);
}

pub fn qrc_asymmetric_rcrng_generate(
    _: &mut AsymmetricRandState,
    output: &mut [u8],
    length: usize,
) -> bool {
    return qrc_rcrng_generate(output, length);
}
