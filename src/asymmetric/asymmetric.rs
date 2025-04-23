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
