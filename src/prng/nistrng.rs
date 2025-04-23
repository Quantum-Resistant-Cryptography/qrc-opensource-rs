use crate::cipher::aes::{qrc_aes_ecb_encrypt_block, qrc_aes_initialize, QrcAesCipherType, QrcAesKeyparams, QrcAesState};

use core::default::Default;


pub const QRCTEST_NIST_RNG_SEED_SIZE: usize = 48;

pub struct QrctestNistAes256State {
    pub key: [u8; 32],
    pub ctr: [u8; 16],
	pub rctr: u32,
}
impl Default for QrctestNistAes256State {
    fn default() -> Self {
        Self {
            key: [Default::default(); 32],
            ctr: [Default::default(); 16],
            rctr: Default::default(),
        }
    }
}

/*
* \brief Initialize the random provider state with a seed
* and optional personalization string
*
* \param seed 48 bytes of random seed
* \param info the optional personalization string
* \param infolen the length of the personalization string, can not exceed 48 bytes
* \return 0 for success
*/
pub fn qrc_nistrng_prng_initialize(rng_ctx: &mut QrctestNistAes256State, seed: &[u8], info: &[u8], infolen: usize) {
	let tmps = &mut [0u8; 48];

	for i in 0..48 {
		tmps[i] = seed[i];
	}

	for i in 0..infolen {
		tmps[i] ^= info[i];
	}

	for i in 0..32usize {
		rng_ctx.key[i] = 0x00;
	}

	for i in 0..16usize {
		rng_ctx.ctr[i] = 0x00;
	}

	qrc_nistrng_prng_update(&mut rng_ctx.key, &mut rng_ctx.ctr, tmps, 48);
    rng_ctx.rctr = 1;
}

/*
* \brief Generate pseudo-random bytes using the random provider
* Initialize must first be called with a random seed
*
* \param output the pseudo-random output array
* \param outlen the requested number of bytes to generate
* \return true for success
*/
pub fn qrc_nistrng_prng_generate(rng_ctx: &mut QrctestNistAes256State, output: &mut [u8], mut outlen: usize) -> bool {
	let tmpb = &mut [0u8; 16];
	let mut i = 0;

	while outlen > 0 {
		/* increment counter */
		increment_counter(&mut rng_ctx.ctr);

		aes256_ecb(&mut rng_ctx.key, &mut rng_ctx.ctr, tmpb);
		let rmd = if outlen > 15 { 16 } else { outlen };

		for j in 0..rmd {
			output[i + j] = tmpb[j];
		}

		i += rmd;
		outlen -= rmd;
	}

	qrc_nistrng_prng_update(&mut rng_ctx.key, &mut rng_ctx.ctr, &[], 0);
	rng_ctx.rctr = rng_ctx.rctr.wrapping_add(1);

	return true;
}


/*
* \brief Update the random provider with new keying material
*
* \param key the DRBG key
* \param counter the DRBG counter
* \param info the optional personalization string
* \param infolen the length of the personalization string, can not exceed 48 bytes
*/
pub fn qrc_nistrng_prng_update(key: &mut [u8], counter: &mut [u8], info: &[u8], infolen: usize) {
	let tmpk = &mut [0u8; 48];

    for i in 0..3 {
		increment_counter(counter);
		/* generate output */
		aes256_ecb(key, counter, &mut tmpk[(16 * i)..]);
	}

    for i in 0..infolen {
		tmpk[i] ^= info[i];
	}

    for i in 0..32 {
		key[i] = tmpk[i];
	}

	for i in 0..16 {
		counter[i] = tmpk[32 + i];
	}
}

fn increment_counter(counter: &mut [u8]) {
	for i in (12..=15).rev() {
		if counter[i] == 0xFF {
			counter[i] = 0x00;
		} else {
			counter[i] += 1;
			break;
		}
	}
}

fn aes256_ecb(key: &[u8], counter: &[u8], buffer: &mut [u8]) {
	let state = &mut QrcAesState::default();

	/* jgu checked false warning */
	/*lint -save -e747 */
	let kp = &mut QrcAesKeyparams::default();
	kp.key = key.to_vec();
	kp.keylen = 32;

	qrc_aes_initialize(state, kp.clone(), QrcAesCipherType::AES256);

	/*lint -restore */
	qrc_aes_ecb_encrypt_block(state.clone(), buffer, counter);
}