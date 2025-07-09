/* The AGPL version 3 License (AGPLv3)
* 
* Copyright (c) 2021 Digital Freedom Defence Inc.
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
*
*
*
* Copyright (c) Original-2021 John G. Underhill <john.underhill@mailfence.com>
* Copyright (c) 2022-Present QRC Eurosmart SA <opensource-support@qrcrypto.ch>
*
* The following code is a derivative work of the code from the QSC Cryptographic library in C, 
* which is licensed AGPLv3. This code therefore is also licensed under the terms of 
* the GNU Affero General Public License, version 3. The AGPL version 3 License (AGPLv3). */

use crate::{common::common::QRC_SYSTEM_IS_LITTLE_ENDIAN, digest::sha3::{qrc_cshake_initialize, qrc_cshake_squeezeblocks, qrc_keccak_absorb_key_custom, qrc_keccak_dispose, qrc_keccak_finalize, qrc_keccak_initialize_state, qrc_keccak_update, qrc_kmac_finalize, qrc_kmac_initialize, qrc_kmac_update, QrcKeccakRate, QrcKeccakState, QRC_KECCAK_512_RATE, QRC_KECCAK_KMAC_DOMAIN_ID, QRC_KECCAK_PERMUTATION_MIN_ROUNDS, QRC_KECCAK_STATE_SIZE}, tools::intutils::{qrc_intutils_clear64, qrc_intutils_copy64, qrc_intutils_copy8, qrc_intutils_le32to8, qrc_intutils_le64to8, qrc_intutils_le8to64, qrc_intutils_min, qrc_intutils_rotl64, qrc_intutils_transform_8to64, qrc_intutils_verify, qrc_intutils_xor}};

use core::{mem::size_of, default::Default};

#[cfg(feature = "no_std")]
use alloc::vec::Vec;

/*
\def QRC_CSX_AUTHENTICATED
* \brief Enables KMAC authentication mode
*/
pub const QRC_CSX_AUTHENTICATED: bool = true;

/*
* \def QRC_CSX_AUTH_KMAC
* \brief Sets the authentication mode to standard KMAC-R24.
* Remove this definition to enable the reduced rounds version using KMAC-R12.
*/
pub const QRC_CSX_AUTH_KMAC: bool = false;
pub const QRC_CSX_KPA_AUTHENTICATION: bool = false;

/*
\def QRC_CSX_KMAC_R12
* \brief Enables the reduced rounds KMAC-R12 implementation.
* Unrem this flag to enable the reduced rounds KMAC implementation.
*/
pub const QRC_CSX_AUTH_KMACR12: bool = true;

/*
\def QRC_CSX_BLOCK_SIZE
* \brief The internal block size in bytes, required by the encryption and decryption functions
*/
pub const QRC_CSX_BLOCK_SIZE: usize = 128;

/*
\def QRC_CSX_INFO_SIZE
* \brief The maximum byte length of the info string
*/
pub const QRC_CSX_INFO_SIZE: usize = 48;

/*
\def QRC_CSX_KEY_SIZE
* \brief The size in bytes of the CSX-512 input cipher-key
*/
pub const QRC_CSX_KEY_SIZE: usize = 64;

/*
\def QRC_CSX_MAC_SIZE
* \brief The CSX-512 MAC code array length in bytes
*/
pub const QRC_CSX_MAC_SIZE: usize = 64;

/*
\def QRC_CSX_NONCE_SIZE
* \brief The byte size of the nonce array
*/
pub const QRC_CSX_NONCE_SIZE: usize = 16;

/*
\def QRC_CSX_STATE_SIZE
* \brief The uint64 size of the internal state array
*/
pub const QRC_CSX_STATE_SIZE: usize = 16;

/* 
* \struct qrc_csx_keyparams
* \brief The key parameters structure containing key, nonce, and info arrays and lengths.
* Use this structure to load an input cipher-key and optional info tweak, using the qrc_csx_initialize function.
* Keys must be random and secret, and align to the corresponding key size of the cipher implemented.
* The info parameter is optional, and can be a salt or cryptographic key.
* The nonce is always QRC_CSX_BLOCK_SIZE in length.
*/
#[derive(Clone)]
pub struct QrcCsxKeyparams {
	pub key: Vec<u8>,			/*< The input cipher key */
	pub keylen: usize,			/*< The length in bytes of the cipher key */
	pub nonce: Vec<u8>,			/*< The nonce or initialization vector */
	pub info: Vec<u8>,			/*< The information tweak */
	pub infolen: usize,			/*< The length in bytes of the information tweak */
}
impl Default for QrcCsxKeyparams{
    fn default() -> Self {
        Self {
            key: Default::default(),
			keylen: Default::default(),
			nonce: Default::default(),
            info: Default::default(),
            infolen: Default::default(),
        }
    }
}

/* 
* \struct qrc_csx_state
* \brief The internal state structure containing the round-key array.
*/
#[derive(Clone)]
pub struct QrcCsxState {
	pub state: [u64; QRC_CSX_STATE_SIZE],		/*< the primary state array */
    //pub kstate: qrc_kpa_state, IF QRC_CSX_KPA_AUTHENTICATION		/*< the KPA state structure */
	pub kstate: QrcKeccakState,					/*< the KMAC state structure */
	pub counter: u64,       					/*< the processed bytes counter */
	pub encrypt: bool,							/*< the transformation mode; true for encryption */
}
impl Default for QrcCsxState{
    fn default() -> Self {
        Self {
            state: Default::default(),
			kstate: Default::default(),
			counter: Default::default(),
            encrypt: Default::default(),
        }
    }
}

/* public functions */

/*
* \brief Dispose of the CSX cipher state
*
* \warning The dispose function must be called when disposing of the cipher.
* This function destroys the internal state of the cipher.
*
* \param ctx: [struct] The cipher state structure
*/
pub fn qrc_csx_dispose(ctx: &mut QrcCsxState) {

	/* clear state */
	if QRC_CSX_AUTHENTICATED {
		qrc_keccak_dispose(&mut ctx.kstate);
	}

	qrc_intutils_clear64(&mut ctx.state, QRC_CSX_STATE_SIZE);
	ctx.counter = 0;
	ctx.encrypt = false;
}

/*
* \brief Initialize the state with the input cipher-key and optional info tweak.
*
* \param ctx: [struct] The cipher state structure
* \param keyparams: [const][struct] The secret input cipher-key and nonce structure
* \param encryption: Initialize the cipher for encryption, or false for decryption mode
*/
pub fn qrc_csx_initialize(ctx: &mut QrcCsxState, keyparams: QrcCsxKeyparams, encryption: bool) {
	ctx.counter = 0;
	ctx.encrypt = encryption;

	if QRC_CSX_AUTHENTICATED {

		let kstate = &mut QrcKeccakState::default();
		let buf = &mut [0u8; QRC_KECCAK_512_RATE];
		let cpk = &mut [0u8; QRC_CSX_KEY_SIZE];
		let mck = &mut [0u8; QRC_CSX_KEY_SIZE];
		let nme = &mut [0u8; CSX_NAME_LENGTH];

		/* load the information string */
		if keyparams.infolen == 0 {
			qrc_intutils_copy8(nme, &CSX_NAME, CSX_NAME_LENGTH);
		} else {
			let inflen = qrc_intutils_min(keyparams.infolen, CSX_NAME_LENGTH);
			qrc_intutils_copy8(nme, &keyparams.info, inflen);
		}

		/* initialize the cSHAKE generator */
		let rate = QrcKeccakRate::QrcKeccakRate512 as usize;
		qrc_cshake_initialize(kstate, rate, &keyparams.key, keyparams.keylen, nme, CSX_NAME_LENGTH, &[], 0);

		/* extract the cipher key */
		qrc_cshake_squeezeblocks(kstate, rate, buf, 1);
		qrc_intutils_copy8(cpk, buf, QRC_CSX_KEY_SIZE);
		csx_load_key(ctx, cpk, &keyparams.nonce, &CSX_INFO);

		/* extract the mac key */
		qrc_cshake_squeezeblocks(kstate, rate, buf, 1);
		qrc_intutils_copy8(mck, buf, QRC_CSX_KEY_SIZE);

		/* initialize the mac generator */
		qrc_intutils_clear64(&mut ctx.kstate.state, QRC_KECCAK_STATE_SIZE);

		if QRC_CSX_AUTH_KMACR12 {
			qrc_keccak_initialize_state(&mut ctx.kstate);
			qrc_keccak_absorb_key_custom(&mut ctx.kstate, rate, mck, QRC_CSX_KEY_SIZE, &[], 0, &CSX_KMACR12_NAME, CSX_NAME_LENGTH, QRC_KECCAK_PERMUTATION_MIN_ROUNDS);
		} else {
			qrc_kmac_initialize(&mut ctx.kstate, rate, mck, QRC_CSX_KEY_SIZE, &mut [], 0);
		}

	} else {

		let inf = &mut [0u8; QRC_CSX_INFO_SIZE];

		/* load the information string */
		if keyparams.infolen == 0 {
			qrc_intutils_copy8(inf, &CSX_INFO, QRC_CSX_INFO_SIZE);
		} else {
			let inflen = qrc_intutils_min(keyparams.infolen, QRC_CSX_INFO_SIZE);
			qrc_intutils_copy8(inf, &keyparams.info, inflen);
		}

		qrc_intutils_clear64(&mut ctx.state, QRC_CSX_STATE_SIZE);
		csx_load_key(ctx, &keyparams.key, &keyparams.nonce, inf);
	}
}

/*
* \brief Set the associated data string used in authenticating the message.
* The associated data may be packet header information, domain specific data, or a secret shared by a group.
* The associated data must be set after initialization, and before each transformation call.
* The data is erased after each call to the transform.
*
* \warning The cipher must be initialized before this function can be called
*
* \param ctx: [struct] The cipher state structure
* \param data: [const] The associated data array
* \param length: The associated data array length
*/
pub fn qrc_csx_set_associated(ctx: &mut QrcCsxState, data: &[u8], length: usize) {
	if length != 0 {
		let code = &mut [0u8; size_of::<u32>()];

		/* add the ad data to the hash */
		csx_mac_update(ctx, data, length);
		/* add the length of the ad */
		qrc_intutils_le32to8(code, length as u32);
		csx_mac_update(ctx, code, size_of::<u32>());
	}
}

/*
* \brief Transform an array of bytes.
* In encryption mode, the input plain-text is encrypted and then an authentication MAC code is appended to the cipher-text.
* In decryption mode, the input cipher-text is authenticated internally and compared to the MAC code appended to the cipher-text,
* if the codes to not match, the cipher-text is not decrypted and the call fails.
*
* \warning The cipher must be initialized before this function can be called
*
* \param ctx: [struct] The cipher state structure
* \param output: A pointer to the output array
* \param input: [const] A pointer to the input array
* \param length: The number of bytes to transform
*
* \return: Returns true if the cipher has been transformed the data successfully, false on failure
*/
pub fn qrc_csx_transform(ctx: &mut QrcCsxState, output: &mut [u8], input: &[u8], length: usize) -> bool {
	let mut res = true;

	if QRC_CSX_AUTHENTICATED {

		let ncopy = &mut [0u8; QRC_CSX_NONCE_SIZE];
		res = false;

		/* store the nonce */
		qrc_intutils_le64to8(ncopy, ctx.state[12]);
		qrc_intutils_le64to8(&mut ncopy[size_of::<u64>()..], ctx.state[13]);

		/* update the processed bytes counter */
		ctx.counter += length as u64;

		/* update the mac with the nonce */
		csx_mac_update(ctx, ncopy, QRC_CSX_NONCE_SIZE);

		if ctx.encrypt {
			/* use the transform to generate the key-stream and encrypt the data  */
			csx_transform(ctx, output, input, length);

			/* update the mac with the cipher-text */
			csx_mac_update(ctx, output, length);

			/* mac the cipher-text appending the code to the end of the array */
			csx_finalize(ctx, &mut output[length..]);
			res = true;
		} else {
			let code= &mut [0u8; QRC_CSX_MAC_SIZE];

			/* update the mac with the cipher-text */
			csx_mac_update(ctx, input, length);

			/* generate the internal mac code */
			csx_finalize(ctx, code);

			/* compare the mac code with the one embedded in the cipher-text, bypassing the transform if the mac check fails */
			if qrc_intutils_verify(code, &input[length..], QRC_CSX_MAC_SIZE) == 0 {
				/* generate the key-stream and decrypt the array */
				csx_transform(ctx, output, input, length);
				res = true;
			}
		}
	} else {
		csx_transform(ctx, output, input, length);	
	}

	return res;
}

/*
* \brief A multi-call transform for a large array of bytes, such as required by file encryption.
* This call can be used to transform and authenticate a very large array of bytes (+1GB).
* On the last call in the sequence, set the finalize parameter to true to complete authentication,
* and write the MAC code to the end of the output array in encryption mode, 
* or compare to the embedded MAC code and authenticate in decryption mode.
* In encryption mode, the input plain-text is encrypted, then authenticated, and the MAC code is appended to the cipher-text.
* In decryption mode, the input cipher-text is authenticated internally and compared to the MAC code appended to the cipher-text,
* if the codes to not match, the cipher-text is not decrypted and the call fails.
*
* \warning The cipher must be initialized before this function can be called
*
* \param ctx: [struct] The cipher state structure
* \param output: A pointer to the output array
* \param input: [const] A pointer to the input array
* \param length: The number of bytes to transform
* \param finalize: Complete authentication on a stream if set to true
*
* \return: Returns true if the cipher has been transformed the data successfully, false on failure
*/
pub fn qrc_csx_extended_transform(ctx: &mut QrcCsxState, output: &mut [u8], input: &[u8], length: usize, finalize: bool) -> bool {
	let mut res = true;

	if QRC_CSX_AUTHENTICATED {

		let ncopy = &mut [0u8; QRC_CSX_NONCE_SIZE];
		res = false;

		/* store the nonce */
		qrc_intutils_le64to8(ncopy, ctx.state[12]);
		qrc_intutils_le64to8(&mut ncopy[size_of::<u64>()..], ctx.state[13]);

		/* update the processed bytes counter */
		ctx.counter += length as u64;

		/* update the mac with the nonce */
		csx_mac_update(ctx, ncopy, QRC_CSX_NONCE_SIZE);

		if ctx.encrypt {
			/* use the transform to generate the key-stream and encrypt the data  */
			csx_transform(ctx, output, input, length);

			/* update the mac with the cipher-text */
			csx_mac_update(ctx, output, length);

			if finalize	{
				/* mac the cipher-text appending the code to the end of the array */
				csx_finalize(ctx, &mut output[length..]);
			}

			res = true;
		} else {
			let code = &mut [0u8; QRC_CSX_MAC_SIZE];

			/* update the mac with the cipher-text */
			csx_mac_update(ctx, input, length);

			if finalize	{
				/* generate the internal mac code */
				csx_finalize(ctx, code);

				/* compare the mac code with the one embedded in the cipher-text, bypassing the transform if the mac check fails */
				if qrc_intutils_verify(code, &input[length..], QRC_CSX_MAC_SIZE) == 0 {
					/* generate the key-stream and decrypt the array */
					csx_transform(ctx, output, input, length);
					res = true;
				}
			} else {
				/* generate the key-stream and decrypt the array */
				csx_transform(ctx, output, input, length);
				res = true;
			}
		}

	} else {
		csx_transform(ctx, output, input, length);
	}

	return res;
}

/*
\def CSX_ROUND_COUNT
* \brief The number of mixing rounds used by CSX-512
*/
const CSX_ROUND_COUNT: usize = 40;
/*
\def CSX_NAME_LENGTH
* \brief The byte size of the name array
*/
const CSX_NAME_LENGTH: usize = 14;

const CSX_INFO: [u8; QRC_CSX_INFO_SIZE] = [
	0x43, 0x53, 0x58, 0x35, 0x31, 0x32, 0x20, 0x4B, 0x4D, 0x41, 0x43, 0x20, 0x61, 0x75, 0x74, 0x68,
	0x65, 0x6E, 0x74, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x20, 0x76, 0x65, 0x72, 0x2E, 0x20,
	0x31, 0x63, 0x20, 0x43, 0x45, 0x58, 0x2B, 0x2B, 0x20, 0x6C, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79
];

const CSX_NAME: [u8; CSX_NAME_LENGTH] = [
	0x43, 0x53, 0x58, 0x35, 0x31, 0x32, 0x2D, 0x4B, 0x4D, 0x41, 0x43, 0x35, 0x31, 0x32
];

const CSX_KMACR12_NAME: [u8; CSX_NAME_LENGTH] = [
	0x43, 0x53, 0x58, 0x35, 0x31, 0x32, 0x2D, 0x4B, 0x4D, 0x41, 0x43, 0x52, 0x31, 0x32
];

fn csx_increment(ctx: &mut QrcCsxState) {
	ctx.state[12] = ctx.state[12].wrapping_add(1);

	if ctx.state[12] == 0 {
		ctx.state[13] =  ctx.state[13].wrapping_add(1);
	}
}

fn csx_permute_p1024c(ctx: QrcCsxState, output: &mut [u8]) {
	let mut x0 = ctx.state[0];
	let mut x1 = ctx.state[1];
	let mut x2 = ctx.state[2];
	let mut x3 = ctx.state[3];
	let mut x4 = ctx.state[4];
	let mut x5 = ctx.state[5];
	let mut x6 = ctx.state[6];
	let mut x7 = ctx.state[7];
	let mut x8 = ctx.state[8];
	let mut x9 = ctx.state[9];
	let mut x10 = ctx.state[10];
	let mut x11 = ctx.state[11];
	let mut x12 = ctx.state[12];
	let mut x13 = ctx.state[13];
	let mut x14 = ctx.state[14];
	let mut x15 = ctx.state[15];
	let mut ctr = CSX_ROUND_COUNT;

	/* new rotational constants=
	38,19,10,55
	33,4,51,13
	16,34,56,51
	4,53,42,41
	34,41,59,17
	23,31,37,20
	31,44,47,46
	12,47,44,30 */

	while ctr != 0 {
		/* round n */
		x0 = x0.wrapping_add(x4);
		x12 = qrc_intutils_rotl64(x12 ^ x0, 38);
		x8 = x8.wrapping_add(x12);
		x4 = qrc_intutils_rotl64(x4 ^ x8, 19);
		x0 = x0.wrapping_add(x4);
		x12 = qrc_intutils_rotl64(x12 ^ x0, 10);
		x8 = x8.wrapping_add(x12);
		x4 = qrc_intutils_rotl64(x4 ^ x8, 55);
		x1 = x1.wrapping_add(x5);
		x13 = qrc_intutils_rotl64(x13 ^ x1, 33);
		x9 = x9.wrapping_add(x13);
		x5 = qrc_intutils_rotl64(x5 ^ x9, 4);
		x1 = x1.wrapping_add(x5);
		x13 = qrc_intutils_rotl64(x13 ^ x1, 51);
		x9 = x9.wrapping_add(x13);
		x5 = qrc_intutils_rotl64(x5 ^ x9, 13);
		x2 = x2.wrapping_add(x6);
		x14 = qrc_intutils_rotl64(x14 ^ x2, 16);
		x10 = x10.wrapping_add(x14);
		x6 = qrc_intutils_rotl64(x6 ^ x10, 34);
		x2 = x2.wrapping_add(x6);
		x14 = qrc_intutils_rotl64(x14 ^ x2, 56);
		x10 = x10.wrapping_add(x14);
		x6 = qrc_intutils_rotl64(x6 ^ x10, 51);
		x3 = x3.wrapping_add(x7);
		x15 = qrc_intutils_rotl64(x15 ^ x3, 4);
		x11 = x11.wrapping_add(x15);
		x7 = qrc_intutils_rotl64(x7 ^ x11, 53);
		x3 = x3.wrapping_add(x7);
		x15 = qrc_intutils_rotl64(x15 ^ x3, 42);
		x11 = x11.wrapping_add(x15);
		x7 = qrc_intutils_rotl64(x7 ^ x11, 41);
		/* round n+1 */
		x0 = x0.wrapping_add(x5);
		x15 = qrc_intutils_rotl64(x15 ^ x0, 34);
		x10 = x10.wrapping_add(x15);
		x5 = qrc_intutils_rotl64(x5 ^ x10, 41);
		x0 = x0.wrapping_add(x5);
		x15 = qrc_intutils_rotl64(x15 ^ x0, 59);
		x10 = x10.wrapping_add(x15);
		x5 = qrc_intutils_rotl64(x5 ^ x10, 17);
		x1 = x1.wrapping_add(x6);
		x12 = qrc_intutils_rotl64(x12 ^ x1, 23);
		x11 = x11.wrapping_add(x12);
		x6 = qrc_intutils_rotl64(x6 ^ x11, 31);
		x1 = x1.wrapping_add(x6);
		x12 = qrc_intutils_rotl64(x12 ^ x1, 37);
		x11 = x11.wrapping_add(x12);
		x6 = qrc_intutils_rotl64(x6 ^ x11, 20);
		x2 = x2.wrapping_add(x7);
		x13 = qrc_intutils_rotl64(x13 ^ x2, 31);
		x8 = x8.wrapping_add(x13);
		x7 = qrc_intutils_rotl64(x7 ^ x8, 44);
		x2 = x2.wrapping_add(x7);
		x13 = qrc_intutils_rotl64(x13 ^ x2, 47);
		x8 = x8.wrapping_add(x13);
		x7 = qrc_intutils_rotl64(x7 ^ x8, 46);
		x3 = x3.wrapping_add(x4);
		x14 = qrc_intutils_rotl64(x14 ^ x3, 12);
		x9 = x9.wrapping_add(x14);
		x4 = qrc_intutils_rotl64(x4 ^ x9, 47);
		x3 = x3.wrapping_add(x4);
		x14 = qrc_intutils_rotl64(x14 ^ x3, 44);
		x9 = x9.wrapping_add(x14);
		x4 = qrc_intutils_rotl64(x4 ^ x9, 30);
		ctr -= 2;
	}

	qrc_intutils_le64to8(output, x0.wrapping_add(ctx.state[0]));
	qrc_intutils_le64to8(&mut output[8..], x1.wrapping_add(ctx.state[1]));
	qrc_intutils_le64to8(&mut output[16..], x2.wrapping_add(ctx.state[2]));
	qrc_intutils_le64to8(&mut output[24..], x3.wrapping_add(ctx.state[3]));
	qrc_intutils_le64to8(&mut output[32..], x4.wrapping_add(ctx.state[4]));
	qrc_intutils_le64to8(&mut output[40..], x5.wrapping_add(ctx.state[5]));
	qrc_intutils_le64to8(&mut output[48..], x6.wrapping_add(ctx.state[6]));
	qrc_intutils_le64to8(&mut output[56..], x7.wrapping_add(ctx.state[7]));
	qrc_intutils_le64to8(&mut output[64..], x8.wrapping_add(ctx.state[8]));
	qrc_intutils_le64to8(&mut output[72..], x9.wrapping_add(ctx.state[9]));
	qrc_intutils_le64to8(&mut output[80..], x10.wrapping_add(ctx.state[10]));
	qrc_intutils_le64to8(&mut output[88..], x11.wrapping_add(ctx.state[11]));
	qrc_intutils_le64to8(&mut output[96..], x12.wrapping_add(ctx.state[12]));
	qrc_intutils_le64to8(&mut output[104..], x13.wrapping_add(ctx.state[13]));
	qrc_intutils_le64to8(&mut output[112..], x14.wrapping_add(ctx.state[14]));
	qrc_intutils_le64to8(&mut output[120..], x15.wrapping_add(ctx.state[15]));
}

fn csx_mac_update(ctx: &mut QrcCsxState, input: &[u8], length: usize) {
	let rate = QrcKeccakRate::QrcKeccakRate512 as usize;
	if QRC_CSX_AUTH_KMACR12 {
		qrc_keccak_update(&mut ctx.kstate, rate, input, length, QRC_KECCAK_PERMUTATION_MIN_ROUNDS);
	} else {
		qrc_kmac_update(&mut ctx.kstate, rate, input, length);
	}
}

fn csx_transform(ctx: &mut QrcCsxState, output: &mut [u8], input: &[u8], mut length: usize) {
	let mut oft = 0;

	/* generate remaining blocks */
	while length >= QRC_CSX_BLOCK_SIZE {
		csx_permute_p1024c(ctx.clone(), &mut output[oft..]);
		qrc_intutils_xor(&mut output[oft..], &input[oft..], QRC_CSX_BLOCK_SIZE);
		csx_increment(ctx);
		oft += QRC_CSX_BLOCK_SIZE;
		length -= QRC_CSX_BLOCK_SIZE;
	}

	/* generate unaligned key-stream */
	if length != 0 {
		let tmp = &mut [0u8; QRC_CSX_BLOCK_SIZE];
		csx_permute_p1024c(ctx.clone(), tmp);
		csx_increment(ctx);
		qrc_intutils_copy8(&mut output[oft..], tmp, length);
		qrc_intutils_xor(&mut output[oft..], &input[oft..], length);
	}
}

fn csx_load_key(ctx: &mut QrcCsxState, key: &[u8], nonce: &[u8], code: &[u8]) {
	if QRC_SYSTEM_IS_LITTLE_ENDIAN {
		qrc_intutils_copy64(&mut ctx.state, &qrc_intutils_transform_8to64(key), 8);
		qrc_intutils_copy64(&mut ctx.state[8..], &qrc_intutils_transform_8to64(code), 4);
		qrc_intutils_copy64(&mut ctx.state[12..], &qrc_intutils_transform_8to64(nonce), 2);
		qrc_intutils_copy64(&mut ctx.state[14..], &qrc_intutils_transform_8to64(&code[32..]), 2);
	} else {
		ctx.state[0] = qrc_intutils_le8to64(key);
		ctx.state[1] = qrc_intutils_le8to64(&key[8..]);
		ctx.state[2] = qrc_intutils_le8to64(&key[16..]);
		ctx.state[3] = qrc_intutils_le8to64(&key[24..]);
		ctx.state[4] = qrc_intutils_le8to64(&key[32..]);
		ctx.state[5] = qrc_intutils_le8to64(&key[40..]);
		ctx.state[6] = qrc_intutils_le8to64(&key[48..]);
		ctx.state[7] = qrc_intutils_le8to64(&key[56..]);
		ctx.state[8] = qrc_intutils_le8to64(code);
		ctx.state[9] = qrc_intutils_le8to64(&code[8..]);
		ctx.state[10] = qrc_intutils_le8to64(&code[16..]);
		ctx.state[11] = qrc_intutils_le8to64(&code[24..]);
		ctx.state[12] = qrc_intutils_le8to64(nonce);
		ctx.state[13] = qrc_intutils_le8to64(&nonce[8..]);
		ctx.state[14] = qrc_intutils_le8to64(&code[32..]);
		ctx.state[15] = qrc_intutils_le8to64(&code[40..]);
	}
}

fn csx_finalize(ctx: &mut QrcCsxState, output: &mut [u8]) {
	let ctr = &mut  [0u8; size_of::<u64>()];

	qrc_intutils_le64to8(ctr, ctx.counter);
	csx_mac_update(ctx, ctr, size_of::<u64>());

	let rate = QrcKeccakRate::QrcKeccakRate512 as usize;
	if QRC_CSX_AUTH_KMACR12 {
		/* update the counter */
		qrc_keccak_update(&mut ctx.kstate, rate, ctr, size_of::<u64>(), QRC_KECCAK_PERMUTATION_MIN_ROUNDS);
		/* finalize the mac and append code to output */
		qrc_keccak_finalize(&mut ctx.kstate, rate, output, QRC_CSX_MAC_SIZE, QRC_KECCAK_KMAC_DOMAIN_ID as usize, QRC_KECCAK_PERMUTATION_MIN_ROUNDS);
	} else {
		/* finalize the mac and append code to output */
		qrc_kmac_finalize(&mut ctx.kstate, rate, output, QRC_CSX_MAC_SIZE);
	}
}