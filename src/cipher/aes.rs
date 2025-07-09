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

use crate::{common::common::QRC_SYSTEM_AESNI_ENABLED, digest::{sha2::{qrc_hkdf256_expand, qrc_hkdf256_extract, qrc_hmac256_blockupdate, qrc_hmac256_dispose, qrc_hmac256_blockfinalize, qrc_hmac256_initialize, QrcHmac256State, QRC_HMAC_256_MAC_SIZE}, sha3::{qrc_cshake256_compute, qrc_cshake_initialize, qrc_cshake_squeezeblocks, qrc_keccak_dispose, qrc_kmac_finalize, qrc_kmac_initialize, qrc_kmac_update, QrcKeccakRate, QrcKeccakState, QRC_KECCAK_256_RATE, QRC_KECCAK_STATE_SIZE}}, tools::intutils::{qrc_intutils_be8increment, qrc_intutils_be8to32, qrc_intutils_clear32, qrc_intutils_clear64, qrc_intutils_clear8, qrc_intutils_copy8, qrc_intutils_le32to8, qrc_intutils_le64to8, qrc_intutils_le8increment, qrc_intutils_min, qrc_intutils_verify}};

use core::{mem::size_of, default::Default};

#[cfg(feature = "no_std")]
use alloc::{vec::Vec, borrow::ToOwned};

/*
\def QRC_HBA_KMAC_EXTENSION
* Enables the cSHAKE extensions for the HBA cipher mode
*///
pub const QRC_HBA_KMAC_EXTENSION: bool = true;

///*
//\def QRC_HBA_HKDF_EXTENSION
//* Enables the HKDF extensions for the HBA cipher-mode; alternative to HBA(cSHAKE)
//*/
pub const QRC_HBA_HKDF_EXTENSION: bool = true;

/* \enum qrc_aes_cipher_mode
* The pre-defined cipher mode implementations
*/
#[derive(PartialEq)]
pub enum QrcAesCipherType {
	AES128 = 1,	/*< The AES-128 block cipher */
	AES256 = 2,	/*< The AES-256 block cipher */
}
/* \enum qrc_aes_cipher_mode
* The pre-defined cipher mode implementations
*/
#[derive(PartialEq)]
pub enum QrcAesCipherMode {
	CBC = 1,	/*< Cipher Block Chaining */
	CTR = 2,	/*< segmented integer counter */
	ECB = 3,	/*< Electronic CodeBook mode (insecure) */
}

/**********************************
*     AES CONSTANTS AND SIZES      *
***********************************/

/*
\def QRC_AES_BLOCK_SIZE
* The internal block size in bytes, required by the encryption and decryption functions.
*/
pub const QRC_AES_BLOCK_SIZE: usize = 16;

/*
\def QRC_AES_IV_SIZE
* The initialization vector size in bytes.
*/
pub const QRC_AES_IV_SIZE: usize = 16;

/*
\def QRC_AES128_KEY_SIZE
* The size in bytes of the AES-128 input cipher-key.
*/
pub const QRC_AES128_KEY_SIZE: usize = 16;

/*
\def QRC_AES256_KEY_SIZE
* The size in bytes of the AES-256 input cipher-key.
*/
pub const QRC_AES256_KEY_SIZE: usize = 32;

/*
\def QRC_HBA256_MAC_LENGTH
* The HBA-256 MAC code array length in bytes.
*/
pub const QRC_HBA256_MAC_LENGTH: usize = 32;

/*
\def QRC_HBA_MAXAAD_SIZE
* The maximum allowed AAD size.
*/
pub const QRC_HBA_MAXAAD_SIZE: usize = 256;

/*
\def QRC_HBA_MAXINFO_SIZE
* The maximum allowed key info size.
*/
pub const QRC_HBA_MAXINFO_SIZE: usize = 256;


/*
\def QRC_HBA_KMAC_AUTH
* Use KMAC to authenticate HBA; removing this macro is enabled when running in SHAKE extension mode.
* If the QRC_HBA_KMAC_EXTENSION is disabled, HMAC(SHA2) is the default authentication mode in HBA.
*/
pub const QRC_HBA_KMAC_AUTH: bool = if QRC_HBA_KMAC_EXTENSION {
    true
} else {
    false
};

/* \struct qrc_aes_keyparams
* The key parameters structure containing key and info arrays and lengths.
* Use this structure to load an input cipher-key and optional info tweak, using the qrc_aes_initialize function.
* Keys must be random and secret, and align to the corresponding key size of the cipher implemented.
* The info parameter is optional, and can be a salt or cryptographic key.
*/
#[derive(Clone)]
pub struct QrcAesKeyparams {
	pub key: Vec<u8>,				    /*< [const] The input cipher key */
	pub keylen: usize,					/*< The length in bytes of the cipher key */
	pub nonce: Vec<u8>,					/*< The nonce or initialization vector */
	pub info: Vec<u8>,			        /*< [const] The information tweak */
	pub infolen: usize,					/*< The length in bytes of the HBA information tweak */
}
impl Default for QrcAesKeyparams {
    fn default() -> Self {
        Self {
			key: Default::default(),
            keylen: Default::default(),
            nonce: Default::default(),
			info: Default::default(),
			infolen: Default::default()
        }
    }
}

/* \struct qrc_aes_state
* The internal state structure containing the round-key array.
*/
#[derive(Clone)]
pub struct QrcAesState{
	pub roundkeys: [u32; 124],		    /*< The round-keys 32-bit sub-key array */
	pub roundkeylen: usize,				/*< The round-key array length */
	pub rounds: usize,					/*< The number of transformation rounds */
	pub nonce: Vec<u8>,					/*< The nonce or initialization vector */
}
impl Default for QrcAesState {
    fn default() -> Self {
        Self {
			roundkeys: [Default::default(); 124],
            roundkeylen: Default::default(),
            rounds: Default::default(),
			nonce: Default::default()
        }
    }
}

/* common functions */

/*
* \brief Erase the round-key array and size
*/
pub fn qrc_aes_dispose(state: &mut QrcAesState) {
	/* erase the state members */
	qrc_intutils_clear32(&mut state.roundkeys, 124);
    state.roundkeylen = 0;
}

/*
* \brief Initialize the state with the input cipher-key and optional info tweak.
* The qrc_aes_state round-key array must be initialized and size set before passing the state to this function.
*
* \param state: [struct] The qrc_aes_state structure
* \param keyparams: [const] The input cipher-key, expanded to the state round-key array
* \param encryption: Initialize the cipher for encryption, false for decryption mode
*
* \warning When using a CTR mode, the cipher is always initialized for encryption.
*/
pub fn qrc_aes_initialize(state: &mut QrcAesState, keyparams: QrcAesKeyparams, ctype: QrcAesCipherType) {
	state.nonce = keyparams.nonce.clone();

	qrc_intutils_clear32(&mut state.roundkeys, 124);

	if ctype == QrcAesCipherType::AES256 {
		state.roundkeylen = AES256_ROUNDKEY_SIZE;
		state.rounds = 14;
		aes_standard_expand(state, keyparams);
	} else if ctype == QrcAesCipherType::AES128 {
		state.roundkeylen = AES128_ROUNDKEY_SIZE;
		state.rounds = 10;
		aes_standard_expand(state, keyparams);
	} else {
		state.rounds = 0;
		state.roundkeylen = 0;
	}
}

/* cbc mode */

/*
* \brief Decrypt a length of cipher-text using Cipher Block Chaining mode. \n
*
* \warning the qrc_aes_initialize function must be called first to initialize the state
*
* \param state: [struct] The initialized qrc_aes_state structure
* \param output: The output byte array; receives the decrypted plain-text
* \param input: [const] The input cipher-text bytes
* \param length: The number of input cipher-text bytes to decrypt
*/
pub fn qrc_aes_cbc_decrypt(state: &mut QrcAesState, output: &mut [u8], outputlen: &mut usize, input: &[u8], mut length: usize) {
	let tmpb = &mut [0u8; QRC_AES_BLOCK_SIZE];
	let mut oft = 0;

	while length > QRC_AES_BLOCK_SIZE {
		qrc_aes_cbc_decrypt_block(state, &mut output[oft..], &input[oft..]);
		length -= QRC_AES_BLOCK_SIZE;
		oft += QRC_AES_BLOCK_SIZE;
	}

	qrc_aes_cbc_decrypt_block(state, tmpb, &input[oft..]);
	let nlen = qrc_pkcs7_padding_length(tmpb);
	qrc_intutils_copy8(&mut output[oft..], tmpb, QRC_AES_BLOCK_SIZE - nlen);
	*outputlen = oft + QRC_AES_BLOCK_SIZE - nlen;
}

/*
* \brief Encrypt a length of cipher-text using Cipher Block Chaining mode. \n
*
* \warning the qrc_aes_initialize function must be called first to initialize the state
*
* \param state: [struct] The initialized qrc_aes_state structure
* \param output: The output byte array; receives the encrypted plain-text
* \param input: [const] The input plain-text bytes
* \param length: The number of input plain-text bytes to encrypt
*/
pub fn qrc_aes_cbc_encrypt(state: &mut QrcAesState, output: &mut [u8], input: &[u8], mut length: usize) {
	let mut oft = 0;

	while length > QRC_AES_BLOCK_SIZE {
		qrc_aes_cbc_encrypt_block(state, &mut output[oft..], &input[oft..]);
		length -= QRC_AES_BLOCK_SIZE;
		oft += QRC_AES_BLOCK_SIZE;
	}

	if length != 0 {
		let tmpb = &mut [0u8; QRC_AES_BLOCK_SIZE];
		qrc_intutils_copy8(tmpb, &input[oft..], length);

		if length < QRC_AES_BLOCK_SIZE {
			qrc_pkcs7_add_padding(tmpb, QRC_AES_BLOCK_SIZE - length);
		}

		qrc_aes_cbc_encrypt_block(state, &mut output[oft..], tmpb);
	}
}

/*
* \brief Decrypt one 16-byte block of cipher-text using Cipher Block Chaining mode. \n
*
* \warning the qrc_aes_initialize function must be called first to initialize the state
*
* \param state: [struct] The initialized qrc_aes_state structure
* \param output: The output byte array; receives the decrypted plain-text
* \param input: [const] The input cipher-text block of bytes
*/
pub fn qrc_aes_cbc_decrypt_block(state: &mut QrcAesState, output: &mut [u8], input: &[u8]) {
	let tmpv = &mut [0u8; QRC_AES_BLOCK_SIZE];

	qrc_intutils_copy8(tmpv, input, QRC_AES_BLOCK_SIZE);
	aes_decrypt_block(state.clone(), output, input);

	for i in 0..QRC_AES_BLOCK_SIZE {
		output[i] ^= state.nonce[i];
	}

	qrc_intutils_copy8(&mut state.nonce, tmpv, QRC_AES_BLOCK_SIZE);
}

/*
* \brief Encrypt one 16-byte block of cipher-text using Cipher Block Chaining mode. \n
*
* \warning the qrc_aes_initialize function must be called first to initialize the state
*
* \param state: [struct] The initialized qrc_aes_state structure
* \param output: The output byte array; receives the encrypted cipher-text
* \param input: [const] The input plain-text block of bytes
*/
pub fn qrc_aes_cbc_encrypt_block(state: &mut QrcAesState, output: &mut [u8], input: &[u8]) {
	for i in 0..QRC_AES_BLOCK_SIZE {
		state.nonce[i] ^= input[i];
	}

	aes_encrypt_block(state.clone(), output, &state.nonce);
	qrc_intutils_copy8(&mut state.nonce, output, QRC_AES_BLOCK_SIZE);
}

/* pkcs7 */

/*
* \brief Add padding to a plain-text block pad before encryption.
*
* \param input: The block of input plain-text
* \param offset: The first byte in the block to pad
* \param length: The length of the plain-text block
*/
pub fn qrc_pkcs7_add_padding(input: &mut [u8], length: usize) {

	let padoft = QRC_AES_BLOCK_SIZE - length;

	let code = length as u8;
	let mut ctr = padoft;

	while ctr != QRC_AES_BLOCK_SIZE	{
		input[ctr] = code;
		ctr += 1;
	}
}

/*
* \brief Get the number of padded bytes in a block of decrypted cipher-text.
*
* \param input: [const] The block of input plain-text
* \param offset: The first byte in the block to pad
* \param length: The length of the plain-text block
*
* \return: The length of the block padding
*/
pub fn qrc_pkcs7_padding_length(input: &[u8]) -> usize {
	let mut count = input[QRC_AES_BLOCK_SIZE - 1] as usize;
    count = if count < QRC_AES_BLOCK_SIZE { count } else { 0 };

	if count != 0 {
		for i in 2..=count {
			if input[QRC_AES_BLOCK_SIZE - i] as usize != count {
				count = 0;
				break;
			}
		}
	}

	return count;
}

/* ctr mode */

/*
* \brief Transform a length of data using a Big Endian block cipher Counter mode. \n
* The CTR mode will encrypt plain-text, and decrypt cipher-text.
*
* \warning the qrc_aes_initialize function must be called first to initialize the state
*
* \param state: [struct] The initialized qrc_aes_state structure
* \param output: The output byte array; receives the transformed text
* \param input: [const] The input data byte array
* \param length: The number of input bytes to transform
*/
pub fn qrc_aes_ctrbe_transform(state: &mut QrcAesState, output: &mut [u8], input: &[u8], mut length: usize) {
    let mut oft = 0;

	while length >= QRC_AES_BLOCK_SIZE {
		aes_encrypt_block(state.clone(), &mut output[oft..], &state.nonce);

		for i in 0..QRC_AES_BLOCK_SIZE {
			output[oft + i] ^= input[oft + i];
		}

		qrc_intutils_be8increment(&mut state.nonce, QRC_AES_BLOCK_SIZE);

		length -= QRC_AES_BLOCK_SIZE;
		oft += QRC_AES_BLOCK_SIZE;
	}

	if length != 0 {
		let tmpb = &mut [0u8; QRC_AES_BLOCK_SIZE];

		aes_encrypt_block(state.clone(), tmpb, &state.nonce);

		for i in 0..length {
			output[oft + i] = tmpb[i] ^ input[oft + i];
		}

		qrc_intutils_be8increment(&mut state.nonce, QRC_AES_BLOCK_SIZE);
	}
}

/*
* \brief Transform a length of data using a Little Endian block cipher Counter mode. \n
* The CTR mode will encrypt plain-text, and decrypt cipher-text.
*
* \warning the qrc_aes_initialize function must be called first to initialize the state
*
* \param state: [struct] The initialized qrc_aes_state structure
* \param output: The output byte array; receives the transformed text
* \param input: [const] The input data byte array
* \param length: The number of input bytes to transform
*/
pub fn qrc_aes_ctrle_transform(state: &mut QrcAesState, output: &mut [u8], input: &[u8], mut length: usize) {
	let mut oft = 0;

	while length >= QRC_AES_BLOCK_SIZE {
		aes_encrypt_block(state.clone(), &mut output[oft..], &state.nonce);

		for i in 0..QRC_AES_BLOCK_SIZE {
			output[oft + i] ^= input[oft + i];
		}

		qrc_intutils_le8increment(&mut state.nonce, QRC_AES_BLOCK_SIZE);

		length -= QRC_AES_BLOCK_SIZE;
		oft += QRC_AES_BLOCK_SIZE;
	}

	if length != 0 {
		let tmpb = &mut [0u8; QRC_AES_BLOCK_SIZE];

		aes_encrypt_block(state.clone(), tmpb, &state.nonce);

		for i in 0..length {
			output[oft + i] = tmpb[i] ^ input[oft + i];
		}

		qrc_intutils_le8increment(&mut state.nonce, QRC_AES_BLOCK_SIZE);
	}
}

/* ecb mode */

/*
* \brief Decrypt one 16-byte block of cipher-text using Electronic CodeBook Mode mode. \n
* \warning ECB is not a secure mode, and should be used only for testing, or building more complex primitives.
*
* \param state: [struct] The initialized qrc_aes_state structure
* \param output: The output byte array; receives the decrypted plain-text
* \param input: [const] The input cipher-text block of bytes
*/
pub fn qrc_aes_ecb_decrypt_block(state: QrcAesState, output: &mut [u8], input: &[u8]) {
	aes_decrypt_block(state, output, input);
}

/*
* \brief Encrypt one 16-byte block of cipher-text using Electronic CodeBook Mode mode. \n
* \warning ECB is not a secure mode, and should be used only for testing, or building more complex primitives.
*
* \param state: [struct] The initialized qrc_aes_state structure
* \param output: The output byte array; receives the encrypted cipher-text
* \param input: [const] The input plain-text block of bytes
*/
pub fn qrc_aes_ecb_encrypt_block(state: QrcAesState, output: &mut [u8], input: &[u8]) {
	aes_encrypt_block(state, output, input);
}

/* HBA-256 */

/* \struct qrc_aes_hba256_state
* The HBA-256 state array; pointers for the cipher state, mac-key and length, transformation mode, and the state counter.
* Used by the long-form of the HBA api, and initialized by the hba_initialize function.
*/
pub struct QrcAesHba256State {
	pub kstate: QrcKeccakState,	        	/*< the mac state */
	pub hstate: QrcHmac256State,        	/*< the mac state */
	pub cstate: QrcAesState,				/*< the underlying block-ciphers state structure */
	pub counter: u64,					    /*< the processed bytes counter */
	pub mkey: [u8; 32],					    /*< the mac generators key array */
	pub cust: [u8; QRC_HBA_MAXINFO_SIZE],	/*< the ciphers custom key */
	pub custlen: usize,						/*< the custom key array length */
	pub encrypt: bool,						/*< the transformation mode; true for encryption */
}
impl Default for QrcAesHba256State {
	fn default() -> Self {
		Self {
			kstate: QrcKeccakState::default(),
			hstate: QrcHmac256State::default(),
			cstate: QrcAesState::default(),
			counter: Default::default(),
			mkey: [Default::default(); 32],
			cust: [Default::default(); QRC_HBA_MAXINFO_SIZE],
			custlen: Default::default(),
			encrypt: Default::default()
		}
	}
}

/*
* \brief Dispose of the HBA-256 cipher state
*
* \warning The dispose function must be called when disposing of the cipher.
* This function destroys internal arrays allocated on the heap,
* and must be called before the state goes out of scope.
*
* \param state: [struct] The HBA state structure; contains internal state information
*/
pub fn qrc_aes_hba256_dispose(state: &mut QrcAesHba256State) {
    if QRC_HBA_KMAC_EXTENSION {
		qrc_keccak_dispose(&mut state.kstate);
    } else {
		qrc_hmac256_dispose(&mut state.hstate);
    }

    qrc_aes_dispose(&mut state.cstate);
    qrc_intutils_clear8(&mut state.cust, QRC_HBA_MAXINFO_SIZE);
    qrc_intutils_clear8(&mut state.mkey, 32);

    state.counter = 0;
    state.custlen = 0;
    state.encrypt = false;
}

/*
* \brief Initialize the cipher and load the keying material.
* Initializes the cipher state to an AES-256 instance.
*
* \warning The initialize function must be called before either the associated data or transform functions are called.
*
* \param state: [struct] The HBA state structure; contains internal state information
* \param keyparams: [const][struct] The HBA key parameters, includes the key, and optional AAD and user info arrays
* \param encrypt: The cipher encryption mode; true for encryption, false for decryption
*/
pub fn qrc_aes_hba256_initialize(state: &mut QrcAesHba256State, keyparams: QrcAesKeyparams, encrypt: bool) {
	let cprk = &mut [0u8; QRC_AES256_KEY_SIZE];

	state.custlen = qrc_intutils_min(keyparams.infolen, QRC_HBA_MAXINFO_SIZE);

	if state.custlen != 0 {
		qrc_intutils_clear8(&mut state.cust, QRC_HBA_MAXINFO_SIZE);
		qrc_intutils_copy8(&mut state.cust, &keyparams.info, state.custlen);
	}

	qrc_intutils_clear8(&mut state.mkey, 32);

	/* generate the cipher and mac keys */
	aes_hba256_genkeys(keyparams.clone(), cprk, &mut state.mkey);

	/* initialize the mac state */
    if QRC_HBA_KMAC_EXTENSION {
        qrc_kmac_initialize(&mut state.kstate, QRC_KECCAK_256_RATE, &mut state.mkey, HBA256_MKEY_LENGTH, &mut [], 0);
    } else {
        qrc_hmac256_initialize(&mut state.hstate, &state.mkey, HBA256_MKEY_LENGTH);
    }

	/* initialize the key parameters struct, info is optional */
	let kp = QrcAesKeyparams {
        key: cprk.to_vec(),
        keylen: QRC_AES256_KEY_SIZE,
        nonce: keyparams.nonce,
        info: [].to_vec(),
        infolen: 0,
    };
	/* initialize the cipher state */
	qrc_aes_initialize(&mut state.cstate, kp, QrcAesCipherType::AES256);

	/* populate the hba state structure with mac-key and counter */
	/* the state counter always initializes at 1 */
	state.counter = 1;
	state.encrypt = encrypt;
}

/*
* \brief Set the associated data string used in authenticating the message.
* The associated data may be packet header information, domain specific data, or a secret shared by a group.
* The associated data must be set after initialization, and before each transformation call.
* The data is erased after each call to the transform.
*
* \param state: [struct] The HBA-256 state structure; contains internal state information
* \param data: [const] The associated data array
* \param datalen: The associated data array length
*/
pub fn qrc_aes_hba256_set_associated(state: &mut QrcAesHba256State, data: &[u8], datalen: usize) {
	/* process the additional data */
	if datalen != 0 {
		let actr = &mut [0u8; size_of::<u32>()];

		/* add the additional data to the mac */
		aes_hba256_update(state, data, datalen);
		/* 1.1a encode with the ad size */
		qrc_intutils_le32to8(actr, datalen as u32);
		aes_hba256_update(state, actr, size_of::<u32>());
	}
}

/*
* \brief Transform an array of bytes using an instance of AES-256.
* In encryption mode, the input plain-text is encrypted and then an authentication MAC code is appended to the cipher-text.
* In decryption mode, the input cipher-text is authenticated internally and compared to the mac code appended to the cipher-text,
* if the codes to not match, the cipher-text is not decrypted and the call fails.
*
* \warning The cipher must be initialized before this function can be called
*
* \param state: [struct] The HBA state structure; contains internal state information
* \param output: The output byte array
* \param input: [const] The input byte array
* \param length: The number of bytes to transform
*
* \return: Returns true if the cipher has been initialized successfully, false on failure
*/
pub fn qrc_aes_hba256_transform(state: &mut QrcAesHba256State, output: &mut [u8], input: &[u8], length: usize) -> bool {
	let mut res = false;

	/* update the processed bytes counter */
	state.counter += length as u64;

    let nonce = &state.cstate.nonce.to_owned();
	if state.encrypt {
		/* update the mac with the nonce */
		aes_hba256_update(state, nonce, QRC_AES_BLOCK_SIZE);
		/* use aes counter-mode to encrypt the array */
		qrc_aes_ctrle_transform(&mut state.cstate, output, input, length);
		/* update the mac with the cipher-text */
		aes_hba256_update(state, output, length);
		/* mac the cipher-text appending the code to the end of the array */
		aes_hba256_finalize(state, &mut output[length..]);
		res = true;
	} else {
		let code = &mut [0u8; QRC_HBA256_MAC_LENGTH];

		/* update the mac with the nonce */
		aes_hba256_update(state, nonce, QRC_AES_BLOCK_SIZE);
		/* update the mac with the cipher-text */
		aes_hba256_update(state, input, length);
		/* mac the cipher-text to the mac */
		aes_hba256_finalize(state, code);

		/* test the mac for equality, bypassing the transform if the mac check fails */
		if qrc_intutils_verify(code, &input[length..], QRC_HBA256_MAC_LENGTH) == 0 {
			/* use aes counter-mode to decrypt the array */
			qrc_aes_ctrle_transform(&mut state.cstate, output, input, length);
			res = true;
		}
	}

	return res;
}

/*
\def AES128_ROUND_COUNT
* The number of Rijndael mixing rounds used by AES-128.
*/
const AES128_ROUND_COUNT: usize = 10;

/*
\def AES256_ROUND_COUNT
* The number of Rijndael mixing rounds used by AES-256.
*/
const AES256_ROUND_COUNT: usize = 14;

/*
\def ROUNDKEY_ELEMENT_SIZE
* The round key element size in bytes.
*/
const ROUNDKEY_ELEMENT_SIZE: usize = if QRC_SYSTEM_AESNI_ENABLED {
    16
} else {
    4
};

/*
\def AES_NONCE_SIZE
* The size byte size of the CTR nonce and CBC initialization vector.
*/
//const AES_NONCE_SIZE: usize = QRC_AES_BLOCK_SIZE;

/*
\def AES128_ROUNDKEY_SIZE
* The size of the AES-128 internal round-key array in bytes.
* Use this macro to define the size of the round-key array in an qrc_aes_state struct.
*/
const AES128_ROUNDKEY_SIZE: usize = (AES128_ROUND_COUNT + 1) * (QRC_AES_BLOCK_SIZE / ROUNDKEY_ELEMENT_SIZE);

/*
\def AES256_ROUNDKEY_SIZE
* The size of the AES-256 internal round-key array in bytes.
* Use this macro to define the size of the round-key array in an qrc_aes_state struct.
*/
const AES256_ROUNDKEY_SIZE: usize = (AES256_ROUND_COUNT + 1) * (QRC_AES_BLOCK_SIZE / ROUNDKEY_ELEMENT_SIZE);

/* HBA */

/*
\def HBA_INFO_LENGTH
* The HBA version information array length.
*/
//const HBA_INFO_LENGTH: usize = 16;

/*
\def HBA256_MKEY_LENGTH
* The size of the hba-256 mac key array
*/
const HBA256_MKEY_LENGTH: usize = 32;

/*
\def HBA512_MKEY_LENGTH
* The size of the hba-512 mac key array
*/
//const HBA512_MKEY_LENGTH: usize = 64;

/*
\def HBA_NAME_LENGTH
* The HBA implementation specific name array length.
*/
const HBA_NAME_LENGTH: usize = if QRC_HBA_KMAC_EXTENSION {
    29
} else {
    33
};
const HBA_NAME_LENGTH_MAX: usize = 33;


/* rijndael rcon, and s-box constant tables */

const AES_SBOX: [u8; 256] = [
	0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
	0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
	0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
	0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
	0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
	0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
	0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
	0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
	0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
	0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
	0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
	0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
	0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
	0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
	0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
	0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
];

const AES_ISBOX: [u8; 256] = [
	0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
	0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
	0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
	0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
	0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
	0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
	0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
	0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
	0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
	0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
	0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
	0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
	0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
	0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
	0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
];

const RCON: [u32; 30] = [
	0x00000000, 0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000,
	0x80000000, 0x1B000000, 0x36000000, 0x6C000000, 0xD8000000, 0xAB000000, 0x4D000000, 0x9A000000,
	0x2F000000, 0x5E000000, 0xBC000000, 0x63000000, 0xC6000000, 0x97000000, 0x35000000, 0x6A000000,
	0xD4000000, 0xB3000000, 0x7D000000, 0xFA000000, 0xEF000000, 0xC5000000
];



fn aes_add_roundkey(state: &mut [u8], skeys: &[u32]) {
    let mut k: u32;
    for i in (0..QRC_AES_BLOCK_SIZE).step_by(size_of::<u32>()) {
		k = skeys[i/size_of::<u32>()];
		state[i] ^= (k >> 24) as u8;
		state[i + 1] ^= ((k >> 16) & 0xFF) as u8 ;
		state[i + 2] ^= ((k >> 8) & 0xFF) as u8 ;
		state[i + 3] ^= (k & 0xFF) as u8;
    }
}

fn aes_gf256_reduce(x: u32) -> u8 {
	let y = x >> 8;

	return (x ^ y ^ (y << 1) ^ (y << 3) ^ (y << 4)) as u8 & 0xFF;
}


fn aes_invmix_columns(state: &mut [u8]) {
	for i in (0..QRC_AES_BLOCK_SIZE).step_by(size_of::<u32>()) {
		let s0 = state[i] as u32;
		let s1 = state[i + 1] as u32;
		let s2 = state[i + 2] as u32;
		let s3 = state[i + 3] as u32;

		let t0 = (s0 << 1) ^ (s0 << 2) ^ (s0 << 3) ^ s1 ^ (s1 << 1) ^ (s1 << 3)
			^ s2 ^ (s2 << 2) ^ (s2 << 3) ^ s3 ^ (s3 << 3);

		let t1 = s0 ^ (s0 << 3) ^ (s1 << 1) ^ (s1 << 2) ^ (s1 << 3)
			^ s2 ^ (s2 << 1) ^ (s2 << 3) ^ s3 ^ (s3 << 2) ^ (s3 << 3);

		let t2 = s0 ^ (s0 << 2) ^ (s0 << 3) ^ s1 ^ (s1 << 3)
			^ (s2 << 1) ^ (s2 << 2) ^ (s2 << 3) ^ s3 ^ (s3 << 1) ^ (s3 << 3);

		let t3 = s0 ^ (s0 << 1) ^ (s0 << 3) ^ s1 ^ (s1 << 2) ^ (s1 << 3)
			^ s2 ^ (s2 << 3) ^ (s3 << 1) ^ (s3 << 2) ^ (s3 << 3);

		state[i] = aes_gf256_reduce(t0);
		state[i + 1] = aes_gf256_reduce(t1);
		state[i + 2] = aes_gf256_reduce(t2);
		state[i + 3] = aes_gf256_reduce(t3);
	}
}

fn aes_invshift_rows(state: &mut [u8]) {
	let mut tmp = state[13];
	state[13] = state[9];
	state[9] = state[5];
	state[5] = state[1];
	state[1] = tmp;

	tmp = state[2];
	state[2] = state[10];
	state[10] = tmp;
	tmp = state[6];
	state[6] = state[14];
	state[14] = tmp;

	tmp = state[3];
	state[3] = state[7];
	state[7] = state[11];
	state[11] = state[15];
	state[15] = tmp;
}

fn aes_invsub_bytes(state: &mut [u8]) {
	for i in 0..QRC_AES_BLOCK_SIZE {
		state[i] = AES_ISBOX[state[i] as usize];
	}
}

fn aes_mix_columns(state: &mut [u8]) {
	for i in (0..QRC_AES_BLOCK_SIZE).step_by(size_of::<u32>()) {
		let s0 = state[i + 0] as u32;
		let s1 = state[i + 1] as u32;
		let s2 = state[i + 2] as u32;
		let s3 = state[i + 3] as u32;

		let t0 = (s0 << 1) ^ s1 ^ (s1 << 1) ^ s2 ^ s3;
		let t1 = s0 ^ (s1 << 1) ^ s2 ^ (s2 << 1) ^ s3;
		let t2 = s0 ^ s1 ^ (s2 << 1) ^ s3 ^ (s3 << 1);
		let t3 = s0 ^ (s0 << 1) ^ s1 ^ s2 ^ (s3 << 1);

		state[i + 0] = (t0 ^ (((!(t0 >> 8)).wrapping_add(1)) & 0x0000011B)) as u8;
		state[i + 1] = (t1 ^ (((!(t1 >> 8)).wrapping_add(1)) & 0x0000011B)) as u8;
		state[i + 2] = (t2 ^ (((!(t2 >> 8)).wrapping_add(1)) & 0x0000011B)) as u8;
		state[i + 3] = (t3 ^ (((!(t3 >> 8)).wrapping_add(1)) & 0x0000011B)) as u8;
	}
}

fn aes_shift_rows(state: &mut [u8]) {
	let mut tmp = state[1];
	state[1] = state[5];
	state[5] = state[9];
	state[9] = state[13];
	state[13] = tmp;

	tmp = state[2];
	state[2] = state[10];
	state[10] = tmp;
	tmp = state[6];
	state[6] = state[14];
	state[14] = tmp;

	tmp = state[15];
	state[15] = state[11];
	state[11] = state[7];
	state[7] = state[3];
	state[3] = tmp;
}

fn aes_sub_bytes(state: &mut [u8], sbox: &[u8]) {
	for i in 0..QRC_AES_BLOCK_SIZE {
		state[i] = sbox[state[i] as usize];
	}
}

fn aes_substitution(rot: u32) -> u32 {
	let mut val = rot & 0xFF;
	let mut res = AES_SBOX[val as usize] as u32;
	val = (rot >> 8) & 0xFF;
	res |= ((AES_SBOX[val as usize] as u32) << 8) as u32;
	val = (rot >> 16) & 0xFF;
	res |= ((AES_SBOX[val as usize] as u32) << 16) as u32 ;
	val = (rot >> 24) & 0xFF;

	return res as u32 | (((AES_SBOX[val as usize]) as u32) << 24) as u32;
}

fn aes_decrypt_block(state: QrcAesState, output: &mut [u8], input: &[u8]) {
	let s = &mut [0u8; 16];

	let buf = input;
	qrc_intutils_copy8(s, buf, QRC_AES_BLOCK_SIZE);
	aes_add_roundkey(s, &state.roundkeys[(state.rounds << 2)..]);

	for i in (1..(state.rounds)).rev() {

		aes_invshift_rows(s);
		aes_invsub_bytes(s);
		aes_add_roundkey(s, &state.roundkeys[(i << 2)..]);
		aes_invmix_columns(s);
	}

	aes_invshift_rows(s);
	aes_invsub_bytes(s);
	aes_add_roundkey(s, &state.roundkeys);
	qrc_intutils_copy8(output, s, QRC_AES_BLOCK_SIZE);
}

fn aes_encrypt_block(state: QrcAesState, output: &mut [u8], input: &[u8]) {
	let buf = &mut [0u8; QRC_AES_BLOCK_SIZE];

	qrc_intutils_copy8(buf, input, QRC_AES_BLOCK_SIZE);
	aes_add_roundkey(buf, &state.roundkeys);

	for i in 1..state.rounds {
		aes_sub_bytes(buf, &AES_SBOX);
		aes_shift_rows(buf);
		aes_mix_columns(buf);
		aes_add_roundkey(buf, &state.roundkeys[(i << 2)..]);
	}

	aes_sub_bytes(buf, &AES_SBOX);
	aes_shift_rows(buf);

	aes_add_roundkey(buf, &state.roundkeys[(state.rounds << 2)..]);

	qrc_intutils_copy8(output, buf, QRC_AES_BLOCK_SIZE);
}

fn aes_expand_rot(key: &mut [u32], mut keyindex: u32, keyoffset: u32, rconindex: u32) {
	let mut subkey = keyindex - keyoffset;
	key[keyindex as usize] = key[subkey as usize] ^ aes_substitution((key[keyindex as usize - 1] << 8) | ((key[keyindex as usize - 1] >> 24) & 0xFF)) ^ RCON[rconindex as usize];
	keyindex += 1;
	subkey += 1;
	key[keyindex as usize] = key[subkey as usize] ^ key[keyindex as usize - 1];
    keyindex += 1;
	subkey += 1;
	key[keyindex as usize] = key[subkey as usize] ^ key[keyindex as usize - 1];
    keyindex += 1;
	subkey += 1;
	key[keyindex as usize] = key[subkey as usize] ^ key[keyindex as usize - 1];
}

fn aes_expand_sub(key: &mut [u32], mut keyindex: u32, keyoffset: u32) {
	let mut subkey = keyindex - keyoffset;
	key[keyindex as usize] = aes_substitution(key[keyindex as usize - 1]) ^ key[subkey as usize];
	keyindex += 1;
	subkey += 1;
	key[keyindex as usize] = key[subkey as usize] ^ key[keyindex as usize - 1];
	keyindex += 1;
	subkey += 1;
	key[keyindex as usize] = key[subkey as usize] ^ key[keyindex as usize - 1];
	keyindex += 1;
	subkey += 1;
	key[keyindex as usize] = key[subkey as usize] ^ key[keyindex as usize - 1];
}

fn aes_standard_expand(state: &mut QrcAesState, keyparams: QrcAesKeyparams) {
	/* key in 32 bit words */
	let kwords = keyparams.keylen / size_of::<u32>();

	if kwords == 8 {
		state.roundkeys[0] = qrc_intutils_be8to32(&keyparams.key);
		state.roundkeys[1] = qrc_intutils_be8to32(&keyparams.key[4..]);
		state.roundkeys[2] = qrc_intutils_be8to32(&keyparams.key[8..]);
		state.roundkeys[3] = qrc_intutils_be8to32(&keyparams.key[12..]);
		state.roundkeys[4] = qrc_intutils_be8to32(&keyparams.key[16..]);
		state.roundkeys[5] = qrc_intutils_be8to32(&keyparams.key[20..]);
		state.roundkeys[6] = qrc_intutils_be8to32(&keyparams.key[24..]);
		state.roundkeys[7] = qrc_intutils_be8to32(&keyparams.key[28..]);

		/* k256 r: 8,16,24,32,40,48,56 s: 12,20,28,36,44,52 */
		aes_expand_rot(&mut state.roundkeys, 8, 8, 1);
		aes_expand_sub(&mut state.roundkeys, 12, 8);
		aes_expand_rot(&mut state.roundkeys, 16, 8, 2);
		aes_expand_sub(&mut state.roundkeys, 20, 8);
		aes_expand_rot(&mut state.roundkeys, 24, 8, 3);
		aes_expand_sub(&mut state.roundkeys, 28, 8);
		aes_expand_rot(&mut state.roundkeys, 32, 8, 4);
		aes_expand_sub(&mut state.roundkeys, 36, 8);
		aes_expand_rot(&mut state.roundkeys, 40, 8, 5);
		aes_expand_sub(&mut state.roundkeys, 44, 8);
		aes_expand_rot(&mut state.roundkeys, 48, 8, 6);
		aes_expand_sub(&mut state.roundkeys, 52, 8);
		aes_expand_rot(&mut state.roundkeys, 56, 8, 7);
	} else {
		state.roundkeys[0] = qrc_intutils_be8to32(&keyparams.key);
		state.roundkeys[1] = qrc_intutils_be8to32(&keyparams.key[4..]);
		state.roundkeys[2] = qrc_intutils_be8to32(&keyparams.key[8..]);
		state.roundkeys[3] = qrc_intutils_be8to32(&keyparams.key[12..]);

		/* k128 r: 4,8,12,16,20,24,28,32,36,40 */
		aes_expand_rot(&mut state.roundkeys, 4, 4, 1);
		aes_expand_rot(&mut state.roundkeys, 8, 4, 2);
		aes_expand_rot(&mut state.roundkeys, 12, 4, 3);
		aes_expand_rot(&mut state.roundkeys, 16, 4, 4);
		aes_expand_rot(&mut state.roundkeys, 20, 4, 5);
		aes_expand_rot(&mut state.roundkeys, 24, 4, 6);
		aes_expand_rot(&mut state.roundkeys, 28, 4, 7);
		aes_expand_rot(&mut state.roundkeys, 32, 4, 8);
		aes_expand_rot(&mut state.roundkeys, 36, 4, 9);
		aes_expand_rot(&mut state.roundkeys, 40, 4, 10);
	}
}

/* Block-cipher counter mode with Hash Based Authentication, -HBA- AEAD authenticated mode */

/* aes-hba256 */

const fn def_aes_hba256_name() -> [u8; HBA_NAME_LENGTH_MAX] {
	if QRC_HBA_KMAC_AUTH {
		return [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x48, 0x42, 0x41, 0x2D, 0x52, 0x48, 0x58, 0x53, 0x32, 0x35, 0x36, 0x2D, 0x4B, 0x4D, 0x41, 0x43, 0x32, 0x35, 0x36, 0x00, 0x00, 0x00, 0x00];
	} else {
		return [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x48, 0x42, 0x41, 0x2D, 0x52, 0x48, 0x58, 0x48, 0x32, 0x35, 0x36, 0x2D, 0x48, 0x4D, 0x41, 0x43, 0x53, 0x48, 0x41, 0x32, 0x32, 0x35, 0x36];
	};
}
const AES_HBA256_NAME: [u8; HBA_NAME_LENGTH] = {
	let a = def_aes_hba256_name();
	const L: usize = HBA_NAME_LENGTH;
    let mut o = [0u8; L];

    let mut i = 0;
    while i < L {
        o[i] = a[i];
        i += 1;
    }
    o
};

fn aes_hba256_update(state: &mut QrcAesHba256State, input: &[u8], length: usize) {
    if QRC_HBA_KMAC_EXTENSION {
	    qrc_kmac_update(&mut state.kstate, QRC_KECCAK_256_RATE, input, length);
    } else {
        qrc_hmac256_blockupdate(&mut state.hstate, input, length);
    }
}

fn aes_hba256_finalize(state: &mut QrcAesHba256State, output: &mut [u8]) {
	let mkey = &mut [0u8; HBA256_MKEY_LENGTH];
	let pctr = &mut [0u8; size_of::<u64>()];
	let tmpn = &mut [0u8; HBA_NAME_LENGTH];

	/* version 1.1a add the nonce, ciphertext, and encoding sizes to the counter */
	let mctr = (QRC_AES_BLOCK_SIZE + state.counter as usize + size_of::<u64>()) as u64;
	/* convert to little endian bytes  */
	qrc_intutils_le64to8(pctr, mctr);
	/* encode with message size, counter, and terminating string sizes */
	aes_hba256_update(state, pctr, size_of::<u64>());

    if QRC_HBA_KMAC_AUTH {
        /* mac the data and add the code to the end of the cipher-text output array */
        qrc_kmac_finalize(&mut state.kstate, QRC_KECCAK_256_RATE, output, QRC_HBA256_MAC_LENGTH);
    } else {
        /* mac the data and add the code to the end of the cipher-text output array */
        qrc_hmac256_blockfinalize(&mut state.hstate, output, &[], 0);
    }

	/* generate the new mac key */
	qrc_intutils_copy8(tmpn, &AES_HBA256_NAME, HBA_NAME_LENGTH);
	/* add 1 + the nonce, and last input size */
	/* append the counter to the end of the mac input array */
	qrc_intutils_le64to8(tmpn, state.counter);

    if QRC_HBA_KMAC_AUTH {
        qrc_cshake256_compute(mkey, HBA256_MKEY_LENGTH, &state.mkey, 32, tmpn, HBA_NAME_LENGTH, &state.cust, state.custlen);
        qrc_intutils_copy8(&mut state.mkey, mkey, HBA256_MKEY_LENGTH);
        qrc_kmac_initialize(&mut state.kstate, QRC_KECCAK_256_RATE, &mut state.mkey, HBA256_MKEY_LENGTH, &mut [], 0);
    }  else {
        /* extract the HKDF key from the state mac-key and salt */
        qrc_hkdf256_extract(mkey, &state.mkey, HBA256_MKEY_LENGTH, tmpn, 32);
        /* key HKDF Expand and generate the next mac-key to state */
        qrc_hkdf256_expand(&mut state.mkey, 32, mkey, HBA256_MKEY_LENGTH, &state.cust, state.custlen);
    }
}

fn aes_hba256_genkeys(keyparams: QrcAesKeyparams, cprk: &mut [u8], mack: &mut [u8]) {
    if QRC_HBA_KMAC_EXTENSION {

        let kstate = &mut QrcKeccakState::default();
        let sbuf = &mut [0u8; QRC_KECCAK_256_RATE];

        qrc_intutils_clear64(&mut kstate.state, QRC_KECCAK_STATE_SIZE);

        let rate = QrcKeccakRate::QrcKeccakRate256 as usize;

        /* initialize an instance of cSHAKE */
        qrc_cshake_initialize(kstate, rate, &keyparams.key, keyparams.keylen, &AES_HBA256_NAME, HBA_NAME_LENGTH, &keyparams.info, keyparams.infolen);

        /* use two permutation calls to seperate the cipher/mac key outputs to match the CEX implementation */
        qrc_cshake_squeezeblocks(kstate, rate, sbuf, 1);
        qrc_intutils_copy8(cprk, sbuf, keyparams.keylen);
        qrc_cshake_squeezeblocks(kstate, rate, sbuf, 1);
        qrc_intutils_copy8(mack, sbuf, HBA256_MKEY_LENGTH);
        /* clear the shake buffer */
        qrc_intutils_clear64(&mut kstate.state, QRC_KECCAK_STATE_SIZE);

    } else {

        let kbuf = &mut [0u8; QRC_AES256_KEY_SIZE + HBA256_MKEY_LENGTH];
        let genk = &mut [0u8; QRC_HMAC_256_MAC_SIZE];

        /* extract the HKDF key from the user-key and salt */
        qrc_hkdf256_extract(genk, &keyparams.key, keyparams.keylen, &AES_HBA256_NAME, HBA_NAME_LENGTH);

        /* key HKDF Expand and generate the key buffer */
        qrc_hkdf256_expand(kbuf, QRC_AES256_KEY_SIZE + HBA256_MKEY_LENGTH, genk, QRC_HMAC_256_MAC_SIZE, &keyparams.info, keyparams.infolen);

        /* copy the cipher and mac keys from the buffer */
        qrc_intutils_copy8(cprk, kbuf, QRC_AES256_KEY_SIZE);
        qrc_intutils_copy8(mack, &kbuf[QRC_AES256_KEY_SIZE..], HBA256_MKEY_LENGTH);

        /* clear the buffer */
        qrc_intutils_clear8(kbuf, QRC_AES256_KEY_SIZE + HBA256_MKEY_LENGTH);

    }
}