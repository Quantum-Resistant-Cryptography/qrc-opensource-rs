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

/**
* \file aes.h
* \brief An implementation of the AES symmetric cipher
*
* AES-256 CTR short-form api example \n
* \code
	fn aes256_crt() -> bool {
		let ctx = &mut QscAesState::default();
		let msg = &mut [0u8; QSC_AES_BLOCK_SIZE];
		let plain = &mut [0u8; QSC_AES_BLOCK_SIZE];
		let nonce = &mut [0u8; QSC_AES_BLOCK_SIZE];
		let nonce2 = &mut [0u8; QSC_AES_BLOCK_SIZE];
		let cipher = &mut [0u8; QSC_AES_BLOCK_SIZE];

		let kp = QscAesKeyparams {
			key: key.to_vec(), 
			keylen: QSC_AES256_KEY_SIZE,
			nonce: nonce.to_vec(),
			info: [].to_vec(),
			infolen: 0,
		};

		qsc_memutils_copy(nonce2, nonce, QSC_AES_BLOCK_SIZE);
		qsc_aes_initialize(ctx, kp.clone(), QscAesCipherType::AES256);
		qsc_aes_ctrbe_transform(ctx, cipher, msg, QSC_AES_BLOCK_SIZE);
		qsc_memutils_copy(&mut ctx.nonce, nonce2, QSC_AES_BLOCK_SIZE);
		qsc_aes_initialize(ctx, kp, QscAesCipherType::AES256);
		qsc_aes_ctrbe_transform(ctx, plain, cipher, QSC_AES_BLOCK_SIZE);
		qsc_aes_dispose(ctx);
		
		return msg == plain
	}
* \endcode
*/

use crate::qsc::{
	common::common::QSC_SYSTEM_AESNI_ENABLED,
	tools::{
		memutils::{
			qsc_memutils_clear,
			qsc_memutils_copy,
		},
		intutils::{
			qsc_intutils_clear8,
			qsc_intutils_be8to32,
			qsc_intutils_be8increment,
			qsc_intutils_le8increment,
			qsc_intutils_le64to8,
			qsc_intutils_le32to8,
			qsc_intutils_verify,
			qsc_intutils_min,
			qsc_intutils_clear64,
		},
	},
	digest::sha3::{
		QscKeccakRate,
		QscKeccakState,
		QSC_KECCAK_256_RATE,
		QSC_KECCAK_STATE_SIZE,
		qsc_kmac_initialize,
		qsc_kmac_update,
		qsc_kmac_finalize,
		qsc_cshake_initialize,
		qsc_cshake256_compute,
		qsc_cshake_squeezeblocks,
	},
};


use std::mem::size_of;
use bytemuck::cast_slice_mut;

/*
\def QSC_HBA_KMAC_EXTENSION
* Enables the cSHAKE extensions for the HBA cipher mode
*///
pub const QSC_HBA_KMAC_EXTENSION: bool = true;

/* \enum qsc_aes_cipher_mode
* The pre-defined cipher mode implementations
*/
#[derive(PartialEq)]
pub enum QscAesCipherType {
	AES128 = 1,	/*< The AES-128 block cipher */
	AES256 = 2,	/*< The AES-256 block cipher */
}

/***********************************
*     AES CONSTANTS AND SIZES      *
***********************************/

/*
\def QSC_AES_BLOCK_SIZE
* The internal block size in bytes, required by the encryption and decryption functions.
*/
pub const QSC_AES_BLOCK_SIZE: usize = 16;

/*
\def QSC_AES256_KEY_SIZE
* The size in bytes of the AES-256 input cipher-key.
*/
pub const QSC_AES256_KEY_SIZE: usize = 32;

/*
\def QSC_HBA256_MAC_LENGTH
* The HBA-256 MAC code array length in bytes.
*/
pub const QSC_HBA256_MAC_LENGTH: usize = 32;

/*
\def QSC_HBA_MAXINFO_SIZE
* The maximum allowed key info size.
*/
pub const QSC_HBA_MAXINFO_SIZE: usize = 256;

/*
\def QSC_HBA_KMAC_AUTH
* Use KMAC to authenticate HBA; removing this macro is enabled when running in SHAKE extension mode.
* If the QSC_HBA_KMAC_EXTENSION is disabled, HMAC(SHA2) is the default authentication mode in HBA.
*/
pub const QSC_HBA_KMAC_AUTH: bool = if QSC_HBA_KMAC_EXTENSION {
    true
} else {
    false
};

/* \struct qsc_aes_keyparams
* The key parameters structure containing key and info arrays and lengths.
* Use this structure to load an input cipher-key and optional info tweak, using the qsc_aes_initialize function.
* Keys must be random and secret, and align to the corresponding key size of the cipher implemented.
* The info parameter is optional, and can be a salt or cryptographic key.
*/
#[derive(Clone)]
pub struct QscAesKeyparams {
	pub key: Vec<u8>,				    /*< [const] The input cipher key */
	pub keylen: usize,					/*< The length in bytes of the cipher key */
	pub nonce: Vec<u8>,					/*< The nonce or initialization vector */
	pub info: Vec<u8>,			        /*< [const] The information tweak */
	pub infolen: usize,					/*< The length in bytes of the HBA information tweak */
}
impl Default for QscAesKeyparams {
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

/* \struct qsc_aes_state
* The internal state structure containing the round-key array.
*/
#[derive(Debug, Clone)]
pub struct QscAesState{
	pub roundkeys: [u32; 124],		    /*< The round-keys 32-bit sub-key array */
	pub roundkeylen: usize,				/*< The round-key array length */
	pub rounds: usize,					/*< The number of transformation rounds */
	pub nonce: Vec<u8>,					/*< The nonce or initialization vector */
}
impl Default for QscAesState {
    fn default() -> Self {
        Self {
			roundkeys: [Default::default(); 124],
            roundkeylen: Default::default(),
            rounds: Default::default(),
			nonce: Default::default()
        }
    }
}

pub struct QscAesHba256State {

	pub kstate: QscKeccakState,	        	/*< the mac state */
	//if !QSC_HBA_KMAC_EXTENSION pub kstate: qsc_hmac256_state;
	pub cstate: QscAesState,				/*< the underlying block-ciphers state structure */
	pub counter: u64,					    /*< the processed bytes counter */
	pub mkey: [u8; 32],					    /*< the mac generators key array */
	pub cust: [u8; QSC_HBA_MAXINFO_SIZE],	/*< the ciphers custom key */
	pub custlen: usize,						/*< the custom key array length */
	pub encrypt: bool,						/*< the transformation mode; true for encryption */
}
impl Default for QscAesHba256State {
    fn default() -> Self {
        Self {
            kstate: QscKeccakState::default(),
			cstate: QscAesState::default(),
            counter: Default::default(),
			mkey: [Default::default(); 32],
            cust: [Default::default(); QSC_HBA_MAXINFO_SIZE],
            custlen: Default::default(),
			encrypt: Default::default()
        }
    }
}


/*
\def AES128_ROUND_COUNT
* The number of Rijndael mixing rounds used by AES-128.
*/
pub const AES128_ROUND_COUNT: usize = 10;

/*
\def AES256_ROUND_COUNT
* The number of Rijndael mixing rounds used by AES-256.
*/
pub const AES256_ROUND_COUNT: usize = 14;

/*
\def ROUNDKEY_ELEMENT_SIZE
* The round key element size in bytes.
*/

pub const ROUNDKEY_ELEMENT_SIZE: usize = if QSC_SYSTEM_AESNI_ENABLED {
    16
} else {
    4
};

/*
\def AES128_ROUNDKEY_SIZE
* The size of the AES-128 internal round-key array in bytes.
* Use this macro to define the size of the round-key array in an qsc_aes_state struct.
*/
pub const AES128_ROUNDKEY_SIZE: usize = (AES128_ROUND_COUNT + 1) * (QSC_AES_BLOCK_SIZE / ROUNDKEY_ELEMENT_SIZE);

/*
\def AES256_ROUNDKEY_SIZE
* The size of the AES-256 internal round-key array in bytes.
* Use this macro to define the size of the round-key array in an qsc_aes_state struct.
*/
pub const AES256_ROUNDKEY_SIZE: usize = (AES256_ROUND_COUNT + 1) * (QSC_AES_BLOCK_SIZE / ROUNDKEY_ELEMENT_SIZE);

/* HBA */
/*
\def HBA256_MKEY_LENGTH
* The size of the hba-256 mac key array
*/
pub const HBA256_MKEY_LENGTH: usize = 32;

/*
\def HBA_NAME_LENGTH
* The HBA implementation specific name array length.
*/
const fn def_aes_hba256_name_length() -> usize {
    if QSC_HBA_KMAC_EXTENSION {
        29
    } else {
        33
    }
}
pub const HBA_NAME_LENGTH_MAX: usize = 33;
pub const HBA_NAME_LENGTH: usize = def_aes_hba256_name_length();


/* rijndael rcon, and s-box constant tables */

pub const AES_SBOX: [u8; 256] = [
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

pub const AES_ISBOX: [u8; 256] = [
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

pub const RCON: [u32; 30] = [
	0x00000000, 0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000,
	0x80000000, 0x1B000000, 0x36000000, 0x6C000000, 0xD8000000, 0xAB000000, 0x4D000000, 0x9A000000,
	0x2F000000, 0x5E000000, 0xBC000000, 0x63000000, 0xC6000000, 0x97000000, 0x35000000, 0x6A000000,
	0xD4000000, 0xB3000000, 0x7D000000, 0xFA000000, 0xEF000000, 0xC5000000
];

fn aes_add_roundkey(state: &mut [u8], skeys: &[u32]) {
    let mut k: u32;
    for i in (0..QSC_AES_BLOCK_SIZE).step_by(size_of::<u32>()) {
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
	for i in (0..QSC_AES_BLOCK_SIZE).step_by(size_of::<u32>()) {
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
	for i in 0..QSC_AES_BLOCK_SIZE {
		state[i] = AES_ISBOX[state[i] as usize];
	}
}

fn aes_mix_columns(state: &mut [u8]) {
	for i in (0..QSC_AES_BLOCK_SIZE).step_by(size_of::<u32>()) {
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
	for i in 0..QSC_AES_BLOCK_SIZE {
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

fn aes_decrypt_block(state: QscAesState, output: &mut [u8], input: &[u8]) {
	let s = &mut [0u8; 16];

	let buf = input;
	qsc_memutils_copy(s, buf, QSC_AES_BLOCK_SIZE);
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
	qsc_memutils_copy(output, s, QSC_AES_BLOCK_SIZE);
}

fn aes_encrypt_block(state: QscAesState, output: &mut [u8], input: &[u8]) {
	let buf = &mut [0u8; QSC_AES_BLOCK_SIZE];

	qsc_memutils_copy(buf, input, QSC_AES_BLOCK_SIZE);
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

	qsc_memutils_copy(output, buf, QSC_AES_BLOCK_SIZE);
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

fn aes_standard_expand(state: &mut QscAesState, keyparams: QscAesKeyparams) {
	/* key in 32 bit words */
	let kwords = keyparams.keylen / size_of::<u32>();

	if kwords == 8 {
		state.roundkeys[0] = qsc_intutils_be8to32(&keyparams.key);
		state.roundkeys[1] = qsc_intutils_be8to32(&keyparams.key[4..]);
		state.roundkeys[2] = qsc_intutils_be8to32(&keyparams.key[8..]);
		state.roundkeys[3] = qsc_intutils_be8to32(&keyparams.key[12..]);
		state.roundkeys[4] = qsc_intutils_be8to32(&keyparams.key[16..]);
		state.roundkeys[5] = qsc_intutils_be8to32(&keyparams.key[20..]);
		state.roundkeys[6] = qsc_intutils_be8to32(&keyparams.key[24..]);
		state.roundkeys[7] = qsc_intutils_be8to32(&keyparams.key[28..]);

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
		state.roundkeys[0] = qsc_intutils_be8to32(&keyparams.key);
		state.roundkeys[1] = qsc_intutils_be8to32(&keyparams.key[4..]);
		state.roundkeys[2] = qsc_intutils_be8to32(&keyparams.key[8..]);
		state.roundkeys[3] = qsc_intutils_be8to32(&keyparams.key[12..]);

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

/**
* \brief Initialize the state with the input cipher-key and optional info tweak.
* The qsc_aes_state round-key array must be initialized and size set before passing the state to this function.
*
* \param state: [struct] The qsc_aes_state structure
* \param keyparams: [const] The input cipher-key, expanded to the state round-key array
* \param encryption: Initialize the cipher for encryption, false for decryption mode
*
* \warning When using a CTR mode, the cipher is always initialized for encryption.
*/
fn qsc_aes_initialize(state: &mut QscAesState, keyparams: QscAesKeyparams, ctype: QscAesCipherType) {
	state.nonce = keyparams.nonce.clone();

    let byte_slice = cast_slice_mut::<u32, u8>(&mut state.roundkeys);
	qsc_memutils_clear(byte_slice);

	if ctype == QscAesCipherType::AES256 {
		state.roundkeylen = AES256_ROUNDKEY_SIZE;
		state.rounds = 14;
		aes_standard_expand(state, keyparams);
	} else if ctype == QscAesCipherType::AES128 {
		state.roundkeylen = AES128_ROUNDKEY_SIZE;
		state.rounds = 10;
		aes_standard_expand(state, keyparams);
	} else {
		state.rounds = 0;
		state.roundkeylen = 0;
	}

}

/* cbc mode */

/**
* \brief Decrypt one 16-byte block of cipher-text using Cipher Block Chaining mode. \n
*
* \warning the qsc_aes_initialize function must be called first to initialize the state
*
* \param state: [struct] The initialized qsc_aes_state structure
* \param output: The output byte array; receives the decrypted plain-text
* \param input: [const] The input cipher-text block of bytes
*/
#[allow(dead_code)]
fn qsc_aes_cbc_decrypt_block(state: &mut QscAesState, output: &mut [u8], input: &[u8]) {
	let tmpv = &mut [0u8; QSC_AES_BLOCK_SIZE];

	qsc_memutils_copy(tmpv, input, QSC_AES_BLOCK_SIZE);
	aes_decrypt_block(state.clone(), output, input);

	for i in 0..QSC_AES_BLOCK_SIZE {
		output[i] ^= state.nonce[i];
	}

	qsc_memutils_copy(&mut state.nonce, tmpv, QSC_AES_BLOCK_SIZE);
}

/**
* \brief Encrypt one 16-byte block of cipher-text using Cipher Block Chaining mode. \n
*
* \warning the qsc_aes_initialize function must be called first to initialize the state
*
* \param state: [struct] The initialized qsc_aes_state structure
* \param output: The output byte array; receives the encrypted cipher-text
* \param input: [const] The input plain-text block of bytes
*/
#[allow(dead_code)]
fn qsc_aes_cbc_encrypt_block(state: &mut QscAesState, output: &mut [u8], input: &[u8]) {
	for i in 0..QSC_AES_BLOCK_SIZE {
		state.nonce[i] ^= input[i];
	}

	aes_encrypt_block(state.clone(), output, &state.nonce);
	qsc_memutils_copy(&mut state.nonce, output, QSC_AES_BLOCK_SIZE);
}

/* ctr mode */

/**
* \brief Transform a length of data using a Big Endian block cipher Counter mode. \n
* The CTR mode will encrypt plain-text, and decrypt cipher-text.
*
* \warning the qsc_aes_initialize function must be called first to initialize the state
*
* \param state: [struct] The initialized qsc_aes_state structure
* \param output: The output byte array; receives the transformed text
* \param input: [const] The input data byte array
* \param length: The number of input bytes to transform
*/
#[allow(dead_code)]
fn qsc_aes_ctrbe_transform(state: &mut QscAesState, output: &mut [u8], input: &[u8], mut length: usize) {
    let mut oft = 0;

	while length >= QSC_AES_BLOCK_SIZE {
		aes_encrypt_block(state.clone(), &mut output[oft..], &state.nonce);

		for i in 0..QSC_AES_BLOCK_SIZE {
			output[oft + i] ^= input[oft + i];
		}

		qsc_intutils_be8increment(&mut state.nonce, QSC_AES_BLOCK_SIZE);

		length -= QSC_AES_BLOCK_SIZE;
		oft += QSC_AES_BLOCK_SIZE;
	}

	if length != 0 {
		let tmpb = &mut [0u8; QSC_AES_BLOCK_SIZE];

		aes_encrypt_block(state.clone(), tmpb, &state.nonce);

		for i in 0..length {
			output[oft + i] = tmpb[i] ^ input[oft + i];
		}

		qsc_intutils_be8increment(&mut state.nonce, QSC_AES_BLOCK_SIZE);
	}
}

/**
* \brief Transform a length of data using a Little Endian block cipher Counter mode. \n
* The CTR mode will encrypt plain-text, and decrypt cipher-text.
*
* \warning the qsc_aes_initialize function must be called first to initialize the state
*
* \param state: [struct] The initialized qsc_aes_state structure
* \param output: The output byte array; receives the transformed text
* \param input: [const] The input data byte array
* \param length: The number of input bytes to transform
*/
fn qsc_aes_ctrle_transform(state: &mut QscAesState, output: &mut [u8], input: &[u8], mut length: usize) {
	let mut oft = 0;

	while length >= QSC_AES_BLOCK_SIZE {
		aes_encrypt_block(state.clone(), &mut output[oft..], &state.nonce);

		for i in 0..QSC_AES_BLOCK_SIZE {
			output[oft + i] ^= input[oft + i];
		}

		qsc_intutils_le8increment(&mut state.nonce, QSC_AES_BLOCK_SIZE);

		length -= QSC_AES_BLOCK_SIZE;
		oft += QSC_AES_BLOCK_SIZE;
	}

	if length != 0 {
		let tmpb = &mut [0u8; QSC_AES_BLOCK_SIZE];

		aes_encrypt_block(state.clone(), tmpb, &state.nonce);

		for i in 0..length {
			output[oft + i] = tmpb[i] ^ input[oft + i];
		}

		qsc_intutils_le8increment(&mut state.nonce, QSC_AES_BLOCK_SIZE);
	}
}

/* ecb mode */

/**
* \brief Decrypt one 16-byte block of cipher-text using Electronic CodeBook Mode mode. \n
* \warning ECB is not a secure mode, and should be used only for testing, or building more complex primitives.
*
* \param state: [struct] The initialized qsc_aes_state structure
* \param output: The output byte array; receives the decrypted plain-text
* \param input: [const] The input cipher-text block of bytes
*/
#[allow(dead_code)]
fn qsc_aes_ecb_decrypt_block(state: QscAesState, output: &mut [u8], input: &[u8]) {
	aes_decrypt_block(state, output, input);
}

/**
* \brief Encrypt one 16-byte block of cipher-text using Electronic CodeBook Mode mode. \n
* \warning ECB is not a secure mode, and should be used only for testing, or building more complex primitives.
*
* \param state: [struct] The initialized qsc_aes_state structure
* \param output: The output byte array; receives the encrypted cipher-text
* \param input: [const] The input plain-text block of bytes
*/
#[allow(dead_code)]
fn qsc_aes_ecb_encrypt_block(state: QscAesState, output: &mut [u8], input: &[u8]) {
	aes_encrypt_block(state, output, input);
}

/**
* \brief Erase the round-key array and size
*/
#[allow(dead_code)]
fn qsc_aes_dispose(state: &mut QscAesState) {
	/* erase the state members */
    let byte_slice = cast_slice_mut::<u32, u8>(&mut state.roundkeys);
    qsc_memutils_clear(byte_slice);
    state.roundkeylen = 0;
}


/* Block-cipher counter mode with Hash Based Authentication, -HBA- AEAD authenticated mode */

/* aes-hba256 */

const fn def_aes_hba256_name() -> [u8; HBA_NAME_LENGTH_MAX] {
	if QSC_HBA_KMAC_AUTH {
		return [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x48, 0x42, 0x41, 0x2D, 0x52, 0x48, 0x58, 0x53, 0x32, 0x35, 0x36, 0x2D, 0x4B, 0x4D, 0x41, 0x43, 0x32, 0x35, 0x36, 0x00, 0x00, 0x00, 0x00];
	} else {
		return [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x48, 0x42, 0x41, 0x2D, 0x52, 0x48, 0x58, 0x48, 0x32, 0x35, 0x36, 0x2D, 0x48, 0x4D, 0x41, 0x43, 0x53, 0x48, 0x41, 0x32, 0x32, 0x35, 0x36];
	};
}
pub const AES_HBA256_NAME: [u8; HBA_NAME_LENGTH] = {
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

fn aes_hba256_update(state: &mut QscAesHba256State, input: &[u8], length: usize) {
    if QSC_HBA_KMAC_EXTENSION {
	    qsc_kmac_update(&mut state.kstate, QSC_KECCAK_256_RATE, input, length);
    }
}

fn aes_hba256_finalize(state: &mut QscAesHba256State, output: &mut [u8]) {
	let mkey = &mut [0u8; HBA256_MKEY_LENGTH];
	let pctr = &mut [0u8; size_of::<u64>()];
	let tmpn = &mut [0u8; HBA_NAME_LENGTH];

	/* version 1.1a add the nonce, ciphertext, and encoding sizes to the counter */
	let mctr = (QSC_AES_BLOCK_SIZE + state.counter as usize + size_of::<u64>()) as u64;
	/* convert to little endian bytes  */
	qsc_intutils_le64to8(pctr, mctr);
	/* encode with message size, counter, and terminating string sizes */
	aes_hba256_update(state, pctr, size_of::<u64>());

    if QSC_HBA_KMAC_AUTH {
        /* mac the data and add the code to the end of the cipher-text output array */
        qsc_kmac_finalize(&mut state.kstate, QSC_KECCAK_256_RATE, output, QSC_HBA256_MAC_LENGTH);
    }

	/* generate the new mac key */
	qsc_memutils_copy(tmpn, &AES_HBA256_NAME, HBA_NAME_LENGTH);
	/* add 1 + the nonce, and last input size */
	/* append the counter to the end of the mac input array */
	qsc_intutils_le64to8(tmpn, state.counter);

    if QSC_HBA_KMAC_AUTH {
        qsc_cshake256_compute(mkey, HBA256_MKEY_LENGTH, &state.mkey, 32, tmpn, HBA_NAME_LENGTH, &state.cust, state.custlen);
        qsc_memutils_copy(&mut state.mkey, mkey, HBA256_MKEY_LENGTH);
        qsc_kmac_initialize(&mut state.kstate, QSC_KECCAK_256_RATE, &mut state.mkey, HBA256_MKEY_LENGTH, &mut [], 0);
    }
}

fn aes_hba256_genkeys(keyparams: QscAesKeyparams, cprk: &mut [u8], mack: &mut [u8]) {
    if QSC_HBA_KMAC_EXTENSION {

        let kstate = &mut QscKeccakState::default();
        let sbuf = &mut [0u8; QSC_KECCAK_256_RATE];

        qsc_intutils_clear64(&mut kstate.state, QSC_KECCAK_STATE_SIZE);

        let rate = QscKeccakRate::QscKeccakRate256 as usize;

        /* initialize an instance of cSHAKE */
        qsc_cshake_initialize(kstate, rate, &keyparams.key, keyparams.keylen, &AES_HBA256_NAME, HBA_NAME_LENGTH, &keyparams.info, keyparams.infolen);

        /* use two permutation calls to seperate the cipher/mac key outputs to match the CEX implementation */
        qsc_cshake_squeezeblocks(kstate, rate, sbuf, 1);
        qsc_memutils_copy(cprk, sbuf, keyparams.keylen);
        qsc_cshake_squeezeblocks(kstate, rate, sbuf, 1);
        qsc_memutils_copy(mack, sbuf, HBA256_MKEY_LENGTH);
        /* clear the shake buffer */
        qsc_intutils_clear64(&mut kstate.state, QSC_KECCAK_STATE_SIZE);

    }
}

/**
* \brief Initialize the cipher and load the keying material.
* Initializes the cipher state to an AES-256 instance.
*
* \warning The initialize function must be called before either the associated data or transform functions are called.
*
* \param state: [struct] The HBA state structure; contains internal state information
* \param keyparams: [const][struct] The HBA key parameters, includes the key, and optional AAD and user info arrays
* \param encrypt: The cipher encryption mode; true for encryption, false for decryption
*/
#[allow(dead_code)]
fn qsc_aes_hba256_initialize(state: &mut QscAesHba256State, keyparams: QscAesKeyparams, encrypt: bool) {
	let cprk = &mut [0u8; QSC_AES256_KEY_SIZE];

	state.custlen = qsc_intutils_min(keyparams.infolen, QSC_HBA_MAXINFO_SIZE);

	if state.custlen != 0 {
		qsc_memutils_clear(&mut state.cust);
		qsc_memutils_copy(&mut state.cust, &keyparams.info, state.custlen);
	}

	qsc_intutils_clear8(&mut state.mkey, 32);

	/* generate the cipher and mac keys */
	aes_hba256_genkeys(keyparams.clone(), cprk, &mut state.mkey);

	/* initialize the mac state */
    if QSC_HBA_KMAC_EXTENSION {
        qsc_kmac_initialize(&mut state.kstate, QSC_KECCAK_256_RATE, &mut state.mkey, HBA256_MKEY_LENGTH, &mut [], 0);
    }

	/* initialize the key parameters struct, info is optional */
	let kp = QscAesKeyparams {
        key: cprk.to_vec(),
        keylen: QSC_AES256_KEY_SIZE,
        nonce: keyparams.nonce,
        info: [].to_vec(),
        infolen: 0,
    };
	/* initialize the cipher state */
	qsc_aes_initialize(&mut state.cstate, kp, QscAesCipherType::AES256);

	/* populate the hba state structure with mac-key and counter */
	/* the state counter always initializes at 1 */
	state.counter = 1;
	state.encrypt = encrypt;
}

/**
* \brief Set the associated data string used in authenticating the message.
* The associated data may be packet header information, domain specific data, or a secret shared by a group.
* The associated data must be set after initialization, and before each transformation call.
* The data is erased after each call to the transform.
*
* \param state: [struct] The HBA-256 state structure; contains internal state information
* \param data: [const] The associated data array
* \param datalen: The associated data array length
*/
#[allow(dead_code)]
fn qsc_aes_hba256_set_associated(state: &mut QscAesHba256State, data: &[u8], datalen: usize) {
	/* process the additional data */
	if datalen != 0 {
		let actr = &mut [0u8; size_of::<u32>()];

		/* add the additional data to the mac */
		aes_hba256_update(state, data, datalen);
		/* 1.1a encode with the ad size */
		qsc_intutils_le32to8(actr, datalen as u32);
		aes_hba256_update(state, actr, size_of::<u32>());
	}
}

/**
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
#[allow(dead_code)]
fn qsc_aes_hba256_transform(state: &mut QscAesHba256State, output: &mut [u8], input: &[u8], length: usize) -> bool {
	let mut res = false;

	/* update the processed bytes counter */
	state.counter += length as u64;

    let nonce = &state.cstate.nonce.to_owned();
	if state.encrypt {
		/* update the mac with the nonce */
		aes_hba256_update(state, nonce, QSC_AES_BLOCK_SIZE);
		/* use aes counter-mode to encrypt the array */
		qsc_aes_ctrle_transform(&mut state.cstate, output, input, length);
		/* update the mac with the cipher-text */
		aes_hba256_update(state, output, length);
		/* mac the cipher-text appending the code to the end of the array */
		aes_hba256_finalize(state, &mut output[length..]);
		res = true;
	} else {
		let code = &mut [0u8; QSC_HBA256_MAC_LENGTH];

		/* update the mac with the nonce */
		aes_hba256_update(state, nonce, QSC_AES_BLOCK_SIZE);
		/* update the mac with the cipher-text */
		aes_hba256_update(state, input, length);
		/* mac the cipher-text to the mac */
		aes_hba256_finalize(state, code);

		/* test the mac for equality, bypassing the transform if the mac check fails */
		if qsc_intutils_verify(code, &input[length..], QSC_HBA256_MAC_LENGTH) == 0 {
			/* use aes counter-mode to decrypt the array */
			qsc_aes_ctrle_transform(&mut state.cstate, output, input, length);
			res = true;
		}
	}

	return res;
}
