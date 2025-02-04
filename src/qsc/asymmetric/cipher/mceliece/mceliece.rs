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
* \file mceliece.h
* \brief Contains the primary public api for the Niederreiter dual form of the McEliece asymmetric cipher implementation.
*
* \par Example
* \code
	fn mceliece() -> bool {
		let seed = [0u8; QSC_MCELIECE_SEED_SIZE];

		let publickey = &mut vec![0u8; QSC_MCELIECE_PUBLICKEY_SIZE];
		let privatekey = &mut vec![0u8; QSC_MCELIECE_PRIVATEKEY_SIZE];

		let secret1 = &mut [0u8; QSC_MCELIECE_SHAREDSECRET_SIZE];
		let secret2 = &mut [0u8; QSC_MCELIECE_SHAREDSECRET_SIZE];

		let ciphertext = &mut [0u8; QSC_MCELIECE_CIPHERTEXT_SIZE];

		qsc_mceliece_generate_keypair(publickey, privatekey, seed);	
		qsc_mceliece_encrypt(secret1, ciphertext, publickey, seed);
		qsc_mceliece_decrypt(secret2, ciphertext, privatekey);

		return secret1 == secret2;
	}
* \endcode
*
* \remarks
* Classic McEliece is a KEM designed for IND-CCA2 security at a very high security level, even against quantum computers. \n
* The KEM is built conservatively from a PKE designed for OW-CPA security, namely Niederreiter's dual version of McEliece's PKE using binary Goppa codes. \n
* Every level of the construction is designed so that future cryptographic auditors can be confident in the long-term security of post-quantum public-key encryption. \n
*
* Based entirely on the C reference branch of Dilithium taken from the NIST Post Quantum Competition Round 3 submission. \n
* The NIST Post Quantum Competition <a href="https://csrc.nist.gov/Projects/post-quantum-cryptography/round-3-submissions">Round 3</a> Finalists. \n
* The <a href="https://classic.mceliece.org/">McEliece</a> website. \n
* The McEliece <a href="https://classic.mceliece.org/nist/mceliece-20201010.pdf">Algorithm</a> Specification. \n
* Authors: Daniel J. Bernstein, Tung Chou, Tanja Lange, and Peter Schwabe. \n
* Updated by Stiepan A. Kovac on February 7, 2024.
* c to rust 2024-2025
*/

use crate::qsc::{
	asymmetric::cipher::mceliece::mceliecebase::{
		qsc_mceliece_ref_decapsulate,
		qsc_mceliece_ref_encapsulate,
		qsc_mceliece_ref_generate_keypair,
	},
	prng::secrand::{QscSecrandState, qsc_secrand_initialize, qsc_secrand_destroy, qsc_secrand_generate},
	common::common::{
		QSC_MCELIECE_S3N4608T96,
		QSC_MCELIECE_S5N6688T128,
		QSC_MCELIECE_S5N6960T119,
		QSC_MCELIECE_S5N8192T128,
	},
};


/*
* \def QSC_MCELIECE_SEED_SIZE
* \brief The byte size of the seed array
*/
pub const QSC_MCELIECE_CIPHERTEXT_SIZE: usize = if QSC_MCELIECE_S3N4608T96 {
    188
} else if QSC_MCELIECE_S5N6688T128 {
    240
} else if QSC_MCELIECE_S5N6960T119 {
    226
} else if QSC_MCELIECE_S5N8192T128 {
    240
} else {
    0
};

/*
* \def QSC_MCELIECE_PRIVATEKEY_SIZE
* \brief The byte size of the secret private-key array
*/
pub const QSC_MCELIECE_PRIVATEKEY_SIZE: usize = if QSC_MCELIECE_S3N4608T96 {
    13608
} else if QSC_MCELIECE_S5N6688T128 {
    13932
} else if QSC_MCELIECE_S5N6960T119 {
    13948
} else if QSC_MCELIECE_S5N8192T128 {
    14120
} else {
    0
};

/*
* \def QSC_MCELIECE_PUBLICKEY_SIZE
* \brief The byte size of the public-key array
*/
pub const QSC_MCELIECE_PUBLICKEY_SIZE: usize = if QSC_MCELIECE_S3N4608T96 {
    524160
} else if QSC_MCELIECE_S5N6688T128 {
    1044992
} else if QSC_MCELIECE_S5N6960T119 {
    1047319
} else if QSC_MCELIECE_S5N8192T128 {
    1357824
} else {
    0
};


/*
* \def QSC_MCELIECE_SEED_SIZE
* \brief The byte size of the seed array
*/
pub const QSC_MCELIECE_SEED_SIZE: usize = 32;

/*
* \def QSC_MCELIECE_SHAREDSECRET_SIZE
* \brief The byte size of the shared secret-key array
*/
pub const QSC_MCELIECE_SHAREDSECRET_SIZE: usize = 32;

/**
* \brief Decapsulates the shared secret for a given cipher-text using a private-key
*
* \param secret: Pointer to a shared secret key, an array of QSC_MCELIECE_SHAREDSECRET_SIZE constant size
* \param ciphertext: [const] Pointer to the cipher-text array of QSC_MCELIECE_CIPHERTEXT_SIZE constant size
* \param privatekey: [const] Pointer to the private-key array of QSC_MCELIECE_PRIVATEKEY_SIZE constant size
* \return Returns true for success
*/
fn qsc_mceliece_decapsulate(secret: &mut [u8], ciphertext: &[u8], privatekey: &[u8]) -> bool {

    let mut res = false;

	if secret.len() == QSC_MCELIECE_SHAREDSECRET_SIZE && ciphertext.len() == QSC_MCELIECE_CIPHERTEXT_SIZE && privatekey.len() == QSC_MCELIECE_PRIVATEKEY_SIZE {
		res = qsc_mceliece_ref_decapsulate(secret, ciphertext, privatekey) == 0;
	}

	return res;
}

/**
* \brief Decrypts the shared secret for a given cipher-text using a private-key
* Used in conjunction with the encrypt function.
*
* \param secret: Pointer to the output shared secret key, an array of QSC_KYBER_SHAREDSECRET_SIZE constant size
* \param ciphertext: [const] Pointer to the cipher-text array of QSC_KYBER_CIPHERTEXT_SIZE constant size
* \param privatekey: [const] Pointer to the secret-key array of QSC_KYBER_PRIVATEKEY_SIZE constant size
* \return Returns true for success
*/
pub fn qsc_mceliece_decrypt(secret: &mut [u8], ciphertext: &[u8], privatekey: &[u8]) -> bool {
	let mut res = false;

	if secret.len() == QSC_MCELIECE_SHAREDSECRET_SIZE && ciphertext.len() == QSC_MCELIECE_CIPHERTEXT_SIZE && privatekey.len() == QSC_MCELIECE_PRIVATEKEY_SIZE {
		res = qsc_mceliece_decapsulate(secret, ciphertext, privatekey);
	}

	return res;
}

/**
* \brief Generates cipher-text and encapsulates a shared secret key using a public-key
*
* \param secret: Pointer to a shared secret, a uint8_t array of QSC_MCELIECE_SHAREDSECRET_SIZE constant size
* \param ciphertext: Pointer to the cipher-text array of QSC_MCELIECE_CIPHERTEXT_SIZE constant size
* \param publickey: [const] Pointer to the public-key array of QSC_MCELIECE_PUBLICKEY_SIZE constant size
* \param rng_generate: Pointer to a random generator function
*/
fn qsc_mceliece_encapsulate(secrand_state: &mut QscSecrandState, secret: &mut [u8], ciphertext: &mut [u8], publickey: &[u8], rng_generate: fn(&mut QscSecrandState, &mut [u8], usize) -> bool) {
	if secret.len() == QSC_MCELIECE_SHAREDSECRET_SIZE && ciphertext.len() == QSC_MCELIECE_CIPHERTEXT_SIZE && publickey.len() == QSC_MCELIECE_PUBLICKEY_SIZE {
		qsc_mceliece_ref_encapsulate(secrand_state, ciphertext, secret, publickey, rng_generate);
	}
}

/**
* \brief Generates cipher-text and encapsulates a shared secret key using a public-key
* Used in conjunction with the encrypt function.
*
* \warning Cipher-text array must be sized to the QSC_KYBER_CIPHERTEXT_SIZE.
*
* \param secret: Pointer to the shared secret key, a uint8_t array of QSC_KYBER_SHAREDSECRET_SIZE constant size
* \param ciphertext: Pointer to the cipher-text array of QSC_KYBER_CIPHERTEXT_SIZE constant size
* \param publickey: [const] Pointer to the public-key array of QSC_KYBER_PUBLICKEY_SIZE constant size
* \param seed: [const] A pointer to the random seed array
*/
pub fn qsc_mceliece_encrypt(secret: &mut [u8], ciphertext: &mut [u8], publickey: &[u8], seed: [u8; QSC_MCELIECE_SEED_SIZE]) {
	let secrand_state = &mut QscSecrandState::default();
	qsc_secrand_initialize(secrand_state, &seed, QSC_MCELIECE_SEED_SIZE, &[], 0);
	if secret.len() == QSC_MCELIECE_SHAREDSECRET_SIZE && ciphertext.len() == QSC_MCELIECE_CIPHERTEXT_SIZE && publickey.len() == QSC_MCELIECE_PUBLICKEY_SIZE {
		qsc_mceliece_encapsulate(secrand_state, secret, ciphertext, publickey, qsc_secrand_generate);
	}
	qsc_secrand_destroy(secrand_state);
}

/**
* \brief Generates public and private key for the McEliece key encapsulation mechanism
*
* \param publickey: Pointer to the output public-key array of QSC_MCELIECE_PUBLICKEY_SIZE constant size
* \param privatekey: Pointer to output private-key array of QSC_MCELIECE_PRIVATEKEY_SIZE constant size
* \param rng_generate: Pointer to the random generator function
*/
pub fn qsc_mceliece_generate_keypair(publickey: &mut [u8], privatekey: &mut [u8], seed: [u8; QSC_MCELIECE_SEED_SIZE]) {
	let secrand_state = &mut QscSecrandState::default();
	qsc_secrand_initialize(secrand_state, &seed, QSC_MCELIECE_SEED_SIZE, &[], 0);
	if publickey.len() == QSC_MCELIECE_PUBLICKEY_SIZE && privatekey.len() == QSC_MCELIECE_PRIVATEKEY_SIZE {
		qsc_mceliece_ref_generate_keypair(secrand_state, publickey, privatekey, qsc_secrand_generate);
	}
	qsc_secrand_destroy(secrand_state);
}
