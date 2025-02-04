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
* \file kyber.h
* \brief Contains the primary public api for the Kyber CCA-secure Key Encapsulation Mechanism implementation
* \date January 10, 2018
* \updated February 7, 2024
* \c to rust 2024-2025
*
*
* \par Example
* \code
	fn kyber() -> bool {
		let seed = [0u8; QSC_KYBER_SEED_SIZE];

		let publickey = &mut vec![0u8; QSC_KYBER_PUBLICKEY_SIZE];
		let privatekey = &mut vec![0u8; QSC_KYBER_PRIVATEKEY_SIZE];

		let secret1 = &mut [0u8; QSC_KYBER_SHAREDSECRET_SIZE];
		let secret2 = &mut [0u8; QSC_KYBER_SHAREDSECRET_SIZE];

		let ciphertext = &mut [0u8; QSC_KYBER_CIPHERTEXT_SIZE];

		qsc_kyber_generate_keypair(publickey, privatekey, seed);
		qsc_kyber_encrypt(secret1, ciphertext, publickey, seed);
		qsc_kyber_decrypt(secret2, ciphertext, privatekey);

		return secret1 == secret2;
	}
* \endcode
*
* \remarks
* Based on the C reference branch of PQ-Crystals Kyber; including base code, comments, and api. \n
* Removed the K=2 parameter, and added a K=5. The NIST '512' parameter has fallen below the threshold
* required by NIST PQ S1 minimum. \n
* The new K5 parameter may have a better chance of long-term security, with only a small increase in cost. \n
*
* The NIST Post Quantum Competition <a href="https://csrc.nist.gov/Projects/post-quantum-cryptography/round-3-submissions">Round 3</a> Finalists. \n
* The <a href="https://pq-crystals.org/kyber/index.shtml">Kyber</a> website. \n
* The Kyber <a href="https://pq-crystals.org/kyber/data/kyber-specification-round3-20210131.pdf">Algorithm</a> Specification. \n
*/

use crate::qsc::{
	common::common::QSC_SYSTEM_HAS_AVX2,
	prng::secrand::QscSecrandState,
	asymmetric::cipher::kyber::kyberbase::{
		QSC_KYBER_INDCPA_BYTES,
		QSC_KYBER_INDCPA_SECRETKEY_BYTES,
		QSC_KYBER_INDCPA_PUBLICKEY_BYTES,
		QSC_KYBER_SYMBYTES,
		qsc_kyber_ref_decapsulate,
		qsc_kyber_ref_encapsulate,
		qsc_kyber_ref_generate_keypair,
	},
	prng::secrand::{qsc_secrand_initialize, qsc_secrand_destroy, qsc_secrand_generate},
};

/*
* \def QSC_KYBER_CIPHERTEXT_SIZE
* \brief The byte size of the cipher-text array
*/
pub const QSC_KYBER_CIPHERTEXT_SIZE: usize = QSC_KYBER_INDCPA_BYTES;

/*
* \def QSC_KYBER_PRIVATEKEY_SIZE
* \brief The byte size of the secret private-key array
*/
pub const QSC_KYBER_PRIVATEKEY_SIZE: usize = QSC_KYBER_INDCPA_SECRETKEY_BYTES +  QSC_KYBER_INDCPA_PUBLICKEY_BYTES + (2 * QSC_KYBER_SYMBYTES);

/*
* \def QSC_KYBER_PUBLICKEY_SIZE
* \brief The byte size of the public-key array
*/
pub const QSC_KYBER_PUBLICKEY_SIZE: usize = QSC_KYBER_INDCPA_PUBLICKEY_BYTES;

/*
* \def QSC_KYBER_SEED_SIZE
* \brief The byte size of the seed array
*/
pub const QSC_KYBER_SEED_SIZE: usize = 32;

/*
* \def QSC_KYBER_SHAREDSECRET_SIZE
* \brief The byte size of the shared secret-key array
*/
pub const QSC_KYBER_SHAREDSECRET_SIZE: usize = 32;


/**
* \brief Decapsulates the shared secret for a given cipher-text using a private-key.
* Used in conjunction with the encapsulate function.
*
* \param secret: Pointer to the output shared secret key, an array of QSC_KYBER_SHAREDSECRET_SIZE constant size
* \param ciphertext: [const] Pointer to the cipher-text array of QSC_KYBER_CIPHERTEXT_SIZE constant size
* \param privatekey: [const] Pointer to the secret-key array of QSC_KYBER_PRIVATEKEY_SIZE constant size
* \return Returns true for success
*/
fn qsc_kyber_decapsulate(secret: &mut [u8], ciphertext: &[u8], privatekey: &[u8]) -> bool {
	let mut res = false;

	if secret.len() == QSC_KYBER_SHAREDSECRET_SIZE && ciphertext.len() == QSC_KYBER_CIPHERTEXT_SIZE && privatekey.len() == QSC_KYBER_PRIVATEKEY_SIZE {
		if QSC_SYSTEM_HAS_AVX2 {
			res = qsc_kyber_ref_decapsulate(secret, ciphertext, privatekey);
		} else {
			res = qsc_kyber_ref_decapsulate(secret, ciphertext, privatekey);
		}
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
pub fn qsc_kyber_decrypt(secret: &mut [u8], ciphertext: &[u8], privatekey: &[u8]) -> bool {
	let mut res = false;

	if secret.len() == QSC_KYBER_SHAREDSECRET_SIZE && ciphertext.len() == QSC_KYBER_CIPHERTEXT_SIZE && privatekey.len() == QSC_KYBER_PRIVATEKEY_SIZE {
		res = qsc_kyber_decapsulate(secret, ciphertext, privatekey);
	}

	return res;
}


/**
* \brief Generates cipher-text and encapsulates a shared secret key using a public-key.
* Used in conjunction with the decapsulate function.
*
* \warning Ciphertext array must be sized to the QSC_KYBER_CIPHERTEXT_SIZE.
*
* \param secret: Pointer to the shared secret key, a uint8_t array of QSC_KYBER_SHAREDSECRET_SIZE constant size
* \param ciphertext: Pointer to the cipher-text array of QSC_KYBER_CIPHERTEXT_SIZE constant size
* \param publickey: [const] Pointer to the public-key array of QSC_KYBER_PUBLICKEY_SIZE constant size
* \param rng_generate: A pointer to the random generator function
*/
fn qsc_kyber_encapsulate(secrand_state: &mut QscSecrandState, secret: &mut [u8], ciphertext: &mut [u8], publickey: &[u8], rng_generate: fn(&mut QscSecrandState, &mut [u8], usize) -> bool) {
	if secret.len() == QSC_KYBER_SHAREDSECRET_SIZE && ciphertext.len() == QSC_KYBER_CIPHERTEXT_SIZE && publickey.len() == QSC_KYBER_PUBLICKEY_SIZE {
		if QSC_SYSTEM_HAS_AVX2 {
			qsc_kyber_ref_encapsulate(secrand_state, ciphertext, secret, publickey, rng_generate);	
		} else {
			qsc_kyber_ref_encapsulate(secrand_state, ciphertext, secret, publickey, rng_generate);	
		}
	}
}


/**
* \brief Generates cipher-text and encapsulates a shared secret key using a public-key
* Used in conjunction with the encrypt function.
* 
* \warning Ciphertext array must be sized to the QSC_KYBER_CIPHERTEXT_SIZE.
*
* \param secret: Pointer to the shared secret key, a uint8_t array of QSC_KYBER_SHAREDSECRET_SIZE constant size
* \param ciphertext: Pointer to the cipher-text array of QSC_KYBER_CIPHERTEXT_SIZE constant size
* \param publickey: [const] Pointer to the public-key array of QSC_KYBER_PUBLICKEY_SIZE constant size
* \param seed: [const] A pointer to the random seed array
*/
pub fn qsc_kyber_encrypt(secret: &mut [u8], ciphertext: &mut [u8], publickey: &[u8], seed: [u8; QSC_KYBER_SEED_SIZE]) {
	let secrand_state = &mut QscSecrandState::default();
    qsc_secrand_initialize(secrand_state, &seed, QSC_KYBER_SEED_SIZE, &[], 0);
	if secret.len() == QSC_KYBER_SHAREDSECRET_SIZE && ciphertext.len() == QSC_KYBER_CIPHERTEXT_SIZE && publickey.len() == QSC_KYBER_PUBLICKEY_SIZE {
    	qsc_kyber_encapsulate(secrand_state, secret, ciphertext, publickey, qsc_secrand_generate);
	}
    qsc_secrand_destroy(secrand_state);
}


/**
* \brief Generates public and private key for the KYBER key encapsulation mechanism
*
* \warning Arrays must be sized to QSC_KYBER_PUBLICKEY_SIZE and QSC_KYBER_SECRETKEY_SIZE.
*
* \param publickey: Pointer to the output public-key array of QSC_KYBER_PUBLICKEY_SIZE constant size
* \param privatekey: Pointer to output private-key array of QSC_KYBER_PRIVATEKEY_SIZE constant size
* \param rng_generate: A pointer to the random generator function
*/
pub fn qsc_kyber_generate_keypair(publickey: &mut [u8], privatekey: &mut [u8], seed: [u8; QSC_KYBER_SEED_SIZE]) {
	let secrand_state = &mut QscSecrandState::default();
    qsc_secrand_initialize(secrand_state, &seed, QSC_KYBER_SEED_SIZE, &[], 0);
	if publickey.len() == QSC_KYBER_PUBLICKEY_SIZE && privatekey.len() == QSC_KYBER_PRIVATEKEY_SIZE {
		if QSC_SYSTEM_HAS_AVX2 {
			//qsc_kyber_avx2_generate_keypair(publickey, privatekey, qsc_secrand_generate);
			qsc_kyber_ref_generate_keypair(secrand_state, publickey, privatekey, qsc_secrand_generate);
		} else {
			qsc_kyber_ref_generate_keypair(secrand_state, publickey, privatekey, qsc_secrand_generate);
		}
	}
    qsc_secrand_destroy(secrand_state);
}
