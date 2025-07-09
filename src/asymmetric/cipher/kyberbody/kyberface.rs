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

use crate::{
	asymmetric::{
		asymmetric::{qrc_asymmetric_secrand_generate, AsymmetricRandState},
		cipher::kyberbody::kyberbase::{
			qrc_kyber_ref_decapsulate, qrc_kyber_ref_encapsulate, qrc_kyber_ref_generate_keypair,
			QRC_KYBER_INDCPA_BYTES, QRC_KYBER_INDCPA_PUBLICKEY_BYTES, QRC_KYBER_INDCPA_SECRETKEY_BYTES, QRC_KYBER_SYMBYTES
		}
	}, 
	prng::secrand::{qrc_secrand_destroy, qrc_secrand_initialize}
};

/*
* \def QRC_KYBER_CIPHERTEXT_SIZE
* \brief The byte size of the cipher-text array
*/
pub const QRC_KYBER_CIPHERTEXT_SIZE: usize = QRC_KYBER_INDCPA_BYTES;

/*
* \def QRC_KYBER_PRIVATEKEY_SIZE
* \brief The byte size of the secret private-key array
*/
pub const QRC_KYBER_PRIVATEKEY_SIZE: usize = QRC_KYBER_INDCPA_SECRETKEY_BYTES +  QRC_KYBER_INDCPA_PUBLICKEY_BYTES + (2 * QRC_KYBER_SYMBYTES);

/*
* \def QRC_KYBER_PUBLICKEY_SIZE
* \brief The byte size of the public-key array
*/
pub const QRC_KYBER_PUBLICKEY_SIZE: usize = QRC_KYBER_INDCPA_PUBLICKEY_BYTES;

/*
* \def QRC_KYBER_SEED_SIZE
* \brief The byte size of the seed array
*/
pub const QRC_KYBER_SEED_SIZE: usize = 32;

/*
* \def QRC_KYBER_SHAREDSECRET_SIZE
* \brief The byte size of the shared secret-key array
*/
pub const QRC_KYBER_SHAREDSECRET_SIZE: usize = 32;
/*
* \def QRC_KYBER_ALGNAME
* \brief The formal algorithm name
*/
pub const QRC_KYBER_ALGNAME: &str = "KYBER";

/*
* \brief Decapsulates the shared secret for a given cipher-text using a private-key.
* Used in conjunction with the encapsulate function.
*
* \param secret: Pointer to the output shared secret key, an array of QRC_KYBER_SHAREDSECRET_SIZE constant size
* \param ciphertext: [const] Pointer to the cipher-text array of QRC_KYBER_CIPHERTEXT_SIZE constant size
* \param privatekey: [const] Pointer to the secret-key array of QRC_KYBER_PRIVATEKEY_SIZE constant size
* \return Returns true for success
*/
pub fn qrc_kyber_decapsulate(secret: &mut [u8], ciphertext: &[u8], privatekey: &[u8]) -> bool {
	return qrc_kyber_ref_decapsulate(secret, ciphertext, privatekey);
}


/*
* \brief Decrypts the shared secret for a given cipher-text using a private-key
* Used in conjunction with the encrypt function.
*
* \param secret: Pointer to the output shared secret key, an array of QRC_KYBER_SHAREDSECRET_SIZE constant size
* \param ciphertext: [const] Pointer to the cipher-text array of QRC_KYBER_CIPHERTEXT_SIZE constant size
* \param privatekey: [const] Pointer to the secret-key array of QRC_KYBER_PRIVATEKEY_SIZE constant size
* \return Returns true for success
*/
pub fn qrc_kyber_decrypt(secret: &mut [u8; QRC_KYBER_SHAREDSECRET_SIZE], ciphertext: &[u8; QRC_KYBER_CIPHERTEXT_SIZE], privatekey: &[u8; QRC_KYBER_PRIVATEKEY_SIZE]) -> bool {
	return qrc_kyber_decapsulate(secret, ciphertext, privatekey);
}

/*
* \brief Generates cipher-text and encapsulates a shared secret key using a public-key.
* Used in conjunction with the decapsulate function.
*
* \warning Ciphertext array must be sized to the QRC_KYBER_CIPHERTEXT_SIZE.
*
* \param secret: Pointer to the shared secret key, a uint8_t array of QRC_KYBER_SHAREDSECRET_SIZE constant size
* \param ciphertext: Pointer to the cipher-text array of QRC_KYBER_CIPHERTEXT_SIZE constant size
* \param publickey: [const] Pointer to the public-key array of QRC_KYBER_PUBLICKEY_SIZE constant size
* \param rng_generate: A pointer to the random generator function
*/
pub fn qrc_kyber_encapsulate(asymmetric_state: &mut AsymmetricRandState, secret: &mut [u8], ciphertext: &mut [u8], publickey: &[u8], rng_generate: fn(&mut AsymmetricRandState, &mut [u8], usize) -> bool) {
	qrc_kyber_ref_encapsulate(asymmetric_state, ciphertext, secret, publickey, rng_generate);	
}

/*
* \brief Generates cipher-text and encapsulates a shared secret key using a public-key
* Used in conjunction with the encrypt function.
* 
* \warning Ciphertext array must be sized to the QRC_KYBER_CIPHERTEXT_SIZE.
*
* \param secret: Pointer to the shared secret key, a uint8_t array of QRC_KYBER_SHAREDSECRET_SIZE constant size
* \param ciphertext: Pointer to the cipher-text array of QRC_KYBER_CIPHERTEXT_SIZE constant size
* \param publickey: [const] Pointer to the public-key array of QRC_KYBER_PUBLICKEY_SIZE constant size
* \param seed: [const] A pointer to the random seed array
*/
pub fn qrc_kyber_encrypt(secret: &mut [u8; QRC_KYBER_SHAREDSECRET_SIZE], ciphertext: &mut [u8; QRC_KYBER_CIPHERTEXT_SIZE], publickey: &[u8; QRC_KYBER_PUBLICKEY_SIZE], seed: [u8; QRC_KYBER_SEED_SIZE]) {
	let asymmetric_state = &mut AsymmetricRandState::default();
    qrc_secrand_initialize(&mut asymmetric_state.secrand_state, &seed, QRC_KYBER_SEED_SIZE, &[], 0);
	qrc_kyber_encapsulate(asymmetric_state, secret, ciphertext, publickey, qrc_asymmetric_secrand_generate);
    qrc_secrand_destroy(&mut asymmetric_state.secrand_state);
}

/*
* \brief Generates public and private key for the KYBER key encapsulation mechanism
*
* \warning Arrays must be sized to QRC_KYBER_PUBLICKEY_SIZE and QRC_KYBER_SECRETKEY_SIZE.
*
* \param publickey: Pointer to the output public-key array of QRC_KYBER_PUBLICKEY_SIZE constant size
* \param privatekey: Pointer to output private-key array of QRC_KYBER_PRIVATEKEY_SIZE constant size
* \param rng_generate: A pointer to the random generator function
*/
pub fn qrc_kyber_generate_keypair(publickey: &mut [u8; QRC_KYBER_PUBLICKEY_SIZE], privatekey: &mut [u8; QRC_KYBER_PRIVATEKEY_SIZE], seed: [u8; QRC_KYBER_SEED_SIZE]) {
	let asymmetric_state = &mut AsymmetricRandState::default();
    qrc_secrand_initialize(&mut asymmetric_state.secrand_state, &seed, QRC_KYBER_SEED_SIZE, &[], 0);
	qrc_kyber_gen_keypair(asymmetric_state, publickey, privatekey, qrc_asymmetric_secrand_generate);
    qrc_secrand_destroy(&mut asymmetric_state.secrand_state);
}
pub fn qrc_kyber_gen_keypair(asymmetric_state: &mut AsymmetricRandState, publickey: &mut [u8], privatekey: &mut [u8], rng_generate: fn(&mut AsymmetricRandState, &mut [u8], usize) -> bool) {
	qrc_kyber_ref_generate_keypair(asymmetric_state, publickey, privatekey, rng_generate);
}