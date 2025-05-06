/*
* 2022 John G. Underhill
* All Rights Reserved.
*
* NOTICE:  All information contained herein is, and remains
* the property of John G. Underhill.
* The intellectual and technical concepts contained
* herein are proprietary to John G. Underhill
* and his suppliers and may be covered by U.S. and Foreign Patents,
* patents in process, and are protected by trade secret or copyright law.
* Dissemination of this information or reproduction of this material
* is strictly forbidden unless prior written permission is obtained
* from Digital Freedom Defense Incorporated.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*
* This library was published publicly in hopes that it would aid in prototyping
* post-quantum secure primitives for educational purposes only.
* All and any commercial uses of this library are exclusively reserved by the author
* John G. Underhill.
* Any use of this library in a commercial context must be approved by the author
* in writing.
* All rights for commercial and/or non-educational purposes, are fully reserved
* by the author.
*/

use crate::{asymmetric::{asymmetric::AsymmetricRandState, cipher::ecdhbody::ecdhbase::{qrc_ed25519_generate_keypair, qrc_ed25519_key_exchange}}, tools::intutils::qrc_intutils_clear8};

/*
* \def QRC_ECDH_PRIVATEKEY_SIZE
* \brief The byte size of the secret private-key array
*/
pub const QRC_ECDH_PRIVATEKEY_SIZE: usize = 32;

/*
* \def QRC_ECDH_PUBLICKEY_SIZE
* \brief The byte size of the public-key array
*/
pub const QRC_ECDH_PUBLICKEY_SIZE: usize = 32;

/*
* \def QRC_ECDH_SHAREDSECRET_SIZE
* \brief The byte size of the shared secret-key array
*/
pub const QRC_ECDH_SHAREDSECRET_SIZE: usize = 32;

/*
* \def QRC_ECDH_SEED_SIZE
* \brief The byte size of the shared secret-key array
*/
pub const QRC_ECDH_SEED_SIZE: usize = 32;

/*
* \def QRC_ECDH_ALGNAME
* \brief The formal algorithm name
*/
pub const QRC_ECDH_ALGNAME: &str = "ECDH";

/*
* \brief Decapsulates the shared secret for a given cipher-text using a private-key
*
* \warning The shared secret array must be sized to the QRC_ECDH_SHAREDSECRET_SIZE.
*
* \param secret: Pointer to a shared secret key, an array of QRC_ECDH_SHAREDSECRET_SIZE
* \param privatekey: [const] Pointer to the private-key array
* \param publickey: [const] Pointer to the public-key array
* \return Returns true for success
*/
pub fn qrc_ecdh_key_exchange(secret: &mut [u8; QRC_ECDH_SHAREDSECRET_SIZE], privatekey: &[u8; QRC_ECDH_PRIVATEKEY_SIZE], publickey: &[u8; QRC_ECDH_PUBLICKEY_SIZE]) -> bool {
	return qrc_ed25519_key_exchange(secret, publickey, privatekey);
}

/*
* \brief Generates public and private key for the ECDH key encapsulation mechanism
*
* \warning Arrays must be sized to QRC_ECDH_PUBLICKEY_SIZE and QRC_ECDH_SECRETKEY_SIZE.
*
* \param publickey: Pointer to the output public-key array
* \param privatekey: Pointer to output private-key array
* \param rng_generate: A pointer to the random generator
*/
pub fn qrc_ecdh_generate_keypair(asymmetric_state: &mut AsymmetricRandState, publickey: &mut [u8; QRC_ECDH_PUBLICKEY_SIZE], privatekey: &mut [u8; QRC_ECDH_PRIVATEKEY_SIZE], rng_generate: fn(&mut AsymmetricRandState, &mut [u8], usize) -> bool) {
	let seed = &mut [0u8; QRC_ECDH_SEED_SIZE];
	rng_generate(asymmetric_state, seed, QRC_ECDH_SEED_SIZE);
	qrc_ed25519_generate_keypair(publickey, privatekey, seed);
	qrc_intutils_clear8(seed, QRC_ECDH_SEED_SIZE);
}


/*
* \brief Generates public and private key for the ECDH key encapsulation mechanism
*
* \warning Arrays must be sized to QRC_ECDH_PUBLICKEY_SIZE and QRC_ECDH_SECRETKEY_SIZE.
*
* \param publickey: Pointer to the output public-key array
* \param privatekey: Pointer to output private-key array
* \param seed: [const] A pointer to the random seed
*/
pub fn qrc_ecdh_generate_seeded_keypair(publickey: &mut [u8; QRC_ECDH_PUBLICKEY_SIZE], privatekey: &mut [u8; QRC_ECDH_PRIVATEKEY_SIZE], seed: &[u8; QRC_ECDH_SEED_SIZE]) {
	qrc_ed25519_generate_keypair(publickey, privatekey, seed);
}