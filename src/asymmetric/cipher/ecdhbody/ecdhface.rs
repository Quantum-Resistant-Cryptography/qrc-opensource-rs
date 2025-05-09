/* The AGPL version 3 License (AGPLv3)
*
* Copyright (c) 2022 Digital Freedom Defence Inc.
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