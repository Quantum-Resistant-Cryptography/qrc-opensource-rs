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

use crate::{asymmetric::{asymmetric::AsymmetricRandState, signature::ecdsabody::ecdsabase::{qrc_ed25519_keypair, qrc_ed25519_sign, qrc_ed25519_verify}}, common::common::QRC_ECDSA_S1EC25519, tools::intutils::qrc_intutils_clear8};

/*
* \def QRC_ECDSA_SIGNATURE_SIZE
* \brief The byte size of the signature array
*/
pub const QRC_ECDSA_SIGNATURE_SIZE: usize = if QRC_ECDSA_S1EC25519 {
    64
} else {
    0
};

/*
* \def QRC_ECDSA_PRIVATEKEY_SIZE
* \brief The byte size of the secret private-key array
*/
pub const QRC_ECDSA_PRIVATEKEY_SIZE: usize = if QRC_ECDSA_S1EC25519 {
    64
} else {
    0
};

/*
* \def QRC_ECDSA_PUBLICKEY_SIZE
* \brief The byte size of the public-key array
*/
pub const QRC_ECDSA_PUBLICKEY_SIZE: usize = if QRC_ECDSA_S1EC25519 {
    32
} else {
    0
};

/*
* \def QRC_ECDSA_SEED_SIZE
* \brief The byte size of the random seed array
*/
pub const QRC_ECDSA_SEED_SIZE: usize = 32;

/*
* \def QRC_ECDSA_ALGNAME
* \brief The formal algorithm name
*/
pub const QRC_ECDSA_ALGNAME: &str = "ECDSA";

/*
* \brief Generates a ECDSA public/private key-pair.
*
* \warning Arrays must be sized to QRC_ECDSA_PUBLICKEY_SIZE and QRC_ECDSA_SECRETKEY_SIZE.
*
* \param publickey: Pointer to the public verification-key array
* \param privatekey: Pointer to the private signature-key array
* \param seed: [const] Pointer to the random 32-byte seed array
*/
pub fn qrc_ecdsa_generate_seeded_keypair(publickey: &mut [u8; QRC_ECDSA_PUBLICKEY_SIZE], privatekey: &mut [u8; QRC_ECDSA_PRIVATEKEY_SIZE], seed: &[u8; QRC_ECDSA_SEED_SIZE]) {
	qrc_ed25519_keypair(publickey, privatekey, seed);
}

/*
* \brief Generates a ECDSA public/private key-pair.
*
* \warning Arrays must be sized to QRC_ECDSA_PUBLICKEY_SIZE and QRC_ECDSA_SECRETKEY_SIZE.
*
* \param publickey: Pointer to the public verification-key array
* \param privatekey: Pointer to the private signature-key array
* \param rng_generate: Pointer to the random generator
*/
pub fn qrc_ecdsa_generate_keypair(asymmetric_state: &mut AsymmetricRandState, publickey: &mut [u8; QRC_ECDSA_PUBLICKEY_SIZE], privatekey: &mut [u8; QRC_ECDSA_PRIVATEKEY_SIZE], rng_generate: fn(&mut AsymmetricRandState, &mut [u8], usize) -> bool) {
	let seed = &mut [0u8; QRC_ECDSA_SEED_SIZE];
	rng_generate(asymmetric_state, seed, QRC_ECDSA_SEED_SIZE);
	qrc_ed25519_keypair(publickey, privatekey, seed);
	qrc_intutils_clear8(seed, QRC_ECDSA_SEED_SIZE);
}

/*
* \brief Takes the message as input and returns an array containing the signature followed by the message.
*
* \warning Signature array must be sized to the size of the message plus QRC_ECDSA_SIGNATURE_SIZE.
*
* \param signedmsg: Pointer to the signed-message array
* \param smsglen: [const] Pointer to the signed message length
* \param message: Pointer to the message array
* \param msglen: The message length
* \param privatekey: [const] Pointer to the private signature-key array
*/
pub fn qrc_ecdsa_sign(signedmsg: &mut [u8], smsglen: &mut usize, message: &[u8], msglen: usize, privatekey: &[u8; QRC_ECDSA_PRIVATEKEY_SIZE]) {
	qrc_ed25519_sign(signedmsg, smsglen, message, msglen, privatekey);
}

/*
* \brief Verifies a signature-message pair with the public key.
*
* \param message: Pointer to the message array to be signed
* \param msglen: Pointer to the message length
* \param signedmsg: [const] Pointer to the signed message array
* \param smsglen: The signed message length
* \param publickey: [const] Pointer to the public verification-key array
* \return Returns true for success
*/
pub fn qrc_ecdsa_verify(message: &mut [u8], msglen: &mut usize, signedmsg: &[u8], smsglen: usize, publickey: &[u8; QRC_ECDSA_PUBLICKEY_SIZE]) -> bool {
	return qrc_ed25519_verify(message, msglen, signedmsg, smsglen, publickey) == 0;
}








