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
*/

use crate::{asymmetric::{asymmetric::{qrc_asymmetric_rcrng_generate, AsymmetricRandState}, signature::dilithiumbody::dilithiumbase::{qrc_dilithium_ref_generate_keypair, qrc_dilithium_ref_open, qrc_dilithium_ref_sign}}, common::common::{QRC_DILITHIUM_S2N256Q8380417K4, QRC_DILITHIUM_S3N256Q8380417K6, QRC_DILITHIUM_S5N256Q8380417K8}};

/*
* \def QRC_DILITHIUM_PRIVATEKEY_SIZE
* \brief The byte size of the secret private-key array
*/
pub const QRC_DILITHIUM_PRIVATEKEY_SIZE: usize = if QRC_DILITHIUM_S2N256Q8380417K4 {
    2544
} else if QRC_DILITHIUM_S3N256Q8380417K6 {
    4016
} else if QRC_DILITHIUM_S5N256Q8380417K8 {
    4880
} else {
    0
};

/*
* \def QRC_DILITHIUM_PUBLICKEY_SIZE
* \brief The byte size of the public-key array
*/
pub const QRC_DILITHIUM_PUBLICKEY_SIZE: usize = if QRC_DILITHIUM_S2N256Q8380417K4 {
    1312
} else if QRC_DILITHIUM_S3N256Q8380417K6 {
    1952
} else if QRC_DILITHIUM_S5N256Q8380417K8 {
    2592
} else {
    0
};

/*
* \def QRC_DILITHIUM_SIGNATURE_SIZE
* \brief The byte size of the signature array
*/
pub const QRC_DILITHIUM_SIGNATURE_SIZE: usize = if QRC_DILITHIUM_S2N256Q8380417K4 {
    2420
} else if QRC_DILITHIUM_S3N256Q8380417K6 {
    3293
} else if QRC_DILITHIUM_S5N256Q8380417K8 {
    4595
} else {
    0
};

/*
* \def QRC_DILITHIUM_ALGNAME
* \brief The formal algorithm name
*/
pub const QRC_DILITHIUM_ALGNAME: &str = "DILITHIUM";

/*
* \brief Generates a Dilithium public/private key-pair.
*
* \warning Arrays must be sized to QRC_DILITHIUM_PUBLICKEY_SIZE and QRC_DILITHIUM_SECRETKEY_SIZE.
*
* \param publickey: Pointer to the public verification-key array
* \param privatekey: Pointer to the private signature-key array
* \param rng_generate: Pointer to the random generator
*/
pub fn qrc_dilithium_generate_keypair(publickey: &mut [u8; QRC_DILITHIUM_PUBLICKEY_SIZE], privatekey: &mut [u8; QRC_DILITHIUM_PRIVATEKEY_SIZE]) {
    let asymmetric_state = &mut AsymmetricRandState::default(); 
	qrc_dilithium_generate_keypair_custrand(asymmetric_state, publickey, privatekey, qrc_asymmetric_rcrng_generate);
}
pub fn qrc_dilithium_generate_keypair_custrand(asymmetric_state: &mut AsymmetricRandState, publickey: &mut [u8; QRC_DILITHIUM_PUBLICKEY_SIZE], privatekey: &mut [u8; QRC_DILITHIUM_PRIVATEKEY_SIZE], rng_generate: fn(&mut AsymmetricRandState, &mut [u8], usize) -> bool) {
	qrc_dilithium_ref_generate_keypair(asymmetric_state, publickey, privatekey, rng_generate);
}

/*
* \brief Takes the message as input and returns an array containing the signature followed by the message.
*
* \warning Signature array must be sized to the size of the message plus QRC_DILITHIUM_SIGNATURE_SIZE.
*
* \param signedmsg: Pointer to the signed-message array
* \param smsglen: The signed message length
* \param message: [const] Pointer to the message array
* \param msglen: The message array length
* \param privatekey: [const] Pointer to the private signature-key
* \param rng_generate: Pointer to the random generator
*/
pub fn qrc_dilithium_sign(signedmsg: &mut [u8], smsglen: &mut usize, message: &[u8], msglen: usize, privatekey: &[u8; QRC_DILITHIUM_PRIVATEKEY_SIZE]) {
    let asymmetric_state = &mut AsymmetricRandState::default(); 
	qrc_dilithium_sign_custrand(asymmetric_state, signedmsg, smsglen, message, msglen, privatekey, qrc_asymmetric_rcrng_generate);
}
pub fn qrc_dilithium_sign_custrand(asymmetric_state: &mut AsymmetricRandState, signedmsg: &mut [u8], smsglen: &mut usize, message: &[u8], msglen: usize, privatekey: &[u8], rng_generate: fn(&mut AsymmetricRandState, &mut [u8], usize) -> bool) {
	qrc_dilithium_ref_sign(asymmetric_state, signedmsg, smsglen, message, msglen, privatekey, rng_generate);
}

/*
* \brief Verifies a signature-message pair with the public key.
*
* \param message: Pointer to the message output array
* \param msglen: Length of the message array
* \param signedmsg: [const] Pointer to the signed message array
* \param smsglen: The signed message length
* \param publickey: [const] Pointer to the public verification-key array
* \return Returns true for success
*/
pub fn qrc_dilithium_verify(message: &mut [u8], msglen: &mut isize, signedmsg: &[u8], smsglen: usize, publickey: &[u8; QRC_DILITHIUM_PUBLICKEY_SIZE]) -> bool {
	return qrc_dilithium_ref_open(message, msglen, signedmsg, smsglen, publickey);
}
