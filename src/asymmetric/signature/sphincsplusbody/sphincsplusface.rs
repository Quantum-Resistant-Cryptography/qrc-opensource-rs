/* The AGPL version 3 License (AGPLv3)
*
* Copyright (c) 2024 DFD & QRC Eurosmart SA
* This file is part of the QRC Cryptographic library
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

use crate::{
    asymmetric::{
        asymmetric::{qrc_asymmetric_rcrng_generate, AsymmetricRandState},
        signature::sphincsplusbody::sphincsplusbase::{sphincsplus_ref_generate_keypair, sphincsplus_ref_sign, sphincsplus_ref_sign_open}
    },
    common::common::{QRC_SPHINCSPLUS_S3S192SHAKERF, QRC_SPHINCSPLUS_S3S192SHAKERS, QRC_SPHINCSPLUS_S5S256SHAKERF, QRC_SPHINCSPLUS_S5S256SHAKERS}
};

/*
* \def QRC_SPHINCSPLUS_SIGNATURE_SIZE
* \brief The byte size of the signature array
*/
pub const QRC_SPHINCSPLUS_SIGNATURE_SIZE: usize = if QRC_SPHINCSPLUS_S3S192SHAKERS {
    16224
} else if QRC_SPHINCSPLUS_S3S192SHAKERF {
    35664
} else if QRC_SPHINCSPLUS_S5S256SHAKERS {
    29792
} else if QRC_SPHINCSPLUS_S5S256SHAKERF {
    49856
} else {
    0
};

/*
* \def QRC_SPHINCSPLUS_PRIVATEKEY_SIZE
* \brief The byte size of the secret private-key array
*/
pub const QRC_SPHINCSPLUS_PRIVATEKEY_SIZE: usize = if QRC_SPHINCSPLUS_S3S192SHAKERS {
    96
} else if QRC_SPHINCSPLUS_S3S192SHAKERF {
    96
} else if QRC_SPHINCSPLUS_S5S256SHAKERS {
    128
} else if QRC_SPHINCSPLUS_S5S256SHAKERF {
    128
} else {
    0
};

/*
* \def QRC_SPHINCSPLUS_PUBLICKEY_SIZE
* \brief The byte size of the public-key array
*/
pub const QRC_SPHINCSPLUS_PUBLICKEY_SIZE: usize = if QRC_SPHINCSPLUS_S3S192SHAKERS {
    48
} else if QRC_SPHINCSPLUS_S3S192SHAKERF {
    48
} else if QRC_SPHINCSPLUS_S5S256SHAKERS {
    64
} else if QRC_SPHINCSPLUS_S5S256SHAKERF {
    64
} else {
    0
};

/*
* \def QRC_SPHINCSPLUS_ALGNAME
* \brief The formal algorithm name
*/
pub const QRC_SPHINCSPLUS_ALGNAME: &str = "SPHINCSPLUS";

/*
* \brief Generates a Sphincs+ public/private key-pair.
*
* \warning Arrays must be sized to QRC_SPHINCSPLUS_PUBLICKEY_SIZE and QRC_SPHINCSPLUS_SECRETKEY_SIZE.
*
* \param publickey: Pointer to the public verification-key array
* \param privatekey: Pointer to the private signature-key array
* \param rng_generate: Pointer to the random generator
*/
pub fn qrc_sphincsplus_generate_keypair(publickey: &mut [u8; QRC_SPHINCSPLUS_PUBLICKEY_SIZE], privatekey: &mut [u8; QRC_SPHINCSPLUS_PRIVATEKEY_SIZE]) {
	let asymmetric_state = &mut AsymmetricRandState::default(); 
	qrc_sphincsplus_generate_keypair_custrand(asymmetric_state, publickey, privatekey, qrc_asymmetric_rcrng_generate);
}
pub fn qrc_sphincsplus_generate_keypair_custrand(asymmetric_state: &mut AsymmetricRandState, publickey: &mut [u8], privatekey: &mut [u8], rng_generate: fn(&mut AsymmetricRandState, &mut [u8], usize) -> bool) {
	sphincsplus_ref_generate_keypair(asymmetric_state, publickey, privatekey, rng_generate);
}

/*
* \brief Takes the message as input and returns an array containing the signature followed by the message.
*
* \warning Signature array must be sized to the size of the message plus QRC_SPHINCSPLUS_SIGNATURE_SIZE.
*
* \param signedmsg: Pointer to the signed-message array
* \param smsglen: [const] Pointer to the signed message length
* \param message: Pointer to the message array
* \param msglen: The message length
* \param privatekey: [const] Pointer to the private signature-key array
* \param rng_generate: Pointer to the random generator
*/
pub fn qrc_sphincsplus_sign(signedmsg: &mut [u8], smsglen: &mut usize, message: &[u8], msglen: usize, privatekey: &[u8; QRC_SPHINCSPLUS_PRIVATEKEY_SIZE]) {
	if (signedmsg.len() - message.len()) == QRC_SPHINCSPLUS_SIGNATURE_SIZE {
		let asymmetric_state = &mut AsymmetricRandState::default(); 
		qrc_sphincsplus_sign_custrand(asymmetric_state, signedmsg, smsglen, message, msglen, privatekey, qrc_asymmetric_rcrng_generate);
	}
}
pub fn qrc_sphincsplus_sign_custrand(asymmetric_state: &mut AsymmetricRandState, signedmsg: &mut [u8], smsglen: &mut usize, message: &[u8], msglen: usize, privatekey: &[u8], rng_generate: fn(&mut AsymmetricRandState, &mut [u8], usize) -> bool) {
	sphincsplus_ref_sign(asymmetric_state, signedmsg, smsglen, message, msglen, privatekey, rng_generate);
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
pub fn qrc_sphincsplus_verify(message: &mut [u8], msglen: &mut usize, signedmsg: &[u8], smsglen: usize, publickey: &[u8; QRC_SPHINCSPLUS_PUBLICKEY_SIZE]) -> bool {
	let mut res = false;
	if (signedmsg.len() - message.len()) == QRC_SPHINCSPLUS_SIGNATURE_SIZE {
		res = sphincsplus_ref_sign_open(message, msglen, signedmsg, smsglen, publickey);
	}
	return res;
}