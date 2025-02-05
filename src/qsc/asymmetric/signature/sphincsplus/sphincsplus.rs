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

/*
##### SphincsPlus
Based entirely on the C reference branch of SPHINCS+ taken from the NIST Post Quantum Competition Round 3 submission.
The NIST Post Quantum Competition [Round 3](https://csrc.nist.gov/Projects/post-quantum-cryptography/round-3-submissions) Finalists.
The [SPHINCS+](https://sphincs.org/) website.
The SPHINCS+ [Algorithm](https://sphincs.org/data/sphincs+-specification.pdf) Specification.

Date: June 14, 2018
Updated: July 2, 2021
Rust Translation: 2024

The primary public api for the Sphincs+ asymmetric signature scheme implementation:
```rust
use qrc_opensource_rs::{
  asymmetric::signature::sphincsplus::{
    qsc_sphincsplus_generate_keypair, qsc_sphincsplus_sign, qsc_sphincsplus_verify,
    QSC_SPHINCSPLUS_PRIVATEKEY_SIZE, QSC_SPHINCSPLUS_PUBLICKEY_SIZE, QSC_SPHINCSPLUS_SIGNATURE_SIZE, QRCS_CRYPTO_HASH_SIZE,
  },
  provider::rcrng::qsc_rcrng_generate,
};

let privatekey = &mut [0u8; QSC_SPHINCSPLUS_PRIVATEKEY_SIZE];
let publickey = &mut [0u8; QSC_SPHINCSPLUS_PUBLICKEY_SIZE];
let hash = &mut [0u8; QRCS_CRYPTO_HASH_SIZE];
qsc_rcrng_generate(hash, QRCS_CRYPTO_HASH_SIZE);
let mut hashlen = 0;
let sig = &mut [0u8; QSC_SPHINCSPLUS_SIGNATURE_SIZE + QRCS_CRYPTO_HASH_SIZE];
let mut siglen = 0;

qsc_sphincsplus_generate_keypair(publickey, privatekey, qsc_rcrng_generate);
qsc_sphincsplus_sign(sig, &mut siglen, hash, QRCS_CRYPTO_HASH_SIZE, privatekey, qsc_rcrng_generate);
qsc_sphincsplus_verify(hash, &mut hashlen, sig, siglen, publickey);
```
*/

use crate::qsc::{
	common::common::{
		QSC_SPHINCSPLUS_S3S192SHAKERS,
		QSC_SPHINCSPLUS_S3S192SHAKERF,
		QSC_SPHINCSPLUS_S5S256SHAKERS,
		QSC_SPHINCSPLUS_S5S256SHAKERF,
	},
	asymmetric::signature::sphincsplus::sphincsplusbase::{
		sphincsplus_ref_generate_keypair,
		sphincsplus_ref_sign,
		sphincsplus_ref_sign_open,
	},
};

/*
* \def QSC_SPHINCSPLUS_SIGNATURE_SIZE
* \brief The byte size of the signature array
*/
pub const QSC_SPHINCSPLUS_SIGNATURE_SIZE: usize = if QSC_SPHINCSPLUS_S3S192SHAKERS {
    16224
} else if QSC_SPHINCSPLUS_S3S192SHAKERF {
    35664
} else if QSC_SPHINCSPLUS_S5S256SHAKERS {
    29792
} else if QSC_SPHINCSPLUS_S5S256SHAKERF {
    49856
} else {
    0
};

/*
* \def QSC_SPHINCSPLUS_PRIVATEKEY_SIZE
* \brief The byte size of the secret private-key array
*/
pub const QSC_SPHINCSPLUS_PRIVATEKEY_SIZE: usize = if QSC_SPHINCSPLUS_S3S192SHAKERS {
    96
} else if QSC_SPHINCSPLUS_S3S192SHAKERF {
    96
} else if QSC_SPHINCSPLUS_S5S256SHAKERS {
    128
} else if QSC_SPHINCSPLUS_S5S256SHAKERF {
    128
} else {
    0
};

/*
* \def QSC_SPHINCSPLUS_PUBLICKEY_SIZE
* \brief The byte size of the public-key array
*/
pub const QSC_SPHINCSPLUS_PUBLICKEY_SIZE: usize = if QSC_SPHINCSPLUS_S3S192SHAKERS {
    48
} else if QSC_SPHINCSPLUS_S3S192SHAKERF {
    48
} else if QSC_SPHINCSPLUS_S5S256SHAKERS {
    64
} else if QSC_SPHINCSPLUS_S5S256SHAKERF {
    64
} else {
    0
};
pub const QRCS_CRYPTO_HASH_SIZE: usize = 64;

/**
* \brief Generates a Sphincs+ public/private key-pair.
*
* \warning Arrays must be sized to QSC_SPHINCSPLUS_PUBLICKEY_SIZE and QSC_SPHINCSPLUS_SECRETKEY_SIZE.
*
* \param publickey: Pointer to the public verification-key array
* \param privatekey: Pointer to the private signature-key array
* \param rng_generate: Pointer to the random generator
*/
pub fn qsc_sphincsplus_generate_keypair(publickey: &mut [u8], privatekey: &mut [u8], rng_generate: fn(&mut [u8], usize) -> bool) {
	if publickey.len() == QSC_SPHINCSPLUS_PUBLICKEY_SIZE && privatekey.len() == QSC_SPHINCSPLUS_PRIVATEKEY_SIZE {
		sphincsplus_ref_generate_keypair(publickey, privatekey, rng_generate);
	}
}

/**
* \brief Takes the message as input and returns an array containing the signature followed by the message.
*
* \warning Signature array must be sized to the size of the message plus QSC_SPHINCSPLUS_SIGNATURE_SIZE.
*
* \param signedmsg: Pointer to the signed-message array
* \param smsglen: [const] Pointer to the signed message length
* \param message: Pointer to the message array
* \param msglen: The message length
* \param privatekey: [const] Pointer to the private signature-key array
* \param rng_generate: Pointer to the random generator
*/
pub fn qsc_sphincsplus_sign(signedmsg: &mut [u8], smsglen: &mut usize, message: &[u8], msglen: usize, privatekey: &[u8], rng_generate: fn(&mut [u8], usize) -> bool) {

	if signedmsg.len() == QSC_SPHINCSPLUS_SIGNATURE_SIZE + QRCS_CRYPTO_HASH_SIZE && smsglen == &mut 0 && message.len() == QRCS_CRYPTO_HASH_SIZE && privatekey.len() == QSC_SPHINCSPLUS_PRIVATEKEY_SIZE {
		sphincsplus_ref_sign(signedmsg, smsglen, message, msglen, privatekey, rng_generate);
	}
}

/**
* \brief Verifies a signature-message pair with the public key.
*
* \param message: Pointer to the message array to be signed
* \param msglen: Pointer to the message length
* \param signedmsg: [const] Pointer to the signed message array
* \param smsglen: The signed message length
* \param publickey: [const] Pointer to the public verification-key array
* \return Returns true for success
*/
pub fn qsc_sphincsplus_verify(message: &mut [u8], msglen: &mut usize, signedmsg: &[u8], smsglen: usize, publickey: &[u8]) -> bool {
	let mut res = false;

	if message.len() == QRCS_CRYPTO_HASH_SIZE && msglen == &mut 0 && signedmsg.len() == QSC_SPHINCSPLUS_SIGNATURE_SIZE + QRCS_CRYPTO_HASH_SIZE && publickey.len() == QSC_SPHINCSPLUS_PUBLICKEY_SIZE {
		res = sphincsplus_ref_sign_open(message, msglen, signedmsg, smsglen, publickey);
	}

	return res;
}