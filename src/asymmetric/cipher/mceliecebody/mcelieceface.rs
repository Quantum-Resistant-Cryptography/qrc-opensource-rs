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
        asymmetric::{AsymmetricRandState, qrc_asymmetric_secrand_generate},
        cipher::mceliecebody::mceliecebase::{
            qrc_mceliece_ref_decapsulate, qrc_mceliece_ref_encapsulate,
            qrc_mceliece_ref_generate_keypair,
        },
    },
    common::common::{
        QRC_MCELIECE_S3N4608T96, QRC_MCELIECE_S5N6688T128, QRC_MCELIECE_S5N6960T119,
        QRC_MCELIECE_S5N8192T128,
    },
    prng::secrand::{qrc_secrand_destroy, qrc_secrand_initialize},
};

#[cfg(feature = "no_std")]
use alloc::vec::Vec;

/*
* \def QRC_MCELIECE_SEED_SIZE
* \brief The byte size of the seed array
*/
pub const QRC_MCELIECE_CIPHERTEXT_SIZE: usize = if QRC_MCELIECE_S3N4608T96 {
    188
} else if QRC_MCELIECE_S5N6688T128 {
    240
} else if QRC_MCELIECE_S5N6960T119 {
    226
} else if QRC_MCELIECE_S5N8192T128 {
    240
} else {
    0
};

/*
* \def QRC_MCELIECE_PRIVATEKEY_SIZE
* \brief The byte size of the secret private-key array
*/
pub const QRC_MCELIECE_PRIVATEKEY_SIZE: usize = if QRC_MCELIECE_S3N4608T96 {
    13608
} else if QRC_MCELIECE_S5N6688T128 {
    13932
} else if QRC_MCELIECE_S5N6960T119 {
    13948
} else if QRC_MCELIECE_S5N8192T128 {
    14120
} else {
    0
};

/*
* \def QRC_MCELIECE_PUBLICKEY_SIZE
* \brief The byte size of the public-key array
*/
pub const QRC_MCELIECE_PUBLICKEY_SIZE: usize = if QRC_MCELIECE_S3N4608T96 {
    524160
} else if QRC_MCELIECE_S5N6688T128 {
    1044992
} else if QRC_MCELIECE_S5N6960T119 {
    1047319
} else if QRC_MCELIECE_S5N8192T128 {
    1357824
} else {
    0
};

/*
* \def QRC_MCELIECE_SEED_SIZE
* \brief The byte size of the seed array
*/
pub const QRC_MCELIECE_SEED_SIZE: usize = 32;

/*
* \def QRC_MCELIECE_SHAREDSECRET_SIZE
* \brief The byte size of the shared secret-key array
*/
pub const QRC_MCELIECE_SHAREDSECRET_SIZE: usize = 32;

/*
* \def QRC_MCELIECE_ALGNAME
* \brief The formal algorithm name
*/
pub const QRC_MCELIECE_ALGNAME: &str = "MCELIECE";

/*
* \brief Decapsulates the shared secret for a given cipher-text using a private-key
*
* \param secret: Pointer to a shared secret key, an array of QRC_MCELIECE_SHAREDSECRET_SIZE constant size
* \param ciphertext: [const] Pointer to the cipher-text array of QRC_MCELIECE_CIPHERTEXT_SIZE constant size
* \param privatekey: [const] Pointer to the private-key array of QRC_MCELIECE_PRIVATEKEY_SIZE constant size
* \return Returns true for success
*/
pub fn qrc_mceliece_decapsulate(
    secret: &mut [u8; QRC_MCELIECE_SHAREDSECRET_SIZE],
    ciphertext: &[u8; QRC_MCELIECE_CIPHERTEXT_SIZE],
    privatekey: &[u8],
) -> bool {
    if privatekey.len() == QRC_MCELIECE_PRIVATEKEY_SIZE {
        return qrc_mceliece_ref_decapsulate(secret, ciphertext, privatekey) == 0;
    } else {
        return false;
    }
    
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
pub fn qrc_mceliece_decrypt(
    secret: &mut [u8; QRC_MCELIECE_SHAREDSECRET_SIZE],
    ciphertext: &[u8; QRC_MCELIECE_CIPHERTEXT_SIZE],
    privatekey: &[u8],
) -> bool {
    return qrc_mceliece_decapsulate(secret, ciphertext, privatekey);
}

/*
* \brief Generates cipher-text and encapsulates a shared secret key using a public-key
*
* \param secret: Pointer to a shared secret, a uint8_t array of QRC_MCELIECE_SHAREDSECRET_SIZE constant size
* \param ciphertext: Pointer to the cipher-text array of QRC_MCELIECE_CIPHERTEXT_SIZE constant size
* \param publickey: [const] Pointer to the public-key array of QRC_MCELIECE_PUBLICKEY_SIZE constant size
* \param rng_generate: Pointer to a random generator function
*/
pub fn qrc_mceliece_encapsulate(
    asymmetric_state: &mut AsymmetricRandState,
    secret: &mut [u8; QRC_MCELIECE_SHAREDSECRET_SIZE],
    ciphertext: &mut [u8; QRC_MCELIECE_CIPHERTEXT_SIZE],
    publickey: &[u8],
    rng_generate: fn(&mut AsymmetricRandState, &mut [u8], usize) -> bool,
) {
    if publickey.len() == QRC_MCELIECE_PUBLICKEY_SIZE {
        qrc_mceliece_ref_encapsulate(
            asymmetric_state,
            ciphertext,
            secret,
            publickey,
            rng_generate,
        );
    }
}

/*
* \brief Generates cipher-text and encapsulates a shared secret key using a public-key
* Used in conjunction with the encrypt function.
*
* \warning Cipher-text array must be sized to the QRC_KYBER_CIPHERTEXT_SIZE.
*
* \param secret: Pointer to the shared secret key, a uint8_t array of QRC_KYBER_SHAREDSECRET_SIZE constant size
* \param ciphertext: Pointer to the cipher-text array of QRC_KYBER_CIPHERTEXT_SIZE constant size
* \param publickey: [const] Pointer to the public-key array of QRC_KYBER_PUBLICKEY_SIZE constant size
* \param seed: [const] A pointer to the random seed array
*/
pub fn qrc_mceliece_encrypt(
    secret: &mut [u8; QRC_MCELIECE_SHAREDSECRET_SIZE],
    ciphertext: &mut [u8; QRC_MCELIECE_CIPHERTEXT_SIZE],
    publickey: &[u8],
    seed: [u8; QRC_MCELIECE_SEED_SIZE],
) {
    if publickey.len() == QRC_MCELIECE_PUBLICKEY_SIZE {
        let asymmetric_state = &mut AsymmetricRandState::default();
        qrc_secrand_initialize(
            &mut asymmetric_state.secrand_state,
            &seed,
            QRC_MCELIECE_SEED_SIZE,
            &[],
            0,
        );
        qrc_mceliece_encapsulate(
            asymmetric_state,
            secret,
            ciphertext,
            publickey,
            qrc_asymmetric_secrand_generate,
        );
        qrc_secrand_destroy(&mut asymmetric_state.secrand_state);
    }
}

/*
* \brief Generates public and private key for the McEliece key encapsulation mechanism
*
* \param publickey: Pointer to the output public-key array of QRC_MCELIECE_PUBLICKEY_SIZE constant size
* \param privatekey: Pointer to output private-key array of QRC_MCELIECE_PRIVATEKEY_SIZE constant size
* \param rng_generate: Pointer to the random generator function
*/
pub fn qrc_mceliece_generate_keypair(
    publickey: &mut [u8],
    privatekey: &mut Vec<u8>,
    seed: [u8; QRC_MCELIECE_SEED_SIZE],
) {
    if privatekey.len() == QRC_MCELIECE_PRIVATEKEY_SIZE
        && publickey.len() == QRC_MCELIECE_PUBLICKEY_SIZE
    {
        let asymmetric_state = &mut AsymmetricRandState::default();
        qrc_secrand_initialize(
            &mut asymmetric_state.secrand_state,
            &seed,
            QRC_MCELIECE_SEED_SIZE,
            &[],
            0,
        );
        qrc_mceliece_gen_keypair(
            asymmetric_state,
            publickey,
            privatekey,
            qrc_asymmetric_secrand_generate,
        );
        qrc_secrand_destroy(&mut asymmetric_state.secrand_state);
    }
}

pub fn qrc_mceliece_gen_keypair(
    asymmetric_state: &mut AsymmetricRandState,
    publickey: &mut [u8],
    privatekey: &mut [u8],
    rng_generate: fn(&mut AsymmetricRandState, &mut [u8], usize) -> bool,
) {
    if privatekey.len() == QRC_MCELIECE_PRIVATEKEY_SIZE
        && publickey.len() == QRC_MCELIECE_PUBLICKEY_SIZE
    {
        qrc_mceliece_ref_gen_keypair(asymmetric_state, publickey, privatekey, rng_generate);
    }
}

fn qrc_mceliece_ref_gen_keypair(
    asymmetric_state: &mut AsymmetricRandState,
    publickey: &mut [u8],
    privatekey: &mut [u8],
    rng_generate: fn(&mut AsymmetricRandState, &mut [u8], usize) -> bool,
) {
    if privatekey.len() == QRC_MCELIECE_PRIVATEKEY_SIZE
        && publickey.len() == QRC_MCELIECE_PUBLICKEY_SIZE
    {
        qrc_mceliece_ref_generate_keypair(asymmetric_state, publickey, privatekey, rng_generate);
    }
}
