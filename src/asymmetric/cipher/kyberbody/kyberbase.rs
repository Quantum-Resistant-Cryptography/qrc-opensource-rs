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
    asymmetric::asymmetric::AsymmetricRandState,
    common::common::{QRC_KYBER_S3Q3329N256K3, QRC_KYBER_S5Q3329N256K4, QRC_KYBER_S6Q3329N256K5},
    digest::sha3::{
        QRC_KECCAK_128_RATE, QrcKeccakState, qrc_keccak_dispose, qrc_sha3_compute256,
        qrc_sha3_compute512, qrc_shake_initialize, qrc_shake_squeezeblocks, qrc_shake256_compute,
    },
    tools::intutils::{
        qrc_intutils_cmov, qrc_intutils_copy8, qrc_intutils_le8to32, qrc_intutils_verify,
    },
};
use core::default::Default;

#[cfg(feature = "no_std")]
use alloc::borrow::ToOwned;

/* \cond DOXYGEN_IGNORE */

/*
\def QRC_KYBER_K
* Read Only: The k level
*/
pub const QRC_KYBER_K: usize = if QRC_KYBER_S3Q3329N256K3 {
    3
} else if QRC_KYBER_S5Q3329N256K4 {
    4
} else if QRC_KYBER_S6Q3329N256K5 {
    5
} else {
    0
};

/*
\def QRC_KYBER_N
* Read Only: The polynomial dimension N
*/
pub const QRC_KYBER_N: usize = 256;

/*
\def QRC_KYBER_Q
* Read Only: The modulus prime factor Q
*/
pub const QRC_KYBER_Q: usize = 3329;

/*
\def QRC_KYBER_ETA
* Read Only: The binomial distribution factor
*/
pub const QRC_KYBER_ETA: usize = 2;

/*
\def QRC_KYBER_MSGBYTES
* Read Only: The size in bytes of the shared secret
*/
pub const QRC_KYBER_MSGBYTES: usize = 32;

/*
\def QRC_KYBER_SYMBYTES
* Read Only: The size in bytes of hashes, and seeds
*/
pub const QRC_KYBER_SYMBYTES: usize = 32;

/*
\def QRC_KYBER_POLYBYTES
* Read Only: The secret key base multiplier
*/
pub const QRC_KYBER_POLYBYTES: usize = 384;

/*
\def QRC_KYBER_POLYVEC_BYTES
* Read Only: The base size of the compressed public key polynolial
*/
pub const QRC_KYBER_POLYVECBASE_BYTES: usize = if QRC_KYBER_K == 3 {
    320
} else if QRC_KYBER_K == 4 || QRC_KYBER_K == 5 {
    352
} else {
    0
};

/*
\def QRC_KYBER_POLYCOMPRESSED_BYTES
* Read Only: The cipher-text compressed byte size
*/
pub const QRC_KYBER_POLYCOMPRESSED_BYTES: usize = if QRC_KYBER_K == 3 {
    128
} else if QRC_KYBER_K == 4 || QRC_KYBER_K == 5 {
    160
} else {
    0
};

/*
\def QRC_KYBER_POLYVEC_COMPRESSED_BYTES
* Read Only: The base size of the public key
*/
pub const QRC_KYBER_POLYVEC_COMPRESSED_BYTES: usize = QRC_KYBER_K * QRC_KYBER_POLYVECBASE_BYTES;

/*
\def QRC_KYBER_POLYVEC_BYTES
* Read Only: The base size of the secret key
*/
pub const QRC_KYBER_POLYVEC_BYTES: usize = QRC_KYBER_K * QRC_KYBER_POLYBYTES;

/*
\def QRC_KYBER_INDCPA_PUBLICKEY_BYTES
* Read Only: The base INDCPA formatted public key size in bytes
*/
pub const QRC_KYBER_INDCPA_PUBLICKEY_BYTES: usize = QRC_KYBER_POLYVEC_BYTES + QRC_KYBER_SYMBYTES;

/*
\def QRC_KYBER_INDCPA_SECRETKEY_BYTES
* Read Only: The base INDCPA formatted private key size in bytes
*/
pub const QRC_KYBER_INDCPA_SECRETKEY_BYTES: usize = QRC_KYBER_POLYVEC_BYTES;

/*
\def QRC_KYBER_INDCPA_BYTES
* Read Only: The size of the INDCPA formatted output cipher-text
*/
pub const QRC_KYBER_INDCPA_BYTES: usize =
    QRC_KYBER_POLYVEC_COMPRESSED_BYTES + QRC_KYBER_POLYCOMPRESSED_BYTES;

/*
\def QRC_KYBER_PUBLICKEY_BYTES
* Read Only: The byte size of the public-key array
*/
pub const QRC_KYBER_PUBLICKEY_BYTES: usize = QRC_KYBER_INDCPA_PUBLICKEY_BYTES;

/*
\def QRC_KYBER_SECRETKEY_BYTES
* Read Only: The byte size of the secret private-key array
*/
pub const QRC_KYBER_SECRETKEY_BYTES: usize =
    QRC_KYBER_INDCPA_SECRETKEY_BYTES + QRC_KYBER_INDCPA_PUBLICKEY_BYTES + (2 * QRC_KYBER_SYMBYTES);

/*
\def QRC_KYBER_CIPHERTEXT_BYTES
* Read Only: The byte size of the cipher-text array
*/
pub const QRC_KYBER_CIPHERTEXT_BYTES: usize = QRC_KYBER_INDCPA_BYTES;

/* kem.h */

/*
 * \brief Generates shared secret for given cipher text and private key
 *
 * \param ss: Pointer to output shared secret (an already allocated array of KYBER_SECRET_BYTES bytes)
 * \param ct: [const] Pointer to input cipher text (an already allocated array of KYBER_CIPHERTEXT_SIZE bytes)
 * \param sk: [const] Pointer to input private key (an already allocated array of KYBER_SECRETKEY_SIZE bytes)
 * \return Returns true for success
 */
pub fn qrc_kyber_ref_decapsulate(ss: &mut [u8], ct: &[u8], sk: &[u8]) -> bool {
    let buf = &mut [0u8; 2 * QRC_KYBER_SYMBYTES];
    let cmp = &mut [0u8; QRC_KYBER_CIPHERTEXT_BYTES];
    let kr = &mut [0u8; 2 * QRC_KYBER_SYMBYTES];

    let pk = &sk[QRC_KYBER_INDCPA_SECRETKEY_BYTES..];

    kyber_indcpa_dec(buf, ct, &sk);

    /* Multitarget countermeasure for coins + contributory KEM */
    qrc_intutils_copy8(
        &mut buf[QRC_KYBER_SYMBYTES..],
        &sk[(QRC_KYBER_SECRETKEY_BYTES - (2 * QRC_KYBER_SYMBYTES))..],
        QRC_KYBER_SYMBYTES,
    );
    qrc_sha3_compute512(kr, buf, 2 * QRC_KYBER_SYMBYTES);

    /* coins are in kr+QRC_KYBER_SYMBYTES */
    kyber_indcpa_enc(cmp, buf, pk, &kr[QRC_KYBER_SYMBYTES..]);

    let fail = qrc_intutils_verify(&ct, cmp, QRC_KYBER_CIPHERTEXT_BYTES);

    /* overwrite coins in kr with H(c) */
    qrc_sha3_compute256(
        &mut kr[QRC_KYBER_SYMBYTES..],
        &ct,
        QRC_KYBER_CIPHERTEXT_BYTES,
    );

    /* Overwrite pre-k with z on re-encryption failure */
    qrc_intutils_cmov(
        kr,
        &sk[(QRC_KYBER_SECRETKEY_BYTES - QRC_KYBER_SYMBYTES)..],
        QRC_KYBER_SYMBYTES,
        fail as u8,
    );

    /* hash concatenation of pre-k and H(c) to k */
    qrc_shake256_compute(ss, QRC_KYBER_MSGBYTES, kr, 2 * QRC_KYBER_SYMBYTES);

    return fail == 0;
}

/*
 * \brief Generates cipher text and shared secret for given public key
 *
 * \param ct: Pointer to output cipher text (an already allocated array of KYBER_CIPHERTEXT_SIZE bytes)
 * \param ss: Pointer to output shared secret (an already allocated array of KYBER_BYTES bytes)
 * \param pk: [const] Pointer to input public key (an already allocated array of KYBER_PUBLICKEY_SIZE bytes)
 * \param rng_generate: Pointer to the random generator function
 */
pub fn qrc_kyber_ref_encapsulate(
    asymmetric_state: &mut AsymmetricRandState,
    ct: &mut [u8],
    ss: &mut [u8],
    pk: &[u8],
    rng_generate: fn(&mut AsymmetricRandState, &mut [u8], usize) -> bool,
) {
    let buf = &mut [0u8; 2 * QRC_KYBER_SYMBYTES];
    let kr = &mut [0u8; 2 * QRC_KYBER_SYMBYTES];

    rng_generate(asymmetric_state, buf, QRC_KYBER_SYMBYTES);
    /* Don't release system RNG output */
    let buf2 = buf.clone();
    qrc_sha3_compute256(buf, &buf2, QRC_KYBER_SYMBYTES);

    /* Multitarget countermeasure for coins + contributory KEM */
    qrc_sha3_compute256(
        &mut buf[QRC_KYBER_SYMBYTES..],
        &pk,
        QRC_KYBER_PUBLICKEY_BYTES,
    );
    qrc_sha3_compute512(kr, buf, 2 * QRC_KYBER_SYMBYTES);

    /* coins are in kr+QRC_KYBER_SYMBYTES */
    kyber_indcpa_enc(ct, buf, &pk, &kr[QRC_KYBER_SYMBYTES..]);

    /* overwrite coins in kr with H(c) */
    qrc_sha3_compute256(
        &mut kr[QRC_KYBER_SYMBYTES..],
        ct,
        QRC_KYBER_CIPHERTEXT_BYTES,
    );
    /* hash concatenation of pre-k and H(c) to k */
    qrc_shake256_compute(ss, QRC_KYBER_MSGBYTES, kr, 2 * QRC_KYBER_SYMBYTES);
}

/*
 * \brief Generates public and private key for the CCA-Secure Kyber key encapsulation mechanism
 *
 * \param pk: Pointer to output public key (an already allocated array of KYBER_PUBLICKEY_SIZE bytes)
 * \param sk: Pointer to output private key (an already allocated array of KYBER_SECRETKEY_SIZE bytes)
 * \param rng_generate: Pointer to the random generator function
 */
pub fn qrc_kyber_ref_generate_keypair(
    asymmetric_state: &mut AsymmetricRandState,
    pk: &mut [u8],
    sk: &mut [u8],
    rng_generate: fn(&mut AsymmetricRandState, &mut [u8], usize) -> bool,
) {
    kyber_indcpa_keypair(asymmetric_state, pk, sk, rng_generate);
    qrc_intutils_copy8(
        &mut sk[QRC_KYBER_INDCPA_SECRETKEY_BYTES..],
        pk,
        QRC_KYBER_INDCPA_PUBLICKEY_BYTES,
    );

    qrc_sha3_compute256(
        &mut sk[(QRC_KYBER_SECRETKEY_BYTES - 2 * QRC_KYBER_SYMBYTES)..],
        pk,
        QRC_KYBER_PUBLICKEY_BYTES,
    );
    /* Value z for pseudo-random output on reject */
    rng_generate(
        asymmetric_state,
        &mut sk[(QRC_KYBER_SECRETKEY_BYTES - QRC_KYBER_SYMBYTES)..],
        QRC_KYBER_SYMBYTES,
    );
}

/* \endcond DOXYGEN_IGNORE */

pub const KYBER_ZETA_SIZE: usize = 128;
//pub const KYBER_MONT: usize = 2285; /* 2^16 mod q */
pub const KYBER_QINV: usize = 62209; /* q^-1 mod 2^16 */
pub const KYBER_GEN_MATRIX_NBLOCKS: usize =
    (12 * QRC_KYBER_N / 8 * (1 << 12) / QRC_KYBER_Q + QRC_KECCAK_128_RATE) / QRC_KECCAK_128_RATE;

const KYBER_ZETAS: [u16; KYBER_ZETA_SIZE] = [
    0xFBEC, 0xFD0A, 0xFE99, 0xFA13, 0x05D5, 0x058E, 0x011F, 0x00CA, 0xFF55, 0x026E, 0x0629, 0x00B6,
    0x03C2, 0xFB4E, 0xFA3E, 0x05BC, 0x023D, 0xFAD3, 0x0108, 0x017F, 0xFCC3, 0x05B2, 0xF9BE, 0xFF7E,
    0xFD57, 0x03F9, 0x02DC, 0x0260, 0xF9FA, 0x019B, 0xFF33, 0xF9DD, 0x04C7, 0x028C, 0xFDD8, 0x03F7,
    0xFAF3, 0x05D3, 0xFEE6, 0xF9F8, 0x0204, 0xFFF8, 0xFEC0, 0xFD66, 0xF9AE, 0xFB76, 0x007E, 0x05BD,
    0xFCAB, 0xFFA6, 0xFEF1, 0x033E, 0x006B, 0xFA73, 0xFF09, 0xFC49, 0xFE72, 0x03C1, 0xFA1C, 0xFD2B,
    0x01C0, 0xFBD7, 0x02A5, 0xFB05, 0xFBB1, 0x01AE, 0x022B, 0x034B, 0xFB1D, 0x0367, 0x060E, 0x0069,
    0x01A6, 0x024B, 0x00B1, 0xFF15, 0xFEDD, 0xFE34, 0x0626, 0x0675, 0xFF0A, 0x030A, 0x0487, 0xFF6D,
    0xFCF7, 0x05CB, 0xFDA6, 0x045F, 0xF9CA, 0x0284, 0xFC98, 0x015D, 0x01A2, 0x0149, 0xFF64, 0xFFB5,
    0x0331, 0x0449, 0x025B, 0x0262, 0x052A, 0xFAFB, 0xFA47, 0x0180, 0xFB41, 0xFF78, 0x04C2, 0xFAC9,
    0xFC96, 0x00DC, 0xFB5D, 0xF985, 0xFB5F, 0xFA06, 0xFB02, 0x031A, 0xFA1A, 0xFCAA, 0xFC9A, 0x01DE,
    0xFF94, 0xFECC, 0x03E4, 0x03DF, 0x03BE, 0xFA4C, 0x05F2, 0x065C,
];

/* reduce.c */

fn kyber_montgomery_reduce(a: u32) -> u32 {
    let u = (a as i64).wrapping_mul((KYBER_QINV as u32) as i64) as i16;
    let t0 = (u as i32).wrapping_mul(QRC_KYBER_Q as i32);
    let mut t1 = (a as i32).wrapping_sub(t0) as u32;
    t1 >>= 16;

    return ((t1 as u64) as i16) as u32;
}

fn kyber_barrett_reduce(a: u32) -> u32 {
    let v = (((1 << 26) + QRC_KYBER_Q / 2) / QRC_KYBER_Q) as u32;
    let mut t = (((v.wrapping_mul(a).wrapping_add(1 << 25)) as i32) >> 26) as u32;
    t = t.wrapping_mul(QRC_KYBER_Q as u32);
    return a.wrapping_sub(t);
}

/* poly.h */

/*
* \struct qrc_kyber_poly
* \brief Contains an N sized array of 16bit coefficients. /n
* Elements of R_q = Z_q[X] / (X^n + 1). /n
* Represents polynomial coeffs[0] + X * coeffs[1] + X^2 * xoeffs[2] + ... + X^{n-1} * coeffs[n-1]
*
* \var qrc_kyber_poly::coeffs
* The array of 16bit coefficients
*/
#[derive(Clone, Copy)]
struct QrcKyberPoly {
    coeffs: [u32; QRC_KYBER_N],
}
impl Default for QrcKyberPoly {
    fn default() -> Self {
        Self {
            coeffs: [Default::default(); QRC_KYBER_N],
        }
    }
}

/*
* \struct qrc_kyber_polyvec
* \brief Contains a K sized vector of qrc_kyber_poly structures
*
* \var qrc_kyber_polyvec::vec
* The polynomial vector array
*/
#[derive(Clone, Copy)]
struct QrcKyberPolyvec {
    vec: [QrcKyberPoly; QRC_KYBER_K],
}
impl Default for QrcKyberPolyvec {
    fn default() -> Self {
        Self {
            vec: [QrcKyberPoly::default(); QRC_KYBER_K],
        }
    }
}

/* cbd.c */

fn kyber_cbd2(r: &mut QrcKyberPoly, buf: [u8; 2 * QRC_KYBER_N / 4]) {
    for i in 0..(QRC_KYBER_N / 8) {
        let t = qrc_intutils_le8to32(&buf[(4 * i)..]);
        let mut d = t & 0x55555555;
        d += (t >> 1) & 0x55555555;

        for j in 0..8 {
            let a = ((d >> (4 * j)) & 0x03) as u32;
            let b = ((d >> ((4 * j) + 2)) & 0x03) as u32;
            r.coeffs[(8 * i) + j] = a.wrapping_sub(b);
        }
    }
}

/* kyber_ntt.c */

fn kyber_fqmul(a: u32, b: u32) -> u32 {
    return kyber_montgomery_reduce(a.wrapping_mul(b)) as u32;
}

fn kyber_ntt(r: &mut [u32; QRC_KYBER_N]) {
    let mut k = 1;

    let mut len = 128;
    loop {
        if len < 2 {
            break;
        }
        let mut start = 0;
        loop {
            if start >= QRC_KYBER_N {
                break;
            }
            let zeta = (KYBER_ZETAS[k] as i16) as u32;
            k += 1;

            for j in start..(start + len) {
                let t = kyber_fqmul(zeta, r[j + len]);
                r[j + len] = r[j].wrapping_sub(t);
                r[j] = r[j].wrapping_add(t);
            }
            start = (start + len) + len;
        }
        len >>= 1;
    }
}

fn kyber_invntt(r: &mut [u32; 256]) {
    let f = 1441 as i16;
    let mut k = 127;

    let mut len = 2;
    loop {
        if len > 128 {
            break;
        }
        let mut start = 0;
        loop {
            if start >= 256 {
                break;
            }
            let zeta = (KYBER_ZETAS[k] as i16) as u32;
            k -= 1;

            for j in start..(start + len) {
                let t = r[j];
                r[j] = kyber_barrett_reduce(t.wrapping_add(r[j + len]));
                r[j + len] = r[j + len].wrapping_sub(t);
                r[j + len] = kyber_fqmul(zeta, r[j + len]);
            }
            start = (start + len) + len
        }
        len <<= 1;
    }

    for j in 0..256 {
        r[j] = kyber_fqmul(r[j], f as u32);
    }
}

fn kyber_basemul(r: &mut [u32], a: &[u32], b: &[u32], zeta: u32) {
    r[0] = kyber_fqmul(a[1], b[1]);
    r[0] = kyber_fqmul(r[0], zeta);
    r[0] = r[0].wrapping_add(kyber_fqmul(a[0], b[0]));
    r[1] = kyber_fqmul(a[0], b[1]);
    r[1] = r[1].wrapping_add(kyber_fqmul(a[1], b[0]));
}

/* poly.c */

fn kyber_poly_cbd_eta1(r: &mut QrcKyberPoly, buf: [u8; QRC_KYBER_ETA * QRC_KYBER_N / 4]) {
    kyber_cbd2(r, buf);
}

fn kyber_poly_cbd_eta2(r: &mut QrcKyberPoly, buf: [u8; QRC_KYBER_ETA * QRC_KYBER_N / 4]) {
    kyber_cbd2(r, buf);
}

fn kyber_poly_compress(mut r: &mut [u8], a: QrcKyberPoly) {
    let t = &mut [0u8; 8];
    if QRC_KYBER_POLYCOMPRESSED_BYTES == 128 {
        for i in 0..(QRC_KYBER_N / 8) {
            for j in 0..8 {
                /* map to positive standard representatives */
                let mut u = a.coeffs[(8 * i) + j];
                u += (u >> 15) & QRC_KYBER_Q as u32;
                t[j] = ((((u << 4) as u16 + QRC_KYBER_Q as u16 / 2) / QRC_KYBER_Q as u16) & 0x000F)
                    as u8;
            }

            r[0] = (t[0] | (t[1] << 4)) as u8;
            r[1] = (t[2] | (t[3] << 4)) as u8;
            r[2] = (t[4] | (t[5] << 4)) as u8;
            r[3] = (t[6] | (t[7] << 4)) as u8;
            r = &mut r[4..];
        }
    } else if QRC_KYBER_POLYCOMPRESSED_BYTES == 160 {
        for i in 0..(QRC_KYBER_N / 8) {
            for j in 0..8 {
                /* map to positive standard representatives */
                let mut u = a.coeffs[(8 * i) + j];
                u = u.wrapping_add((u >> 15) & QRC_KYBER_Q as u32);
                t[j] =
                    ((((u << 5) as u32 + QRC_KYBER_Q as u32 / 2) / QRC_KYBER_Q as u32) & 31) as u8;
            }

            r[0] = (t[0] | (t[1] << 5)) as u8;
            r[1] = ((t[1] >> 3) | (t[2] << 2) | (t[3] << 7)) as u8;
            r[2] = (t[3] >> 1) | (t[4] << 4);
            r[3] = ((t[4] >> 4) | (t[5] << 1) | (t[6] << 6)) as u8;
            r[4] = ((t[6] >> 2) | (t[7] << 3)) as u8;
            r = &mut r[5..];
        }
    }
}

fn kyber_poly_decompress(r: &mut QrcKyberPoly, mut a: &[u8]) {
    if QRC_KYBER_POLYCOMPRESSED_BYTES == 128 {
        for i in 0..(QRC_KYBER_N / 2) {
            r.coeffs[2 * i] = ((((a[0] & 15) as u16 * QRC_KYBER_Q as u16) + 8) >> 4) as u32;
            r.coeffs[(2 * i) + 1] = ((((a[0] >> 4) as u16 * QRC_KYBER_Q as u16) + 8) >> 4) as u32;
            a = &a[1..];
        }
    } else if QRC_KYBER_POLYCOMPRESSED_BYTES == 160 {
        let t = &mut [0u8; 8];

        for i in 0..(QRC_KYBER_N / 8) {
            t[0] = (a[0] >> 0) as u8;
            t[1] = ((a[0] >> 5) | (a[1] << 3)) as u8;
            t[2] = (a[1] >> 2) as u8;
            t[3] = ((a[1] >> 7) | (a[2] << 1)) as u8;
            t[4] = ((a[2] >> 4) | (a[3] << 4)) as u8;
            t[5] = (a[3] >> 1) as u8;
            t[6] = ((a[3] >> 6) | (a[4] << 2)) as u8;
            t[7] = (a[4] >> 3) as u8;
            a = &a[5..];

            for j in 0..8 {
                r.coeffs[(8 * i) + j] =
                    (((t[j] & 31) as u32 * QRC_KYBER_Q as u32 + 16) >> 5 as u16) as u32;
            }
        }
    }
}

fn kyber_poly_to_bytes(r: &mut [u8], a: QrcKyberPoly) {
    for i in 0..(QRC_KYBER_N / 2) {
        /* map to positive standard representatives */
        let mut t0 = a.coeffs[2 * i];
        t0 = t0.wrapping_add((t0 >> 15) & QRC_KYBER_Q as u32);
        let mut t1 = a.coeffs[(2 * i) + 1];
        t1 = t1.wrapping_add((t1 >> 15) & QRC_KYBER_Q as u32);
        r[3 * i] = (t0 >> 0) as u8;
        r[(3 * i) + 1] = ((t0 >> 8) | (t1 << 4)) as u8;
        r[(3 * i) + 2] = (t1 >> 4) as u8;
    }
}

fn kyber_poly_from_bytes(r: &mut QrcKyberPoly, a: &[u8]) {
    for i in 0..(QRC_KYBER_N / 2) {
        r.coeffs[2 * i] = ((a[3 * i] >> 0) as u16 | (((a[3 * i + 1] as u16) << 8) & 0x0FFF)) as u32;
        r.coeffs[(2 * i) + 1] =
            ((a[(3 * i) + 1] >> 4) as u16 | (((a[(3 * i) + 2] as u16) << 4) & 0x0FFF)) as u32;
    }
}

fn kyber_poly_from_msg(r: &mut QrcKyberPoly, msg: &[u8]) {
    for i in 0..(QRC_KYBER_N / 8) {
        for j in 0..8 {
            let mask = (!((msg[i] >> j) & 1) as i8).wrapping_add(1) as u32;
            r.coeffs[(8 * i) + j] = mask & ((QRC_KYBER_Q + 1) as u32 / 2);
        }
    }
}

fn kyber_poly_to_msg(msg: &mut [u8], a: QrcKyberPoly) {
    for i in 0..(QRC_KYBER_N / 8) {
        msg[i] = 0;

        for j in 0..8 {
            let mut t = a.coeffs[(8 * i) + j] as u16;
            t = t.wrapping_add((t >> 15) & QRC_KYBER_Q as u16);
            t = (((t << 1).wrapping_add(QRC_KYBER_Q as u16 / 2)) / QRC_KYBER_Q as u16) & 1;
            msg[i] |= (t << j) as u8;
        }
    }
}

fn kyber_poly_get_noise_eta1(r: &mut QrcKyberPoly, seed: &[u8], nonce: u8) {
    let buf = &mut [0u8; QRC_KYBER_ETA * QRC_KYBER_N / 4];
    let extkey = &mut [0u8; QRC_KYBER_SYMBYTES + 1];

    qrc_intutils_copy8(extkey, &seed, QRC_KYBER_SYMBYTES);
    extkey[QRC_KYBER_SYMBYTES] = nonce;

    qrc_shake256_compute(
        buf,
        QRC_KYBER_ETA * QRC_KYBER_N / 4,
        extkey,
        QRC_KYBER_SYMBYTES + 1,
    );
    kyber_poly_cbd_eta1(r, *buf);
}

fn kyber_poly_get_noise_eta2(r: &mut QrcKyberPoly, seed: &[u8], nonce: u8) {
    let buf = &mut [0u8; QRC_KYBER_ETA * QRC_KYBER_N / 4];
    let extkey = &mut [0u8; QRC_KYBER_SYMBYTES + 1];

    qrc_intutils_copy8(extkey, &seed, QRC_KYBER_SYMBYTES);
    extkey[QRC_KYBER_SYMBYTES] = nonce;
    qrc_shake256_compute(
        buf,
        QRC_KYBER_ETA * QRC_KYBER_N / 4,
        extkey,
        QRC_KYBER_SYMBYTES + 1,
    );

    kyber_poly_cbd_eta2(r, *buf);
}

fn kyber_poly_reduce(r: &mut QrcKyberPoly) {
    for i in 0..QRC_KYBER_N {
        r.coeffs[i] = kyber_barrett_reduce(r.coeffs[i]);
    }
}

fn kyber_poly_ntt(r: &mut QrcKyberPoly) {
    kyber_ntt(&mut r.coeffs);
    kyber_poly_reduce(r);
}

fn kyber_poly_invntt_to_mont(r: &mut QrcKyberPoly) {
    kyber_invntt(&mut r.coeffs);
}

fn kyber_poly_basemul_montgomery(r: &mut QrcKyberPoly, a: QrcKyberPoly, b: QrcKyberPoly) {
    for i in 0..(QRC_KYBER_N / 4) {
        kyber_basemul(
            &mut r.coeffs[(4 * i)..(4 * i) + 2],
            &a.coeffs[(4 * i)..(4 * i) + 2],
            &b.coeffs[(4 * i)..(4 * i) + 2],
            (KYBER_ZETAS[64 + i] as i16) as u32,
        );
        kyber_basemul(
            &mut r.coeffs[((4 * i) + 2)..((4 * i) + 2) + 2],
            &a.coeffs[((4 * i) + 2)..((4 * i) + 2) + 2],
            &b.coeffs[((4 * i) + 2)..((4 * i) + 2) + 2],
            ((!KYBER_ZETAS[64 + i] as u32).wrapping_add(1) as i16) as u32,
        );
    }
}

fn kyber_poly_to_mont(r: &mut QrcKyberPoly) {
    let f = ((1usize.wrapping_shl(32)) % QRC_KYBER_Q) as u32;

    for i in 0..QRC_KYBER_N {
        r.coeffs[i] = kyber_montgomery_reduce(r.coeffs[i].wrapping_mul(f)) as u32;
    }
}

fn kyber_poly_add(r: &mut QrcKyberPoly, a: QrcKyberPoly, b: QrcKyberPoly) {
    for i in 0..QRC_KYBER_N {
        r.coeffs[i] = a.coeffs[i].wrapping_add(b.coeffs[i]);
    }
}

fn kyber_poly_sub(r: &mut QrcKyberPoly, a: QrcKyberPoly, b: QrcKyberPoly) {
    for i in 0..QRC_KYBER_N {
        r.coeffs[i] = a.coeffs[i].wrapping_sub(b.coeffs[i]);
    }
}

/* polyvec.c */

fn kyber_polyvec_compress(mut r: &mut [u8], a: QrcKyberPolyvec) {
    if QRC_KYBER_K == 4 || QRC_KYBER_K == 5 {
        let t = &mut [0u16; 8];

        for i in 0..QRC_KYBER_K {
            for j in 0..(QRC_KYBER_N / 8) {
                for k in 0..8 {
                    t[k] = a.vec[i].coeffs[(8 * j) + k] as u16;
                    t[k] = t[k]
                        .wrapping_add((((t[k] as i16 >> 15) as u32) & QRC_KYBER_Q as u32) as u16);
                    t[k] = (((((t[k] as u32) << 11) + QRC_KYBER_Q as u32 / 2) / QRC_KYBER_Q as u32)
                        & 0x07FF) as u16;
                }

                r[0] = (t[0] >> 0) as u8;
                r[1] = ((t[0] >> 8) | (t[1] << 3)) as u8;
                r[2] = ((t[1] >> 5) | (t[2] << 6)) as u8;
                r[3] = (t[2] >> 2) as u8;
                r[4] = ((t[2] >> 10) | (t[3] << 1)) as u8;
                r[5] = ((t[3] >> 7) | (t[4] << 4)) as u8;
                r[6] = ((t[4] >> 4) | (t[5] << 7)) as u8;
                r[7] = (t[5] >> 1) as u8;
                r[8] = ((t[5] >> 9) | (t[6] << 2)) as u8;
                r[9] = ((t[6] >> 6) | (t[7] << 5)) as u8;
                r[10] = (t[7] >> 3) as u8;
                r = &mut r[11..];
            }
        }
    } else if QRC_KYBER_K == 3 {
        let t = &mut [0u16; 8];

        for i in 0..QRC_KYBER_K {
            for j in 0..(QRC_KYBER_N / 4) {
                for k in 0..4 {
                    t[k] = a.vec[i].coeffs[(4 * j) + k] as u16;
                    t[k] = t[k]
                        .wrapping_add((((t[k] as i16 >> 15) as u16) & QRC_KYBER_Q as u16) as u16);
                    t[k] = (((((t[k] as u32) << 10) + QRC_KYBER_Q as u32 / 2) / QRC_KYBER_Q as u32)
                        & 0x03FF) as u16;
                }

                r[0] = (t[0] >> 0) as u8;
                r[1] = ((t[0] >> 8) | (t[1] << 2)) as u8;
                r[2] = ((t[1] >> 6) | (t[2] << 4)) as u8;
                r[3] = ((t[2] >> 4) | (t[3] << 6)) as u8;
                r[4] = (t[3] >> 2) as u8;
                r = &mut r[5..];
            }
        }
    }
}

fn kyber_polyvec_decompress(r: &mut QrcKyberPolyvec, mut a: &[u8]) {
    if QRC_KYBER_K == 4 || QRC_KYBER_K == 5 {
        let t = &mut [0u16; 8];
        for i in 0..QRC_KYBER_K {
            for j in 0..(QRC_KYBER_N / 8) {
                t[0] = a[0] as u16 | (a[1] as u16) << 8;
                t[1] = (a[1] as u16) >> 3 | (a[2] as u16) << 5;
                t[2] = (a[2] as u16) >> 6 | (a[3] as u16) << 2 | (a[4] as u16) << 10;
                t[3] = (a[4] as u16) >> 1 | (a[5] as u16) << 7;
                t[4] = (a[5] as u16) >> 4 | (a[6] as u16) << 4;
                t[5] = (a[6] as u16) >> 7 | (a[7] as u16) << 1 | (a[8] as u16) << 9;
                t[6] = (a[8] as u16) >> 2 | (a[9] as u16) << 6;
                t[7] = (a[9] as u16) >> 5 | (a[10] as u16) << 3;
                a = &a[11..];

                for k in 0..8 {
                    r.vec[i].coeffs[(8 * j) + k] =
                        (((t[k] & 0x7FF) as u32 * QRC_KYBER_Q as u32 + 1024) >> 11) as u32;
                }
            }
        }
    } else if QRC_KYBER_K == 3 {
        let t = &mut [0u16; 4];
        for i in 0..QRC_KYBER_K {
            for j in 0..(QRC_KYBER_N / 4) {
                t[0] = a[0] as u16 | (a[1] as u16) << 8;
                t[1] = (a[1] as u16) >> 2 | (a[2] as u16) << 6;
                t[2] = (a[2] as u16) >> 4 | (a[3] as u16) << 4;
                t[3] = (a[3] as u16) >> 6 | (a[4] as u16) << 2;
                a = &a[5..];

                for k in 0..4 {
                    r.vec[i].coeffs[(4 * j) + k] =
                        (((t[k] & 0x3FF) as u32 * QRC_KYBER_Q as u32 + 512) >> 10) as u32;
                }
            }
        }
    }
}

fn kyber_polyvec_to_bytes(r: &mut [u8], a: QrcKyberPolyvec) {
    for i in 0..QRC_KYBER_K {
        kyber_poly_to_bytes(&mut r[(i * QRC_KYBER_POLYBYTES)..], a.vec[i]);
    }
}

fn kyber_polyvec_from_bytes(r: &mut QrcKyberPolyvec, a: &[u8]) {
    for i in 0..QRC_KYBER_K {
        kyber_poly_from_bytes(&mut r.vec[i], &a[(i * QRC_KYBER_POLYBYTES)..]);
    }
}

fn kyber_polyvec_ntt(r: &mut QrcKyberPolyvec) {
    for i in 0..QRC_KYBER_K {
        kyber_poly_ntt(&mut r.vec[i]);
    }
}

fn kyber_polyvec_invntt_to_mont(r: &mut QrcKyberPolyvec) {
    for i in 0..QRC_KYBER_K {
        kyber_poly_invntt_to_mont(&mut r.vec[i]);
    }
}

fn kyber_polyvec_basemul_acc_montgomery(
    r: &mut QrcKyberPoly,
    a: QrcKyberPolyvec,
    b: QrcKyberPolyvec,
) {
    let t = &mut QrcKyberPoly::default();

    kyber_poly_basemul_montgomery(r, a.vec[0], b.vec[0]);

    for i in 1..QRC_KYBER_K {
        kyber_poly_basemul_montgomery(t, a.vec[i], b.vec[i]);
        kyber_poly_add(r, r.to_owned(), t.to_owned());
    }

    kyber_poly_reduce(r);
}

fn kyber_polyvec_reduce(r: &mut QrcKyberPolyvec) {
    for i in 0..QRC_KYBER_K {
        kyber_poly_reduce(&mut r.vec[i]);
    }
}

fn kyber_polyvec_add(r: &mut QrcKyberPolyvec, a: QrcKyberPolyvec, b: QrcKyberPolyvec) {
    for i in 0..QRC_KYBER_K {
        kyber_poly_add(&mut r.vec[i], a.vec[i], b.vec[i]);
    }
}

/* indcpa.c */

fn kyber_pack_pk(r: &mut [u8], pk: QrcKyberPolyvec, seed: &[u8]) {
    kyber_polyvec_to_bytes(r, pk);
    qrc_intutils_copy8(&mut r[QRC_KYBER_POLYVEC_BYTES..], &seed, QRC_KYBER_SYMBYTES);
}

fn kyber_unpack_pk(pk: &mut QrcKyberPolyvec, seed: &mut [u8; QRC_KYBER_SYMBYTES], packedpk: &[u8]) {
    kyber_polyvec_from_bytes(pk, &packedpk);
    qrc_intutils_copy8(
        seed,
        &packedpk[QRC_KYBER_POLYVEC_BYTES..],
        QRC_KYBER_SYMBYTES,
    );
}

fn kyber_pack_sk(r: &mut [u8], sk: QrcKyberPolyvec) {
    kyber_polyvec_to_bytes(r, sk);
}

fn kyber_unpack_sk(sk: &mut QrcKyberPolyvec, packedsk: &[u8]) {
    kyber_polyvec_from_bytes(sk, &packedsk);
}

fn kyber_pack_ciphertext(r: &mut [u8], b: QrcKyberPolyvec, v: QrcKyberPoly) {
    kyber_polyvec_compress(r, b);
    kyber_poly_compress(&mut r[QRC_KYBER_POLYVEC_COMPRESSED_BYTES..], v);
}

fn kyber_unpack_ciphertext(b: &mut QrcKyberPolyvec, v: &mut QrcKyberPoly, c: &[u8]) {
    kyber_polyvec_decompress(b, &c);
    kyber_poly_decompress(v, &c[QRC_KYBER_POLYVEC_COMPRESSED_BYTES..]);
}

fn kyber_rej_uniform(r: &mut [u32], len: u32, buf: &[u8], buflen: u32) -> u32 {
    let mut ctr = 0;
    let mut pos = 0;

    loop {
        if ctr >= len || pos + 3 > buflen {
            break;
        }

        let val0 = (((buf[pos as usize] >> 0) as u16
            | ((buf[pos as usize + 1] as u16) << 8) as u16)
            & 0x0FFF) as u16;
        let val1 = (((buf[pos as usize + 1] >> 4) as u16
            | ((buf[pos as usize + 2] as u16) << 4) as u16)
            & 0x0FFF) as u16;
        pos += 3;

        if val0 < QRC_KYBER_Q as u16 {
            r[ctr as usize] = val0 as u32;
            ctr += 1;
        }

        if ctr < len && val1 < QRC_KYBER_Q as u16 {
            r[ctr as usize] = val1 as u32;
            ctr += 1;
        }
    }

    return ctr;
}

fn kyber_gen_matrix(a: &mut [QrcKyberPolyvec; QRC_KYBER_K], seed: &[u8], transposed: u32) {
    let state = &mut QrcKeccakState::default();
    let buf = &mut [0u8; KYBER_GEN_MATRIX_NBLOCKS * QRC_KECCAK_128_RATE + 2];
    let extseed = &mut [0u8; QRC_KYBER_SYMBYTES + 2];

    qrc_intutils_copy8(extseed, seed, QRC_KYBER_SYMBYTES);

    for i in 0..QRC_KYBER_K {
        for j in 0..QRC_KYBER_K {
            if transposed != 0 {
                extseed[QRC_KYBER_SYMBYTES] = i as u8;
                extseed[QRC_KYBER_SYMBYTES + 1] = j as u8;
            } else {
                extseed[QRC_KYBER_SYMBYTES] = j as u8;
                extseed[QRC_KYBER_SYMBYTES + 1] = i as u8;
            }

            qrc_shake_initialize(state, QRC_KECCAK_128_RATE, extseed, QRC_KYBER_SYMBYTES + 2);
            qrc_shake_squeezeblocks(state, QRC_KECCAK_128_RATE, buf, KYBER_GEN_MATRIX_NBLOCKS);

            let mut buflen = (KYBER_GEN_MATRIX_NBLOCKS * QRC_KECCAK_128_RATE) as u32;
            let mut ctr =
                kyber_rej_uniform(&mut a[i].vec[j].coeffs, QRC_KYBER_N as u32, buf, buflen);

            loop {
                if ctr >= QRC_KYBER_N as u32 {
                    break;
                }

                let off = buflen % 3;

                for k in 0..off {
                    buf[k as usize] = buf[(buflen - off + k) as usize];
                }

                qrc_shake_squeezeblocks(state, QRC_KECCAK_128_RATE, &mut buf[(off as usize)..], 1);
                buflen = off + QRC_KECCAK_128_RATE as u32;
                ctr += kyber_rej_uniform(
                    &mut a[i].vec[j].coeffs[(ctr as usize)..],
                    QRC_KYBER_N as u32 - ctr,
                    buf,
                    buflen,
                );
            }

            qrc_keccak_dispose(state);
        }
    }
}

fn kyber_indcpa_keypair(
    asymmetric_state: &mut AsymmetricRandState,
    pk: &mut [u8],
    sk: &mut [u8],
    rng_generate: fn(&mut AsymmetricRandState, &mut [u8], usize) -> bool,
) {
    let a = &mut [QrcKyberPolyvec::default(); QRC_KYBER_K];
    let e = &mut QrcKyberPolyvec::default();
    let pkpv = &mut QrcKyberPolyvec::default();
    let skpv = &mut QrcKyberPolyvec::default();
    let buf = &mut [0u8; 2 * QRC_KYBER_SYMBYTES];

    let mut nonce = 0;
    rng_generate(asymmetric_state, buf, QRC_KYBER_SYMBYTES);

    let buf2 = buf.clone();
    qrc_sha3_compute512(buf, &buf2, QRC_KYBER_SYMBYTES);

    let publicseed = buf.to_owned();
    kyber_gen_matrix(a, &publicseed, 0);

    let noiseseed = &buf.to_owned()[QRC_KYBER_SYMBYTES..];
    for i in 0..QRC_KYBER_K {
        kyber_poly_get_noise_eta1(&mut skpv.vec[i], noiseseed, nonce);
        nonce += 1;
    }

    for i in 0..QRC_KYBER_K {
        kyber_poly_get_noise_eta1(&mut e.vec[i], noiseseed, nonce);
        nonce += 1;
    }

    kyber_polyvec_ntt(skpv);
    kyber_polyvec_ntt(e);

    for i in 0..QRC_KYBER_K {
        kyber_polyvec_basemul_acc_montgomery(&mut pkpv.vec[i], a[i], skpv.to_owned());
        kyber_poly_to_mont(&mut pkpv.vec[i]);
    }

    kyber_polyvec_add(pkpv, pkpv.to_owned(), e.to_owned());
    kyber_polyvec_reduce(pkpv);

    kyber_pack_sk(sk, skpv.to_owned());
    kyber_pack_pk(pk, pkpv.to_owned(), &publicseed);
}

fn kyber_indcpa_enc(c: &mut [u8], m: &[u8], pk: &[u8], coins: &[u8]) {
    let sp = &mut QrcKyberPolyvec::default();
    let pkpv = &mut QrcKyberPolyvec::default();
    let ep = &mut QrcKyberPolyvec::default();
    let at = &mut [QrcKyberPolyvec::default(); QRC_KYBER_K];
    let b = &mut QrcKyberPolyvec::default();
    let v = &mut QrcKyberPoly::default();
    let k = &mut QrcKyberPoly::default();
    let epp = &mut QrcKyberPoly::default();
    let seed = &mut [0u8; QRC_KYBER_SYMBYTES];

    let mut nonce = 0;
    kyber_unpack_pk(pkpv, seed, pk);
    kyber_poly_from_msg(k, m);
    kyber_gen_matrix(at, &seed.to_owned(), 1);

    for i in 0..QRC_KYBER_K {
        kyber_poly_get_noise_eta1(&mut sp.vec[i], coins, nonce);
        nonce += 1;
    }

    for i in 0..QRC_KYBER_K {
        kyber_poly_get_noise_eta2(&mut ep.vec[i], coins, nonce);
        nonce += 1;
    }

    kyber_poly_get_noise_eta2(epp, coins, nonce);
    kyber_polyvec_ntt(sp);

    for i in 0..QRC_KYBER_K {
        kyber_polyvec_basemul_acc_montgomery(&mut b.vec[i], at[i], sp.to_owned());
    }

    kyber_polyvec_basemul_acc_montgomery(v, pkpv.to_owned(), sp.to_owned());
    kyber_polyvec_invntt_to_mont(b);
    kyber_poly_invntt_to_mont(v);
    kyber_polyvec_add(b, b.to_owned(), ep.to_owned());
    kyber_poly_add(v, v.to_owned(), epp.to_owned());
    kyber_poly_add(v, v.to_owned(), k.to_owned());
    kyber_polyvec_reduce(b);
    kyber_poly_reduce(v);

    kyber_pack_ciphertext(c, b.to_owned(), v.to_owned());
}

fn kyber_indcpa_dec(m: &mut [u8], c: &[u8], sk: &[u8]) {
    let b = &mut QrcKyberPolyvec::default();
    let skpv = &mut QrcKyberPolyvec::default();
    let v = &mut QrcKyberPoly::default();
    let mp = &mut QrcKyberPoly::default();

    kyber_unpack_ciphertext(b, v, c);
    kyber_unpack_sk(skpv, sk);
    kyber_polyvec_ntt(b);
    kyber_polyvec_basemul_acc_montgomery(mp, skpv.to_owned(), b.to_owned());
    kyber_poly_invntt_to_mont(mp);
    kyber_poly_sub(mp, v.to_owned(), mp.to_owned());
    kyber_poly_reduce(mp);
    kyber_poly_to_msg(m, mp.to_owned());
}
