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

use crate::{asymmetric::asymmetric::AsymmetricRandState, common::common::{QRC_DILITHIUM_S2N256Q8380417K4, QRC_DILITHIUM_S3N256Q8380417K6, QRC_DILITHIUM_S5N256Q8380417K8}, digest::sha3::{qrc_keccak_incremental_block_absorb, qrc_keccak_incremental_finalize, qrc_keccak_incremental_squeeze, qrc_keccak_initialize_state, qrc_keccak_squeezeblocks, qrc_shake256_compute, QrcKeccakState, QRC_KECCAK_128_RATE, QRC_KECCAK_256_RATE, QRC_KECCAK_PERMUTATION_ROUNDS, QRC_KECCAK_SHAKE_DOMAIN_ID}, tools::intutils::{qrc_intutils_clear8, qrc_intutils_copy32i, qrc_intutils_copy8, qrc_intutils_verify}};

#[cfg(feature = "no_std")]
use alloc::borrow::ToOwned;

/* \cond DOXYGEN_IGNORE */

pub const QRC_DILITHIUM_RANDOMIZED_SIGNING: bool = false;

/* #define QRC_DILITHIUM_RANDOMIZED_SIGNING */
pub const QRC_DILITHIUM_MODE: usize = if QRC_DILITHIUM_S2N256Q8380417K4 {
    2
} else if QRC_DILITHIUM_S3N256Q8380417K6 {
    3
} else if QRC_DILITHIUM_S5N256Q8380417K8 {
    5
} else {
    0
};

pub const QRC_DILITHIUM_N: usize = 256;

pub const QRC_DILITHIUM_K: usize = if QRC_DILITHIUM_S2N256Q8380417K4 {
    4
} else if QRC_DILITHIUM_S3N256Q8380417K6 {
    6
} else if QRC_DILITHIUM_S5N256Q8380417K8 {
    8
} else {
    0
};

pub const QRC_DILITHIUM_L: usize = if QRC_DILITHIUM_S2N256Q8380417K4 {
    4
} else if QRC_DILITHIUM_S3N256Q8380417K6 {
    5
} else if QRC_DILITHIUM_S5N256Q8380417K8 {
    7
} else {
    0
};

/*
* \struct qrc_dilithium_poly
* \brief Array of coefficients of length N
*/
#[derive(Clone, Copy, Debug)]
pub struct QrcDilithiumPoly {
    pub coeffs: [i32; QRC_DILITHIUM_N],            /*< The coefficients  */
}
impl Default for QrcDilithiumPoly {
    fn default() -> Self {
        Self {
            coeffs: [Default::default(); QRC_DILITHIUM_N],
        }
    }
}

/*
* \struct qrc_dilithium_polyvecl
* \brief Vectors of polynomials of length L
*/
#[derive(Clone, Copy, Debug)]
pub struct QrcDilithiumPolyvecl {
    pub vec: [QrcDilithiumPoly; QRC_DILITHIUM_L],    /*< The poly vector of L  */
}
impl Default for QrcDilithiumPolyvecl {
    fn default() -> Self {
        Self {
            vec: [QrcDilithiumPoly::default(); QRC_DILITHIUM_L],
        }
    }
}


/*
* \struct qrc_dilithium_polyveck
* \brief Vectors of polynomials of length K
*/
#[derive(Clone, Copy)]
pub struct QrcDilithiumPolyveck {
    pub vec: [QrcDilithiumPoly; QRC_DILITHIUM_K],    /*< The poly vector of K  */
}
impl Default for QrcDilithiumPolyveck {
    fn default() -> Self {
        Self {
            vec: [QrcDilithiumPoly::default(); QRC_DILITHIUM_K],
        }
    }
}

/*
* \brief Generates a Dilithium public/private key-pair.
* Arrays must be sized to DILITHIUM_PUBLICKEY_SIZE and DILITHIUM_SECRETKEY_SIZE.
*
* \param pk: The public verification key
* \param sk: The private signature key
* \param rng_generate: The random generator
*/
pub fn qrc_dilithium_ref_generate_keypair(asymmetric_state: &mut AsymmetricRandState, pk: &mut [u8], sk: &mut [u8], rng_generate: fn(&mut AsymmetricRandState, &mut [u8], usize) -> bool) {
    let mat = &mut [QrcDilithiumPolyvecl::default(); QRC_DILITHIUM_K];
    let s1 = &mut QrcDilithiumPolyvecl::default();
    let s2 = &mut QrcDilithiumPolyveck::default();
    let t1 = &mut QrcDilithiumPolyveck::default();
    let t0 = &mut QrcDilithiumPolyveck::default();
    let seed = &mut [0u8; 3 * DILITHIUM_SEEDBYTES];
    let seedbuf = &mut [0u8; 3 * DILITHIUM_SEEDBYTES];
    let tr = &mut [0u8; DILITHIUM_CRHBYTES];

    /* Get randomness for rho, rhoprime and key */
    rng_generate(asymmetric_state, seed, DILITHIUM_SEEDBYTES);
    qrc_shake256_compute(seedbuf, 3 * DILITHIUM_SEEDBYTES, seed, DILITHIUM_SEEDBYTES);
    let key = &seedbuf.clone()[2 * DILITHIUM_SEEDBYTES..];
    let (rho, rhoprime) = seedbuf.split_at_mut(DILITHIUM_SEEDBYTES);

    /* Expand matrix */
    dilithium_polyvec_matrix_expand(mat, rho);
    /* Sample short vectors s1 and s2 */
    dilithium_polyvecl_uniform_eta(s1, rhoprime, 0);
    dilithium_polyveck_uniform_eta(s2, rhoprime, QRC_DILITHIUM_L as u16);

    /* Matrix-vector multiplication */
    let s1hat = &mut s1.clone();
    dilithium_polyvecl_ntt(s1hat);
    dilithium_polyvec_matrix_pointwise_montgomery(t1, mat, s1hat.clone());
    dilithium_polyveck_reduce(t1);
    dilithium_polyveck_invntt_to_mont(t1);

    /* Add error vector s2 */
    dilithium_polyveck_add(t1, t1.clone(), s2.clone());

    /* Extract t1 and write public key */
    dilithium_polyveck_caddq(t1);
    dilithium_polyveck_power2_round(t1, t0, t1.clone());
    dilithium_pack_pk(pk, rho, t1.clone());


    /* Compute CRH(rho, t1) and write secret key */
    qrc_shake256_compute(tr, DILITHIUM_CRHBYTES, pk, DILITHIUM_PUBLICKEY_SIZE);

    dilithium_pack_sk(sk, rho, tr, key, t0.clone(), s1.clone(), s2.clone());
}

/*
* \brief Takes the message as input and returns an array containing the signature
*
* \param sig: The signed message
* \param siglen: The signed message length
* \param m: [const] The message to be signed
* \param mlen: The message length
* \param sk: [const] The private signature key
* \param rng_generate: The random generator
*/
pub fn qrc_dilithium_ref_sign_signature(asymmetric_state: &mut AsymmetricRandState, sig: &mut [u8], siglen: &mut usize, m: &[u8], mlen: usize, sk: &[u8], rng_generate: fn(&mut AsymmetricRandState, &mut [u8], usize) -> bool) {
    let mat = &mut [QrcDilithiumPolyvecl::default(); QRC_DILITHIUM_K];
    let s1 = &mut QrcDilithiumPolyvecl::default();
    let y = &mut QrcDilithiumPolyvecl::default();
    let z = &mut QrcDilithiumPolyvecl::default();
    let h = &mut QrcDilithiumPolyveck::default();
    let s2 = &mut QrcDilithiumPolyveck::default();
    let t0 = &mut QrcDilithiumPolyveck::default();
    let w1 = &mut QrcDilithiumPolyveck::default();
    let w0 = &mut QrcDilithiumPolyveck::default();
    let cp = &mut QrcDilithiumPoly::default();
    let kctx = &mut QrcKeccakState::default();
     
    let mut nonce = 0;

    let rho = &mut [0u8; DILITHIUM_SEEDBYTES];
    let tr = &mut [0u8; DILITHIUM_CRHBYTES];
    let key = &mut [0u8; DILITHIUM_SEEDBYTES + DILITHIUM_CRHBYTES];
    let mu = &mut [0u8; DILITHIUM_CRHBYTES];
    let rhoprime = &mut [0u8; DILITHIUM_CRHBYTES];


    dilithium_unpack_sk(rho, tr, key, t0, s1, s2, sk);


    /* Compute CRH(tr, msg) */
    qrc_keccak_initialize_state(kctx);
    qrc_keccak_incremental_block_absorb(kctx, QRC_KECCAK_256_RATE, tr, DILITHIUM_CRHBYTES);
    qrc_keccak_incremental_block_absorb(kctx, QRC_KECCAK_256_RATE, m, mlen);
    qrc_keccak_incremental_finalize(kctx, QRC_KECCAK_256_RATE, QRC_KECCAK_SHAKE_DOMAIN_ID);
    qrc_keccak_incremental_squeeze(kctx, QRC_KECCAK_256_RATE, mu, DILITHIUM_CRHBYTES);


    qrc_intutils_copy8(&mut key[DILITHIUM_SEEDBYTES..], mu, DILITHIUM_CRHBYTES);
    if QRC_DILITHIUM_RANDOMIZED_SIGNING {
        rng_generate(asymmetric_state, rhoprime, DILITHIUM_CRHBYTES);
    } else {
        qrc_shake256_compute(rhoprime, DILITHIUM_CRHBYTES, key, DILITHIUM_SEEDBYTES + DILITHIUM_CRHBYTES);
    }

    /* Expand matrix and transform vectors */
    dilithium_polyvec_matrix_expand(mat, rho);
    dilithium_polyvecl_ntt(s1);
    dilithium_polyveck_ntt(s2);

    
    dilithium_polyveck_ntt(t0);

    loop {
        /* Sample intermediate vector y */
        dilithium_polyvecl_uniform_gamma1(y, rhoprime, nonce);
        nonce += 1;
        for i in 0..QRC_DILITHIUM_L {
            qrc_intutils_copy32i(&mut z.vec[i].coeffs, &y.vec[i].coeffs, 256);
        }
        dilithium_polyvecl_ntt(z);

        /* Matrix-vector multiplication */
        dilithium_polyvec_matrix_pointwise_montgomery(w1, mat, z.clone());
        dilithium_polyveck_reduce(w1);
        dilithium_polyveck_invntt_to_mont(w1);

        /* Decompose w and call the random oracle */
        dilithium_polyveck_caddq(w1);
        dilithium_polyveck_decompose(w1, w0, w1.clone());
        dilithium_polyveck_pack_w1(sig, w1.clone());


        qrc_keccak_initialize_state(kctx);
        qrc_keccak_incremental_block_absorb(kctx, QRC_KECCAK_256_RATE, mu, DILITHIUM_CRHBYTES);
        qrc_keccak_incremental_block_absorb(kctx, QRC_KECCAK_256_RATE, sig, QRC_DILITHIUM_K * DILITHIUM_POLYW1_PACKEDBYTES);
        qrc_keccak_incremental_finalize(kctx, QRC_KECCAK_256_RATE, QRC_KECCAK_SHAKE_DOMAIN_ID);
        qrc_keccak_incremental_squeeze(kctx, QRC_KECCAK_256_RATE, sig, DILITHIUM_SEEDBYTES);


        dilithium_poly_challenge(cp, sig);
        dilithium_poly_ntt(cp);


        /* Compute z, reject if it reveals secret */
        dilithium_polyvecl_pointwise_poly_montgomery(z, cp.clone(), s1.clone());
        dilithium_polyvecl_invntt_to_mont(z);
        dilithium_polyvecl_add(z, z.clone(), y.clone());
        dilithium_polyvecl_reduce(z);

        
        
        //exit(0);
        
        
        if dilithium_polyvecl_chknorm(z.clone(), (DILITHIUM_GAMMA1 - DILITHIUM_BETA) as i32) != 0 {
            continue;
        }

        /* Check that subtracting cs2 does not change high bits of w and low bits
           do not reveal secret information */
        dilithium_polyveck_pointwise_poly_montgomery(h, cp.clone(), s2.clone());
        dilithium_polyveck_invntt_to_mont(h);
        let w01 = w0.clone();
        dilithium_polyveck_sub(w0, w01, h.clone());
        dilithium_polyveck_reduce(w0);

        if dilithium_polyveck_chknorm(w0.clone(), (DILITHIUM_GAMMA2 - DILITHIUM_BETA) as i32) != 0 {
            continue;
        }

        /* Compute hints for w1 */

        dilithium_polyveck_pointwise_poly_montgomery(h, cp.clone(), t0.clone());
        dilithium_polyveck_invntt_to_mont(h);
        dilithium_polyveck_reduce(h);

        if dilithium_polyveck_chknorm(h.clone(), DILITHIUM_GAMMA2 as i32) != 0 {
            continue;
        }

        dilithium_polyveck_add(w0, w0.clone(), h.clone());
        dilithium_polyveck_caddq(w0);
        let n = dilithium_polyveck_make_hint(h, w0.clone(), w1.clone());

        if n > DILITHIUM_OMEGA as u32 {
            continue;
        }

        break;
    }

    /* Write signature */
    let sig1 = &sig.to_owned();
    dilithium_pack_sig(&mut sig[..DILITHIUM_SIGNATURE_SIZE], sig1, z.clone(), h.clone());
    *siglen = DILITHIUM_SIGNATURE_SIZE;
}

/*
* \brief Takes the message as input and returns an array containing the signature followed by the message
*
* \param sm: The signed message
* \param smlen: The signed message length
* \param m: [const] The message to be signed
* \param mlen: The message length
* \param sk: [const] The private signature key
* \param rng_generate: The random generator
*/
pub fn qrc_dilithium_ref_sign(asymmetric_state: &mut AsymmetricRandState, sm: &mut [u8], smlen: &mut usize, m: &[u8], mlen: usize, sk: &[u8], rng_generate: fn(&mut AsymmetricRandState, &mut [u8], usize) -> bool) {
    for i in 0..mlen {
        sm[DILITHIUM_SIGNATURE_SIZE + mlen - 1 - i] = m[mlen - 1 - i];
    }

    let sm1 = &sm.to_owned()[DILITHIUM_SIGNATURE_SIZE..];
    qrc_dilithium_ref_sign_signature(asymmetric_state, sm, smlen, sm1, mlen, sk, rng_generate);
    *smlen += mlen;
}

/*
* \brief Verifies a signature-message pair with the public key.
*
* \param sig: [const] The message to be signed
* \param siglen: The message length
* \param m: [const] The signed message
* \param mlen: The signed message length
* \param pk: [const] The public verification key
* \return Returns true for success
*/
pub fn qrc_dilithium_ref_verify(sig: &[u8], siglen: usize, m: &[u8], mlen: usize, pk: &[u8]) -> bool {
    let buf = &mut [0u8; QRC_DILITHIUM_K * DILITHIUM_POLYW1_PACKEDBYTES];
    let rho = &mut [0u8; DILITHIUM_SEEDBYTES];
    let mu = &mut [0u8; DILITHIUM_CRHBYTES];
    let c = &mut [0u8; DILITHIUM_SEEDBYTES];
    let c2 = &mut [0u8; DILITHIUM_SEEDBYTES];
    let mat = &mut [QrcDilithiumPolyvecl::default(); QRC_DILITHIUM_K];
    let z = &mut QrcDilithiumPolyvecl::default();
    let h = &mut QrcDilithiumPolyveck::default();
    let t1 = &mut QrcDilithiumPolyveck::default();
    let w1 = &mut QrcDilithiumPolyveck::default();
    let cp = &mut QrcDilithiumPoly::default();
    let kctx = &mut QrcKeccakState::default();

    let mut res = false;

    if siglen >= DILITHIUM_SIGNATURE_SIZE {
        dilithium_unpack_pk(rho, t1, &pk[..DILITHIUM_PUBLICKEY_SIZE]);

        if dilithium_unpack_sig(c, z, h, sig) == 0 {
            if dilithium_polyvecl_chknorm(z.clone(), (DILITHIUM_GAMMA1 - DILITHIUM_BETA) as i32) == 0 {
                /* Compute CRH(CRH(rho, t1), msg) */
                qrc_shake256_compute(mu, DILITHIUM_CRHBYTES, pk, DILITHIUM_PUBLICKEY_SIZE);

                qrc_keccak_incremental_block_absorb(kctx, QRC_KECCAK_256_RATE, mu, DILITHIUM_CRHBYTES);
                qrc_keccak_incremental_block_absorb(kctx, QRC_KECCAK_256_RATE, m, mlen);
                qrc_keccak_incremental_finalize(kctx, QRC_KECCAK_256_RATE, QRC_KECCAK_SHAKE_DOMAIN_ID);
                qrc_keccak_incremental_squeeze(kctx, QRC_KECCAK_256_RATE, mu, DILITHIUM_CRHBYTES);

                /* Matrix-vector multiplication; compute Az - c2^dt1 */
                dilithium_poly_challenge(cp, c);
                dilithium_polyvec_matrix_expand(mat, rho);

                dilithium_polyvecl_ntt(z);
                dilithium_polyvec_matrix_pointwise_montgomery(w1, mat, z.clone());

                dilithium_poly_ntt(cp);
                dilithium_polyveck_shiftl(t1);
                dilithium_polyveck_ntt(t1);
                dilithium_polyveck_pointwise_poly_montgomery(t1, cp.clone(), t1.clone());

                let w11 = w1.clone();
                dilithium_polyveck_sub(w1, w11, t1.clone());
                dilithium_polyveck_reduce(w1);
                dilithium_polyveck_invntt_to_mont(w1);

                /* Reconstruct w1 */
                dilithium_polyveck_caddq(w1);
                dilithium_polyveck_use_hint(w1, w1.clone(), h.clone());
                dilithium_polyveck_pack_w1(buf, w1.clone());

                /* Call random oracle and verify challenge */
                qrc_keccak_initialize_state(kctx);
                qrc_keccak_incremental_block_absorb(kctx, QRC_KECCAK_256_RATE, mu, DILITHIUM_CRHBYTES);
                qrc_keccak_incremental_block_absorb(kctx, QRC_KECCAK_256_RATE, buf, QRC_DILITHIUM_K * DILITHIUM_POLYW1_PACKEDBYTES);
                qrc_keccak_incremental_finalize(kctx, QRC_KECCAK_256_RATE, QRC_KECCAK_SHAKE_DOMAIN_ID);
                qrc_keccak_incremental_squeeze(kctx, QRC_KECCAK_256_RATE, c2, DILITHIUM_SEEDBYTES);

                res = qrc_intutils_verify(c, c2, DILITHIUM_SEEDBYTES) == 0;
            }
        }
    }

    return res
}

/*
* \brief Verifies a signature-message pair with the public key.
*
* \param m: The message to be signed
* \param mlen: The message length
* \param sm: [const] The signed message
* \param smlen: The signed message length
* \param pk: [const] The public verification key
* \return Returns true for success
*/
pub fn qrc_dilithium_ref_open(m: &mut [u8], mlen: &mut isize, sm: &[u8], smlen: usize, pk: &[u8]) -> bool {
    *mlen = -1;
    let mut res = false;

    if smlen >= DILITHIUM_SIGNATURE_SIZE {
        *mlen = (smlen - DILITHIUM_SIGNATURE_SIZE) as isize;
        res = qrc_dilithium_ref_verify(sm, DILITHIUM_SIGNATURE_SIZE, &sm[DILITHIUM_SIGNATURE_SIZE..], mlen.clone() as usize, pk);

        if res {
            /* All good, copy msg, return 0 */
            qrc_intutils_copy8(m, &sm[DILITHIUM_SIGNATURE_SIZE..], mlen.clone() as usize);
        }
    }

    return res;
}

/* \endcond DOXYGEN_IGNORE */

/* params.h */

//const DILITHIUM_MONT: isize = -4186625; /* 2^32 % DILITHIUM_Q */
const DILITHIUM_QINV: usize = 58728449; /* q^(-1) mod 2^32 */

const DILITHIUM_SEEDBYTES: usize = 32;
const DILITHIUM_CRHBYTES: usize = 48;
const DILITHIUM_Q: usize = 8380417;
const DILITHIUM_D: usize = 13;
//const DILITHIUM_ROOT_OF_UNITY: usize = 1753;

const DILITHIUM_ETA: usize = if QRC_DILITHIUM_MODE == 2 {
    2
} else if QRC_DILITHIUM_MODE == 3 {
    4
} else if QRC_DILITHIUM_MODE == 5 {
    2
} else {
    0
};

const DILITHIUM_TAU: usize = if QRC_DILITHIUM_MODE == 2 {
    39
} else if QRC_DILITHIUM_MODE == 3 {
    49
} else if QRC_DILITHIUM_MODE == 5 {
    60
} else {
    0
};

const DILITHIUM_BETA: usize = if QRC_DILITHIUM_MODE == 2 {
    78
} else if QRC_DILITHIUM_MODE == 3 {
    196
} else if QRC_DILITHIUM_MODE == 5 {
    120
} else {
    0
};

const DILITHIUM_GAMMA1: usize = if QRC_DILITHIUM_MODE == 2 {
    1 << 17
} else if QRC_DILITHIUM_MODE == 3 {
    1 << 19
} else if QRC_DILITHIUM_MODE == 5 {
    1 << 19
} else {
    0
};

const DILITHIUM_GAMMA2: usize = if QRC_DILITHIUM_MODE == 2 {
    (DILITHIUM_Q-1) / 88
} else if QRC_DILITHIUM_MODE == 3 {
    (DILITHIUM_Q-1) / 32
} else if QRC_DILITHIUM_MODE == 5 {
    (DILITHIUM_Q-1) / 32
} else {
    0
};

const DILITHIUM_OMEGA: usize = if QRC_DILITHIUM_MODE == 2 {
    80
} else if QRC_DILITHIUM_MODE == 3 {
    55
} else if QRC_DILITHIUM_MODE == 5 {
    75
} else {
    0
};

const DILITHIUM_POLYT1_PACKEDBYTES: usize =  320;
const DILITHIUM_POLYT0_PACKEDBYTES: usize =  416;
const DILITHIUM_POLYVECH_PACKEDBYTES: usize = DILITHIUM_OMEGA + QRC_DILITHIUM_K;

const DILITHIUM_POLYZ_PACKEDBYTES: usize = if DILITHIUM_GAMMA1 == (1 << 17) {
    576
} else if DILITHIUM_GAMMA1 == (1 << 19) {
    640
} else {
    0
};

const DILITHIUM_POLYW1_PACKEDBYTES: usize = if DILITHIUM_GAMMA2 == (DILITHIUM_Q-1) / 88 {
    192
} else if DILITHIUM_GAMMA2 == (DILITHIUM_Q-1) / 32 {
    128
} else {
    0
};

const DILITHIUM_POLYETA_PACKEDBYTES: usize = if DILITHIUM_ETA == 2 {
    96
} else if DILITHIUM_ETA == 4 {
    128
} else {
    0
};

const DILITHIUM_PUBLICKEY_SIZE: usize = DILITHIUM_SEEDBYTES + QRC_DILITHIUM_K * DILITHIUM_POLYT1_PACKEDBYTES;
//const DILITHIUM_PRIVATEKEY_SIZE: usize = 2 * DILITHIUM_SEEDBYTES + DILITHIUM_CRHBYTES + QRC_DILITHIUM_L * DILITHIUM_POLYETA_PACKEDBYTES + QRC_DILITHIUM_K * DILITHIUM_POLYETA_PACKEDBYTES + QRC_DILITHIUM_K * DILITHIUM_POLYT0_PACKEDBYTES;
const DILITHIUM_SIGNATURE_SIZE: usize = DILITHIUM_SEEDBYTES + QRC_DILITHIUM_L * DILITHIUM_POLYZ_PACKEDBYTES + DILITHIUM_POLYVECH_PACKEDBYTES;

const DILITHIUM_POLY_UNIFORM_NBLOCKS: usize = (768 + QRC_KECCAK_128_RATE - 1) / QRC_KECCAK_128_RATE;

const DILITHIUM_POLY_UNIFORM_ETA_NBLOCKS: usize = if DILITHIUM_ETA == 2 {
    (136 + QRC_KECCAK_128_RATE - 1) / QRC_KECCAK_128_RATE
} else if DILITHIUM_ETA == 4 {
    (227 + QRC_KECCAK_128_RATE - 1) / QRC_KECCAK_128_RATE
} else {
    0
};

const DILITHIUM_POLY_UNIFORM_GAMMA1_NBLOCKS: usize = if DILITHIUM_GAMMA1 == (1 << 17) {
    (576 + QRC_KECCAK_256_RATE - 1) / QRC_KECCAK_256_RATE
} else if DILITHIUM_GAMMA1 == (1 << 19) {
    (640 + QRC_KECCAK_256_RATE - 1) / QRC_KECCAK_256_RATE
} else {
    0
};



const DILITHIUM_ZETAS: [u32; QRC_DILITHIUM_N] = [
    0x00000000, 0x000064F7, 0xFFD83102, 0xFFF81503, 0x00039E44, 0xFFF42118, 0xFFF2A128, 0x00071E24,
    0x001BDE2B, 0x0023E92B, 0xFFFA84AD, 0xFFE0147F, 0x002F9A75, 0xFFD3FB09, 0x002F7A49, 0x0028E527,
    0x00299658, 0x000FA070, 0xFFEF85A4, 0x0036B788, 0xFFF79D90, 0xFFEEEAA0, 0x0027F968, 0xFFDFD37B,
    0xFFDFADD6, 0xFFC51AE7, 0xFFEAA4F7, 0xFFCDFC98, 0x001AD035, 0xFFFFB422, 0x003D3201, 0x000445C5,
    0x00294A67, 0x00017620, 0x002EF4CD, 0x0035DEC5, 0xFFE6A503, 0xFFC9302C, 0xFFD947D4, 0x003BBEAF,
    0xFFC51585, 0xFFD18E7C, 0x00368A96, 0xFFD43E41, 0x00360400, 0xFFFB6A4D, 0x0023D69C, 0xFFF7C55D,
    0xFFE6123D, 0xFFE6EAD6, 0x00357E1E, 0xFFC5AF59, 0x0035843F, 0xFFDF5617, 0xFFE7945C, 0x0038738C,
    0x000C63A8, 0x00081B9A, 0x000E8F76, 0x003B3853, 0x003B8534, 0xFFD8FC30, 0x001F9D54, 0xFFD54F2D,
    0xFFC406E5, 0xFFE8AC81, 0xFFC7E1CF, 0xFFD19819, 0xFFE9D65D, 0x003509EE, 0x002135C7, 0xFFE7CFBB,
    0xFFECCF75, 0x001D9772, 0xFFC1B072, 0xFFF0BCF6, 0xFFCF5280, 0xFFCFD2AE, 0xFFC890E0, 0x0001EFCA,
    0x003410F2, 0xFFF0FE85, 0x0020C638, 0x00296E9F, 0xFFD2B7A3, 0xFFC7A44B, 0xFFF9BA6D, 0xFFDA3409,
    0xFFF5C282, 0xFFED4113, 0xFFFFA63B, 0xFFEC09F7, 0xFFFA2BDD, 0x001495D4, 0x001C4563, 0xFFEA2C62,
    0xFFCCFBE9, 0x00040AF0, 0x0007C417, 0x002F4588, 0x0000AD00, 0xFFEF36BE, 0x000DCD44, 0x003C675A,
    0xFFC72BCA, 0xFFFFDE7E, 0x00193948, 0xFFCE69C0, 0x0024756C, 0xFFFCC7DF, 0x000B98A1, 0xFFEBE808,
    0x0002E46C, 0xFFC9C808, 0x003036C2, 0xFFE3BFF6, 0xFFDB3C93, 0xFFFD4AE0, 0x00141305, 0x00147792,
    0x00139E25, 0xFFE7D0E0, 0xFFF39944, 0xFFEA0802, 0xFFD1EEA2, 0xFFC4C79C, 0xFFC8A057, 0x003A97D9,
    0x001FEA93, 0x0033FF5A, 0x002358D4, 0x003A41F8, 0xFFCCFF72, 0x00223DFB, 0xFFDAAB9F, 0xFFC9A422,
    0x000412F5, 0x00252587, 0xFFED24F0, 0x00359B5D, 0xFFCA48A0, 0xFFC6A2FC, 0xFFEDBB56, 0xFFCF45DE,
    0x000DBE5E, 0x001C5E1A, 0x000DE0E6, 0x000C7F5A, 0x00078F83, 0xFFE7628A, 0xFFFF5704, 0xFFF806FC,
    0xFFF60021, 0xFFD05AF6, 0x001F0084, 0x0030EF86, 0xFFC9B97D, 0xFFF7FCD6, 0xFFF44592, 0xFFC921C2,
    0x00053919, 0x0004610C, 0xFFDACD41, 0x003EB01B, 0x003472E7, 0xFFCD003B, 0x001A7CC7, 0x00031924,
    0x002B5EE5, 0x00291199, 0xFFD87A3A, 0x00134D71, 0x003DE11C, 0x00130984, 0x0025F051, 0x00185A46,
    0xFFC68518, 0x001314BE, 0x00283891, 0xFFC9DB90, 0xFFD25089, 0x001C853F, 0x001D0B4B, 0xFFEFF6A6,
    0xFFEBA8BE, 0x0012E11B, 0xFFCD5E3E, 0xFFEA2D2F, 0xFFF91DE4, 0x001406C7, 0x00327283, 0xFFE20D6E,
    0xFFEC7953, 0x001D4099, 0xFFD92578, 0xFFEB05AD, 0x0016E405, 0x000BDBE7, 0x00221DE8, 0x0033F8CF,
    0xFFF7B934, 0xFFD4CA0C, 0xFFE67FF8, 0xFFE3D157, 0xFFD8911B, 0xFFC72C12, 0x000910D8, 0xFFC65E1F,
    0xFFE14658, 0x00251D8B, 0x002573B7, 0xFFFD7C8F, 0x001DDD98, 0x00336898, 0x0002D4BB, 0xFFED93A7,
    0xFFCF6CBE, 0x00027C1C, 0x0018AA08, 0x002DFD71, 0x000C5CA5, 0x0019379A, 0xFFC7A167, 0xFFE48C3D,
    0xFFD1A13C, 0x0035C539, 0x003B0115, 0x00041DC0, 0x0021C4F7, 0xFFF11BF4, 0x001A35E7, 0x0007340E,
    0xFFF97D45, 0x001A4CD0, 0xFFE47CAE, 0x001D2668, 0xFFE68E98, 0xFFEF2633, 0xFFFC05DA, 0xFFC57FDB,
    0xFFD32764, 0xFFDDE1AF, 0xFFF993DD, 0xFFDD1D09, 0x0002CC93, 0xFFF11805, 0x00189C2A, 0xFFC9E5A9,
    0xFFF78A50, 0x003BCF2C, 0xFFFF434E, 0xFFEB36DF, 0x003C15CA, 0x00155E68, 0xFFF316B6, 0x001E29CE
];

/* reduce.c */

fn dilithium_montgomery_reduce(a: i64) -> i32 {
    let mut t = a as i32 * DILITHIUM_QINV as i32;
    t = ((a - t as i64 * DILITHIUM_Q as i64) >> 32) as i32;

    return t;
}

fn dilithium_reduce32(a: i32) -> i32 {
    let mut t = (a + (1 << 22)) >> 23;
    t = a - t * DILITHIUM_Q as i32;

    return t;
}

fn dilithium_caddq(mut a: i32) -> i32 {
    a += (a >> 31) & DILITHIUM_Q as i32; 

    return a;
}

/* rounding.c */

fn dilithium_power2_round(a0: &mut i32, a: i32) -> i32 {
    let a1 = (a + (1 << (DILITHIUM_D - 1)) - 1) >> DILITHIUM_D;
    *a0 = a - (a1 << DILITHIUM_D);

    return a1;
}

fn dilithium_decompose(a0: &mut i32, a: i32) -> i32 {
    let mut a1 = (a + 127) >> 7;
    if DILITHIUM_GAMMA2 == (DILITHIUM_Q - 1) / 32 {
        a1 = ((a1 * 1025) + (1 << 21)) >> 22;
        a1 &= 15;
    } else if DILITHIUM_GAMMA2 == (DILITHIUM_Q - 1) / 88 {
        a1 = ((a1 * 11275) + (1 << 23)) >> 24;
        a1 ^= ((43 - a1) >> 31) & a1;
    }

    *a0 = a - (a1 * 2 * DILITHIUM_GAMMA2 as i32);
    *a0 -= ((((DILITHIUM_Q as i32 - 1) / 2) - *a0) >> 31) & DILITHIUM_Q as i32;

    return a1;
}

fn dilithium_make_hint(a0: i32, a1: i32) -> u32 {
    let mut res = 1;

    if a0 <= DILITHIUM_GAMMA2 as i32 || a0 > DILITHIUM_Q as i32 - DILITHIUM_GAMMA2 as i32 || (a0 == DILITHIUM_Q as i32 - DILITHIUM_GAMMA2 as i32 && a1 == 0) {
        res = 0;
    }

    return res;
}

fn dilithium_use_hint(a: i32, hint: u32) -> i32 {
    let mut a0 = 0;
    let a1 = dilithium_decompose(&mut a0, a);

    let mut res = a1;

    if hint != 0 {
        if DILITHIUM_GAMMA2 == (DILITHIUM_Q - 1) / 32 {
                if a0 > 0 {
                    res = (a1 + 1) & 15;
                } else {
                    res = (a1 - 1) & 15;
                }
        } else if DILITHIUM_GAMMA2 == (DILITHIUM_Q - 1) / 88 {
            if a0 > 0 {
                res = if a1 == 43 { 0 } else { a1 + 1 };
            } else {
                res = if a1 == 0 { 43 } else { a1 - 1 };
            }
        }
    }

    return res;
}

/* qrc_dilithium_poly.c */

fn dilithium_shake128_stream_init(kctx: &mut QrcKeccakState, seed: &[u8], nonce: u16) {
    let tn = &mut [0u8; 2];
    tn[0] = nonce as u8;
    tn[1] = (nonce >> 8) as u8;

    qrc_keccak_initialize_state(kctx);
    qrc_keccak_incremental_block_absorb(kctx, QRC_KECCAK_128_RATE, seed, DILITHIUM_SEEDBYTES);
    qrc_keccak_incremental_block_absorb(kctx, QRC_KECCAK_128_RATE, tn, 2);
    qrc_keccak_incremental_finalize(kctx, QRC_KECCAK_128_RATE, QRC_KECCAK_SHAKE_DOMAIN_ID);
}

fn dilithium_shake256_stream_init(kctx: &mut QrcKeccakState, seed: &[u8], nonce: u16) {
    let tn = &mut [0u8; 2];
    tn[0] = nonce as u8;
    tn[1] = (nonce >> 8) as u8;

    qrc_keccak_initialize_state(kctx);
    qrc_keccak_incremental_block_absorb(kctx, QRC_KECCAK_256_RATE, seed, DILITHIUM_CRHBYTES);
    qrc_keccak_incremental_block_absorb(kctx, QRC_KECCAK_256_RATE, tn, 2);
    qrc_keccak_incremental_finalize(kctx, QRC_KECCAK_256_RATE, QRC_KECCAK_SHAKE_DOMAIN_ID);
}

/* dilithium_ntt.c */

fn dilithium_ntt(a: &mut [i32; QRC_DILITHIUM_N]) {
    let mut k = 0;

    let mut len = 128;
    while len > 0 {
        let mut start = 0;
        while start < QRC_DILITHIUM_N {
            k += 1;
            let zeta = DILITHIUM_ZETAS[k] as i32;

            let mut j = start;
            while j < start + len {
                let t = dilithium_montgomery_reduce(zeta as i64 * a[j + len] as i64);
                a[j + len] = a[j] - t;
                a[j] = a[j] + t;
                j += 1;
            }
            start = j + len;
        }
        len >>= 1;
    }
}

fn dilithium_invntt_to_mont(a: &mut [i32; QRC_DILITHIUM_N]) {
    const F: i32 = 41978; /* mont ^ 2 / 256 */

    let mut k = 256;

    let mut len = 1;
    while len < QRC_DILITHIUM_N {
        let mut start = 0;
        while start < QRC_DILITHIUM_N {
            k -= 1;
            let zeta = -(DILITHIUM_ZETAS[k] as i32);

            let mut j = start;
            while j < start + len {
                let t = a[j];
                a[j] = t + a[j + len];
                a[j + len] = t - a[j + len];
                a[j + len] = dilithium_montgomery_reduce(zeta as i64 * a[j + len] as i64);
                j += 1;
            }
            start = j + len;
        }
        len <<= 1;
    }

    for j in 0..QRC_DILITHIUM_N {
        a[j] = dilithium_montgomery_reduce(F as i64 * a[j] as i64);
    }
}

fn dilithium_poly_reduce(a: &mut QrcDilithiumPoly) {
    for i in 0..QRC_DILITHIUM_N {
        a.coeffs[i] = dilithium_reduce32(a.coeffs[i]);
    }
}

fn dilithium_poly_caddq(a: &mut QrcDilithiumPoly) {
    for i in 0..QRC_DILITHIUM_N {
        a.coeffs[i] = dilithium_caddq(a.coeffs[i]);
    }
}

fn dilithium_poly_add(c: &mut QrcDilithiumPoly, a: QrcDilithiumPoly, b: QrcDilithiumPoly) {
    for i in 0..QRC_DILITHIUM_N {
        c.coeffs[i] = a.coeffs[i] + b.coeffs[i];
    }
}

fn dilithium_poly_sub(c: &mut QrcDilithiumPoly, a: QrcDilithiumPoly, b: QrcDilithiumPoly) {
    for i in 0..QRC_DILITHIUM_N {
        c.coeffs[i] = a.coeffs[i] - b.coeffs[i];
    }
}

fn dilithium_poly_shiftl(a: &mut QrcDilithiumPoly) {
    for i in 0..QRC_DILITHIUM_N {
        a.coeffs[i] <<= DILITHIUM_D;
    }
}

fn dilithium_poly_ntt(a: &mut QrcDilithiumPoly) {
    dilithium_ntt(&mut a.coeffs);
}

fn dilithium_poly_invntt_to_mont(a: &mut QrcDilithiumPoly) {
    dilithium_invntt_to_mont(&mut a.coeffs);
}

fn dilithium_poly_pointwise_montgomery(c: &mut QrcDilithiumPoly, a: QrcDilithiumPoly, b: QrcDilithiumPoly) {
    for i in 0..QRC_DILITHIUM_N {
        c.coeffs[i] = dilithium_montgomery_reduce(a.coeffs[i] as i64 * b.coeffs[i] as i64);
    }
}

fn dilithium_poly_power2_round(a1: &mut QrcDilithiumPoly, a0: &mut QrcDilithiumPoly, a: QrcDilithiumPoly) {
    for i in 0..QRC_DILITHIUM_N {
        a1.coeffs[i] = dilithium_power2_round(&mut a0.coeffs[i], a.coeffs[i]);
    }
}

fn dilithium_poly_decompose(a1: &mut QrcDilithiumPoly, a0: &mut QrcDilithiumPoly, a: QrcDilithiumPoly) {
    for i in 0..QRC_DILITHIUM_N {
        a1.coeffs[i] = dilithium_decompose(&mut a0.coeffs[i], a.coeffs[i]);
    }
}

fn dilithium_poly_make_hint(h: &mut QrcDilithiumPoly, a0: QrcDilithiumPoly, a1: QrcDilithiumPoly) -> u32 {
    let mut s = 0u32;

    for i in 0..QRC_DILITHIUM_N {
        h.coeffs[i] = dilithium_make_hint(a0.coeffs[i], a1.coeffs[i]) as i32;
        s += h.coeffs[i] as u32;
    }

    return s;
}

fn dilithium_poly_use_hint(b: &mut QrcDilithiumPoly, a: QrcDilithiumPoly, h: QrcDilithiumPoly) {
    for i in 0..QRC_DILITHIUM_N {
        b.coeffs[i] = dilithium_use_hint(a.coeffs[i], h.coeffs[i] as u32);
    }
}

fn dilithium_poly_chknorm(a: QrcDilithiumPoly, b: i32) -> i32 {
    let mut res = 0;

    if b > (DILITHIUM_Q as i32 - 1) / 8 {
        res = 1;
    } else {
        /* It is ok to leak which coefficient violates the bound since
           the probability for each coefficient is independent of secret
           data but we must not leak the sign of the centralized representative. */
        for i in 0..QRC_DILITHIUM_N {
            /* Absolute value */
            let mut t = a.coeffs[i] >> 31;
            t = a.coeffs[i] - (t & 2 * a.coeffs[i]);

            if t >= b {
                res = 1;
                break;
            }
        }
    }

    return res;
}

fn dilithium_rej_uniform(a: &mut [i32], len: usize, buf: &[u8], buflen: usize) -> usize {
    let mut ctr = 0;
    let mut pos = 0;

    while ctr < len && pos + 3 <= buflen {
        let mut t = buf[pos] as u32;
        pos += 1;
        t |= (buf[pos] as u32) << 8;
        pos += 1;
        t |= (buf[pos] as u32) << 16;
        pos += 1;
        t &= 0x007FFFFF;

        if t < DILITHIUM_Q as u32 {
            a[ctr] = t as i32;
            ctr += 1;
        }
    }


    return ctr;
}

fn dilithium_poly_uniform(a: &mut QrcDilithiumPoly, seed: &[u8], nonce: u16) {
    let buf = &mut [0u8; DILITHIUM_POLY_UNIFORM_NBLOCKS * QRC_KECCAK_128_RATE + 2];
    let kctx = &mut QrcKeccakState::default();

    let mut buflen = DILITHIUM_POLY_UNIFORM_NBLOCKS * QRC_KECCAK_128_RATE;
    dilithium_shake128_stream_init(kctx, seed, nonce);
    qrc_keccak_squeezeblocks(kctx, buf, DILITHIUM_POLY_UNIFORM_NBLOCKS, QRC_KECCAK_128_RATE, QRC_KECCAK_PERMUTATION_ROUNDS);

    let mut ctr = dilithium_rej_uniform(&mut a.coeffs, QRC_DILITHIUM_N, buf, buflen);

    while ctr < QRC_DILITHIUM_N {
        let off = buflen % 3;

        for i in 0..off {
            buf[i] = buf[buflen - off + i];
        }

        qrc_keccak_squeezeblocks(kctx, &mut buf[off..], 1, QRC_KECCAK_128_RATE, QRC_KECCAK_PERMUTATION_ROUNDS);
        buflen = QRC_KECCAK_128_RATE + off;
        ctr += dilithium_rej_uniform(&mut a.coeffs[ctr..], QRC_DILITHIUM_N - ctr, buf, buflen);
    }
}

fn dilithium_rej_eta(a: &mut [i32], len: usize, buf: &[u8], buflen: usize) -> usize {
    let mut ctr = 0;
    let mut pos = 0;

    while ctr < len && pos < buflen {
        let mut t0 = buf[pos] as u32 & 0x0F;
        let mut t1 = buf[pos] as u32 >> 4;
        pos += 1;

    if DILITHIUM_ETA == 2 {
            if t0 < 15 {
                t0 = t0 - (205 * t0 >> 10) * 5;
                a[ctr] = 2 - t0 as i32;
                ctr += 1;
            }

            if t1 < 15 && ctr < len {
                t1 = t1 - (205 * t1 >> 10) * 5;
                a[ctr] = 2 - t1 as i32;
                ctr += 1;
            }
        } else if DILITHIUM_ETA == 4 {
            if t0 < 9 {
                a[ctr] = 4 - t0 as i32;
                ctr += 1;
            }

            if t1 < 9 && ctr < len {
                a[ctr] = 4 - t1 as i32;
                ctr += 1;
            }
        }
    }

    return ctr;
}

fn dilithium_poly_challenge(c: &mut QrcDilithiumPoly, seed: &[u8]) {
    let buf = &mut [0u8; QRC_KECCAK_256_RATE];
    let kctx = &mut QrcKeccakState::default();

    qrc_keccak_initialize_state(kctx);
    qrc_keccak_incremental_block_absorb(kctx, QRC_KECCAK_256_RATE, seed, DILITHIUM_SEEDBYTES);
    qrc_keccak_incremental_finalize(kctx, QRC_KECCAK_256_RATE, QRC_KECCAK_SHAKE_DOMAIN_ID);
    qrc_keccak_squeezeblocks(kctx, buf, 1, QRC_KECCAK_256_RATE, QRC_KECCAK_PERMUTATION_ROUNDS);

    let mut signs = 0;
    let mut pos = 8;

    for i in 0..8 {
        signs |= (buf[i] as i64) << (8 * i);
    }

    for i in 0..QRC_DILITHIUM_N {
        c.coeffs[i] = 0;
    }

    for i in QRC_DILITHIUM_N - DILITHIUM_TAU..QRC_DILITHIUM_N {
        let mut b: u8;
        loop {
            if pos >= QRC_KECCAK_256_RATE {
                qrc_keccak_squeezeblocks(kctx, buf, 1, QRC_KECCAK_256_RATE, QRC_KECCAK_PERMUTATION_ROUNDS);
                pos = 0;
            }

            b = buf[pos];
            pos += 1;

            if !(b as usize > i) {
                break;
            }
        }

        c.coeffs[i] = c.coeffs[b as usize];
        c.coeffs[b as usize] = 1 - 2 * ((signs as i32) & 1);
        signs >>= 1;
    }
}

fn dilithium_polyeta_pack(r: &mut [u8], a: QrcDilithiumPoly) {
    let t: &mut [u8; 8] = &mut [0u8; 8];

    if DILITHIUM_ETA == 2 {
        for i in 0..QRC_DILITHIUM_N / 8 {
            t[0] = (DILITHIUM_ETA as i32 - a.coeffs[8 * i]) as u8;
            t[1] = (DILITHIUM_ETA as i32 - a.coeffs[(8 * i) + 1]) as u8;
            t[2] = (DILITHIUM_ETA as i32 - a.coeffs[(8 * i) + 2]) as u8;
            t[3] = (DILITHIUM_ETA as i32 - a.coeffs[(8 * i) + 3]) as u8;
            t[4] = (DILITHIUM_ETA as i32 - a.coeffs[(8 * i) + 4]) as u8;
            t[5] = (DILITHIUM_ETA as i32 - a.coeffs[(8 * i) + 5]) as u8;
            t[6] = (DILITHIUM_ETA as i32 - a.coeffs[(8 * i) + 6]) as u8;
            t[7] = (DILITHIUM_ETA as i32 - a.coeffs[(8 * i) + 7]) as u8;

            r[3 * i] = ((t[0] >> 0) | (t[1] << 3) | (t[2] << 6)) as u8;
            r[(3 * i) + 1] = ((t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7)) as u8;
            r[(3 * i) + 2] = ((t[5] >> 1) | (t[6] << 2) | (t[7] << 5)) as u8;
        }
    } else if DILITHIUM_ETA == 4 {
        for i in 0..QRC_DILITHIUM_N / 2 {
            t[0] = (DILITHIUM_ETA as i32 - a.coeffs[2 * i]) as u8;
            t[1] = (DILITHIUM_ETA as i32 - a.coeffs[(2 * i) + 1]) as u8;
            r[i] = (t[0] | (t[1] << 4)) as u8;
        }
    }
}

fn dilithium_polyeta_unpack(r: &mut QrcDilithiumPoly, a: &[u8]) {
    if DILITHIUM_ETA == 2 {
        for i in 0..QRC_DILITHIUM_N / 8 {
            r.coeffs[8 * i] = (a[3 * i] >> 0) as i32 & 7;
            r.coeffs[(8 * i) + 1] = (a[3 * i] >> 3) as i32 & 7;
            r.coeffs[(8 * i) + 2] = ((a[3 * i] >> 6) | (a[(3 * i) + 1] << 2)) as i32 & 7;
            r.coeffs[(8 * i) + 3] = (a[(3 * i) + 1] >> 1) as i32 & 7;
            r.coeffs[(8 * i) + 4] = (a[(3 * i) + 1] >> 4) as i32 & 7;
            r.coeffs[(8 * i) + 5] = ((a[(3 * i) + 1] >> 7) | (a[(3 * i) + 2] << 1)) as i32 & 7;
            r.coeffs[(8 * i) + 6] = (a[(3 * i) + 2] >> 2) as i32 & 7;
            r.coeffs[(8 * i) + 7] = (a[(3 * i) + 2] >> 5) as i32 & 7;

            r.coeffs[8 * i] = DILITHIUM_ETA as i32 - r.coeffs[8 * i];
            r.coeffs[(8 * i) + 1] = DILITHIUM_ETA as i32 - r.coeffs[(8 * i) + 1];
            r.coeffs[(8 * i) + 2] = DILITHIUM_ETA as i32 - r.coeffs[(8 * i) + 2];
            r.coeffs[(8 * i) + 3] = DILITHIUM_ETA as i32 - r.coeffs[(8 * i) + 3];
            r.coeffs[(8 * i) + 4] = DILITHIUM_ETA as i32 - r.coeffs[(8 * i) + 4];
            r.coeffs[(8 * i) + 5] = DILITHIUM_ETA as i32 - r.coeffs[(8 * i) + 5];
            r.coeffs[(8 * i) + 6] = DILITHIUM_ETA as i32 - r.coeffs[(8 * i) + 6];
            r.coeffs[(8 * i) + 7] = DILITHIUM_ETA as i32 - r.coeffs[(8 * i) + 7];
        }
    } else if DILITHIUM_ETA == 4 {
        for i in 0..QRC_DILITHIUM_N / 2 {
            r.coeffs[2 * i] = a[i] as i32 & 0x0F;
            r.coeffs[(2 * i) + 1] = a[i] as i32 >> 4;
            r.coeffs[2 * i] = DILITHIUM_ETA as i32 - r.coeffs[2 * i];
            r.coeffs[(2 * i) + 1] = DILITHIUM_ETA as i32 - r.coeffs[(2 * i) + 1];
        }
    }
}

fn dilithium_polyt1_pack(r: &mut [u8], a: QrcDilithiumPoly) {
    for i in 0..QRC_DILITHIUM_N / 4 {
        r[5 * i] = (a.coeffs[4 * i] >> 0) as u8;
        r[(5 * i) + 1] = ((a.coeffs[4 * i] >> 8) | (a.coeffs[(4 * i) + 1] << 2)) as u8;
        r[(5 * i) + 2] = ((a.coeffs[(4 * i) + 1] >> 6) | (a.coeffs[(4 * i) + 2] << 4)) as u8;
        r[(5 * i) + 3] = ((a.coeffs[(4 * i) + 2] >> 4) | (a.coeffs[(4 * i) + 3] << 6)) as u8;
        r[(5 * i) + 4] = (a.coeffs[(4 * i) + 3] >> 2) as u8;
    }
}

fn dilithium_polyt1_unpack(r: &mut QrcDilithiumPoly, a: &[u8]) {
    for i in 0..QRC_DILITHIUM_N / 4 {
        r.coeffs[4 * i] = (((a[5 * i] as u32) >> 0)| (a[(5 * i) + 1] as u32) << 8) as i32 & 0x000003FF;
        r.coeffs[(4 * i) + 1] = (((a[(5 * i) + 1] as u32) >> 2) | ((a[(5 * i) + 2] as u32) << 6)) as i32 & 0x000003FF;
        r.coeffs[(4 * i) + 2] = (((a[(5 * i) + 2] as u32) >> 4) | ((a[(5 * i) + 3] as u32) << 4)) as i32 & 0x000003FF;
        r.coeffs[(4 * i) + 3] = (((a[(5 * i) + 3] as u32) >> 6) | ((a[(5 * i) + 4] as u32) << 2)) as i32 & 0x000003FF;
    }
}

fn dilithium_polyt0_pack(r: &mut [u8], a: QrcDilithiumPoly) {
    let mut t = [0u32; 8];

    for i in 0..QRC_DILITHIUM_N / 8 {
        t[0] = (1 << (DILITHIUM_D - 1)) - a.coeffs[8 * i] as u32;
        t[1] = (1 << (DILITHIUM_D - 1)) - a.coeffs[(8 * i) + 1] as u32;
        t[2] = (1 << (DILITHIUM_D - 1)) - a.coeffs[(8 * i) + 2] as u32;
        t[3] = (1 << (DILITHIUM_D - 1)) - a.coeffs[(8 * i) + 3] as u32;
        t[4] = (1 << (DILITHIUM_D - 1)) - a.coeffs[(8 * i) + 4] as u32;
        t[5] = (1 << (DILITHIUM_D - 1)) - a.coeffs[(8 * i) + 5] as u32;
        t[6] = (1 << (DILITHIUM_D - 1)) - a.coeffs[(8 * i) + 6] as u32;
        t[7] = (1 << (DILITHIUM_D - 1)) - a.coeffs[(8 * i) + 7] as u32;

        r[13 * i] = t[0] as u8;
        r[(13 * i) + 1] = (t[0] >> 8) as u8;
        r[(13 * i) + 1] |= (t[1] << 5) as u8;
        r[(13 * i) + 2] = (t[1] >> 3) as u8;
        r[(13 * i) + 3] = (t[1] >> 11) as u8;
        r[(13 * i) + 3] |= (t[2] << 2) as u8;
        r[(13 * i) + 4] = (t[2] >> 6) as u8;
        r[(13 * i) + 4] |= (t[3] << 7) as u8;
        r[(13 * i) + 5] = (t[3] >> 1) as u8;
        r[(13 * i) + 6] = (t[3] >> 9) as u8;
        r[(13 * i) + 6] |= (t[4] << 4) as u8;
        r[(13 * i) + 7] = (t[4] >> 4) as u8;
        r[(13 * i) + 8] = (t[4] >> 12) as u8;
        r[(13 * i) + 8] |= (t[5] << 1) as u8;
        r[(13 * i) + 9] = (t[5] >> 7) as u8;
        r[(13 * i) + 9] |= (t[6] << 6) as u8;
        r[(13 * i) + 10] = (t[6] >> 2) as u8;
        r[(13 * i) + 11] = (t[6] >> 10) as u8;
        r[(13 * i) + 11] |= (t[7] << 3) as u8;
        r[(13 * i) + 12] = (t[7] >> 5) as u8;
    }
}

fn dilithium_polyt0_unpack(r: &mut QrcDilithiumPoly, a: &[u8]) {
    for i in 0..QRC_DILITHIUM_N / 8 {
        r.coeffs[8 * i] = a[13 * i] as i32;
        r.coeffs[8 * i] |= (a[(13 * i) + 1] as i32) << 8;
        r.coeffs[8 * i] &= 0x00001FFF;

        r.coeffs[(8 * i) + 1] = (a[(13 * i) + 1] as i32) >> 5;
        r.coeffs[(8 * i) + 1] |= (a[(13 * i) + 2] as i32) << 3;
        r.coeffs[(8 * i) + 1] |= (a[(13 * i) + 3] as i32) << 11;
        r.coeffs[(8 * i) + 1] &= 0x00001FFF;

        r.coeffs[(8 * i) + 2] = (a[(13 * i) + 3] as i32) >> 2;
        r.coeffs[(8 * i) + 2] |= (a[(13 * i) + 4] as i32) << 6;
        r.coeffs[(8 * i) + 2] &= 0x00001FFF;

        r.coeffs[(8 * i) + 3] = (a[(13 * i) + 4] as i32) >> 7;
        r.coeffs[(8 * i) + 3] |= (a[(13 * i) + 5] as i32) << 1;
        r.coeffs[(8 * i) + 3] |= (a[(13 * i) + 6] as i32) << 9;
        r.coeffs[(8 * i) + 3] &= 0x00001FFF;

        r.coeffs[(8 * i) + 4] = (a[(13 * i) + 6] as i32) >> 4;
        r.coeffs[(8 * i) + 4] |= (a[(13 * i) + 7] as i32) << 4;
        r.coeffs[(8 * i) + 4] |= (a[(13 * i) + 8] as i32) << 12;
        r.coeffs[(8 * i) + 4] &= 0x00001FFF;

        r.coeffs[(8 * i) + 5] = (a[(13 * i) + 8] as i32) >> 1;
        r.coeffs[(8 * i) + 5] |= (a[(13 * i) + 9] as i32) << 7;
        r.coeffs[(8 * i) + 5] &= 0x00001FFF;

        r.coeffs[(8 * i) + 6] = (a[(13 * i) + 9] as i32) >> 6;
        r.coeffs[(8 * i) + 6] |= (a[(13 * i) + 10] as i32) << 2;
        r.coeffs[(8 * i) + 6] |= (a[(13 * i) + 11] as i32) << 10;
        r.coeffs[(8 * i) + 6] &= 0x00001FFF;

        r.coeffs[(8 * i) + 7] = (a[(13 * i) + 11] as i32) >> 3;
        r.coeffs[(8 * i) + 7] |= (a[(13 * i) + 12] as i32) << 5;
        r.coeffs[(8 * i) + 7] &= 0x00001FFF;

        r.coeffs[8 * i] = (1 << (DILITHIUM_D - 1)) - r.coeffs[8 * i];
        r.coeffs[(8 * i) + 1] = (1 << (DILITHIUM_D - 1)) - r.coeffs[(8 * i) + 1];
        r.coeffs[(8 * i) + 2] = (1 << (DILITHIUM_D - 1)) - r.coeffs[(8 * i) + 2];
        r.coeffs[(8 * i) + 3] = (1 << (DILITHIUM_D - 1)) - r.coeffs[(8 * i) + 3];
        r.coeffs[(8 * i) + 4] = (1 << (DILITHIUM_D - 1)) - r.coeffs[(8 * i) + 4];
        r.coeffs[(8 * i) + 5] = (1 << (DILITHIUM_D - 1)) - r.coeffs[(8 * i) + 5];
        r.coeffs[(8 * i) + 6] = (1 << (DILITHIUM_D - 1)) - r.coeffs[(8 * i) + 6];
        r.coeffs[(8 * i) + 7] = (1 << (DILITHIUM_D - 1)) - r.coeffs[(8 * i) + 7];
    }
}

fn dilithium_polyz_pack(r: &mut [u8], a: QrcDilithiumPoly) {
    let mut t = [0u32; 4];

    if DILITHIUM_GAMMA1 == (1 << 17) {
        for i in 0..QRC_DILITHIUM_N / 4 {
            t[0] = (DILITHIUM_GAMMA1 as i32 - a.coeffs[4 * i]) as u32;
            t[1] = (DILITHIUM_GAMMA1 as i32 - a.coeffs[(4 * i) + 1]) as u32;
            t[2] = (DILITHIUM_GAMMA1 as i32 - a.coeffs[(4 * i) + 2]) as u32;
            t[3] = (DILITHIUM_GAMMA1 as i32 - a.coeffs[(4 * i) + 3]) as u32;

            r[9 * i] = t[0] as u8;
            r[(9 * i) + 1] = (t[0] >> 8) as u8;
            r[(9 * i) + 2] = (t[0] >> 16) as u8;
            r[(9 * i) + 2] |= (t[1] << 2) as u8;
            r[(9 * i) + 3] = (t[1] >> 6) as u8;
            r[(9 * i) + 4] = (t[1] >> 14) as u8;
            r[(9 * i) + 4] |= (t[2] << 4) as u8;
            r[(9 * i) + 5] = (t[2] >> 4) as u8;
            r[(9 * i) + 6] = (t[2] >> 12) as u8;
            r[(9 * i) + 6] |= (t[3] << 6) as u8;
            r[(9 * i) + 7] = (t[3] >> 2) as u8;
            r[(9 * i) + 8] = (t[3] >> 10) as u8;
        }
    } else if DILITHIUM_GAMMA1 == (1 << 19) {
        for i in 0..QRC_DILITHIUM_N / 2 {
            t[0] = (DILITHIUM_GAMMA1 as i32 - a.coeffs[2 * i]) as u32;
            t[1] = (DILITHIUM_GAMMA1 as i32 - a.coeffs[(2 * i) + 1]) as u32;

            r[5 * i] = t[0] as u8;
            r[(5 * i) + 1] = (t[0] >> 8) as u8;
            r[(5 * i) + 2] = (t[0] >> 16) as u8;
            r[(5 * i) + 2] |= (t[1] << 4) as u8;
            r[(5 * i) + 3] = (t[1] >> 4) as u8;
            r[(5 * i) + 4] = (t[1] >> 12) as u8;
        }
    }
}

fn dilithium_polyz_unpack(r: &mut QrcDilithiumPoly, a: &[u8]) {
    if DILITHIUM_GAMMA1 == (1 << 17) {
        for i in 0..QRC_DILITHIUM_N / 4 {
            r.coeffs[4 * i] = a[9 * i] as i32;
            r.coeffs[4 * i] |= (a[(9 * i) + 1] as i32) << 8;
            r.coeffs[4 * i] |= (a[(9 * i) + 2] as i32) << 16;
            r.coeffs[4 * i] &= 0x0003FFFF;

            r.coeffs[(4 * i) + 1] = (a[(9 * i) + 2] as i32) >> 2;
            r.coeffs[(4 * i) + 1] |= (a[(9 * i) + 3] as i32)<< 6;
            r.coeffs[(4 * i) + 1] |= (a[(9 * i) + 4] as i32) << 14;
            r.coeffs[(4 * i) + 1] &= 0x0003FFFF;

            r.coeffs[(4 * i) + 2] = (a[(9 * i) + 4] as i32) >> 4;
            r.coeffs[(4 * i) + 2] |= (a[(9 * i) + 5] as i32) << 4;
            r.coeffs[(4 * i) + 2] |= (a[(9 * i) + 6] as i32) << 12;
            r.coeffs[(4 * i) + 2] &= 0x0003FFFF;

            r.coeffs[(4 * i) + 3] = (a[(9 * i) + 6] as i32) >> 6;
            r.coeffs[(4 * i) + 3] |= (a[(9 * i) + 7] as i32) << 2;
            r.coeffs[(4 * i) + 3] |= (a[(9 * i) + 8] as i32) << 10;
            r.coeffs[(4 * i) + 3] &= 0x0003FFFF;

            r.coeffs[4 * i] = DILITHIUM_GAMMA1 as i32 - r.coeffs[4 * i];
            r.coeffs[(4 * i) + 1] = DILITHIUM_GAMMA1 as i32 - r.coeffs[(4 * i) + 1];
            r.coeffs[(4 * i) + 2] = DILITHIUM_GAMMA1 as i32 - r.coeffs[(4 * i) + 2];
            r.coeffs[(4 * i) + 3] = DILITHIUM_GAMMA1 as i32 - r.coeffs[(4 * i) + 3];
        }
    } else if DILITHIUM_GAMMA1 == (1 << 19) {
        for i in 0..QRC_DILITHIUM_N / 2 {
            r.coeffs[2 * i] = a[5 * i] as i32;
            r.coeffs[2 * i] |= (a[(5 * i) + 1] as i32) << 8;
            r.coeffs[2 * i] |= (a[(5 * i) + 2] as i32) << 16;
            r.coeffs[2 * i] &= 0x000FFFFF;

            r.coeffs[(2 * i) + 1] = (a[(5 * i) + 2] as i32) >> 4;
            r.coeffs[(2 * i) + 1] |= (a[(5 * i) + 3] as i32) << 4;
            r.coeffs[(2 * i) + 1] |= (a[(5 * i) + 4] as i32) << 12;
            r.coeffs[2 * i] &= 0x000FFFFF;

            r.coeffs[2 * i] = DILITHIUM_GAMMA1 as i32 - r.coeffs[2 * i];
            r.coeffs[(2 * i) + 1] = DILITHIUM_GAMMA1 as i32 - r.coeffs[(2 * i) + 1];
        }
    }
}

fn dilithium_polyw1_pack(r: &mut [u8], a: QrcDilithiumPoly) {
    if DILITHIUM_GAMMA2 == (DILITHIUM_Q - 1) / 88 {
        for i in 0..QRC_DILITHIUM_N / 4 {
            r[3 * i] = a.coeffs[4 * i] as u8;
            r[3 * i] |= (a.coeffs[(4 * i) + 1] << 6) as u8;
            r[(3 * i) + 1] = (a.coeffs[(4 * i) + 1] >> 2) as u8;
            r[(3 * i) + 1] |= (a.coeffs[(4 * i) + 2] << 4) as u8;
            r[(3 * i) + 2] = (a.coeffs[(4 * i) + 2] >> 4) as u8;
            r[(3 * i) + 2] |= (a.coeffs[(4 * i) + 3] << 2) as u8;
        }
    } else if DILITHIUM_GAMMA2 == (DILITHIUM_Q - 1) / 32 {
        for i in 0..QRC_DILITHIUM_N / 2 {
            r[i] = (a.coeffs[2 * i] | (a.coeffs[(2 * i) + 1] << 4)) as u8;
        }
    }
}

fn dilithium_poly_uniform_eta(a: &mut QrcDilithiumPoly, seed: &[u8], nonce: u16) {
    let buf= &mut [0u8; DILITHIUM_POLY_UNIFORM_ETA_NBLOCKS * QRC_KECCAK_128_RATE];
    let kctx = &mut QrcKeccakState::default();

    let buflen = DILITHIUM_POLY_UNIFORM_ETA_NBLOCKS * QRC_KECCAK_128_RATE;
    dilithium_shake128_stream_init(kctx, seed, nonce);
    qrc_keccak_squeezeblocks(kctx, buf, DILITHIUM_POLY_UNIFORM_ETA_NBLOCKS, QRC_KECCAK_128_RATE, QRC_KECCAK_PERMUTATION_ROUNDS);

    let mut ctr = dilithium_rej_eta(&mut a.coeffs, QRC_DILITHIUM_N, buf, buflen);

    while ctr < QRC_DILITHIUM_N {
        qrc_keccak_squeezeblocks(kctx, buf, 1, QRC_KECCAK_128_RATE, QRC_KECCAK_PERMUTATION_ROUNDS);
        ctr += dilithium_rej_eta(&mut a.coeffs[ctr..], QRC_DILITHIUM_N - ctr, buf, QRC_KECCAK_128_RATE);
    }
}

fn dilithium_poly_uniform_gamma1(a: &mut QrcDilithiumPoly, seed: &[u8], nonce: u16) {
    let buf = &mut [0u8; DILITHIUM_POLY_UNIFORM_GAMMA1_NBLOCKS * QRC_KECCAK_256_RATE];
    let kctx = &mut QrcKeccakState::default();

    dilithium_shake256_stream_init(kctx, seed, nonce);
    qrc_keccak_squeezeblocks(kctx, buf, DILITHIUM_POLY_UNIFORM_GAMMA1_NBLOCKS, QRC_KECCAK_256_RATE, QRC_KECCAK_PERMUTATION_ROUNDS);
    dilithium_polyz_unpack(a, buf);
}

/* polyvec.c */

fn dilithium_polyvec_matrix_expand(mat: &mut [QrcDilithiumPolyvecl; QRC_DILITHIUM_K], rho: &[u8]) {
    for i in 0..QRC_DILITHIUM_K {
        for j in 0..QRC_DILITHIUM_L {
            dilithium_poly_uniform(&mut mat[i].vec[j], rho, ((i << 8) + j) as u16);
        }
    }
}

fn dilithium_polyvecl_pointwise_acc_montgomery(w: &mut QrcDilithiumPoly, u: QrcDilithiumPolyvecl, v: QrcDilithiumPolyvecl) {
    let t = &mut QrcDilithiumPoly::default();

    dilithium_poly_pointwise_montgomery(w, u.vec[0], v.vec[0]);

    for i in 1..QRC_DILITHIUM_L {
        dilithium_poly_pointwise_montgomery(t, u.vec[i], v.vec[i]);
        let w1 = w.clone();
        dilithium_poly_add(w, w1, t.clone());
    }
}

fn dilithium_polyvec_matrix_pointwise_montgomery(t: &mut QrcDilithiumPolyveck, mat: &[QrcDilithiumPolyvecl; QRC_DILITHIUM_K], v: QrcDilithiumPolyvecl) {
    for i in 0..QRC_DILITHIUM_K {
        dilithium_polyvecl_pointwise_acc_montgomery(&mut t.vec[i], mat[i], v);
    }
}

fn dilithium_polyvecl_uniform_eta(v: &mut QrcDilithiumPolyvecl, seed: &[u8], mut nonce: u16) {
    for i in 0..QRC_DILITHIUM_L {
        dilithium_poly_uniform_eta(&mut v.vec[i], seed, nonce);
        nonce += 1;
    }
}

fn dilithium_polyvecl_uniform_gamma1(v: &mut QrcDilithiumPolyvecl, seed: &[u8], nonce: u16) {
    for i in 0..QRC_DILITHIUM_L {
        dilithium_poly_uniform_gamma1(&mut v.vec[i], seed, ((QRC_DILITHIUM_L * nonce as usize) + i) as u16);
    }
}

fn dilithium_polyvecl_reduce(v: &mut QrcDilithiumPolyvecl) {
    for i in 0..QRC_DILITHIUM_L {
        dilithium_poly_reduce(&mut v.vec[i]);
    }
}

fn dilithium_polyvecl_add(w: &mut QrcDilithiumPolyvecl, u: QrcDilithiumPolyvecl, v: QrcDilithiumPolyvecl) {
    for i in 0..QRC_DILITHIUM_L {
        dilithium_poly_add(&mut w.vec[i], u.vec[i], v.vec[i]);
    }
}

fn dilithium_polyvecl_ntt(v: &mut QrcDilithiumPolyvecl) {
    for i in 0..QRC_DILITHIUM_L {
        dilithium_poly_ntt(&mut v.vec[i]);
    }
}

fn dilithium_polyvecl_invntt_to_mont(v: &mut QrcDilithiumPolyvecl) {
    for i in 0..QRC_DILITHIUM_L {
        dilithium_poly_invntt_to_mont(&mut v.vec[i]);
    }
}

fn dilithium_polyvecl_pointwise_poly_montgomery(r: &mut QrcDilithiumPolyvecl, a: QrcDilithiumPoly, v: QrcDilithiumPolyvecl) {
    for i in 0..QRC_DILITHIUM_L {
        dilithium_poly_pointwise_montgomery(&mut r.vec[i], a, v.vec[i]);
    }
}

fn dilithium_polyvecl_chknorm(v: QrcDilithiumPolyvecl, bound: i32) -> i32 {
    let mut res = 0;

    for i in 0..QRC_DILITHIUM_L {
        if dilithium_poly_chknorm(v.vec[i], bound) != 0 {
            res = 1;
            break;
        }
    }

    return res;
}

fn dilithium_polyveck_uniform_eta(v: &mut QrcDilithiumPolyveck, seed: &[u8], mut nonce: u16) {
    for i in 0..QRC_DILITHIUM_K {
        dilithium_poly_uniform_eta(&mut v.vec[i], seed, nonce);
        nonce += 1;
    }
}

fn dilithium_polyveck_reduce(v: &mut QrcDilithiumPolyveck) {
    for i in 0..QRC_DILITHIUM_K {
        dilithium_poly_reduce(&mut v.vec[i]);
    }
}

fn dilithium_polyveck_caddq(v: &mut QrcDilithiumPolyveck) {
    for i in 0..QRC_DILITHIUM_K {
        dilithium_poly_caddq(&mut v.vec[i]);
    }
}

fn dilithium_polyveck_add(w: &mut QrcDilithiumPolyveck, u: QrcDilithiumPolyveck, v: QrcDilithiumPolyveck) {
    for i in 0..QRC_DILITHIUM_K {
        dilithium_poly_add(&mut w.vec[i], u.vec[i], v.vec[i]);
    }
}

fn dilithium_polyveck_sub(w: &mut QrcDilithiumPolyveck, u: QrcDilithiumPolyveck, v: QrcDilithiumPolyveck) {
    for i in 0..QRC_DILITHIUM_K {
        dilithium_poly_sub(&mut w.vec[i], u.vec[i], v.vec[i]);
    }
}

fn dilithium_polyveck_shiftl(v: &mut QrcDilithiumPolyveck) {
    for i in 0..QRC_DILITHIUM_K {
        dilithium_poly_shiftl(&mut v.vec[i]);
    }
}

fn dilithium_polyveck_ntt(v: &mut QrcDilithiumPolyveck) {
    for i in 0..QRC_DILITHIUM_K {
        dilithium_poly_ntt(&mut v.vec[i]);
    }
}

fn dilithium_polyveck_invntt_to_mont(v: &mut QrcDilithiumPolyveck) {
    for i in 0..QRC_DILITHIUM_K {
        dilithium_poly_invntt_to_mont(&mut v.vec[i]);
    }
}

fn dilithium_polyveck_pointwise_poly_montgomery(r: &mut QrcDilithiumPolyveck, a: QrcDilithiumPoly, v: QrcDilithiumPolyveck) {
    for i in 0..QRC_DILITHIUM_K {
        dilithium_poly_pointwise_montgomery(&mut r.vec[i], a, v.vec[i]);
    }
}

fn dilithium_polyveck_chknorm(v: QrcDilithiumPolyveck, bound: i32) -> i32 {
    let mut res = 0;

    for i in 0..QRC_DILITHIUM_K {
        if dilithium_poly_chknorm(v.vec[i], bound) != 0 {
            res = 1;
            break;
        }
    }

    return res;
}

fn dilithium_polyveck_power2_round(v1: &mut QrcDilithiumPolyveck, v0: &mut QrcDilithiumPolyveck, v: QrcDilithiumPolyveck) {
    for i in 0..QRC_DILITHIUM_K {
        dilithium_poly_power2_round(&mut v1.vec[i], &mut v0.vec[i], v.vec[i]);
    }
}

fn dilithium_polyveck_decompose(v1: &mut QrcDilithiumPolyveck, v0: &mut QrcDilithiumPolyveck, v: QrcDilithiumPolyveck) {
    for i in 0..QRC_DILITHIUM_K {
        dilithium_poly_decompose(&mut v1.vec[i], &mut v0.vec[i], v.vec[i]);
    }
}

fn dilithium_polyveck_make_hint(h: &mut QrcDilithiumPolyveck, v0: QrcDilithiumPolyveck, v1: QrcDilithiumPolyveck) -> u32 {
    let mut s = 0;

    for i in 0..QRC_DILITHIUM_K {
        s += dilithium_poly_make_hint(&mut h.vec[i], v0.vec[i], v1.vec[i]);
    }

    return s;
}

fn dilithium_polyveck_use_hint(w: &mut QrcDilithiumPolyveck, u: QrcDilithiumPolyveck, h: QrcDilithiumPolyveck) {
    for i in 0..QRC_DILITHIUM_K {
        dilithium_poly_use_hint(&mut w.vec[i], u.vec[i], h.vec[i]);
    }
}

fn dilithium_polyveck_pack_w1(r: &mut [u8], w1: QrcDilithiumPolyveck) {
    for i in 0..QRC_DILITHIUM_K {
        dilithium_polyw1_pack(&mut r[i * DILITHIUM_POLYW1_PACKEDBYTES..], w1.vec[i]);
    }
}

/* packing.c */

fn dilithium_pack_pk(mut pk: &mut [u8], rho: &[u8], t1: QrcDilithiumPolyveck) {
    for i in 0..DILITHIUM_SEEDBYTES {
        pk[i] = rho[i];
    }

    pk = &mut pk[DILITHIUM_SEEDBYTES..];

    for i in 0..QRC_DILITHIUM_K {
        dilithium_polyt1_pack(&mut pk[i * DILITHIUM_POLYT1_PACKEDBYTES..], t1.vec[i]);
    }
}

fn dilithium_unpack_pk(rho: &mut [u8], t1: &mut QrcDilithiumPolyveck, mut pk: &[u8]) {
    for i in 0..DILITHIUM_SEEDBYTES {
        rho[i] = pk[i];
    }

    pk = &pk[DILITHIUM_SEEDBYTES..];

    for i in 0..QRC_DILITHIUM_K {
        dilithium_polyt1_unpack(&mut t1.vec[i], &pk[i * DILITHIUM_POLYT1_PACKEDBYTES..]);
    }
}

fn dilithium_pack_sk(mut sk: &mut [u8], rho: &[u8], tr: &[u8], key: &[u8], t0: QrcDilithiumPolyveck, s1: QrcDilithiumPolyvecl, s2: QrcDilithiumPolyveck) {
    qrc_intutils_copy8(sk, rho, DILITHIUM_SEEDBYTES);
    sk = &mut sk[DILITHIUM_SEEDBYTES..];

    qrc_intutils_copy8(sk, key, DILITHIUM_SEEDBYTES);
    sk = &mut sk[DILITHIUM_SEEDBYTES..];

    qrc_intutils_copy8(sk, tr, DILITHIUM_CRHBYTES);
    sk = &mut sk[DILITHIUM_CRHBYTES..];


    for i in 0..QRC_DILITHIUM_L {
        dilithium_polyeta_pack(&mut sk[i * DILITHIUM_POLYETA_PACKEDBYTES..], s1.vec[i]);
    }
    sk = &mut sk[QRC_DILITHIUM_L * DILITHIUM_POLYETA_PACKEDBYTES..];

    for i in 0..QRC_DILITHIUM_K {
        dilithium_polyeta_pack(&mut sk[i * DILITHIUM_POLYETA_PACKEDBYTES..], s2.vec[i]);
    }
    sk = &mut sk[QRC_DILITHIUM_K * DILITHIUM_POLYETA_PACKEDBYTES..];

    for i in 0..QRC_DILITHIUM_K {
        dilithium_polyt0_pack(&mut sk[i * DILITHIUM_POLYT0_PACKEDBYTES..], t0.vec[i]);
    }
}

fn dilithium_unpack_sk(rho: &mut [u8], tr: &mut [u8], key: &mut [u8], t0: &mut QrcDilithiumPolyveck, s1: &mut QrcDilithiumPolyvecl, s2: &mut QrcDilithiumPolyveck, mut sk: &[u8]) {
    qrc_intutils_copy8(rho, sk, DILITHIUM_SEEDBYTES);
    sk = &sk[DILITHIUM_SEEDBYTES..];

    qrc_intutils_copy8(key, sk, DILITHIUM_SEEDBYTES);
    sk = &sk[DILITHIUM_SEEDBYTES..];

    qrc_intutils_copy8(tr, sk, DILITHIUM_CRHBYTES);
    sk = &sk[DILITHIUM_CRHBYTES..];


    for i in 0..QRC_DILITHIUM_L {
        dilithium_polyeta_unpack(&mut s1.vec[i], &sk[i * DILITHIUM_POLYETA_PACKEDBYTES..]);
    }
    sk = &sk[QRC_DILITHIUM_L * DILITHIUM_POLYETA_PACKEDBYTES..];

    for i in 0..QRC_DILITHIUM_K {
        dilithium_polyeta_unpack(&mut s2.vec[i], &sk[i * DILITHIUM_POLYETA_PACKEDBYTES..]);
    }
    sk = &sk[QRC_DILITHIUM_K * DILITHIUM_POLYETA_PACKEDBYTES..];

    for i in 0..QRC_DILITHIUM_K {
        dilithium_polyt0_unpack(&mut t0.vec[i], &sk[i * DILITHIUM_POLYT0_PACKEDBYTES..]);
    }
}

fn dilithium_pack_sig(mut sig: &mut [u8], c: &[u8], z: QrcDilithiumPolyvecl, h: QrcDilithiumPolyveck) {
    for i in 0..DILITHIUM_SEEDBYTES {
        sig[i] = c[i];
    }

    sig = &mut sig[DILITHIUM_SEEDBYTES..];

    for i in 0..QRC_DILITHIUM_L {
        dilithium_polyz_pack(&mut sig[i * DILITHIUM_POLYZ_PACKEDBYTES..], z.vec[i]);
    }

    sig = &mut sig[QRC_DILITHIUM_L * DILITHIUM_POLYZ_PACKEDBYTES..];

    /* Encode h */
    qrc_intutils_clear8(sig, DILITHIUM_OMEGA + QRC_DILITHIUM_K);
    let mut k = 0;

    for i in 0..QRC_DILITHIUM_K {
        for j in 0..QRC_DILITHIUM_N {
            if h.vec[i].coeffs[j] != 0 {
                sig[k] = j as u8;
                k += 1;
            }
        }

        sig[DILITHIUM_OMEGA + i] = k as u8;
    }
}

fn dilithium_unpack_sig(c: &mut [u8], z: &mut QrcDilithiumPolyvecl, h: &mut QrcDilithiumPolyveck, mut sig: &[u8]) -> i32 {
    let mut res = 0;

    qrc_intutils_copy8(c, sig, DILITHIUM_SEEDBYTES);
    sig = &sig[DILITHIUM_SEEDBYTES..];

    for i in 0..QRC_DILITHIUM_L {
        dilithium_polyz_unpack(&mut z.vec[i], &sig[i * DILITHIUM_POLYZ_PACKEDBYTES..]);
    }

    sig = &sig[QRC_DILITHIUM_L * DILITHIUM_POLYZ_PACKEDBYTES..];

    /* Decode h */
    let mut k = 0usize;

    for i in 0..QRC_DILITHIUM_K {
        for j in 0..QRC_DILITHIUM_N {
            h.vec[i].coeffs[j] = 0;
        }

        if sig[DILITHIUM_OMEGA + i] < k as u8 || sig[DILITHIUM_OMEGA + i] > DILITHIUM_OMEGA as u8 {
            res = 1;
            break;
        }

        for j in k..sig[DILITHIUM_OMEGA + i] as usize {
            /* Coefficients are ordered for strong unforgeability */
            if j > k && sig[j] <= sig[j - 1] {
                res = 1;
                break;
            }

            h.vec[i].coeffs[sig[j] as usize] = 1;
        }

        if res != 0 {
            break;
        }

        k = sig[DILITHIUM_OMEGA + i] as usize;
    }

    if res == 0 {
        /* Extra indices are zero for strong unforgeability */
        for j in k..DILITHIUM_OMEGA {
            if sig[j] != 0 {
                res = 1;
                break;
            }
        }
    }

    return res;
}
