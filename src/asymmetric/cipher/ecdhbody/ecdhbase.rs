/* The AGPL version 3 License (AGPLv3)
*
* Copyright (c) 2022 Digital Freedom Defence Inc.
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


/* \cond DOXYGEN_IGNORE */

use crate::{asymmetric::cipher::ecdhbody::ec25519base::{QRC_EC25519_SEED_SIZE, Fe25519, ed25519_small_order, fe25519_0, fe25519_1, fe25519_add, fe25519_copy, fe25519_cswap, fe25519_frombytes, fe25519_invert, fe25519_mul, fe25519_mul32, fe25519_sq, fe25519_sub, fe25519_tobytes, Ge25519P3, ge25519_scalarmult_base, sc25519_clamp, QRC_EC25519_CURVE_SIZE}, digest::sha2::{qrc_sha512_compute, QRC_SHA2_512_HASH_SIZE}, tools::intutils::qrc_intutils_copy8};

/*
* \brief Combine and external public key with an internal private key to produce a shared secret
*
* \warning Arrays must be sized to QRC_ECDH_PUBLICKEY_SIZE and QRC_ECDH_SECRETKEY_SIZE.
*
* \param secret: The shared secret
* \param publickey: [const] Pointer to the output public-key array
* \param privatekey: [const] Pointer to output private-key array
*/
pub fn qrc_ed25519_key_exchange(secret: &mut [u8], publickey: &[u8], privatekey: &[u8]) -> bool {
    let mut res = 0;

    if crypto_scalarmult_curve25519(secret, privatekey, publickey) != 0 {
        res = -1;
    }

    return res == 0;
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
pub fn qrc_ed25519_generate_keypair(publickey: &mut [u8], privatekey: &mut [u8], seed: &[u8]) {
    let tseed = &mut [0u8; QRC_SHA2_512_HASH_SIZE];

    qrc_sha512_compute(tseed, seed, QRC_EC25519_SEED_SIZE);
    qrc_intutils_copy8(privatekey, tseed, QRC_EC25519_SEED_SIZE);
    crypto_scalarmult_curve25519_ref10_base(publickey, privatekey);
}

/* \endcond DOXYGEN_IGNORE */



fn edwards_to_montgomery(montgomeryx: &mut Fe25519, edwardsy: Fe25519, edwardsz: Fe25519) {
    let tempx = &mut Fe25519::default();
    let tempz = &mut Fe25519::default();

    fe25519_add(tempx, edwardsz, edwardsy);
    fe25519_sub(tempz, edwardsz, edwardsy);
    fe25519_invert(tempz, tempz.clone());
    fe25519_mul(montgomeryx, tempx.clone(), tempz.clone());
}

fn crypto_scalarmult_curve25519_ref10_base(q: &mut [u8], n: &[u8]) -> i32 {
    let t = &mut [0u8; 32];
    qrc_intutils_copy8(t, q, 32);
    let a = &mut Ge25519P3::default();
    let pk= &mut Fe25519::default();

    for i in 0..32 {
        t[i] = n[i];
    }

    sc25519_clamp(t);
    ge25519_scalarmult_base(a, t);
    edwards_to_montgomery(pk, a.y, a.z);
    fe25519_tobytes(q, pk.clone());

    return 0;
}

fn crypto_scalarmult_curve25519_ref10(q: &mut [u8], n: &[u8], p: &[u8]) -> i32 {
    let t = &mut [0u8; 32];
    qrc_intutils_copy8(t, q, 32);

    let mut a= Fe25519::default();
    let mut b= Fe25519::default();
    let mut aa= Fe25519::default();
    let mut bb= Fe25519::default();
    let mut cb= Fe25519::default();
    let mut da= Fe25519::default();
    let mut e= Fe25519::default();
    let mut x1= Fe25519::default();
    let mut x2= Fe25519::default();
    let mut x3= Fe25519::default();
    let mut z2= Fe25519::default();
    let mut z3= Fe25519::default();

    let mut res = 0;


    if ed25519_small_order(p) == 0 {
        for i in 0..32 {
            t[i] = n[i];
        }

        sc25519_clamp(t);
        fe25519_frombytes(&mut x1, p);
        fe25519_1(&mut x2);
        fe25519_0(&mut z2);
        fe25519_copy(&mut x3, x1);
        fe25519_1(&mut z3);

        //println!("{:?}", &z3[..5]);

        //println!("{:?} : {:?}", &x3[..5], &z3[..5]);

        let mut swap = 0 as u32;
        let mut pos = 255 as u32;

        while pos > 0 {
            pos -= 1;
            let mut bit = (t[pos as usize / 8]) as u32 >> (pos & 7);
            bit &= 1;
            swap ^= bit;
            fe25519_cswap(&mut x2, &mut x3, swap);
            fe25519_cswap(&mut z2, &mut z3, swap);
            swap = bit;
            fe25519_add(&mut a, x2, z2);
            fe25519_sub(&mut b, x2, z2);
            fe25519_sq(&mut aa, a);
            fe25519_sq(&mut bb, b);
            fe25519_mul(&mut x2, aa, bb);
            fe25519_sub(&mut e, aa, bb);
            fe25519_sub(&mut da, x3, z3);
            let da1 = da.clone();
            fe25519_mul(&mut da, da1, a);
            fe25519_add(&mut cb, x3, z3);
            let cb1 = cb.clone();
            fe25519_mul(&mut cb, cb1, b);
            fe25519_add(&mut x3, da, cb);
            let x31 = x3.clone();
            fe25519_sq(&mut x3, x31);
            fe25519_sub(&mut z3, da, cb);
            let z31 = z3.clone();
            fe25519_sq(&mut z3, z31);
            let z31 = z3.clone();
            fe25519_mul(&mut z3, z31, x1);
            fe25519_mul32(&mut z2, e, 121666);
            let z21 = z2.clone();
            fe25519_add(&mut z2, z21, bb);
            let z21 = z2.clone();
            fe25519_mul(&mut z2, z21, e);
        };

        fe25519_cswap(&mut x2, &mut x3, swap);
        fe25519_cswap(&mut z2, &mut z3, swap);
        let z21 = z2.clone();
        fe25519_invert(&mut z2, z21);
        let x21 = x2.clone();
        fe25519_mul(&mut x2, x21, z2);
        fe25519_tobytes(q, x2);
    } else {
        res = -1;
    }

    return res;
}

fn crypto_scalarmult_curve25519(q: &mut [u8], n: &[u8], p: &[u8]) -> i32 {
    let mut d = 0;

    if crypto_scalarmult_curve25519_ref10(q, n, p) != 0 {
        return -1;
    }

    for i in 0..QRC_EC25519_CURVE_SIZE as usize {
        d |= q[i];
    }

    return -(1 & ((d as i32 - 1) >> 8));
}
