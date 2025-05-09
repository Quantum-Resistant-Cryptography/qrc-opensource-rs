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

/* \cond DOXYGEN_IGNORE */

use crate::{asymmetric::cipher::ecdhbody::ec25519base::{ge25519_double_scalarmult_vartime, ge25519_frombytes_negate_vartime, ge25519_has_small_order, ge25519_is_canonical, Ge25519P2, Ge25519P3, ge25519_p3_tobytes, ge25519_scalarmult_base, ge25519_tobytes, qrc_sc25519_verify, sc25519_clamp, sc25519_is_canonical, sc25519_muladd, sc25519_reduce, QRC_EC25519_PUBLICKEY_SIZE, QRC_EC25519_SEED_SIZE, QRC_EC25519_SIGNATURE_SIZE}, digest::sha2::{qrc_sha512_compute, qrc_sha512_finalize, qrc_sha512_initialize, qrc_sha512_update, QrcSha512State}, tools::intutils::{qrc_intutils_are_equal8, qrc_intutils_clear8, qrc_intutils_copy8}};

#[cfg(feature = "no_std")]
use alloc::borrow::ToOwned;

/*
* \brief Combine and external public key with an internal private key to produce a shared secret
*
* \warning Arrays must be sized to QRC_ECDH_PUBLICKEY_SIZE and QRC_ECDH_SECRETKEY_SIZE.
*
* \param publickey: Pointer to the output public-key array
* \param privatekey: Pointer to output private-key array
* \param secret: The shared secret
*/
pub fn qrc_ed25519_keypair(publickey: &mut [u8], privatekey: &mut [u8], seed: &[u8]) {
	let a = &mut Ge25519P3::default();

	qrc_sha512_compute(privatekey, seed, QRC_EC25519_SEED_SIZE);
	sc25519_clamp(privatekey);

	ge25519_scalarmult_base(a, privatekey);
	ge25519_p3_tobytes(publickey, a.clone());

	qrc_intutils_copy8(privatekey, seed, QRC_EC25519_SEED_SIZE);
	qrc_intutils_copy8(&mut privatekey[QRC_EC25519_SEED_SIZE..], publickey, QRC_EC25519_PUBLICKEY_SIZE);
}

/*
* \brief Takes the message as input and returns an array containing the signature followed by the message.
*
* \param signedmsg: The signed message
* \param smsglen: The signed message length
* \param message: [const] The message to be signed
* \param msglen: The message length
* \param secretkey: [const] The private signature key
* \return Returns 0 for success
*/
pub fn qrc_ed25519_sign(signedmsg: &mut [u8], smsglen: &mut usize, message: &[u8], msglen: usize, privatekey: &[u8]) -> i32 {
	qrc_intutils_copy8(&mut signedmsg[QRC_EC25519_SIGNATURE_SIZE..], message, msglen);

	let slen = &mut 0;
	let mut res = 0;

	let m = &signedmsg[QRC_EC25519_SIGNATURE_SIZE..].to_owned();
	if ecdsa_ed25519_sign(signedmsg, slen, m, msglen, privatekey) != 0 || slen.clone() != QRC_EC25519_SIGNATURE_SIZE {
		*smsglen = 0;
		qrc_intutils_clear8(signedmsg, msglen + QRC_EC25519_SIGNATURE_SIZE);
		res = -1;
	} else {
		*smsglen = msglen + slen.clone();
	}

	return res;
}

/*
* \brief Verifies a signature-message pair with the public key.
*
* \param message: The message to be signed
* \param msglen: The message length
* \param signedmsg: [const] The signed message
* \param smsglen: The signed message length
* \param publickey: [const] The public verification key
* \return Returns 0 for success
*/
pub fn qrc_ed25519_verify(message: &mut [u8], msglen: &mut usize, signedmsg: &[u8], smsglen: usize, publickey: &[u8]) -> i32 {
	let msglen1 = smsglen - QRC_EC25519_SIGNATURE_SIZE;
	let mut res = 0;

	if ecdsa_ed25519_verify(signedmsg, &signedmsg[QRC_EC25519_SIGNATURE_SIZE..], msglen1, publickey) == false {
		qrc_intutils_clear8(message, msglen1);
		*msglen = 0;
		res = -1;
	} else {
		*msglen = msglen1;
		qrc_intutils_copy8(message, &signedmsg[QRC_EC25519_SIGNATURE_SIZE..], msglen1);
	}

	return res;
}

/* \endcond DOXYGEN_IGNORE */

fn ecdsa_ed25519_sign(sm: &mut [u8], smlen: &mut usize, m: &[u8], mlen: usize, sk: &[u8]) -> i32 {
	let az = &mut [0u8; 64];
	let nonce = &mut [0u8; 64];
	let hram = &mut [0u8; 64];
	let ctx = &mut QrcSha512State::default();
	let r = &mut Ge25519P3::default();

	/* hash 1st half of sk to az */
	qrc_sha512_compute(az, sk, 32);

	qrc_sha512_initialize(ctx);
	/* update with 2nd half of az */
	qrc_sha512_update(ctx, &az[32..], 32);
	/* update hash with m */
	qrc_sha512_update(ctx, m, mlen);
	/* finalize to nonce */
	qrc_sha512_finalize(ctx, nonce);

	/* move 2nd half of sk to 2nd half of sig */
	qrc_intutils_copy8(&mut sm[32..], &sk[32..], 32);
    /* reduce nonce */
	sc25519_reduce(nonce);
    /* scalar on nonce */
	ge25519_scalarmult_base(r, nonce);
	/* scalar to 1st half of sig */
	ge25519_p3_tobytes(sm, r.clone());

	qrc_sha512_initialize(ctx);
	/* update hash with sig */
	qrc_sha512_update(ctx, sm, 64);
	/* update hash with message */
	qrc_sha512_update(ctx, m, mlen);
	/* finalize to hram */
	qrc_sha512_finalize(ctx, hram);
    /* reduce hram */
	sc25519_reduce(hram);
	/* clamp az */
	sc25519_clamp(az);
	/* muladd hram, az, nonce to 2nd half of sig */
	sc25519_muladd(&mut sm[32..], &hram.clone(), &az.clone(), &nonce.clone());

	/* cleanup */
	qrc_intutils_clear8(az, 64);
	qrc_intutils_clear8(nonce, 64);

	*smlen = 64;
	return 0;
}

fn ecdsa_ed25519_verify(sig: &[u8], m: &[u8], mlen: usize, pk: &[u8]) -> bool {
	let ctx = &mut QrcSha512State::default();
	let h = &mut [0u8; 64];
	let rcheck = &mut [0u8; 32];
	let a = &mut Ge25519P3::default();
	let r = &mut Ge25519P2::default();

	let mut res = true;

	if (sig[63] & 240) == 0 && sc25519_is_canonical(&sig[32..]) == 0 {
		res = false;
	} else if ge25519_has_small_order(sig) != 0 {
		res = false;
	} else if ge25519_is_canonical(pk) == 0 || ge25519_has_small_order(pk) != 0 {
		res = false;
	} else if ge25519_frombytes_negate_vartime(a, pk) != 0 {
		res = false;
	}

	if res == true {
		qrc_sha512_initialize(ctx);
		qrc_sha512_update(ctx, sig, 32);
		qrc_sha512_update(ctx, pk, 32);
		qrc_sha512_update(ctx, m, mlen);
		qrc_sha512_finalize(ctx, h);
		sc25519_reduce(h);

		ge25519_double_scalarmult_vartime(r, h, a.clone(), &sig[32..]);
		ge25519_tobytes(rcheck, r.clone());

		if ((qrc_sc25519_verify(rcheck, sig, 32) == 0) | ((!(rcheck == sig)))) != true || (qrc_intutils_are_equal8(sig, rcheck, 32) == false) {
			res = false;
		}
	}

	return res;
}