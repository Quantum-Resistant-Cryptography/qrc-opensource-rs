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

use crate::{asymmetric::asymmetric::AsymmetricRandState, common::common::{QRC_MCELIECE_S3N4608T96, QRC_MCELIECE_S5N6688T128, QRC_MCELIECE_S5N6960T119, QRC_MCELIECE_S5N8192T128}, digest::sha3::qrc_shake256_compute, tools::intutils::{qrc_intutils_clear16, qrc_intutils_clear16i, qrc_intutils_clear32i, qrc_intutils_clear8, qrc_intutils_clear8all, qrc_intutils_copy16, qrc_intutils_copy64, qrc_intutils_copy8, qrc_intutils_min, qrc_intutils_transform_32to8, qrc_intutils_transform_8to16, qrc_intutils_transform_itou_16, qrc_intutils_transform_itou_32, qrc_intutils_transform_utoi_16}};

use core::mem::size_of;

#[cfg(feature = "no_std")]
use alloc::{vec, borrow::ToOwned};


 /* \cond DOXYGEN_IGNORE */
 
 /* operations.h */
 
 /*
 * \brief Decapsulates the shared secret for a given cipher-text using a private-key
 *
 * \param key: Pointer to a shared secret key, an array of QRC_MCELIECE_SHAREDSECRET_SIZE constant size
 * \param c: [const] Pointer to the cipher-text array of QRC_MCELIECE_CIPHERTEXT_SIZE constant size
 * \param sk: [const] Pointer to the secret-key array of QRC_MCELIECE_PRIVATEKEY_SIZE constant size
 * \return Returns 0 for success
 */
 pub fn qrc_mceliece_ref_decapsulate(key: &mut [u8], c: &[u8], sk: &[u8]) -> i32 {
	let conf = &mut [0u8; 32];

	let preimage = &mut [0u8; 1 + MCELIECE_SYS_N / 8 + (MCELIECE_SYND_BYTES + 32)];
	let two_e = &mut [0u8; 1 + MCELIECE_SYS_N / 8];

	let s = &sk[40 + MCELIECE_IRR_BYTES + MCELIECE_COND_BYTES..];

	two_e[0] = 2;
	let mut ret_confirm = 0;
	let ret_decrypt = decrypt(&mut two_e[1..], &sk[40..], c) as u8;

	qrc_shake256_compute(conf, MCELIECE_SHAREDSECRET_SIZE, two_e, 1 + MCELIECE_SYS_N / 8);

	for i in 0..32 {
		ret_confirm |= conf[i] ^ c[MCELIECE_SYND_BYTES + i];
	}

	let mut m = (ret_decrypt | ret_confirm) as u16;
	m = m.wrapping_sub(1);
	m >>= 8;

	preimage[0] = m as u8 & 1;

	for i in 0..MCELIECE_SYS_N / 8 {
		preimage[i+1] = (!m as u8 & s[i]) | (m as u8 & two_e[1..][i]);
	}

	for i in 0..MCELIECE_SYND_BYTES + 32 {
		preimage[i+1+(MCELIECE_SYS_N / 8)] = c[i];
	}

	qrc_shake256_compute(key, MCELIECE_SHAREDSECRET_SIZE, preimage, 1 + MCELIECE_SYS_N / 8 + (MCELIECE_SYND_BYTES + 32));

	if QRC_MCELIECE_S5N6960T119 {
		// clear outputs (set to all 1's) if padding bits are not all zero
		let padding_ok = check_c_padding(c);
		let mask = padding_ok as u8;

		for i in 0..32 {
			key[i] |= mask;
		}

		return (ret_decrypt.wrapping_add(ret_confirm)) as i32 + padding_ok;
	} else {
		return (ret_decrypt.wrapping_add(ret_confirm)) as i32;
	}
}

 /*
 * \brief Generates cipher-text and encapsulates a shared secret key using a public-key
 *
 * \param secret: Pointer to a shared secret, a uint8_t array of QRC_MCELIECE_SHAREDSECRET_SIZE
 * \param ciphertext: Pointer to the cipher-text array
 * \param publickey: [const] Pointer to the public-key array
 * \param rng_generate: Pointer to the random generator
 * \return Returns 0 for success
 */
pub fn qrc_mceliece_ref_encapsulate(asymmetric_state: &mut AsymmetricRandState, c: &mut [u8], key: &mut [u8], pk: &[u8], rng_generate: fn(&mut AsymmetricRandState, &mut [u8], usize) -> bool) -> i32 {
	let one_ec = &mut [0u8; 1 + MCELIECE_SYS_N / 8 + (MCELIECE_SYND_BYTES + 32)];
	let two_e = &mut [0u8; 1 + MCELIECE_SYS_N / 8];
	let e = &mut two_e.to_owned()[1..];

	one_ec[0] = 1;
	two_e[0] = 2;
	encrypt(asymmetric_state, c, pk, e, rng_generate);
	qrc_intutils_copy8(&mut two_e[1..], e, MCELIECE_SYS_N / 8);

	qrc_shake256_compute(&mut c[MCELIECE_SYND_BYTES..], MCELIECE_SHAREDSECRET_SIZE, two_e, 1 + MCELIECE_SYS_N / 8);
	qrc_intutils_copy8(&mut one_ec[1..], e, MCELIECE_SYS_N / 8);
	qrc_intutils_copy8(&mut one_ec[1 + MCELIECE_SYS_N / 8..], c, MCELIECE_SYND_BYTES + 32);
	qrc_shake256_compute(key, MCELIECE_SHAREDSECRET_SIZE, one_ec, 1 + MCELIECE_SYS_N / 8 + (MCELIECE_SYND_BYTES + 32));

	if QRC_MCELIECE_S5N6960T119 {
		/* clear outputs(set to all 0's) if padding bits are not all zero */
		let padding_ok: i32 = check_pk_padding(pk);

		let mut mask = padding_ok;
		mask ^= 0xFF;

		for i in 0..(MCELIECE_SYND_BYTES + 32) {
			c[i] &= mask as u8;
		}

		for i in 0..32 {
			key[i] &= mask as u8;
		}

		return padding_ok;
	} else {
		return 0;
	}
}
 
 /*
 * \brief Generates public and private key for the McEliece key encapsulation mechanism
 *
 * \warning Arrays must be sized to QRC_QRC_MCELIECE_PUBLICKEY_SIZE and QRC_QRC_MCELIECE_SECRETKEY_SIZE.
 *
 * \param publickey: Pointer to the output public-key array of QRC_MCELIECE_PUBLICKEY_SIZE constant size
 * \param privatekey: Pointer to output private-key array of QRC_MCELIECE_PRIVATEKEY_SIZE constant size
 * \param rng_generate: Pointer to the random generator function
 * \return Returns 0 for success
 */
 pub fn qrc_mceliece_ref_generate_keypair(asymmetric_state: &mut AsymmetricRandState, pk: &mut [u8], sk: &mut [u8], rng_generate: fn(&mut AsymmetricRandState, &mut [u8], usize) -> bool) -> i32 {
	let perm = &mut [0u32; 1 << MCELIECE_GFBITS];	/* random permutation as 32-bit integers */
	let pi = &mut [0i16; 1 << MCELIECE_GFBITS];	/* random permutation */
	let f: &mut [Gf; MCELIECE_SYS_T] = &mut [0; MCELIECE_SYS_T];		/* element in GF(2 ^ mt) */
	let irr: &mut [Gf; MCELIECE_SYS_T] = &mut [0; MCELIECE_SYS_T];				/* Goppa polynomial */
	let r = &mut[0u8; (MCELIECE_SYS_N / 8) + ((1 << MCELIECE_GFBITS) * size_of::<u32>()) + (MCELIECE_SYS_T * 2) + 32];
	let seed = &mut [0u8; 33];
    let mut skp: &mut [u8];

	seed[0] = 64;

	rng_generate(asymmetric_state, &mut seed[1..], 32);
	
	loop {	
		let mut rp_start = (MCELIECE_SYS_N / 8) + ((1 << MCELIECE_GFBITS) * size_of::<u32>()) + (MCELIECE_SYS_T * 2);
		skp = sk;

		/* expanding and updating the seed */
		let rlen = (MCELIECE_SYS_N / 8) + ((1 << MCELIECE_GFBITS) * size_of::<u32>()) + (MCELIECE_SYS_T * 2) + 32;
		qrc_shake256_compute(r, rlen, seed, 33);
		qrc_intutils_copy8(skp, &seed[1..], 32);
		skp = &mut skp[32 + 8..];

		qrc_intutils_copy8(&mut seed[1..], &r[(rlen - 32)..], 32);

		/* generating irreducible polynomial */
		rp_start -= MCELIECE_SYS_T*2;
        let rp = &mut r[rp_start..];

		for i in 0..MCELIECE_SYS_T {
			f[i] = load_gf(&rp[(i * 2)..]);
		}

		if genpoly_gen(irr, f) != 0 {
			continue;
		}

		for i in 0..MCELIECE_SYS_T {
			store_gf(&mut skp[i * 2..], irr[i]);
		}
		
		let skp_clone = &skp.to_owned();
		skp = &mut skp[MCELIECE_IRR_BYTES..];

		/* generating permutation */
		rp_start -= (1 << MCELIECE_GFBITS)*4;
        let rp = &mut r[rp_start..];


		for i in 0..(1 << MCELIECE_GFBITS) {
			perm[i] = load4(&rp[i * 4..]);
		}

		if pk_gen(pk, skp_clone, perm, pi) != 0 {
			continue;
		}

		controlbits_from_permutation(skp, pi, MCELIECE_GFBITS as i64, 1 << MCELIECE_GFBITS);
		skp = &mut skp[MCELIECE_COND_BYTES..];

		/* storing the random string s */
		rp_start -= MCELIECE_SYS_N / 8;
        let rp = &mut r[rp_start..];

		qrc_intutils_copy8(skp, rp, MCELIECE_SYS_N / 8);

		/* storing positions of the 32 pivots */
		store8(&mut sk[32..], 0x00000000FFFFFFFF);
		break;
	}

	return 0;
}

 
 /* \endcond DOXYGEN_IGNORE */
 

/* params.h */

pub const MCELIECE_SHAREDSECRET_SIZE: usize = 32;

pub const MCELIECE_GFBITS: usize = if QRC_MCELIECE_S3N4608T96 {
    13
} else if QRC_MCELIECE_S5N6688T128 {
    13
} else if QRC_MCELIECE_S5N6960T119 {
    13
} else if QRC_MCELIECE_S5N8192T128 {
    13
} else {
    0
};
pub const MCELIECE_SYS_N: usize = if QRC_MCELIECE_S3N4608T96 {
    4608
} else if QRC_MCELIECE_S5N6688T128 {
    6688
} else if QRC_MCELIECE_S5N6960T119 {
    6960
} else if QRC_MCELIECE_S5N8192T128 {
    8192
} else {
    0
};
pub const MCELIECE_SYS_T: usize = if QRC_MCELIECE_S3N4608T96 {
    96
} else if QRC_MCELIECE_S5N6688T128 {
    128
} else if QRC_MCELIECE_S5N6960T119 {
    119
} else if QRC_MCELIECE_S5N8192T128 {
    128
} else {
    0
};
pub const MCELIECE_COND_BYTES: usize = (1 << (MCELIECE_GFBITS - 4)) * (2 * MCELIECE_GFBITS - 1);
pub const MCELIECE_IRR_BYTES: usize = MCELIECE_SYS_T * 2;
pub const MCELIECE_PK_NROWS: usize = MCELIECE_SYS_T * MCELIECE_GFBITS;
pub const MCELIECE_PK_NCOLS: usize = MCELIECE_SYS_N - MCELIECE_PK_NROWS;
pub const MCELIECE_PK_ROW_BYTES: usize = (MCELIECE_PK_NCOLS + 7) / 8;
pub const MCELIECE_SYND_BYTES: usize = (MCELIECE_PK_NROWS + 7) / 8;

type Gf = u16;
pub const MCELIECE_GFMASK: Gf = (1 << MCELIECE_GFBITS) - 1;

/* gf.c */

pub fn gf_is_zero(a: Gf) -> Gf {
	let mut t = a as u32;
	t = t.wrapping_sub(1);
	t >>= 19;

	return t as Gf;
}

pub fn gf_add(in0: Gf, in1: Gf) -> Gf {
	return in0 ^ in1;
}

pub fn gf_mul(in0: Gf, in1: Gf) -> Gf {
	let t0 = in0 as u64;
	let t1 = in1 as u64;
	let mut tmp = t0 * (t1 & 1);

	for i in 1..MCELIECE_GFBITS {
		tmp ^= t0 * (t1 & (1 << i));
	}

	let mut t = (tmp & 0x0000000001FF0000) as u64;
	tmp ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);
	t = tmp & 0x000000000000E000;
	tmp ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);

	return tmp as Gf & MCELIECE_GFMASK;
}

pub fn gf_sq2(int: Gf) -> Gf {

	/* input: field element in
	   return: (in^2)^2 */

	let bf: [u64; 4] = [ 0x1111111111111111, 0x0303030303030303, 0x000F000F000F000F, 0x000000FF000000FF ];
	let m: [u64; 4] = [ 0x0001FF0000000000, 0x000000FF80000000, 0x000000007FC00000, 0x00000000003FE000 ];

	let mut x = int as u64;
	x = (x | (x << 24)) & bf[3];
	x = (x | (x << 12)) & bf[2];
	x = (x | (x << 6)) & bf[1];
	x = (x | (x << 3)) & bf[0];

	for i in 0..4 {
		let t = x & m[i];
		x ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);
	}

	return x as Gf & MCELIECE_GFMASK;
}

pub fn gf_sqmul(int: Gf, m: Gf) -> Gf {
	/* input: field element in, m
	   return: (in^2)*m */

	let bm: [u64; 3] = [ 0x0000001FF0000000, 0x000000000FF80000, 0x000000000007E000 ];

	let mut t0 = int as u64;
	let t1 = m as u64;
	let mut x = (t1 << 6) * (t0 & (1 << 6));
	t0 ^= t0 << 7;

	x ^= t1 * (t0 & 0x0000000000004001);
	x ^= (t1 * (t0 & 0x0000000000008002)) << 1;
	x ^= (t1 * (t0 & 0x0000000000010004)) << 2;
	x ^= (t1 * (t0 & 0x0000000000020008)) << 3;
	x ^= (t1 * (t0 & 0x0000000000040010)) << 4;
	x ^= (t1 * (t0 & 0x0000000000080020)) << 5;

	for i in 0..3 {
		let t = x & bm[i];
		x ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);
	}

	return x as Gf & MCELIECE_GFMASK;
}

pub fn gf_sq2mul(int: Gf, m: Gf) -> Gf {
	/* input: field element in, m
	   return: ((in^2)^2)*m */
	let bm: [u64; 6] = [ 0x1FF0000000000000, 0x000FF80000000000, 0x000007FC00000000, 0x00000003FE000000, 0x0000000001FE0000, 0x000000000001E000 ];

	let mut t0 = int as u64;
	let t1 = m as u64;
	let mut x = (t1 << 18) * (t0 & (1 << 6));
	t0 ^= t0 << 21;

	x ^= t1 * (t0 & 0x0000000010000001);
	x ^= (t1 * (t0 & 0x0000000020000002)) << 3;
	x ^= (t1 * (t0 & 0x0000000040000004)) << 6;
	x ^= (t1 * (t0 & 0x0000000080000008)) << 9;
	x ^= (t1 * (t0 & 0x0000000100000010)) << 12;
	x ^= (t1 * (t0 & 0x0000000200000020)) << 15;

	for i in 0..6 {
		let t = x & bm[i];
		x ^= (t >> 9) ^ (t >> 10) ^ (t >> 12) ^ (t >> 13);
	}

	return x as Gf & MCELIECE_GFMASK;
}

pub fn gf_frac(den: Gf, num: Gf) -> Gf {
	/* input: field element den, num */
	/* return: (num/den) */

	let tmp_11 = gf_sqmul(den, den);				/* ^ 11 */
	let tmp_1111 = gf_sq2mul(tmp_11, tmp_11);		/* ^ 1111 */
	let mut out = gf_sq2(tmp_1111);
	out = gf_sq2mul(out, tmp_1111);						/* ^ 11111111 */
	out = gf_sq2(out);
	out = gf_sq2mul(out, tmp_1111);						/* ^ 111111111111 */

	return gf_sqmul(out, num);							/* ^ 1111111111110 = ^ -1 */
}

pub fn gf_inv(den: Gf) -> Gf {
	return gf_frac(den, 1);
}

pub fn bgf_mul(out: &mut [Gf], in0: &[Gf], in1: &[Gf]) {
	/* input: in0, in1 in GF((2^m)^t)
	   output: out = in0*in1 */

	let prod: &mut [Gf; MCELIECE_SYS_T * 2 - 1] = &mut [0; MCELIECE_SYS_T * 2 - 1];

	for i in 0..MCELIECE_SYS_T {
		for j in 0..MCELIECE_SYS_T {
			prod[i + j] ^= gf_mul(in0[i], in1[j]);
		}
	}

	for i in (MCELIECE_SYS_T..=((MCELIECE_SYS_T - 1) * 2)).rev() {
		if QRC_MCELIECE_S3N4608T96 {
			prod[i - MCELIECE_SYS_T + 10] ^= prod[i];
			prod[i - MCELIECE_SYS_T + 9] ^= prod[i];
			prod[i - MCELIECE_SYS_T + 6] ^= prod[i];
			prod[i - MCELIECE_SYS_T] ^= prod[i];
		} else if QRC_MCELIECE_S5N6688T128 || QRC_MCELIECE_S5N8192T128 {
			prod[i - MCELIECE_SYS_T + 7] ^= prod[i];
			prod[i - MCELIECE_SYS_T + 2] ^= prod[i];
			prod[i - MCELIECE_SYS_T + 1] ^= prod[i];
			prod[i - MCELIECE_SYS_T] ^= prod[i];
		} else if QRC_MCELIECE_S5N6960T119 {
			prod[i - MCELIECE_SYS_T + 8] ^= prod[i];
			prod[i - MCELIECE_SYS_T] ^= prod[i];
		}
	}

	qrc_intutils_copy16(out, prod, MCELIECE_SYS_T);
}

/* util.c */

pub fn store_gf(dest: &mut [u8], a: Gf) {
	dest[0] = a as u8 & 0x00FF;
	dest[1] = (a >> 8) as u8;
}

pub fn load_gf(src: &[u8]) -> u16 {
	let mut a = src[1] as u16;
	a <<= 8;
	a |= src[0] as u16;

	return a & MCELIECE_GFMASK;
}

pub fn load4(int: &[u8]) -> u32 {
	let mut ret = int[3] as u32;

	for i in (0..=2).rev() {
		ret <<= 8;
		ret |= int[i] as u32;
	}

	return ret;
}

pub fn store8(out: &mut [u8], int: u64) {
	out[0] = (int & 0xFF) as u8;
	out[1] = (int >> 0x08) as u8 & 0xFF;
	out[2] = (int >> 0x10) as u8 & 0xFF;
	out[3] = (int >> 0x18) as u8 & 0xFF;
	out[4] = (int >> 0x20) as u8 & 0xFF;
	out[5] = (int >> 0x28) as u8 & 0xFF;
	out[6] = (int >> 0x30) as u8 & 0xFF;
	out[7] = (int >> 0x38) as u8 & 0xFF;
}

pub fn load8(int: &[u8]) -> u64 {
	let mut ret = int[7] as u64;

	for i in (0..=6).rev()	{
		ret <<= 8;
		ret |= int[i] as u64;
	}

	return ret;
}

pub fn bitrev(mut a: Gf) -> Gf {
	a = ((a & 0x00FF) << 8) | ((a & 0xFF00) >> 8);
	a = ((a & 0x0F0F) << 4) | ((a & 0xF0F0) >> 4);
	a = ((a & 0x3333) << 2) | ((a & 0xCCCC) >> 2);
	a = ((a & 0x5555) << 1) | ((a & 0xAAAA) >> 1);

	return a >> 3;
}

/* sort */

pub fn int32_minmax(a: &mut i32, b: &mut i32) {
	let ab = *b ^ *a;
	let mut c = *b - *a;
	c ^= ab & (c ^ *b);
	c >>= 31;
	c &= ab;
	*a ^= c;
	*b ^= c;
}

pub fn int32_sort(x: &mut [i32], n: i64) {
	if n >= 2 {
		let mut top = 1;

		loop {
			if top >= n - top {
				break;
			};

			top += top;
		}

		let mut p = top;
		loop {
			if p <= 0 {
				break;
			};

			for i in 0..(n - p) {
				if (i & p) == 0 {
					let mut x1 = x[i as usize];
					let mut x2 = x[(i + p) as usize];
					int32_minmax(&mut x1, &mut x2);
					x[i as usize] = x1;
					x[(i + p) as usize] = x2;
				};
			}

			let mut q = top;
			loop {
				if q <= p {
					break;
				};

				for i in 0..(n - q) {
					if (i & p) == 0 {
						let mut a = x[(i + p) as usize];

						let mut r = q;
						loop {
							if r <= p {
								break;
							};
							int32_minmax(&mut a, &mut x[(i + r) as usize]);
							r >>= 1;
						}

						x[(i + p) as usize] = a;
					}
				}
				q >>= 1;
			}
			p >>= 1;
		}
	}
}

pub fn int64_minmax(a: &mut u64, b: &mut u64) {
	let mut c = b.wrapping_sub(*a);
	c >>= 63;
	c = (!c).wrapping_add(1);
	c &= *a ^ *b;
	*a ^= c;
	*b ^= c;
}

pub fn uint64_sort(x: &mut [u64], n: i64) {
	if n >= 2 {
		let mut top = 1;

		loop {
			if top >= n - top {
				break;
			};

			top += top;
		}

		let mut p = top;
		loop {
			if p <= 0 {
				break;
			};



			for i in 0..(n - p) {
				if (i & p) == 0 {
					let mut x1 = x[i as usize];
					let mut x2 = x[(i + p) as usize];
					int64_minmax(&mut x1, &mut x2);
					x[i as usize] = x1;
					x[(i + p) as usize] = x2;
				};
			}

			let mut q = top;
			loop {
				if q <= p {
					break;
				};

				for i in 0..(n - q) {
					if (i & p) == 0 {
						let mut a = x[(i + p) as usize];

						let mut r = q;
						loop {
							if r <= p {
								break;
							};
							int64_minmax(&mut a, &mut x[(i + r) as usize]);
							r >>= 1;
						}

						x[(i + p) as usize] = a;
					}
				}
				q >>= 1;
			}
			p >>= 1
		}
	}
}

/* root.c */

pub fn eval(f: &[Gf], a: Gf) -> Gf {
	/* input: polynomial f and field element a
	   return f(a) */
	let mut r = f[MCELIECE_SYS_T];
	let mut i = MCELIECE_SYS_T;

	loop {
		i -= 1;
		r = gf_mul(r, a);
		r = gf_add(r, f[i]);		

		if i <= 0 {
			break;
		};
	} 

	return r;
}

pub fn root(out: &mut [Gf], f: &[Gf], l: &[Gf]) {
	/* input: polynomial f and list of field elements L
	   output: out = [ f(a) for a in L ] */

	for i in 0..MCELIECE_SYS_N {
		out[i] = eval(f, l[i]);
	}
}

/* synd.c */

pub fn synd(out: &mut [Gf], f: &[Gf], l: &[Gf], r: &[u8]) {
	/* input: Goppa polynomial f, support L, received word r
	   output: out, the syndrome of length 2t */
	
	qrc_intutils_clear16(out, MCELIECE_SYS_T * 2);

	for i in 0..MCELIECE_SYS_N {
		let c = (r[i / 8] >> (i % 8)) & 1;
		let e = eval(f, l[i]);
		let mut e_inv = gf_inv(gf_mul(e, e));

		for j in 0..(2 * MCELIECE_SYS_T) {
			out[j] = gf_add(out[j], gf_mul(e_inv, c as Gf));
			e_inv = gf_mul(e_inv, l[i]);
		}
	}
}

/* transpose.c */

pub fn transpose_64x64(out: &mut [u64], int: &[u64]) {
	/* input: in, a 64x64 matrix over GF(2) */
	/* output: out, transpose of in */

	let masks: [[u64; 2]; 6] = [
		[0x5555555555555555, 0xAAAAAAAAAAAAAAAA],
		[0x3333333333333333, 0xCCCCCCCCCCCCCCCC],
		[0x0F0F0F0F0F0F0F0F, 0xF0F0F0F0F0F0F0F0],
		[0x00FF00FF00FF00FF, 0xFF00FF00FF00FF00],
		[0x0000FFFF0000FFFF, 0xFFFF0000FFFF0000],
		[0x00000000FFFFFFFF, 0xFFFFFFFF00000000]
	];

	qrc_intutils_copy64(out, int, 64);

	for d in (0..=5).rev() {
		let s = 1 << d;

		for i  in (0..64).step_by(s * 2) {
			for j in i..(i + s) {
				let x = (out[j] & masks[d][0]) | ((out[j + s] & masks[d][0]) << s);
				let y = ((out[j] & masks[d][1]) >> s) | (out[j + s] & masks[d][1]);
				out[j] = x;
				out[j + s] = y;
			}
		}
	}
}

/* benes.c */

pub fn layer_in(data: &mut [[u64; 64]; 2], mut bits: &[u64], lgs: i32) {
	/* middle layers of the benes network */
	let s = 1 << lgs;

	for i in (0..64).step_by(s * 2) {
		for j  in i..(i + s) {
			let mut d = data[0][j] ^ data[0][j + s];
			d &= bits[0];
			bits = &bits[1..];
			data[0][j] ^= d;
			data[0][j + s] ^= d;

			d = data[1][j] ^ data[1][j + s];
			d &= bits[0];
			bits = &bits[1..];
			data[1][j] ^= d;
			data[1][j + s] ^= d;
		}
	}
}

pub fn layer_ex(data: &mut [[u64; 64]; 2], mut bits: &[u64], lgs: i32) {
	let data_merge = &mut [0u64; 128];

	for i in 0..128 {
		if i < 64 {
			data_merge[i] = data[0][i];
		} else {
			data_merge[i] = data[1][i-64];
		}
	}

	/* first and last layers of the benes network */
	let s = 1 << lgs;

	for i in (0..128).step_by(s * 2) {
		for j in i..(i + s) {
			let mut d = data_merge[j] ^ data_merge[j + s];
			d &= bits[0];
			bits = &bits[1..];
			data_merge[j] ^= d;
			data_merge[j + s] ^= d;
		}
	}

	for i in 0..128 {
		if i < 64 {
			data[0][i] = data_merge[i];
		} else {
			data[1][i-64] = data_merge[i];
		}
	}
}

pub fn apply_benes(r: &mut [u8], bits: &[u8], rev: i32) {
	/* input: r, sequence of bits to be permuted bits, condition bits of the Benes network rev,
	0 for normal application, !0 for inverse output: r, permuted bits */

	let r_int_v = &mut [[0u64; 64]; 2];
	let r_int_h = &mut [[0u64; 64]; 2];
	let b_int_v = &mut [0u64; 64];
	let b_int_h = &mut [0u64; 64];
	let r_ptr = r;

	let mut bits_ptr = bits;         
	let mut inc = 0 as i32;

	if rev != 0 {
		bits_ptr = &bits[12288..]; 
		inc = -1024; 
	}

	for i in 0..64 {
		r_int_v[0][i] = load8(&r_ptr[i * 16..]);
		r_int_v[1][i] = load8(&r_ptr[i * 16 + 8..]);
	}
	
	transpose_64x64(&mut r_int_h[0], &r_int_v[0]);
	transpose_64x64(&mut r_int_h[1], &r_int_v[1]);

	for iter in 0..=6 {
		for i in 0..64 {
			b_int_v[i] = load8(bits_ptr); 
			bits_ptr = &bits_ptr[8..];
		}

		bits_ptr = &bits_ptr[inc as usize..];
		transpose_64x64(b_int_h, b_int_v);
		layer_ex(r_int_h, b_int_h, iter);

	}

	transpose_64x64(&mut r_int_v[0], &r_int_h[0]);
	transpose_64x64(&mut r_int_v[1], &r_int_h[1]);

	for iter in 0..=5 {
		for i in 0..64 { 
			b_int_v[i] = load8(bits_ptr); 
			bits_ptr = &bits_ptr[8..];
		}

		bits_ptr = &bits_ptr[inc as usize..];
		layer_in(r_int_v, b_int_v, iter);
	}

	for iter in (0..=4).rev() {
		for i in 0..64 {
			b_int_v[i] = load8(bits_ptr);
			bits_ptr = &bits_ptr[8..];
		}

		bits_ptr = &bits_ptr[inc as usize..];
		layer_in(r_int_v, b_int_v, iter);
	}

	transpose_64x64(&mut r_int_h[0], &r_int_v[0]);
	transpose_64x64(&mut r_int_h[1], &r_int_v[1]);

	for iter in (0..=6).rev() {
		for i in 0..64 {
			b_int_v[i] = load8(bits_ptr);
			bits_ptr = &bits_ptr[8..];
		}

		bits_ptr = &bits_ptr[inc as usize..];
		transpose_64x64(b_int_h, b_int_v);

		layer_ex(r_int_h, b_int_h, iter);
	}

	transpose_64x64(&mut r_int_v[0], &r_int_h[0]);
	transpose_64x64(&mut r_int_v[1], &r_int_h[1]);


	for i in 0..64 {
		store8(&mut r_ptr[i * 16 + 0..], r_int_v[0][i]);
		store8(&mut r_ptr[i * 16 + 8..], r_int_v[1][i]);
	}
}

pub fn support_gen(s: &mut [Gf], c: &[u8]) {
	/* input: condition bits c output: support s */

	let l = &mut [[0u8; (1 << MCELIECE_GFBITS) / 8]; MCELIECE_GFBITS];

	for i in 0..(1 << MCELIECE_GFBITS) {
		let a = bitrev(i as u16);
		for j in 0..MCELIECE_GFBITS {
			l[j][i as usize / 8] |= (((a >> j) & 1) << (i % 8)) as u8;
		}
	}

	for j in 0..MCELIECE_GFBITS {		
		apply_benes(&mut l[j], c, 0);
	}

	for i in 0..MCELIECE_SYS_N {
		s[i] = 0;
		let mut j = MCELIECE_GFBITS;

		loop {
			j -= 1;
			s[i] <<= 1;
			s[i] |= ((l[j][i / 8] >> (i % 8)) & 1) as Gf;

			if j == 0 {
				break;
			}
		}
	}
}

/* bm.c */

pub fn bm(out: &mut [Gf], s: &[Gf]) {
	/* the Berlekamp-Massey algorithm. 
	input: s, sequence of field elements
	output: out, minimal polynomial of s */

	let t: &mut [Gf; MCELIECE_SYS_T + 1] = &mut [0; MCELIECE_SYS_T + 1];
	let c: &mut [Gf; MCELIECE_SYS_T + 1] = &mut [0; MCELIECE_SYS_T + 1];
	let bb: &mut [Gf; MCELIECE_SYS_T + 1] = &mut [0; MCELIECE_SYS_T + 1];

	let mut b = 1;
	let mut l = 0;
	bb[1] = 1;
	c[0] = 1;

	for n in 0..(2 * MCELIECE_SYS_T) {
		let mut d = 0;
		
		for i in 0..=qrc_intutils_min(n, MCELIECE_SYS_T) {
			d ^= gf_mul(c[i], s[n - i]);
		}

		let mut mne = d; 
		mne = mne.wrapping_sub(1);
		mne >>= 15; 
		mne = mne.wrapping_sub(1);

		let mut mle = n as u16;
		mle = mle.wrapping_sub(2 * l); 
		mle >>= 15; 
		mle = mle.wrapping_sub(1);
		mle &= mne;

		qrc_intutils_copy16(t, c, MCELIECE_SYS_T);

		let f = gf_frac(b, d);

		for i in 0..=MCELIECE_SYS_T {
			c[i] ^= gf_mul(f, bb[i]) & mne;
		}

		l = (l & !mle) | ((n as u16 + 1 - l) & mle);

		for i in 0..=MCELIECE_SYS_T {
			bb[i] = (bb[i] & !mle) | (t[i] & mle);
		}

		b = (b & !mle) | (d & mle);

		for i in (1..=MCELIECE_SYS_T).rev() {
			bb[i] = bb[i - 1];
		}

		bb[0] = 0;
	}

	for i in 0..=MCELIECE_SYS_T {
		out[i] = c[MCELIECE_SYS_T - i];
	}
}

/* controlbits.c */

pub fn cbrecursion(out: &mut [u8], mut pos: i64, step: i64, pi: &[u16], w: i64, n: i64, temp: &mut [i32]) {
	/* parameters: 1 <= w <= 14; n = 2^w.
	input: permutation pi of {0,1,...,n-1}
	output: (2m-1)n/2 control bits at positions pos,pos+step,...
	output position pos is by definition 1&(out[pos/8]>>(pos&7))
	caller must 0-initialize positions first, temp must have space for int32_t[2*n] */

	let a = &mut temp.to_owned();
	let b = &mut temp[n as usize..].to_owned();
	/* q can start anywhere between temp+n and temp+n/2 */
	let mut q = qrc_intutils_transform_utoi_16(&qrc_intutils_transform_8to16(&qrc_intutils_transform_32to8(&qrc_intutils_transform_itou_32(&temp[((n + n / 4) as usize)..].to_owned()))));

	if w == 1 {
		out[pos as usize >> 3] ^= (pi[0] << (pos & 7)) as u8;
		return;
	}

	for x in 0..n {
		a[x as usize] = (((pi[x as usize] as i32) ^ 1) << 16) | pi[x as usize ^ 1] as i32;
	}

	int32_sort(a, n); /* a = (id<<16)+pibar */

	for x in 0..n {
		let ax = a[x as usize];
		let px = ax & 0x0000FFFF;
		let mut cx = px;

		if cx > x as i32 {
			cx = x as i32;
		}

		b[x as usize] = (px << 16) | cx;
	}

	/* b = (p<<16)+c */

	for x in 0..n {
		a[x as usize] = (a[x as usize] << 16) | x as i32; /* a = (pibar<<16)+id */
	}

	int32_sort(a, n); /* a = (id<<16)+pibar^-1 */

	for x in 0..n {
		a[x as usize] = (a[x as usize] << 16) + (b[x as usize] >> 16); /* a = (pibar^(-1)<<16)+pibar */
	}

	int32_sort(a, n); /* a = (id<<16)+pibar^2 */

	if w <= 10 {
		for x in 0..n {
			b[x as usize] = ((a[x as usize] & 0x0000FFFF) << 10) | (b[x as usize] & 0x000003FF);
		}

		for _ in 1..(w - 1) {
			/* b = (p<<10)+c */

			for x in 0..n {
				a[x as usize] = ((b[x as usize] & !0x000003FF) << 6) | x as i32; /* a = (p<<16)+id */
			}

			int32_sort(a, n); /* a = (id<<16)+p^{-1} */

			for x in 0..n {
				a[x as usize] = (a[x as usize] << 20) | b[x as usize]; /* a = (p^{-1}<<20)+(p<<10)+c */
			}

			int32_sort(a, n); /* a = (id<<20)+(pp<<10)+cp */

			for x in 0..n {
				let ppcpx = a[x as usize] & 0x000FFFFF;
				let mut ppcx = (a[x as usize] & 0x000FFC00) | (b[x as usize] & 0x000003FF);

				if ppcpx < ppcx {
					ppcx = ppcpx;
				}

				b[x as usize] = ppcx;
			}
		}

		for x in 0..n {
			b[x as usize] &= 0x000003FF;
		}
	} else {
		for x in 0..n {
			b[x as usize] = (a[x as usize] << 16) | (b[x as usize] & 0x0000FFFF);
		}

		for i in 1..(w - 1) {
			/* b = (p<<16)+c */

			for x in 0..n {
				a[x as usize] = (b[x as usize] & !0x0000FFFF) | x as i32;
			}

			int32_sort(a, n); /* a = (id<<16)+p^(-1) */

			for x in 0..n {
				a[x as usize] = (a[x as usize] << 16) | (b[x as usize] & 0x0000FFFF);
			}

			/* a = p^(-1)<<16+c */

			if i < w - 2 {
				for x in 0..n {
					b[x as usize] = (a[x as usize] & !0x0000FFFF) | (b[x as usize] >> 16);
				}

				/* b = (p^(-1)<<16)+p */

				int32_sort(b, n); /* b = (id<<16)+p^(-2) */

				for x in 0..n {
					b[x as usize] = (b[x as usize] << 16) | (a[x as usize] & 0x0000FFFF);
				}
				/* b = (p^(-2)<<16)+c */
			}

			int32_sort(a, n);

			/* a = id<<16+cp */
			for x in 0..n {
				let cpx = (b[x as usize] & !0x0000FFFF) | (a[x as usize] & 0x0000FFFF);

				if cpx < b[x as usize] {
					b[x as usize] = cpx;
				}
			}
		}

		for x in 0..n {
			b[x as usize] &= 0x0000FFFF;
		}
	}

	for x in 0..n {
		a[x as usize] = ((pi[x as usize] as i32) << 16) + x as i32;
	}

	int32_sort(a, n); /* a = (id<<16)+pi^(-1) */

	for j in 0..(n / 2) {
		let x = 2 * j;
		let fj = b[x as usize] & 1;	/* f[j] */
		let fx = x as i32 + fj;		/* f[x] */
		let fx1 = fx ^ 1;				/* f[x+1] */

		out[pos as usize >> 3] ^= (fj << (pos & 7)) as u8;
		pos += step;

		b[x as usize] = (a[x as usize] << 16) | fx as i32;
		b[x as usize + 1] = (a[x as usize + 1] << 16) | fx1;
	}

	/* b = (pi^(-1)<<16)+f */
	int32_sort(b, n);
	/* b = (id<<16)+f(pi) */
	pos += (2 * w - 3) * step * (n / 2);

	for k in 0..(n / 2){
		let y = 2 * k;
		let lk = b[y as usize] & 1;	/* l[k] */
		let ly = y as i32 + lk;		/* l[y] */
		let ly1 = ly ^ 1;				/* l[y+1] */

		out[pos as usize >> 3] ^= (lk << (pos & 7)) as u8;
		pos += step;
		a[y as usize] = (ly << 16) | (b[y as usize] & 0x0000FFFF);
		a[y as usize + 1] = (ly1 << 16) | (b[y as usize + 1] & 0x0000FFFF);
	}

	/* a = (l<<16)+F(pi) */
	int32_sort(a, n); /* a = (id<<16)+F(pi(l)) = (id<<16)+M */
	pos -= (2 * w - 2) * step * (n / 2);

	for j in 0..(n / 2) {
		q[j as usize] = ((a[2 * j as usize] & 0x0000FFFF) >> 1) as i16;
		q[j as usize + n as usize / 2] = ((a[2 * j as usize + 1] & 0x0000FFFF) >> 1) as i16;
	}

	cbrecursion(out, pos, step * 2, &qrc_intutils_transform_itou_16(&q), w - 1, n / 2, temp);
	cbrecursion(out, pos + step, step * 2, &qrc_intutils_transform_itou_16(&q[(n as usize / 2)..]), w - 1, n / 2, temp);

	
}


pub fn layer(p: &mut [i16], cb: &[u8], s: i32, n: i32) {
	/* input: p, an array of int16_t
	   input: n, length of p
	   input: s, meaning that stride-2^s cswaps are performed
	   input: cb, the control bits
	   output: the result of apply the control bits to p */

	let stride = 1 << s;

	let mut index = 0;

	for i in (0..n).step_by(stride * 2) {
		for j in 0..stride {
			let mut d = p[i as usize + j as usize] ^ p[i as usize + j + stride];
			let mut m = ((cb[index >> 3] >> (index & 7)) & 1) as i16;
			m = -m;
			d &= m;
			p[i as usize + j] ^= d;
			p[i as usize + j + stride] ^= d;

			index += 1;
		}
	}
}

pub fn controlbits_from_permutation(out: &mut [u8], pi: &[i16], w: i64, n: i64) {
	/* parameters: 1 <= w <= 14; n = 2^w
	   input: permutation pi of {0,1,...,n-1}
	   output: (2m-1)n/2 control bits at positions 0,1,...
	   output position pos is by definition 1&(out[pos/8]>>(pos&7)) */
	let temp = &mut vec![0i32; n as usize * 2 * size_of::<i32>()];
	let pi_test = &mut vec![0i16; n as usize * size_of::<i16>()];

	loop {
		qrc_intutils_clear8all(out);
		cbrecursion(out, 0, 1, &qrc_intutils_transform_itou_16(pi), w, n, temp);

		// check for correctness

		for i in 0..n {
			pi_test[i as usize] = i as i16;
		}

		let mut ptr = &mut out.to_owned()[..];

		for i in 0..w {
			layer(pi_test, ptr, i as i32, n as i32);
			ptr = &mut ptr[((n as usize >> 4))..];
		}

		for i in (0..w - 1).rev() {
			layer(pi_test, ptr, i as i32, n as i32);
			ptr = &mut ptr[((n as usize >> 4))..];
		}

		let mut diff = 0;

		for i in 0..n {
			diff |= pi[i as usize] ^ pi_test[i as usize];
		}

		if diff == 0 {
			break;
		}
	}

	qrc_intutils_clear16i(pi_test, n as usize * size_of::<i16>());
	qrc_intutils_clear32i(temp, n as usize * 2 * size_of::<i32>());
}

/* decrypt.c */

pub fn decrypt(e: &mut [u8], mut sk: &[u8], c: &[u8]) -> i32 {
	/* Niederreiter decryption with the Berlekamp decoder.
	   input: sk, secret key c, ciphertext
	   output: e, error vector
	   return: 0 for success; 1 for failure */

	let g: &mut [Gf; MCELIECE_SYS_T + 1] = &mut [0; MCELIECE_SYS_T + 1];
	let l: &mut [Gf; MCELIECE_SYS_N] = &mut [0; MCELIECE_SYS_N];
	let s: &mut [Gf; MCELIECE_SYS_T * 2] = &mut [0; MCELIECE_SYS_T * 2];
	let s_cmp: &mut [Gf; MCELIECE_SYS_T * 2] = &mut [0; MCELIECE_SYS_T * 2];
	let locator: &mut [Gf; MCELIECE_SYS_T + 1] = &mut [0; MCELIECE_SYS_T + 1];
	let images: &mut [Gf; MCELIECE_SYS_N] = &mut [0; MCELIECE_SYS_N];
	let r = &mut [0u8; MCELIECE_SYS_N / 8];

	let mut w = 0;
	qrc_intutils_copy8(r, c, MCELIECE_SYND_BYTES);
	qrc_intutils_clear8(&mut r[MCELIECE_SYND_BYTES..], (MCELIECE_SYS_N / 8)-MCELIECE_SYND_BYTES);

	for i in 0..MCELIECE_SYS_T {
		g[i] = load_gf(sk);
		sk = &sk[2..];
	}
	
	g[MCELIECE_SYS_T] = 1;

	support_gen(l, sk);

	

	synd(s, g, l, r);

	bm(locator, s);

	root(images, locator, l);

	qrc_intutils_clear8all(e);

	for i in 0..MCELIECE_SYS_N {
		let t = gf_is_zero(images[i]) & 1;
		e[i / 8] |= (t << (i % 8)) as u8;
		w += t;
	}

	synd(s_cmp, g, l, e);
	let mut check = w;
	check ^= MCELIECE_SYS_T as u16;

	for i in 0..(MCELIECE_SYS_T * 2) {
		check |= s[i] ^ s_cmp[i];
	}

	check = check.wrapping_sub(1);
	check >>= 15;

	return check as i32 ^ 1;
}

/* encrypt.c */

pub fn same_mask(x: u16, y: u16) -> u8 {
	let mut mask = (x ^ y) as u32;
	mask = mask.wrapping_sub(1);
	mask >>= 31;
	mask = !mask.wrapping_sub(1);

	return mask as u8 & 0x000000FF;
}

pub fn gen_e(asymmetric_state: &mut AsymmetricRandState, e: &mut [u8], rng_generate: fn(&mut AsymmetricRandState, &mut [u8], usize) -> bool) {
	/* output: e, an error vector of weight t */
	let ind = &mut [0u16; MCELIECE_SYS_T];
	let val = &mut [0u8; MCELIECE_SYS_T];

	if QRC_MCELIECE_S5N8192T128 {
		let brnd = &mut [0u8; MCELIECE_SYS_T * size_of::<u16>()];

		loop {
			rng_generate(asymmetric_state, brnd, MCELIECE_SYS_T * size_of::<u16>());
	
			for i in 0..MCELIECE_SYS_T {
				ind[i] = load_gf(&mut brnd[(i * 2)..]);
			}
	
			/* check for repetition */
	
			let mut eq = 0;
	
			for i in 0..MCELIECE_SYS_T {
				for j in 0..i {
					if ind[i] == ind[j] {
						eq = 1;
						break;
					}
				}
			}
	
			if eq == 0 {
				break;
			}
		}
	} else {
		let nrnd = &mut [0u16; MCELIECE_SYS_T * 2];
		let brnd = &mut [0u8; MCELIECE_SYS_T * 2 * size_of::<u16>()];

		loop {
			rng_generate(asymmetric_state, brnd, MCELIECE_SYS_T * 2 * size_of::<u16>());		
	
			for i in 0..MCELIECE_SYS_T * 2 {
				nrnd[i] = load_gf(&mut brnd[(i * 2)..]);
			}
	
			/* moving and counting indices in the correct range */
	
			let mut count = 0;
	
			for i in 0..MCELIECE_SYS_T * 2 {
				if nrnd[i] < MCELIECE_SYS_N as u16 {
					ind[count] = nrnd[i];
					count += 1;
	
					if count >= MCELIECE_SYS_T {
						break;
					}
				}
			}
	
			if count < MCELIECE_SYS_T {
				continue;
			}
			
			/* check for repetition */
	
			let mut eq = 0;
	
			for i in 0..MCELIECE_SYS_T {
				for j in 0..i {
					if ind[i] == ind[j] {
						eq = 1;
						break;
					}
				}
			}
	
			if eq == 0 {
				break;
			}
		}
	}

	for j in 0..MCELIECE_SYS_T {
		val[j] = 1 << (ind[j] & 7);
	}

	for i in 0..(MCELIECE_SYS_N / 8) {
		e[i] = 0;

		for j in 0..MCELIECE_SYS_T {
			let mask = same_mask(i as u16, ind[j] >> 3);
			e[i] |= val[j] & mask;
		}
	}
}

pub fn syndrome(s: &mut [u8], pk: &[u8], e: &[u8]) {
	/* input: public key pk, error vector e
	   output: syndrome s */

	let row = &mut [0u8; MCELIECE_SYS_N / 8];
	let mut pk_ptr = pk;

	qrc_intutils_clear8all(s);

	for i in 0..MCELIECE_PK_NROWS {
		qrc_intutils_clear8(row, MCELIECE_SYS_N / 8);

		for j in 0..MCELIECE_PK_ROW_BYTES {
			row[MCELIECE_SYS_N / 8 - MCELIECE_PK_ROW_BYTES + j] = pk_ptr[j];
		}

		if QRC_MCELIECE_S5N6960T119 {
			let tail = MCELIECE_PK_NROWS % 8;
			for j in ((MCELIECE_SYS_N / 8 - 1)..=(MCELIECE_SYS_N / 8 - MCELIECE_PK_ROW_BYTES)).rev() {
				row[j] = (row[j] << tail) | (row[j - 1] >> (8 - tail));
			}

			row[i / 8] |= 1 << (i % 8);

		} else {
			row[i / 8] |= 1 << (i % 8);
		}

		let mut b = 0;

		for j in 0..(MCELIECE_SYS_N / 8) {
			b ^= row[j] & e[j];
		}

		b ^= b >> 4;
		b ^= b >> 2;
		b ^= b >> 1;
		b &= 1;
		s[i / 8] |= b << (i % 8);

		pk_ptr = &pk_ptr[MCELIECE_PK_ROW_BYTES..];
	}
}

pub fn encrypt(asymmetric_state: &mut AsymmetricRandState, s: &mut [u8], pk: &[u8], e: &mut [u8], rng_generate: fn(&mut AsymmetricRandState, &mut [u8], usize) -> bool) {
	gen_e(asymmetric_state, e, rng_generate);
	syndrome(s, pk, e);
}

/* operations.c */

pub fn check_c_padding(c: &[u8]) -> i32 {
	/* Note artifact, no longer used */
	/* check if the padding bits of c are all zero */

	let mut b = c[MCELIECE_SYND_BYTES - 1] >> (MCELIECE_PK_NROWS % 8);
	b -= 1;
	b >>= 7;
	let ret = b as i32;

	return ret - 1;
}

pub fn check_pk_padding(pk: &[u8]) -> i32 {
	/* Note artifact, no longer used */

	let mut b: u8 = 0;

	for i in 0..MCELIECE_PK_NROWS {
		b |= pk[i * MCELIECE_PK_ROW_BYTES + MCELIECE_PK_ROW_BYTES - 1];
	}

	b >>= MCELIECE_PK_NCOLS % 8;
	b -= 1;
	b >>= 7;
	let ret = b;

	return ret as i32 - 1;
}

/* pk_gen.c */

pub fn pk_gen(pk: &mut [u8], mut sk: &[u8], perm: &[u32], pi: &mut [i16]) -> i32 {
	/* input: secret key sk output: public key pk */
	let buf = &mut [0u64; 1 << MCELIECE_GFBITS];
	let g: &mut [Gf; MCELIECE_SYS_T + 1] = &mut [0; MCELIECE_SYS_T + 1];	/* Goppa polynomial */
	let l: &mut [Gf; MCELIECE_SYS_N] = &mut [0; MCELIECE_SYS_N];		/* support */
	let inv: &mut [Gf; MCELIECE_SYS_N] = &mut [0; MCELIECE_SYS_N];

	let mut res = -1;

	let mat = &mut vec![[0u8; (MCELIECE_SYS_N / 8)]; MCELIECE_PK_NROWS * size_of::<u8>()];

	g[MCELIECE_SYS_T] = 1;

	for i in 0..MCELIECE_SYS_T {
		g[i] = load_gf(sk); 
		sk = &sk[2..];
	}		

	for i in 0..(1 << MCELIECE_GFBITS) {
		buf[i] = perm[i] as u64;
		buf[i] <<= 31;
		buf[i] |= i as u64;
	}
	uint64_sort(buf, 1 << MCELIECE_GFBITS);

	for i in 1..(1 << MCELIECE_GFBITS) {
		if (buf[i - 1] >> 31) == (buf[i] >> 31) {
			res = -2;
			break;
		}
	}

	if res != -2 {
		for i in 0..(1 << MCELIECE_GFBITS) {
			pi[i] = buf[i] as i16 & MCELIECE_GFMASK as i16;
		}

		for i in 0..MCELIECE_SYS_N {
			l[i] = bitrev(pi[i] as u16);
		}

		/* filling the matrix */

		root(inv, g, l);

		for i in 0..MCELIECE_SYS_N {
			inv[i] = gf_inv(inv[i]);
		}

		for i in 0..MCELIECE_PK_NROWS {
			for j in 0..(MCELIECE_SYS_N / 8) {
				mat[i][j] = 0;
			}
		}

		for i in 0..MCELIECE_SYS_T {
			for j in (0..MCELIECE_SYS_N).step_by(8) {
				for k in 0..MCELIECE_GFBITS {
					let mut b = (inv[j + 7] >> k & 1) as u8;
					b <<= 1;
					b |= (inv[j + 6] >> k & 1) as u8;
					b <<= 1;
					b |= (inv[j + 5] >> k & 1) as u8;
					b <<= 1;
					b |= (inv[j + 4] >> k & 1) as u8;
					b <<= 1;
					b |= (inv[j + 3] >> k & 1) as u8;
					b <<= 1;
					b |= (inv[j + 2] >> k & 1) as u8;
					b <<= 1;
					b |= (inv[j + 1] >> k & 1) as u8;
					b <<= 1;
					b |= (inv[j + 0] >> k & 1) as u8;

					mat[i * MCELIECE_GFBITS + k][j / 8] = b;
				}
			}


			for j in 0..MCELIECE_SYS_N {
				inv[j] = gf_mul(inv[j], l[j]);
			}
		}

		/* gaussian elimination */

		for i in 0..((MCELIECE_PK_NROWS + 7) / 8) {
			for j in 0..8 {
				let row = i * 8 + j;

				if row >= MCELIECE_PK_NROWS {
					break;
				}
				for k in (row + 1)..MCELIECE_PK_NROWS {
					let mut mask = (mat[row][i] ^ mat[k][i]) as u8;
					mask >>= j;
					mask &= 1;
					mask = (!mask).wrapping_add(1);

					for col in 0..(MCELIECE_SYS_N / 8) {
						mat[row][col] ^= mat[k][col] & mask;
					}
				}


				if ((mat[row][i] >> j) & 1) == 0 {		/* return if not systematic */
					for i in 0..MCELIECE_PK_NROWS {
						qrc_intutils_clear8(&mut mat[i], 836);
					}

					return -1;
				}

				for k in 0..MCELIECE_PK_NROWS {
					if k != row {
						let mut mask = (mat[k][i] >> j) as u8;
						mask &= 1;
						mask = (!mask).wrapping_add(1);

						for col in 0..(MCELIECE_SYS_N / 8) {
							mat[k][col] ^= mat[row][col] & mask;
						}
					}
				}
			}
		}

		if QRC_MCELIECE_S5N6960T119 {
			let mut pk_ptr = pk;
			let tail = MCELIECE_PK_NROWS % 8;

			for i in 0..MCELIECE_PK_NROWS {
				for j in ((MCELIECE_PK_NROWS - 1) / 8)..(MCELIECE_SYS_N / 8 - 1) {
					pk_ptr[0] = &(mat[i][j] >> tail) | (mat[i][j + 1] << (8 - tail)) as u8;
					pk_ptr = &mut pk_ptr[1..];
				}

				pk_ptr[0] = mat[i][(MCELIECE_SYS_N / 8 - 1)-1] >> tail;
				pk_ptr = &mut pk_ptr[1..];
			}
		} else {
			for i in 0..MCELIECE_PK_NROWS {
				qrc_intutils_copy8(&mut pk[(i * MCELIECE_PK_ROW_BYTES)..], &mat[i][(MCELIECE_PK_NROWS / 8)..], MCELIECE_PK_ROW_BYTES);
			}
		}
	}
	res = 0;

	for i in 0..MCELIECE_PK_NROWS {
		qrc_intutils_clear8(&mut mat[i], 836);
	}	

	return res;
}

/* sk_gen.c */

pub fn genpoly_gen(out: &mut [Gf], f: &[Gf]) -> i32 {
	/* input: f, element in GF((2^m)^t)
	   output: out, minimal polynomial of f
	   return: 0 for success and -1 for failure */

	let mat: &mut [[Gf; MCELIECE_SYS_T]; MCELIECE_SYS_T + 1] = &mut [[0; MCELIECE_SYS_T]; MCELIECE_SYS_T + 1];

	/* fill matrix */

	let mut res = 0;
	mat[0][0] = 1;

	for i in 0..MCELIECE_SYS_T	{
		mat[1][i] = f[i];
	}

	for j in 2..=MCELIECE_SYS_T {
		let nmat = mat[j - 1];
		bgf_mul(&mut mat[j], &nmat, f);
	}

	/* gaussian */

	for j in 0..MCELIECE_SYS_T	{
		for k in (j + 1)..MCELIECE_SYS_T	{
			let mask = gf_is_zero(mat[j][j]);

			for c in j..(MCELIECE_SYS_T + 1) {
				mat[c][j] ^= mat[c][k] & mask;
			}
		}

		if mat[j][j] != 0 {
			let inv = gf_inv(mat[j][j]);

			for c in j..(MCELIECE_SYS_T + 1) {
				mat[c][j] = gf_mul(mat[c][j], inv);
			}

			for k in 0..MCELIECE_SYS_T {
				if k != j {
					let t = mat[j][k];

					for c in j..(MCELIECE_SYS_T + 1) {
						mat[c][k] ^= gf_mul(mat[c][j], t);
					}
				}
			}
		} else {
			/* return if not systematic */
			res = -1;
			break;
		}

		for i in 0..MCELIECE_SYS_T {
			out[i] = mat[MCELIECE_SYS_T][i];
		}
	}

	return res;
}