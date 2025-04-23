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
use core::default::Default;

#[cfg(feature = "no_std")]
use alloc::borrow::ToOwned;

/*
* \file donna128
* \brief Donna function definitions
*/

/*
* \struct uint128
* \brief The uint128 state structure
*/
pub struct Uint128 {
	pub high: u64,	/*< The high order bits */
	pub low: u64,	/*< The low order bits */
}
impl Default for Uint128{
    fn default() -> Self {
        Self {
            high: Default::default(),
            low: Default::default(),
        }
    }
}

/*
* \brief Right shift a 128-bit integer
*
* \param x: [const] The base integer
* \param shift: The shift position
* \return The shifted value
*/
pub fn qrc_donna128_shift_right(x: Uint128, shift: usize) -> Uint128 {
    let mut r = Uint128::default();
	let carry = x.high << (64 - shift);
	r.high = x.high >> shift;
	r.low = (x.low >> shift) | carry;

	return r;
}

/*
* \brief Left shift a 128-bit integer
*
* \param x: [const] The base integer
* \param shift: The shift position
* \return The shifted value
*/
pub fn qrc_donna128_shift_left(x: Uint128, shift: usize) -> Uint128 {
    let mut r = Uint128::default();
	let carry = x.low >> (64 - shift);
	r.low = x.low << shift;
	r.high = (x.high << shift) | carry;

	return r;
}

/*
* \brief Bitwise AND the low part of a 128-bit integer
*
* \param x: [const] The base integer
* \param mask: The AND mask
* \return The AND'd value
*/
pub fn qrc_donna128_andl(x: Uint128, mask: u64) -> u64 {
	return x.low & mask;
}

/*
* \brief Bitwise AND the high part of a 128-bit integer
*
* \param x: [const] The base integer
* \param mask: The AND mask
* \return The AND'd value
*/
pub fn qrc_donna128_andh(x: Uint128, mask: u64) -> u64 {
	return x.high & mask;
}

/*
* \brief Add two 128-bit integers
*
* \param x: [const] The first value to add
* \param y: [const] The second value to add
* \return The sum value
*/
pub fn qrc_donna128_add(x: Uint128, y: Uint128) -> Uint128 {
	let mut r = Uint128::default();

	r.low = x.low + y.low;
	r.high = x.high + y.high;

	let carry = (x.low < y.low) as u64;
	r.high += carry;

	return r;
}


/*
* \brief Multiply a 128-bit integer by a 64-bit integer
*
* \param x: [const] The first value to multiply
* \param y: The second value to multiply
* \return The sum value
*/
pub fn qrc_donna128_multiply(x: Uint128, y: u64) -> Uint128 {
    let mut r = Uint128::default();
	let low = &mut 0;
	let high = &mut 0;

	mul64x64to128(x.low, y, low, high);
	r.low = low.to_owned();
	r.high = high.to_owned();

	return r;
}

/*
* \brief Bitwise OR of two 128-bit integers
*
* \param x: [const] The first value to OR
* \param y: The second value to OR
* \return The sum value
*/
pub fn qrc_donna128_or(x: Uint128, y: Uint128) -> Uint128 {
	let mut r = Uint128::default();

	r.low = x.low | y.low;
	r.high = x.high | y.high;

	return r;
}

fn mul64x64to128(x: u64, y: u64, low: &mut u64, high: &mut u64) {
	const HWORD_BITS: usize = 32;
	const HWORD_MASK: u32 = 0xFFFFFFFF;
	let ah = (x >> HWORD_BITS) as u32;
	let al = (x as u32) & HWORD_MASK;
	let bh = (y >> HWORD_BITS) as u32;
	let bl = (y as u32) & HWORD_MASK;

	let mut x0 = (ah as u64).wrapping_mul(bh as u64);
	let x1 = (al as u64).wrapping_mul(bh as u64);
	let mut x2 = (ah as u64).wrapping_mul(bl as u64);
	let x3 = (al as u64).wrapping_mul(bl as u64);

	/* this cannot overflow as(2 ^ 32 - 1) ^ 2 + 2 ^ 32 - 1 < 2 ^ 64 - 1 */
	x2 = x2.wrapping_add(x3 >> HWORD_BITS);
	/* this one can overflow */
	x2 = x2.wrapping_add(x1);
	/* propagate the carry if any */
	x0 = x0.wrapping_add(((x2 < x1) as u64) << HWORD_BITS);

	*high = x0.wrapping_add(x2 >> HWORD_BITS);
	*low = ((x2 & HWORD_MASK as u64) << HWORD_BITS).wrapping_add(x3 & HWORD_MASK as u64);
}