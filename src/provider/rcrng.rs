/* The AGPL version 3 License (AGPLv3)
*
* Copyright (c) 2024 DFD & QRC Eurosmart SA
* This file is part of the QRC Cryptographic library
*
* This program is free software : you can redistribute it and / or modify
* it under the terms of the GNU Affero General public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
* See the GNU Affero General public License for more details.
*
* You should have received a copy of the GNU Affero General public License
* along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

use crate::{
	tools::{
		sysutils::{
			QrcSysutilsDriveSpaceState,
			QrcSysutilsMemoryStatisticsState,
			QRC_SYSUTILS_SYSTEM_NAME_MAX,
			qrc_sysutils_system_timestamp,
			qrc_sysutils_computer_name,
			qrc_sysutils_process_id,
			qrc_sysutils_user_name,
			qrc_sysutils_system_uptime,
			qrc_sysutils_drive_space,
			qrc_sysutils_memory_statistics,
		},
		intutils::{qrc_intutils_min, qrc_intutils_copy8},
	},
	provider::{
		trng::qrc_trng_generate,
		osrng::qrc_osrng_generate,
	},
	digest::sha3::{
		qrc_sha3_compute512,
		qrc_cshake512_compute
	},
};

use core::mem::size_of;

#[cfg(feature = "no_std")]
use alloc::{vec, vec::Vec};

/*
* \def QRC_RCRNG_SEED_MAX
* \brief The maximum seed size that can be extracted from a single generate call
*/
const QRC_RCRNG_SEED_MAX: usize = 10240000;

fn vec_u64_to_slice_u8(vec_u64: &Vec<u64>) -> Vec<u8> {
    let mut vec_u8: Vec<u8> = Vec::new();

    for &value in vec_u64 {
        vec_u8.extend_from_slice(&value.to_be_bytes());
    }

    vec_u8
}

fn rcrng_collect_statistics(seed: &mut [u8]) {
    let dstate = &mut QrcSysutilsDriveSpaceState::default();
    let mstate = &mut QrcSysutilsMemoryStatisticsState::default();
    let buffer= &mut [0u8; 1024];
	let tname = &mut [0u8; QRC_SYSUTILS_SYSTEM_NAME_MAX];
    //let tname = &mut String::with_capacity(QRC_SYSUTILS_SYSTEM_NAME_MAX);

	/* add user statistics */
	let mut ts = qrc_sysutils_system_timestamp();
	/* interspersed with time-stamps, as return from system calls has some entropy variability */
	qrc_intutils_copy8(buffer, &ts.to_le_bytes(), size_of::<u64>());
	let mut oft = size_of::<u64>();
	let mut len = qrc_sysutils_computer_name(tname, QRC_SYSUTILS_SYSTEM_NAME_MAX);
	qrc_intutils_copy8(&mut buffer[oft..], tname, len);
	oft += len;
	let id = qrc_sysutils_process_id();
	qrc_intutils_copy8(&mut buffer[oft..], &id.to_le_bytes(), size_of::<u32>());
	oft += size_of::<u32>();
	len = qrc_sysutils_user_name(tname, QRC_SYSUTILS_SYSTEM_NAME_MAX);
	qrc_intutils_copy8(&mut buffer[oft..], tname, len);
	oft += len;
	ts = qrc_sysutils_system_uptime();
	qrc_intutils_copy8(&mut buffer[oft..], &ts.to_le_bytes(), size_of::<u64>());
	oft += size_of::<u64>();

	/* add drive statistics */
	ts = qrc_sysutils_system_timestamp();
	qrc_intutils_copy8(&mut buffer[oft..], &ts.to_le_bytes(), size_of::<u64>());
	oft += size_of::<u64>();
	qrc_sysutils_drive_space(dstate);
    let dstateu8: &[u8] = &vec_u64_to_slice_u8(&vec![dstate.free, dstate.total, dstate.avail]);
	let dstateu8len = dstateu8.len();
	qrc_intutils_copy8(&mut buffer[oft..], dstateu8, dstateu8len);
	oft += dstateu8len;

	/* add memory statistics */
	ts = qrc_sysutils_system_timestamp();
	qrc_intutils_copy8(&mut buffer[oft..], &ts.to_le_bytes(), size_of::<u64>());
	oft += size_of::<u64>();
	qrc_sysutils_memory_statistics(mstate);
    let mstateu8: &[u8] = &vec_u64_to_slice_u8(&vec![mstate.phystotal, mstate.physavail, mstate.virttotal, mstate.virtavail]);
	let mstateu8len = mstateu8.len();
	qrc_intutils_copy8(&mut buffer[oft..], mstateu8, mstateu8len);
	len = oft + mstateu8len;

	/* compress the statistics */
	qrc_sha3_compute512(seed, buffer, len);
}

/**
* \brief Get an array of random bytes from the auto entropy collection provider.
*
* \param output: Pointer to the output byte array
* \param length: The number of bytes to copy
* \return Returns true for success
*/
pub fn qrc_rcrng_generate(output: &mut [u8], length: usize) -> bool {
	let len = 64;
	let cust = &mut [0u8; 64];
	let key = &mut [0u8; 64];
	let stat = &mut [0u8; 64];

	/* collect timers and system stats, compressed as tertiary seed */
	rcrng_collect_statistics(stat);

	/* add a seed using RDRAND used as cSHAKE custom parameter */
	let mut res = qrc_osrng_generate(cust, len);

	if res == false {
		/* fall-back to system provider */
		res = qrc_trng_generate(cust, len);
	}

	if res == true {
		/* generate primary key using system random provider */
		res = qrc_trng_generate(key, len);
	}

	if res == true {
		/* key cSHAKE-512 to generate the pseudo-random output, using all three entropy sources */
		qrc_cshake512_compute(output, qrc_intutils_min(length, QRC_RCRNG_SEED_MAX), key, len, stat, len, cust, len);
	}

	return res;
}