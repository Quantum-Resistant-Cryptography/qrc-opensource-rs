#![allow(dead_code)]
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
*
*
*
* Copyright (c) Original-2021 John G. Underhill <john.underhill@mailfence.com>
* Copyright (c) 2022-Present QRC Eurosmart SA <opensource-support@qrcrypto.ch>
*
* The following code is a derivative work of the code from the QSC Cryptographic library in C, 
* which is licensed AGPLv3. This code therefore is also licensed under the terms of 
* the GNU Affero General Public License, version 3. The AGPL version 3 License (AGPLv3). */

use crate::tools::intutils::{qrc_intutils_copy8, qrc_intutils_min};

use core::default::Default;

#[cfg(feature = "std")]
use crate::tools::intutils::qrc_intutils_clear8all;

#[cfg(feature = "std")]
use crate::tools::stringutils::qrc_stringutils_string_size;

#[cfg(feature = "std")]
use sysinfo::{Disks, System, get_current_pid};




/*
* \file sysutils
* \brief System functions; provides system statistics, counters, and feature availability
*/

/*
* \def QRC_SYSUTILS_SYSTEM_NAME_MAX
* \brief The system maximum name length
*/
pub const QRC_SYSUTILS_SYSTEM_NAME_MAX: usize = 256;

/*
* \brief Get the computer string name
*
* \param name: The array receiving the computer name string
* \return Returns the size of the computer name in characters
*/
#[cfg(feature = "std")]
pub fn qrc_sysutils_computer_name(name: &mut [u8], maxlen: usize) -> usize {
    qrc_intutils_clear8all(name);
    let sys = System::host_name().unwrap();
    qrc_intutils_copy8(
        name,
        sys.as_bytes(),
        qrc_intutils_min(qrc_stringutils_string_size(&sys), maxlen),
    );
    return qrc_intutils_min(qrc_stringutils_string_size(&sys), maxlen);
}
#[cfg(feature = "no_std")]
pub fn qrc_sysutils_computer_name(name: &mut [u8], maxlen: usize) -> usize {
    qrc_intutils_copy8(name, "UniQS".as_bytes(), qrc_intutils_min(5, maxlen));
    return qrc_intutils_min(5, maxlen);
}

/*
* \struct qrc_sysutils_drive_space_state
* \brief The drive_space state structure
*/
pub struct QrcSysutilsDriveSpaceState {
    pub free: u64,  /*< The free drive space */
    pub total: u64, /*< The total drive space */
    pub avail: u64, /*< The available drive space */
}

impl Default for QrcSysutilsDriveSpaceState {
    fn default() -> Self {
        Self {
            free: Default::default(),
            total: Default::default(),
            avail: Default::default(),
        }
    }
}

/*
* \brief Get the system drive space statistics
*
* \param drive: The drive letter
* \param state: The struct containing the statistics
*/
#[cfg(feature = "std")]
pub fn qrc_sysutils_drive_space(state: &mut QrcSysutilsDriveSpaceState) {
    let disk = &Disks::new_with_refreshed_list()[0];

    state.free = disk.total_space() - disk.available_space();
    state.total = disk.total_space();
    state.avail = disk.available_space();
}
#[cfg(feature = "no_std")]
pub fn qrc_sysutils_drive_space(state: &mut QrcSysutilsDriveSpaceState) {
    state.free = 0;
    state.total = 0;
    state.avail = 0;
}

/*
* \struct qrc_sysutils_memory_statistics_state
* \brief The memory_statistics state structure
*/
pub struct QrcSysutilsMemoryStatisticsState {
    pub phystotal: u64, /*< The total physical memory */
    pub physavail: u64, /*< The available physical memory */
    pub virttotal: u64, /*< The total virtual memory */
    pub virtavail: u64, /*< The available virtual memory */
}
impl Default for QrcSysutilsMemoryStatisticsState {
    fn default() -> Self {
        Self {
            phystotal: Default::default(),
            physavail: Default::default(),
            virttotal: Default::default(),
            virtavail: Default::default(),
        }
    }
}

/*
* \brief Get the memory statistics from the system
*
* \param state: The struct containing the memory statistics
*/
#[cfg(feature = "std")]
pub fn qrc_sysutils_memory_statistics(state: &mut QrcSysutilsMemoryStatisticsState) {
    let system = System::new_all();

    let total_memory = system.total_memory();
    let free_memory = system.free_memory();
    let total_swap = system.total_swap();
    let free_swap = system.free_swap();

    state.phystotal = total_memory;
    state.physavail = total_memory - free_memory;
    state.virttotal = total_memory + total_swap;
    state.virtavail = (total_memory - free_memory) + (total_swap - free_swap);
}
#[cfg(feature = "no_std")]
pub fn qrc_sysutils_memory_statistics(state: &mut QrcSysutilsMemoryStatisticsState) {
    state.phystotal = 0;
    state.physavail = 0;
    state.virttotal = 0;
    state.virtavail = 0;
}

/*
* \brief Get the current process id
*
* \return Returns the process id
*/
#[cfg(feature = "std")]
pub fn qrc_sysutils_process_id() -> u32 {
    return get_current_pid().unwrap().as_u32();
}
#[cfg(feature = "no_std")]
pub fn qrc_sysutils_process_id() -> u32 {
    return 0;
}

/*
* \brief Get the systems logged-on user name string
*
* \param name: The char array that holds the user name
* \return Returns the size of the user name
*/
#[cfg(feature = "std")]
pub fn qrc_sysutils_user_name(name: &mut [u8], maxlen: usize) -> usize {
    qrc_intutils_clear8all(name);
    let sys = whoami::username();
    qrc_intutils_copy8(
        name,
        sys.as_bytes(),
        qrc_intutils_min(qrc_stringutils_string_size(&sys), maxlen),
    );
    return qrc_intutils_min(qrc_stringutils_string_size(&sys), maxlen);
}
#[cfg(feature = "no_std")]
pub fn qrc_sysutils_user_name(name: &mut [u8], maxlen: usize) -> usize {
    qrc_intutils_copy8(name, "UniQS-User".as_bytes(), qrc_intutils_min(10, maxlen));
    return qrc_intutils_min(10, maxlen);
}

/*
* \brief Get the system up-time since boot
*
* \return Returns the system up-time
*/
#[cfg(feature = "std")]
pub fn qrc_sysutils_system_uptime() -> u64 {
    return System::uptime();
}
#[cfg(feature = "no_std")]
pub fn qrc_sysutils_system_uptime() -> u64 {
    return 0;
}

/*
* \brief Get the current high-resolution time-stamp
*
* \return Returns the system time-stamp
*/
#[cfg(feature = "std")]
pub fn qrc_sysutils_system_timestamp() -> u64 {
    return System::boot_time();
}
#[cfg(feature = "no_std")]
pub fn qrc_sysutils_system_timestamp() -> u64 {
    return 0;
}
