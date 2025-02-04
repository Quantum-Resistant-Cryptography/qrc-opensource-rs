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

/**
* \file sysutils.h
* \brief System functions; provides system statistics, counters, and feature availability
*/


use crate::qsc::tools::{
	intutils::qsc_intutils_min,
	stringutils::{
		qsc_stringutils_clear_string,
		qsc_stringutils_string_size,
	},
};

use sysinfo::{System, Disks, get_current_pid};

/*
* \def QSC_SYSUTILS_SYSTEM_NAME_MAX
* \brief The system maximum name length
*/
pub const QSC_SYSUTILS_SYSTEM_NAME_MAX: usize = 256;

/*
* \struct qsc_sysutils_drive_space_state
* \brief The drive_space state structure
*/
pub struct QscSysutilsDriveSpaceState {
	pub free: u64,		/*< The free drive space */
	pub total: u64,		/*< The total drive space */
	pub avail: u64,		/*< The available drive space */
} 

impl Default for QscSysutilsDriveSpaceState {
    fn default() -> Self {
        Self {
			free: Default::default(),
            total: Default::default(),
			avail: Default::default(),
        }
    }
}

/*
* \struct qsc_sysutils_memory_statistics_state
* \brief The memory_statistics state structure
*/
pub struct QscSysutilsMemoryStatisticsState {
	pub phystotal: u64,		/*< The total physical memory */
	pub physavail: u64,	    /*< The available physical memory */
	pub virttotal: u64,     /*< The total virtual memory */
	pub virtavail: u64,	    /*< The available virtual memory */
}

impl Default for QscSysutilsMemoryStatisticsState {
    fn default() -> Self {
        Self {
			phystotal: Default::default(),
            physavail: Default::default(),
			virttotal: Default::default(),
			virtavail: Default::default(),
        }
    }
}


/**
* \brief Get the computer string name
*
* \param name: The array receiving the computer name string
* \return Returns the size of the computer name in characters
*/
pub fn qsc_sysutils_computer_name(name: &mut String, maxlen: usize) -> usize{
	let sys = System::host_name().unwrap();
	qsc_stringutils_clear_string(name);
    name.push_str(&sys[..qsc_intutils_min(qsc_stringutils_string_size(&sys), maxlen)]);
	return qsc_stringutils_string_size(name);
}

/**
* \brief Get the system drive space statistics
*
* \param drive: The drive letter
* \param state: The struct containing the statistics
*/
pub fn qsc_sysutils_drive_space(state: &mut QscSysutilsDriveSpaceState) {
	let disk = &Disks::new_with_refreshed_list()[0];

	state.free = disk.total_space() - disk.available_space();
	state.total = disk.total_space();
	state.avail = disk.available_space();
}

/**
* \brief Get the memory statistics from the system
*
* \param state: The struct containing the memory statistics
*/
pub fn qsc_sysutils_memory_statistics(state: &mut QscSysutilsMemoryStatisticsState) {
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

/**
* \brief Get the current process id
*
* \return Returns the process id
*/
pub fn qsc_sysutils_process_id() -> u32 {
	return get_current_pid().unwrap().as_u32();
}

/**
* \brief Get the systems logged-on user name string
*
* \param name: The char array that holds the user name 
* \return Returns the size of the user name
*/
pub fn qsc_sysutils_user_name(name: &mut String, maxlen: usize) -> usize{
	let sys = whoami::username();
	let sys_cut = &sys[..qsc_intutils_min(qsc_stringutils_string_size(&sys), maxlen)];
	let sys_cut_len = qsc_stringutils_string_size(&sys_cut);
	name.replace_range(..sys_cut_len, sys_cut);
    return sys_cut_len;
}

/**
* \brief Get the system up-time since boot
*
* \return Returns the system up-time
*/
pub fn qsc_sysutils_system_uptime() -> u64 {
	return System::uptime();
}

/**
* \brief Get the current high-resolution time-stamp
*
* \return Returns the system time-stamp
*/
pub fn qsc_sysutils_system_timestamp() -> u64 {
	return System::boot_time();
}