#![allow(dead_code)]
#![cfg(feature = "std")]
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

use crate::{
    common::common::QRC_SYSTEM_MAX_PATH,
    tools::{
        intutils::qrc_intutils_clear_string,
        stringutils::{qrc_stringutils_clear_string, qrc_stringutils_string_size},
    },
};
use directories::{BaseDirs, UserDirs};
use std::fs::{create_dir, metadata};

/*
* \file folderutils
* \brief Folder utilities, common folder support functions
*/

/* \enum qrc_folderutils_directories
* \brief The system special folders enumeration
*/
#[derive(PartialEq)]
pub enum QrcFolderutilsDirectories {
    QrcFolderutilsDirectoriesUserAppData, /*< User App Data directory */
    QrcFolderutilsDirectoriesUserDesktop, /*< User Desktop directory */
    QrcFolderutilsDirectoriesUserDocuments, /*< User Documents directory */
    QrcFolderutilsDirectoriesUserDownloads, /*< User Downloads directory */
    QrcFolderutilsDirectoriesUserFavourites, /*< User Favourites directory */
    QrcFolderutilsDirectoriesUserMusic,   /*< User Music directory */
    QrcFolderutilsDirectoriesUserPictures, /*< User Pictures directory */
    QrcFolderutilsDirectoriesUserPrograms, /*< User Programs directory */
    QrcFolderutilsDirectoriesUserShortcuts, /*< User Shortcuts directory */
    QrcFolderutilsDirectoriesUserVideos,  /*< User Video directory */
}

/*
* \brief Create a new folder

*
* \param path: [const] The full path including the new folder name
* \return Returns true if the folder is created
*/
pub fn qrc_folderutils_create_directory(path: &str) -> bool {
    let _ = create_dir(path);
    return qrc_folderutils_directory_exists(path);
}

/*
* \brief Check if a folder exists

*
* \param path: [const] The full path including the folder name
* \return Returns true if the folder is found
*/
pub fn qrc_folderutils_directory_exists(path: &str) -> bool {
    if let Ok(metadata) = metadata(path) {
        metadata.is_dir()
    } else {
        false // Treat any error as if the path doesn't exist or is not a directory
    }
}

/*
* \brief Get the full path to a special system folder
*
* \param directory: The enum name of the system directory
* \param output: The output string containing the directory path
*/
pub fn qrc_folderutils_get_directory(directory: QrcFolderutilsDirectories, output: &mut String) {
    qrc_intutils_clear_string(output);

    let base_dirs = BaseDirs::new().expect("Could not determine base directories");
    let user_dirs = UserDirs::new().expect("Could not determine user directories");
    let id;

    if directory == QrcFolderutilsDirectories::QrcFolderutilsDirectoriesUserAppData {
        id = base_dirs.data_local_dir().to_path_buf();
    } else if directory == QrcFolderutilsDirectories::QrcFolderutilsDirectoriesUserDesktop {
        id = user_dirs.desktop_dir().unwrap().to_path_buf();
    } else if directory == QrcFolderutilsDirectories::QrcFolderutilsDirectoriesUserDocuments {
        id = user_dirs.document_dir().unwrap().to_path_buf();
    } else if directory == QrcFolderutilsDirectories::QrcFolderutilsDirectoriesUserDownloads {
        id = user_dirs.download_dir().unwrap().to_path_buf();
    } else if directory == QrcFolderutilsDirectories::QrcFolderutilsDirectoriesUserMusic {
        id = user_dirs.audio_dir().unwrap().to_path_buf();
    } else if directory == QrcFolderutilsDirectories::QrcFolderutilsDirectoriesUserPictures {
        id = user_dirs.picture_dir().unwrap().to_path_buf();
    } else if directory == QrcFolderutilsDirectories::QrcFolderutilsDirectoriesUserVideos {
        id = user_dirs.video_dir().unwrap().to_path_buf();
    } else {
        id = user_dirs.document_dir().unwrap().to_path_buf();
    }

    let path: String = id.into_os_string().into_string().unwrap();
    qrc_stringutils_clear_string(output);
    output.push_str(&path[..QRC_SYSTEM_MAX_PATH.min(qrc_stringutils_string_size(&path))]);
}
