#![allow(dead_code)]
#![cfg(feature = "std")]
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
    common::common::{QRC_SYSTEM_MAX_PATH, QRC_SYSTEM_OS_WINDOWS},
    tools::{
        intutils::qrc_intutils_clear_string,
        stringutils::{
            qrc_stringutils_copy_string, qrc_stringutils_reverse_sub_string,
            qrc_stringutils_string_size,
        },
    },
};
use std::io::{
    Read, Result, Seek,
    SeekFrom::{Current, End, Start},
    Write,
};
use std::{
    fs::File,
    fs::{metadata, remove_file},
};

/*
* \file fileutils
* \brief File utilities contains common file related functions
*/

pub const QRC_FILEUTILS_CHUNK_SIZE: usize = 4096;
pub const QRC_FILEUTILS_MAX_EXTENSION: usize = 16;
pub const QRC_FILEUTILS_MAX_FILENAME: usize = QRC_SYSTEM_MAX_PATH;
pub const QRC_FILEUTILS_MAX_PATH: usize = QRC_SYSTEM_MAX_PATH;

pub const QRC_FILEUTILS_DIRECTORY_SEPERATOR: &str = if QRC_SYSTEM_OS_WINDOWS { "\\" } else { "/" };

/* \enum qrc_fileutils_mode
* The file mode enumeration.
*/
#[derive(PartialEq)]
pub enum QrcFileutilsMode {
    QrcFileutilsModeNone = 0,         /*< No mode was specified */
    QrcFileutilsModeRead = 1,         /*< Open file for input operations */
    QrcFileutilsModeReadUpdate = 2, /*< read/update: Open a file for update (both for input and output) */
    QrcFileutilsModeWrite = 3,      /*< Create an empty file for output operations */
    QrcFileutilsModeWriteUpdate = 4, /*< write/update: Create an empty file and open it for update */
    QrcFileutilsModeAppend = 5,      /*< Open file for output at the end of a file */
    QrcFileutilsModeAppendUpdate = 6, /*< append/update: Open a file for update (both for input and output) */
}

/*
* \brief Copy elements from a file to a byte array.
*
* \param path: [const] The full path to the file
* \param stream: The array to write to the file
* \param length: The number of bytes to write to the file
* \return Returns the number of characters written to the byte array
*/
pub fn qrc_fileutils_copy_file_to_stream(path: &str, stream: &mut [u8]) -> usize {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(_) => return 0,
    };
    match file.read(stream) {
        Ok(len) => len,
        Err(_) => 0,
    }
}

/*
* \brief Copy the contents of a stream to a file.
*
* \param [const] path: The full path to the file
* \param [const] stream: The array to write to the file
* \param length: The length of the array
* \return Returns true if the operation succeeded
*/
pub fn qrc_fileutils_copy_stream_to_file(path: &str, stream: &[u8]) -> bool {
    match File::create(path) {
        Ok(mut fp) => {
            if let Err(_) = fp.write_all(stream) {
                return false;
            }
            true
        }
        Err(_) => false,
    }
}

/*
* \brief Delete a file
*
* \param path: [const] The full path to the file ro be deleted
* \return Returns true for success
*/
pub fn qrc_fileutils_delete(path: &str) -> bool {
    match remove_file(path) {
        Ok(_) => return true,
        Err(_) => return false,
    };
}

/*
* \brief Get the file directory
*
* \param directory: The output file extension
* \param dirlen: The length of the directory buffer
* \param path: [const] The full path to the file
* \return Returns the length of the file extension
*/
pub fn qrc_fileutils_get_directory(directory: &mut String, dirlen: usize, path: &str) -> usize {
    let mut pos = 0;

    if dirlen > 0 {
        qrc_intutils_clear_string(directory);
        let pname = qrc_stringutils_reverse_sub_string(path, &QRC_FILEUTILS_DIRECTORY_SEPERATOR);

        if qrc_stringutils_string_size(&pname) != 0 {
            pos = qrc_stringutils_string_size(path) - qrc_stringutils_string_size(&pname);

            if pos > 0 {
                qrc_stringutils_copy_string(directory, pos, &path[..pos]);
            }
        }
    }

    return pos;
}

/*
* \brief Get the file extension
*
* \param extension: The output file extension
* \param extlen: The length of the extension buffer
* \param path: [const] The full path to the file
* \return Returns the length of the file extension
*/
pub fn qrc_fileutils_get_extension(extension: &mut String, extlen: usize, path: &str) -> usize {
    let mut len = 0;
    let mut pos = 0;

    if extlen > 0 {
        qrc_intutils_clear_string(extension);
        let pname = qrc_stringutils_reverse_sub_string(path, ".");

        if qrc_stringutils_string_size(&pname) != 0 {
            pos = qrc_stringutils_string_size(path) - qrc_stringutils_string_size(&pname) - 1;
            len = qrc_stringutils_string_size(path);

            if pos > 0 && extlen >= (len - pos) {
                qrc_stringutils_copy_string(extension, len - pos, &path[pos..]);
            }
        }
    }

    return len - pos;
}

/*
* \brief Get the file name
*
* \param name: The output file name
* \param namelen: The length of the name buffer
* \param path: [const] The full path to the file
* \return Returns the length of the file extension
*/
pub fn qrc_fileutils_get_name(name: &mut String, namelen: usize, path: &str) -> usize {
    let mut len = 0;
    let mut pos = 0;

    if namelen > 0 {
        qrc_intutils_clear_string(name);
        let pname = qrc_stringutils_reverse_sub_string(path, &QRC_FILEUTILS_DIRECTORY_SEPERATOR);

        if qrc_stringutils_string_size(&pname) != 0 {
            len = qrc_stringutils_string_size(path);
            pos = len - qrc_stringutils_string_size(&pname);

            let pext = qrc_stringutils_reverse_sub_string(path, ".");

            if qrc_stringutils_string_size(&pext) != 0 {
                let elen = (len - qrc_stringutils_string_size(&pext)) - 1;

                let slice_len = len - (pos + (len - elen));
                if pos > 0 && namelen >= slice_len {
                    qrc_stringutils_copy_string(name, slice_len, &path[pos..elen]);
                }
            }
        }
    }

    return len - pos;
}

/*
* \brief Get the files size in bytes
*
* \param path: [const] The full path to the file
* \return Returns the length of the file
*/
pub fn qrc_fileutils_get_size(path: &str) -> usize {
    let mut res = 0;

    if qrc_stringutils_string_size(path) != 0 {
        res = File::open(path).unwrap().metadata().unwrap().len() as usize;
    }

    return res;
}

/*
* \brief Test to see if a file exists
*
* \param path: [const] The fully qualified path to the file
* \return Returns true if the file exists
*/
pub fn qrc_fileutils_exists(path: &str) -> bool {
    return metadata(path).is_ok();
}

/*
* \brief Open a file and return the handle
*
* \param path: The fully qualified file path
* \param mode: The file access mode
* \param binary: open the file in binary mode, false is ansi mode
* \return Returns the file handle, or NULL on failure
*/
pub fn qrc_fileutils_open(path: &str, mode: QrcFileutilsMode) -> Option<File> {
    let mut read = false;
    let mut write = false;
    let mut truncate = false;
    let mut append = false;
    let mut create = false;

    if mode == QrcFileutilsMode::QrcFileutilsModeRead {
        read = true;
    } else if mode == QrcFileutilsMode::QrcFileutilsModeReadUpdate {
        read = true;
        write = true;
    } else if mode == QrcFileutilsMode::QrcFileutilsModeWrite {
        write = true;
        truncate = true;
        create = true;
    } else if mode == QrcFileutilsMode::QrcFileutilsModeWriteUpdate {
        read = true;
        write = true;
        truncate = true;
        create = true;
    } else if mode == QrcFileutilsMode::QrcFileutilsModeAppend {
        write = true;
        append = true;
        create = true;
    } else {
        read = true;
        write = true;
        append = true;
        create = true;
    }

    return Some(
        File::options()
            .read(read)
            .write(write)
            .truncate(truncate)
            .append(append)
            .create(create)
            .open(path)
            .unwrap(),
    );
}

/*
* \brief Read data from a file to an output stream
*
* \param output: The output buffer
* \param outlen: The size of the output buffer
* \param position: The starting position within the file
* \param fp: The file pointer
* \return Returns the number of bytes read
*/
pub fn qrc_fileutils_read(
    output: &mut [u8],
    outlen: usize,
    position: usize,
    fp: &mut File,
) -> Result<usize> {
    qrc_fileutils_seekto(fp, position)?;
    fp.read(&mut output[..outlen])
}

/*
* \brief Set the file pointer position
*
* \param fp: The file pointer
* \param position: The position within the file
* \return Returns true if the pointer has been moved
*/
pub fn qrc_fileutils_seekto(fp: &mut File, position: usize) -> Result<()> {
    return fp.seek(Start(position as u64)).map(|_| ());
}

/*
* \brief Reset the file size to a specified byte size
*
* \param fp: The file pointer
* \param length: The new file size
* \return Returns true if the pointer has been moved
*/
pub fn qrc_fileutils_truncate_file(fp: &mut File, length: usize) -> bool {
    let mut res = false;

    fp.seek(End(0)).unwrap();
    let flen = fp.seek(Current(0)).unwrap() as usize;

    if length < flen {
        if fp.set_len(length as u64).is_ok() {
            res = true;
        }
    }

    return res;
}

/*
* \brief Checks if the path is valid
*
* \param path: [const] The full path to the file
* \return Returns true if the path is formed properly
*/
pub fn qrc_fileutils_valid_path(path: &str) -> bool {
    let dir = &mut String::with_capacity(QRC_FILEUTILS_MAX_PATH);
    let ext = &mut String::with_capacity(QRC_FILEUTILS_MAX_EXTENSION);
    let name = &mut String::with_capacity(QRC_FILEUTILS_MAX_FILENAME);

    let mut res = false;

    if qrc_fileutils_get_directory(dir, QRC_FILEUTILS_MAX_PATH, path) > 0 {
        if qrc_fileutils_get_name(name, QRC_FILEUTILS_MAX_EXTENSION, path) > 0 {
            if qrc_fileutils_get_extension(ext, QRC_FILEUTILS_MAX_FILENAME, path) > 0 {
                res = true;
            }
        }
    }

    return res;
}

/*
* \brief Open a file and return the handle
*
* \param input: The input buffer
* \param inlen: The size of the input buffer
* \param position: The starting position within the file
* \param fp: The file pointer
* \return Returns the number of bytes written
*/
pub fn qrc_fileutils_write(
    input: &[u8],
    inlen: usize,
    position: usize,
    fp: &mut File,
) -> Result<usize> {
    qrc_fileutils_seekto(fp, position)?;
    fp.write(&input[..inlen])
}
