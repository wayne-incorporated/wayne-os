// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Implements file based implementation of the Storage trait.

use std::fs::remove_file;
use std::fs::File;
use std::io;
use std::io::Error as IoError;
use std::io::ErrorKind;
use std::io::Read;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use std::result::Result as StdResult;

use super::to_read_data_error;
use super::to_write_data_error;
use super::Error;
use super::Result;
use super::Storage;
use crate::storage::to_remove_error;

pub struct FileStorage {
    root: PathBuf,
}

/// Provides an implementation of the Storage trait that writes the entries to files at a specified
/// path named by the id.
impl FileStorage {
    pub fn new(root: PathBuf) -> StdResult<Self, IoError> {
        if !root.is_dir() {
            return Err(IoError::from(ErrorKind::NotFound));
        }
        Ok(FileStorage { root })
    }

    /// Return true if this path component is allowed.
    fn check_path_component(component: &str) -> bool {
        component != "." && component != ".."
    }

    /// Validity checks on the id performed before touching the file-system.
    pub fn validate_id(id: &str) -> Result<PathBuf> {
        let path = Path::new(id);

        // Get first component.
        let mut itr = path.components();
        let first = PathBuf::from(
            itr.next()
                .ok_or_else(|| Error::InvalidIdForStorage(id.to_string()))?
                .as_os_str(),
        );

        // If there is more than one component or the first component is a special path
        if itr.next().is_some() || !FileStorage::check_path_component(&first.to_string_lossy()) {
            return Err(Error::InvalidIdForStorage(id.to_string()));
        }

        Ok(first)
    }
}

impl Storage for FileStorage {
    /// Read without deserializing.
    fn read_raw(&mut self, id: &str) -> Result<Vec<u8>> {
        let filepath = self.root.join(Self::validate_id(id)?);

        if !filepath.exists() {
            return Err(Error::IdNotFound(id.to_string()));
        }

        let mut contents: Vec<u8> = Vec::new();
        File::open(filepath)
            .map_err(to_read_data_error)?
            .read_to_end(&mut contents)
            .map_err(to_read_data_error)?;

        Ok(contents)
    }

    fn remove(&mut self, id: &str) -> Result<()> {
        let filepath = self.root.join(Self::validate_id(id)?);
        remove_file(filepath).map_err(|err| {
            if err.kind() == io::ErrorKind::NotFound {
                Error::IdNotFound(id.to_string())
            } else {
                to_remove_error(err)
            }
        })
    }

    /// Write without serializing.
    fn write_raw(&mut self, id: &str, data: &[u8]) -> Result<()> {
        let filepath = self.root.join(Self::validate_id(id)?);
        let mut destination = File::create(filepath).map_err(to_write_data_error)?;

        destination.write_all(data).map_err(to_write_data_error)
    }
}

#[cfg(test)]
mod test {
    use std::fs::create_dir;
    use std::time::SystemTime;
    use std::time::UNIX_EPOCH;

    use assert_matches::assert_matches;
    use libchromeos::scoped_path::get_temp_path;
    use libchromeos::scoped_path::ScopedPath;

    use super::*;

    const VALID_TEST_ID: &str = "Test Data";

    struct TestFileStorage {
        storage: FileStorage,
        /// This is needed for its Drop implementation.
        #[allow(dead_code)]
        storage_root: ScopedPath<PathBuf>,
    }

    impl TestFileStorage {
        fn new() -> Self {
            let storage_root = ScopedPath::create(get_temp_path(None)).unwrap();
            let storage = FileStorage::new(storage_root.to_path_buf()).unwrap();
            TestFileStorage {
                storage,
                storage_root,
            }
        }
    }

    impl AsMut<FileStorage> for TestFileStorage {
        fn as_mut(&mut self) -> &mut FileStorage {
            &mut self.storage
        }
    }

    fn get_test_value() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    #[test]
    fn storage_new_success() {
        TestFileStorage::new();
    }

    #[test]
    fn storage_new_notexist() {
        assert!(FileStorage::new(get_temp_path(None)).is_err());
    }

    #[test]
    fn storage_readwrite_success() {
        let mut storage = TestFileStorage::new();

        let test_value = get_test_value();

        storage
            .as_mut()
            .write_data(VALID_TEST_ID, &test_value)
            .unwrap();

        let read_value: u64 = storage.as_mut().read_data(VALID_TEST_ID).unwrap();

        assert_eq!(test_value, read_value);

        assert_matches!(storage.as_mut().remove(VALID_TEST_ID), Ok(()));
    }

    #[test]
    fn storage_read_idnotfound() {
        let mut storage = TestFileStorage::new();

        assert_matches!(
            storage.as_mut().read_data::<u64>(VALID_TEST_ID),
            Err(Error::IdNotFound(_))
        );
    }

    #[test]
    fn storage_removenotfound() {
        let mut storage = TestFileStorage::new();

        assert_matches!(
            storage.as_mut().remove(VALID_TEST_ID),
            Err(Error::IdNotFound(_))
        );
    }

    #[test]
    fn storage_write_ioerror() {
        let mut storage = TestFileStorage::new();

        let path = storage.storage_root.join(VALID_TEST_ID);
        create_dir(path).unwrap();

        assert!(storage
            .as_mut()
            .write_data(VALID_TEST_ID, &get_test_value())
            .is_err());
    }

    #[test]
    fn storage_read_ioerror() {
        let mut storage = TestFileStorage::new();

        let path = storage.storage_root.join(VALID_TEST_ID);
        create_dir(path).unwrap();

        assert!(storage.as_mut().read_data::<u64>(VALID_TEST_ID).is_err());
    }
}
