// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Handles storage of persistent data.

use std::fs::create_dir;
use std::io::Error as IoError;
use std::path::Path;
use std::path::PathBuf;

use libchromeos::chromeos;
use libchromeos::chromeos::get_daemonstore_path;
use libchromeos::scoped_path::get_temp_path;
// Export this so dependencies don't need to explicitly depend on libsirenia.
pub use libsirenia::communication::persistence::Scope;
use libsirenia::storage::FileStorage;
use libsirenia::storage::Storage;
use libsirenia::storage::{self};
use thiserror::Error as ThisError;

#[derive(ThisError, Debug)]
pub enum Error {
    #[error("failed to retrieve daemonstore path: {0:?}")]
    DaemonstorePath(chromeos::Error),
    #[error("storage path doesn't exist for scope: {0:?}")]
    StoragePathNotExist(Scope),
    #[error("domain path doesn't exist: '{0:?}'")]
    DomainNotExist(String),
    #[error("domain is invalid: '{0}'")]
    InvalidDomain(String),
    #[error("failed to create domain '{0:?}': {1:?}")]
    FailedToCreateDomain(String, IoError),
    #[error("failed to create test scope path '{0:?}': {1:?}")]
    CreateTestPath(String, IoError),
    #[error("failed to create filestorage: '{0:?}'")]
    FileStorage(IoError),
    #[error("failed to write data: '{0:?}'")]
    WriteData(storage::Error),
    #[error("failed to read data: '{0:?}'")]
    ReadData(storage::Error),
    #[error("failed to remove data: '{0:?}'")]
    Remove(storage::Error),
}

impl Error {
    pub fn is_unwritten_id(&self) -> bool {
        matches!(
            self,
            Error::DomainNotExist(_)
                | Error::ReadData(storage::Error::IdNotFound(_))
                | Error::Remove(storage::Error::IdNotFound(_))
        )
    }
}

pub type Result<R> = std::result::Result<R, Error>;

/// Check if an error was caused by looking up an entry that was not written yet.
pub fn is_unwritten_id<R>(res: &Result<R>) -> bool {
    if let Err(e) = res {
        e.is_unwritten_id()
    } else {
        false
    }
}

const DAEMON_STORE_NAME: &str = "cronista";
const DEFAULT_SYSTEM_STORAGE_PATH: &str = "/var/lib/cronista";

fn get_system_storage_path() -> PathBuf {
    Path::new(DEFAULT_SYSTEM_STORAGE_PATH).to_path_buf()
}

fn get_session_storage_path() -> Result<PathBuf> {
    get_daemonstore_path(DAEMON_STORE_NAME).map_err(Error::DaemonstorePath)
}

fn get_storage_path(scope: Scope, domain: &str) -> Result<PathBuf> {
    let domain =
        FileStorage::validate_id(domain).map_err(|_| Error::InvalidDomain(domain.to_string()))?;

    let path = match scope {
        Scope::System => get_system_storage_path(),
        Scope::Session => get_session_storage_path()?,
        Scope::Test => get_temp_path(None),
    };
    if !path.exists() {
        return Err(Error::StoragePathNotExist(scope));
    }
    let sub_path = path.join(&domain);
    Ok(sub_path)
}

pub fn initialize_storage() -> Result<()> {
    let test_path = get_temp_path(None);
    if !test_path.is_dir() {
        create_dir(&test_path)
            .map_err(|err| Error::CreateTestPath(test_path.to_string_lossy().to_string(), err))?;
    }
    Ok(())
}

/// Persists the data at the specified location denoted by (scope, domain, identifier).
pub fn persist(scope: Scope, domain: &str, identifier: &str, data: &[u8]) -> Result<()> {
    let path = get_storage_path(scope, domain)?;
    if !path.is_dir() {
        create_dir(&path).map_err(|err| Error::FailedToCreateDomain(domain.to_string(), err))?;
    }
    let mut storage = FileStorage::new(path).map_err(Error::FileStorage)?;
    storage
        .write_raw(identifier, data)
        .map_err(Error::WriteData)
}

/// Removes the data from the specified location denoted by (scope, domain, identifier).
pub fn remove(scope: Scope, domain: &str, identifier: &str) -> Result<()> {
    let path = get_storage_path(scope, domain)?;
    if !path.is_dir() {
        return Err(Error::DomainNotExist(domain.to_string()));
    }
    let mut storage = FileStorage::new(path).map_err(Error::FileStorage)?;
    storage.remove(identifier).map_err(Error::Remove)
}

/// Retrieves the data from the specified location denoted by (scope, domain, identifier).
pub fn retrieve(scope: Scope, domain: &str, identifier: &str) -> Result<Vec<u8>> {
    let path = get_storage_path(scope, domain)?;
    if !path.is_dir() {
        return Err(Error::DomainNotExist(domain.to_string()));
    }
    let mut storage = FileStorage::new(path).map_err(Error::FileStorage)?;
    storage.read_raw(identifier).map_err(Error::ReadData)
}

#[cfg(test)]
mod test {
    use std::fs::File;
    use std::io::Write;
    use std::time::SystemTime;
    use std::time::UNIX_EPOCH;

    use libchromeos::scoped_path::ScopedPath;

    use super::*;

    const TEST_DOMAIN: &str = "DOMAIN";

    const TEST_ID: &str = "TEST ID";

    fn get_test_value() -> [u8; 8] {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_ne_bytes()
    }

    #[test]
    fn storage_success() {
        let path = ScopedPath::create(get_temp_path(None)).unwrap();
        assert!(path.exists());

        let test_value = get_test_value();
        persist(Scope::Test, TEST_DOMAIN, TEST_ID, &test_value).unwrap();

        let got_value = retrieve(Scope::Test, TEST_DOMAIN, TEST_ID).unwrap();
        assert_eq!(got_value, test_value);
    }

    #[test]
    fn persist_writedata() {
        let path = ScopedPath::create(get_temp_path(None)).unwrap();
        let domain_path = path.join(TEST_DOMAIN);
        create_dir(&domain_path).unwrap();
        create_dir(domain_path.join(TEST_ID)).unwrap();

        let test_value = get_test_value();
        assert!(matches!(
            persist(Scope::Test, TEST_DOMAIN, TEST_ID, &test_value),
            Err(Error::WriteData(_))
        ));
    }

    #[test]
    fn persist_failedtocreatedomain() {
        let path = ScopedPath::create(get_temp_path(None)).unwrap();
        {
            let mut file_at_domain_path = File::create(path.join(TEST_DOMAIN)).unwrap();
            file_at_domain_path.write_all("".as_bytes()).unwrap();
        }

        let test_value = get_test_value();
        assert!(matches!(
            persist(Scope::Test, TEST_DOMAIN, TEST_ID, &test_value),
            Err(Error::FailedToCreateDomain(_, _))
        ));
    }

    #[test]
    fn retrieve_domainnotexist() {
        let path = ScopedPath::create(get_temp_path(None)).unwrap();
        assert!(path.exists());

        assert!(matches!(
            retrieve(Scope::Test, TEST_DOMAIN, TEST_ID),
            Err(Error::DomainNotExist(_))
        ));
    }

    #[test]
    fn retrieve_unwrittenid() {
        let path = ScopedPath::create(get_temp_path(None)).unwrap();
        let domain_path = path.join(TEST_DOMAIN);

        assert!(is_unwritten_id(&retrieve(
            Scope::Test,
            TEST_DOMAIN,
            TEST_ID
        )));

        create_dir(&domain_path).unwrap();

        assert!(is_unwritten_id(&retrieve(
            Scope::Test,
            TEST_DOMAIN,
            TEST_ID
        )));
    }

    #[test]
    fn retrieve_readdata() {
        let path = ScopedPath::create(get_temp_path(None)).unwrap();
        let domain_path = path.join(TEST_DOMAIN);
        create_dir(&domain_path).unwrap();
        create_dir(domain_path.join(TEST_ID)).unwrap();

        assert!(matches!(
            retrieve(Scope::Test, TEST_DOMAIN, TEST_ID),
            Err(Error::ReadData(_))
        ));
    }
}
