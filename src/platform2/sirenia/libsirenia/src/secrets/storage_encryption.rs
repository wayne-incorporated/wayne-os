// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Provide a transparent encryption solution for the storage API.

use std::convert::TryFrom;

use base64;
use base64::encode_config;
use flexbuffers::from_slice;
use flexbuffers::to_vec;
use flexbuffers::DeserializationError;
use flexbuffers::SerializationError;
use libchromeos::rand::rand_vec;
use libchromeos::rand::Source;
use libchromeos::secure_blob::SecureBlob;
use openssl::error::ErrorStack;
use openssl::symm::Cipher;
use openssl::symm::Crypter;
use openssl::symm::Mode;
use serde::Deserialize;
use serde::Serialize;
use thiserror::Error as ThisError;

use crate::app_info::AppManifestEntry;
use crate::communication::persistence::Cronista;
use crate::communication::persistence::Scope;
use crate::communication::persistence::Status;
use crate::communication::Digest;
use crate::secrets;
use crate::secrets::compute_sha256;
use crate::secrets::SecretManager;
use crate::secrets::SecretVersion;

const DEFAULT_STORAGE_MAJOR_VERSION: usize = 0;
const DEFAULT_STORAGE_MINOR_VERSION: usize = 0;

const DEFAULT_KEY_SIZE: usize = 32; // AES 256
const DEFAULT_IV_SIZE: usize = 12; // AES-GCM

const MAC_SIZE: usize = 12;

#[derive(ThisError, Debug)]
enum Error {
    #[error("failed to create new crypter: {0:?}")]
    CrypterNew(ErrorStack),
    #[error("failed to update additional authenticated data: {0:?}")]
    AadUpdate(ErrorStack),
    #[error("failed to set tag: {0:?}")]
    SetTag(ErrorStack),
    #[error("failed to get tag: {0:?}")]
    GetTag(ErrorStack),
    #[error("failed to update crypter: {0:?}")]
    Update(ErrorStack),
    #[error("failed to finalize crypter: {0:?}")]
    Finalize(ErrorStack),
    #[error("resulting text doesn't match expected length")]
    LengthMismatch,
    #[error("failed to hash identifier: {0:?}")]
    HashIdentifier(#[source] secrets::Error),
    #[error("failed to get random bytes: {0:?}")]
    RandVec(libchromeos::sys::Error),
    #[error("failed to get storage secret version: {0:?}")]
    StorageSecretVersion(#[source] secrets::Error),
    #[error("failed to derive storage secret: {0:?}")]
    DeriveStorageSecret(#[source] secrets::Error),
    #[error("failed to serialize authenticated data: {0:?}")]
    SerializeAuthenticatedData(#[source] SerializationError),
    #[error("failed to serialize wrapped data: {0:?}")]
    SerializeWrappedData(#[source] SerializationError),
    #[error("storage client failed to persist the data: {0:?}")]
    Persist(#[source] anyhow::Error),
    #[error("failed to deserialize wrapped data: {0:?}")]
    DeserializeWrappedData(#[source] DeserializationError),
    #[error("failed to deserialize authenticated data: {0:?}")]
    DeserializeAuthenticatedData(#[source] DeserializationError),
    #[error("validation of stored data failed.")]
    ValidationFailure,
    #[error("storage client failed to retrieve the data: {0:?}")]
    Retrieve(#[source] anyhow::Error),
}

enum ModeArgs<'a> {
    Decrypt { tag: &'a [u8] },
    Encrypt { tag: &'a mut [u8] },
}

impl<'a> ModeArgs<'a> {
    fn to_mode(&self) -> Mode {
        match self {
            ModeArgs::Decrypt { tag: _ } => Mode::Decrypt,
            ModeArgs::Encrypt { tag: _ } => Mode::Encrypt,
        }
    }
}

/// All fields except the storage_version and iv need to be optional to make
/// backwards compatibility easier.
#[derive(Clone, Debug, Deserialize, Serialize)]
struct AdditionalAuthenticatedData {
    // Represent breaks in forwards compatibility.
    storage_version_major: usize,
    // Represent changes that preserve forwards compatibility.
    storage_version_minor: usize,

    // Crypto fields.
    iv: Vec<u8>,
    salt: Option<Vec<u8>>,
    key_version: Option<SecretVersion>,

    // Storage fields.
    scope: Option<Scope>,
    domain_hash: Option<Vec<u8>>,
    identifier_hash: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct WrappedData {
    /// The associated data is serialized before being included because that is
    /// the form that is covered by the message authentication code (MAC).
    associated_data: Vec<u8>,
    /// The encrypted data.
    cipher_text: Vec<u8>,
    /// The message authentication code used to authenticate the entire struct.
    mac: Vec<u8>,
}

/// A one-way operation to convert a storage domain or identifier to a hash.
fn hash_identifier(identifier: &str) -> Result<Digest, Error> {
    compute_sha256(identifier.as_bytes())
        .map(|d| Digest::try_from(d.as_ref()).expect("Digest size mismatch"))
        .map_err(Error::HashIdentifier)
}

/// Convert a digest to a string that can be used as a filename.
fn digest_to_filename(digest: &[u8]) -> String {
    encode_config(digest, base64::URL_SAFE)
}

/// Wraps CronistaClient with transparent encryption.
pub struct StorageEncryption<'a> {
    app_info: &'a AppManifestEntry,
    secret_manager: &'a SecretManager,
    storage_client: &'a mut dyn Cronista<anyhow::Error>,
}

impl<'a> StorageEncryption<'a> {
    pub fn new(
        app_info: &'a AppManifestEntry,
        secret_manager: &'a SecretManager,
        storage_client: &'a mut dyn Cronista<anyhow::Error>,
    ) -> Self {
        StorageEncryption {
            app_info,
            secret_manager,
            storage_client,
        }
    }

    fn do_crypto(
        &self,
        mode: ModeArgs,
        key: &[u8],
        iv: &[u8],
        associated_data: &[u8],
        text_before: &[u8],
        text_after: &mut [u8],
    ) -> Result<(), Error> {
        let mut crypter = Crypter::new(Cipher::aes_256_gcm(), mode.to_mode(), key, Some(iv))
            .map_err(Error::CrypterNew)?;
        if let ModeArgs::Decrypt { tag } = &mode {
            crypter.set_tag(tag).map_err(Error::SetTag)?;
        }
        crypter
            .aad_update(associated_data)
            .map_err(Error::AadUpdate)?;
        let mut written = crypter
            .update(text_before, text_after)
            .map_err(Error::Update)?;
        written += crypter
            .finalize(&mut text_after[written..])
            .map_err(Error::Finalize)?;
        if written != text_after.len() {
            return Err(Error::LengthMismatch);
        }
        if let ModeArgs::Encrypt { tag } = mode {
            crypter.get_tag(tag).map_err(Error::GetTag)?;
        }
        Ok(())
    }

    fn persist_impl(
        &mut self,
        scope: Scope,
        domain: String,
        identifier: String,
        data: Vec<u8>,
    ) -> Result<Status, Error> {
        let plain_text = SecureBlob::from(data);
        let domain_hash = hash_identifier(&domain)?;
        let identifier_hash = hash_identifier(&identifier)?;

        let iv = rand_vec(DEFAULT_IV_SIZE, Source::Random).map_err(Error::RandVec)?;
        let salt = rand_vec(DEFAULT_KEY_SIZE, Source::Random).map_err(Error::RandVec)?;

        let version = self
            .secret_manager
            .get_storage_secret_version(self.app_info)
            .map_err(Error::StorageSecretVersion)?;

        let key = self
            .secret_manager
            .derive_storage_secret(
                self.app_info,
                version,
                &salt,
                &domain,
                &identifier,
                DEFAULT_KEY_SIZE,
            )
            .map_err(Error::DeriveStorageSecret)?;

        let associated_data = to_vec(AdditionalAuthenticatedData {
            storage_version_major: DEFAULT_STORAGE_MAJOR_VERSION,
            storage_version_minor: DEFAULT_STORAGE_MINOR_VERSION,

            iv: iv.clone(),
            salt: Some(salt),
            key_version: Some(version),

            scope: Some(scope.clone()),
            domain_hash: Some(domain_hash.to_vec()),
            identifier_hash: Some(identifier_hash.to_vec()),
        })
        .map_err(Error::SerializeAuthenticatedData)?;

        let mut cipher_text = vec![0; plain_text.len()];
        let mut mac = vec![0u8; MAC_SIZE];
        self.do_crypto(
            ModeArgs::Encrypt { tag: &mut mac },
            key.as_ref(),
            &iv,
            &associated_data,
            plain_text.as_ref(),
            &mut cipher_text,
        )?;

        let wrapped_data = to_vec(WrappedData {
            associated_data,
            cipher_text,
            mac,
        })
        .map_err(Error::SerializeWrappedData)?;

        // TODO if this fails, there is a risk of IV reuse, so the (Salt, IV, MAC) need to be
        // registered with the tamper resistant log before disclosing the cipher text, and the
        // log needs to be used to load the state of the IV during retrieve operations.
        self.storage_client
            .persist(
                scope,
                digest_to_filename(&*domain_hash),
                digest_to_filename(&*identifier_hash),
                wrapped_data,
            )
            .map_err(Error::Persist)
    }

    fn retrieve_impl(
        &mut self,
        scope: Scope,
        domain: String,
        identifier: String,
    ) -> Result<(Status, Vec<u8>), Error> {
        let domain_hash = hash_identifier(&domain)?;
        let identifier_hash = hash_identifier(&identifier)?;
        let (status, data) = self
            .storage_client
            .retrieve(
                scope.clone(),
                digest_to_filename(&*domain_hash),
                digest_to_filename(&*identifier_hash),
            )
            .map_err(Error::Retrieve)?;
        if data.is_empty() || !matches!(status, Status::Success) {
            return Ok((status, Vec::default()));
        }

        // Ideally, we wouldn't deserialize anything without checking if it is authenticated, but
        // there are fields that are needed to perform the decryption which checks for
        // authentication, so deserialization is needed.
        let wrapped_data: WrappedData = from_slice(&data).map_err(Error::DeserializeWrappedData)?;
        let aad: AdditionalAuthenticatedData = from_slice(&wrapped_data.associated_data)
            .map_err(Error::DeserializeAuthenticatedData)?;

        let max_version = self
            .secret_manager
            .get_storage_secret_version(self.app_info)
            .map_err(Error::StorageSecretVersion)?;
        // TODO replay attack check.

        // Validation.
        if aad.storage_version_major > DEFAULT_STORAGE_MAJOR_VERSION
            || aad.iv.len() != DEFAULT_IV_SIZE
            || !matches!(&aad.key_version, Some(a) if *a <= max_version)
            || !matches!(&aad.salt, Some(a) if a.len() == DEFAULT_KEY_SIZE)
            || !matches!(&aad.scope, Some(a) if a == &scope)
            || !matches!(&aad.domain_hash, Some(a) if a == &*domain_hash)
            || !matches!(&aad.identifier_hash, Some(a) if a == &*identifier_hash)
            || wrapped_data.mac.len() != MAC_SIZE
        {
            return Err(Error::ValidationFailure);
        }

        let key_version = aad.key_version.unwrap();
        let key = self
            .secret_manager
            .derive_storage_secret(
                self.app_info,
                key_version,
                aad.salt.as_ref().unwrap(),
                &domain,
                &identifier,
                DEFAULT_KEY_SIZE,
            )
            .map_err(Error::DeriveStorageSecret)?;

        let mut plain_text = vec![0; wrapped_data.cipher_text.len()];
        self.do_crypto(
            ModeArgs::Decrypt {
                tag: &wrapped_data.mac,
            },
            key.as_ref(),
            &aad.iv,
            &wrapped_data.associated_data,
            &wrapped_data.cipher_text,
            &mut plain_text,
        )?;

        Ok((status, plain_text))
    }
}

impl<'a> Cronista<anyhow::Error> for StorageEncryption<'a> {
    fn persist(
        &mut self,
        scope: Scope,
        domain: String,
        identifier: String,
        data: Vec<u8>,
    ) -> Result<Status, anyhow::Error> {
        match self.persist_impl(scope, domain, identifier, data) {
            Ok(v) => Ok(v),
            Err(Error::Persist(rpc_err)) => Err(rpc_err),
            Err(err) => {
                // This is intentionally kept vague when reporting to CrOS to avoid creating a
                // scenario like the padded oracle attack. Note that the syslog is forwarded to
                // the Chrome OS guest.
                eprintln!("Got error: {:?}", err);
                Ok(Status::CryptoFailure)
            }
        }
    }

    fn remove(
        &mut self,
        scope: Scope,
        domain: String,
        identifier: String,
    ) -> Result<Status, anyhow::Error> {
        self.storage_client.remove(scope, domain, identifier)
    }

    fn retrieve(
        &mut self,
        scope: Scope,
        domain: String,
        identifier: String,
    ) -> Result<(Status, Vec<u8>), anyhow::Error> {
        match self.retrieve_impl(scope, domain, identifier) {
            Ok(v) => Ok(v),
            Err(Error::Retrieve(rpc_err)) => Err(rpc_err),
            Err(err) => {
                // This is intentionally kept vague when reporting to CrOS to avoid creating a
                // scenario like the padded oracle attack. Note that the syslog is forwarded to
                // the Chrome OS guest.
                eprintln!("Got error: {:?}", err);
                Ok((Status::CryptoFailure, Vec::default()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::Write;
    use std::path::Path;

    use assert_matches::assert_matches;
    use base64::decode_config;
    use libchromeos::scoped_path::get_temp_path;
    use libchromeos::scoped_path::ScopedPath;
    use libchromeos::secure_blob::SecureBlob;

    use super::*;
    use crate::app_info::AppManifest;
    use crate::app_info::ExecutableInfo;
    use crate::app_info::SandboxType;
    use crate::app_info::StdErrBehavior;
    use crate::app_info::StorageParameters;
    use crate::communication::persistence::MockCronista;
    use crate::communication::persistence::Scope;
    use crate::secrets::GscSecret;
    use crate::secrets::PlatformSecret;
    use crate::secrets::VersionedSecret;
    use crate::secrets::MAX_VERSION;

    const TEST_MAIN_SECRET_VERSION: usize = 1;
    const TEST_APP_ID: &str = "demo_app";
    const TEST_DOMAIN: &str = "test domain";
    const TEST_IDENTIFIER: &str = "test id";
    const TEST_DATA: &[u8; 17] = b"data for the test";

    /// Convert a filename to the digest it represents.
    fn filename_to_digest(filename: &str) -> Result<Vec<u8>, base64::DecodeError> {
        decode_config(filename, base64::URL_SAFE)
    }

    fn get_test_secret_manager() -> (SecretManager, AppManifest) {
        let platform_secret = PlatformSecret::new(
            SecretManager::default_hash_function(),
            SecureBlob::from(vec![77u8; 64]),
            MAX_VERSION,
        )
        .derive_other_version(TEST_MAIN_SECRET_VERSION)
        .unwrap();
        let gsc_secret = GscSecret::new(
            SecretManager::default_hash_function(),
            SecureBlob::from(vec![77u8; 64]),
            MAX_VERSION,
        )
        .derive_other_version(TEST_MAIN_SECRET_VERSION)
        .unwrap();
        let mut manifest = AppManifest::new();
        let prev = manifest.add_app_manifest_entry(AppManifestEntry {
            app_name: "demo_app".to_string(),
            devmode_only: false,
            exec_info: ExecutableInfo::Path("/usr/bin/demo_app".to_string()),
            exec_args: None,
            sandbox_type: SandboxType::DeveloperEnvironment,
            secrets_parameters: None,
            stderr_behavior: StdErrBehavior::MergeWithStdout,
            storage_parameters: Some(StorageParameters {
                scope: Scope::Test,
                domain: "test".to_string(),
                encryption_key_version: Some(1),
            }),
        });
        assert_eq!(prev, None);
        let manager = SecretManager::new(platform_secret, gsc_secret, &manifest).unwrap();
        (manager, manifest)
    }

    #[test]
    fn check_filename_encoding() {
        let test_path = ScopedPath::create(get_temp_path(None)).unwrap();

        // Make sure the encoding is reversible.
        let digest = hash_identifier(TEST_IDENTIFIER).unwrap();
        let filename = digest_to_filename(&*digest);
        assert_eq!(&filename_to_digest(&filename).unwrap(), &*digest);

        // Perform some basic checks on the encoded name.
        let file_path_component = Path::new(&filename);
        assert!(file_path_component.is_relative());
        assert_eq!(file_path_component.components().count(), 1);

        // Make sure the filesystem accepts the path.
        let file_path = test_path.join(file_path_component);
        let mut file = File::create(&file_path).unwrap();
        file.write_all(b"").unwrap();
        drop(file);

        assert!(file_path.exists());
    }

    #[test]
    fn check_success() {
        let (manager, manifest) = get_test_secret_manager();
        let app_info = manifest.get_app_manifest_entry(TEST_APP_ID).unwrap();
        let mut cronista = MockCronista::new();
        let mut storage = StorageEncryption::new(app_info, &manager, &mut cronista);

        let ret = storage
            .persist(
                Scope::Test,
                TEST_DOMAIN.to_string(),
                TEST_IDENTIFIER.to_string(),
                TEST_DATA.to_vec(),
            )
            .unwrap();
        assert_matches!(ret, Status::Success);

        let ret = storage
            .retrieve(
                Scope::Test,
                TEST_DOMAIN.to_string(),
                TEST_IDENTIFIER.to_string(),
            )
            .unwrap();
        assert_eq!(&ret.1, TEST_DATA);
        assert_matches!(ret.0, Status::Success);
    }

    #[test]
    fn check_idnotfound() {
        let (manager, manifest) = get_test_secret_manager();
        let app_info = manifest.get_app_manifest_entry(TEST_APP_ID).unwrap();
        let mut cronista = MockCronista::new();
        let mut storage = StorageEncryption::new(app_info, &manager, &mut cronista);

        let ret = storage
            .retrieve(
                Scope::Test,
                TEST_DOMAIN.to_string(),
                TEST_IDENTIFIER.to_string(),
            )
            .unwrap();
        assert!(ret.1.is_empty());
        assert_matches!(ret.0, Status::IdNotFound);
    }

    #[test]
    fn authentication_failure() {
        let (manager, manifest) = get_test_secret_manager();
        let app_info = manifest.get_app_manifest_entry(TEST_APP_ID).unwrap();
        let mut cronista = MockCronista::new();
        let key_version = manager.get_storage_secret_version(app_info).unwrap();

        let domain_hash = hash_identifier(TEST_DOMAIN).unwrap();
        let identifier_hash = hash_identifier(TEST_IDENTIFIER).unwrap();

        let iv = rand_vec(DEFAULT_IV_SIZE, Source::Random).unwrap();
        let salt = rand_vec(DEFAULT_KEY_SIZE, Source::Random).unwrap();

        let key = manager
            .derive_storage_secret(
                app_info,
                key_version,
                &salt,
                TEST_DOMAIN,
                TEST_IDENTIFIER,
                DEFAULT_KEY_SIZE,
            )
            .unwrap();

        let mut aad = AdditionalAuthenticatedData {
            storage_version_major: DEFAULT_STORAGE_MAJOR_VERSION,
            storage_version_minor: DEFAULT_STORAGE_MINOR_VERSION,

            iv: iv.clone(),
            salt: Some(salt),
            key_version: Some(key_version),

            scope: Some(Scope::Test),
            domain_hash: Some(domain_hash.to_vec()),
            identifier_hash: Some(identifier_hash.to_vec()),
        };

        let associated_data = to_vec(aad.clone()).unwrap();

        let mut cipher_text = vec![0; TEST_DATA.len()];
        let mut mac = vec![0u8; MAC_SIZE];
        let storage = StorageEncryption::new(app_info, &manager, &mut cronista);
        storage
            .do_crypto(
                ModeArgs::Encrypt { tag: &mut mac },
                key.as_ref(),
                &iv,
                &associated_data,
                TEST_DATA,
                &mut cipher_text,
            )
            .unwrap();

        // Modify some of the associated data and make sure the authentication tag catches it.
        aad.scope = Some(Scope::System);
        let tampered_associated_data = to_vec(aad).unwrap();

        assert_ne!(associated_data, tampered_associated_data);

        assert_matches!(
            storage.do_crypto(
                ModeArgs::Decrypt { tag: &mac },
                key.as_ref(),
                &iv,
                &tampered_associated_data,
                TEST_DATA,
                &mut cipher_text,
            ),
            Err(Error::Finalize(_))
        );
    }
}
