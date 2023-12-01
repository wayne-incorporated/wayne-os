// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Uses cryptography to provide deterministic secret derivation from a root secret.

pub mod storage_encryption;

use std::cell::RefCell;
use std::collections::BTreeMap as Map;
use std::fmt::Debug;
use std::iter;
use std::mem::size_of;
use std::ops::Deref;
use std::rc::Rc;
use std::rc::Weak;

use libchromeos::secure_blob::SecureBlob;
use openssl::error::ErrorStack;
use openssl::hash::DigestBytes;
use openssl::hash::Hasher;
use openssl::hash::MessageDigest;
use openssl::md::Md;
use openssl::pkey::Id;
use openssl::pkey_ctx::PkeyCtx;
use thiserror::Error as ThisError;

use crate::app_info::AppManifest;
use crate::app_info::AppManifestEntry;

/// Salt used when mixing two secrets with HKDF.
const DEFAULT_SALT: &[u8] = &[7u8; 64];

/// A label to differentiate secret given to applications.
const APP_SECRET_LABEL: &[u8] = b"app key";

/// A label to differential secrets used for storage.
const STORAGE_SECRET_LABEL: &[u8] = b"storage key";

pub const MAX_VERSION: usize = 1024;

#[derive(ThisError, Debug)]
pub enum Error {
    #[error("failed to derive key: {0:}")]
    Derive(#[source] ErrorStack),
    #[error("failed to allocate key derivation: {0:}")]
    DeriveNew(#[source] ErrorStack),
    #[error("failed to initialize key derivation: {0:}")]
    DeriveInit(#[source] ErrorStack),
    #[error("failed to set key for key derivation: {0:}")]
    DeriveSetKey(#[source] ErrorStack),
    #[error("failed to set info for key derivation: {0:}")]
    DeriveSetInfo(#[source] ErrorStack),
    #[error("failed to set salt for key derivation: {0:}")]
    DeriveSetSalt(#[source] ErrorStack),
    #[error("failed to set digest for key derivation: {0:}")]
    DeriveSetDigest(#[source] ErrorStack),
    #[error("requested API is is not enabled for `{0}`.")]
    ApiNotEnabledForApp(String),
    #[error("requested version is too large: got {0}; max {1}")]
    VersionTooLarge(String, String),
    #[error("expected secrets to have the same versions: got {0} and {1}")]
    VersionMismatch(String, String),
    #[error("failed to create hasher: {0}")]
    Hasher(#[source] ErrorStack),
    #[error("failed to update hasher: {0}")]
    Update(#[source] ErrorStack),
    #[error("failed to finish hasher: {0}")]
    Finish(#[source] ErrorStack),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Compute digest of the inputs.
fn hash<'a>(
    digest: MessageDigest,
    inputs: impl IntoIterator<Item = &'a &'a [u8]>,
) -> Result<DigestBytes> {
    let mut hasher = Hasher::new(digest).map_err(Error::Hasher)?;
    for input in inputs {
        hasher.update(input).map_err(Error::Update)?;
    }
    hasher.finish().map_err(Error::Finish)
}

pub fn hash_sha256<'a>(inputs: impl IntoIterator<Item = &'a &'a [u8]>) -> Result<DigestBytes> {
    hash(MessageDigest::sha256(), inputs)
}

pub fn compute_sha256(data: &[u8]) -> Result<DigestBytes> {
    hash_sha256(std::iter::once(&data))
}

pub trait VersionedSecret: Clone + Sized {
    /// Represents the secret version.
    type Version: Clone + Debug + Eq + PartialOrd;
    type Previous: VersionedSecretProvider<Secret = Self>;

    /// Access the secret.
    fn secret(&self) -> &[u8];

    /// Access the version.
    fn version(&self) -> Self::Version;

    /// Derive a previous version of the secret.
    fn derive_other_version(&self, version: Self::Version) -> Result<Self>;

    /// Provides a mapping to previous versions excluding the current version.
    fn previous_versions(&self) -> Rc<Self::Previous>;
}

pub trait VersionedSecretProvider: Clone + Sized {
    /// Represents the secret version.
    type Secret: VersionedSecret;

    fn get_secret(
        &self,
        version: <Self::Secret as VersionedSecret>::Version,
    ) -> Result<Self::Secret>;

    fn previous_versions(&self) -> Rc<Self>;
}

#[derive(Clone)]
pub struct HashedVersionedSecret {
    message_digest: MessageDigest,
    secret: SecureBlob,
    version: usize,
    /// Opportunistic cache of the previous version. This reduces duplicated effort and copies of
    /// the secrets during derivation.
    previous: RefCell<Weak<Self>>,
}

impl HashedVersionedSecret {
    pub fn new(message_digest: MessageDigest, secret: SecureBlob, max_version: usize) -> Self {
        HashedVersionedSecret {
            message_digest,
            secret,
            version: max_version,
            previous: RefCell::new(Weak::default()),
        }
    }
}

impl VersionedSecret for HashedVersionedSecret {
    type Version = usize;
    type Previous = Self;

    fn secret(&self) -> &[u8] {
        self.secret.as_ref()
    }

    fn version(&self) -> usize {
        self.version
    }

    fn derive_other_version(&self, version: usize) -> Result<Self> {
        if self.version < version {
            return Err(Error::VersionTooLarge(
                version.to_string(),
                self.version.to_string(),
            ));
        }
        let mut secret = self.secret.clone();
        for _ in version..self.version {
            secret =
                SecureBlob::from(hash(self.message_digest, iter::once(&secret.as_ref()))?.to_vec());
        }
        Ok(HashedVersionedSecret {
            message_digest: self.message_digest,
            secret,
            version,
            previous: RefCell::new(Weak::default()),
        })
    }

    /// Provides a mapping to previous versions without retaining the current version.
    fn previous_versions(&self) -> Rc<Self> {
        if let Some(prev) = self.previous.borrow().deref().upgrade() {
            return prev;
        }

        if self.version > 0 {
            if let Ok(sec) = self.derive_other_version(self.version - 1) {
                let prev = Rc::new(sec);
                self.previous.replace(Rc::downgrade(&prev));
                return prev;
            }
        }

        let prev = Rc::new(HashedVersionedSecret {
            secret: SecureBlob::with_capacity(0),
            version: 0,
            message_digest: self.message_digest,
            previous: RefCell::new(Weak::default()),
        });
        self.previous.replace(Rc::downgrade(&prev));
        prev
    }
}

impl VersionedSecretProvider for HashedVersionedSecret {
    type Secret = Self;

    fn get_secret(&self, version: usize) -> Result<Self::Secret> {
        if self.secret.is_empty() {
            return Err(Error::VersionTooLarge(
                version.to_string(),
                "NaN".to_string(),
            ));
        }
        self.derive_other_version(version)
    }

    /// Provides a mapping to previous versions without retaining the current version.
    fn previous_versions(&self) -> Rc<Self> {
        VersionedSecret::previous_versions(self)
    }
}

/// A hashed versioned secret derived from another versioned secret.
#[derive(Clone)]
pub struct DerivedHashedVersionedSecret<P: VersionedSecret> {
    message_digest: MessageDigest,
    secret: SecureBlob,
    version: (P::Version, usize),

    previous_parents: Rc<P::Previous>,
    salt: Vec<u8>,
    input: Vec<u8>,
    max_version: usize,

    /// Opportunistic cache of the previous version. This reduces duplicated effort and copies of
    /// the secrets during derivation.
    previous: RefCell<Weak<Self>>,
}

impl<P: VersionedSecret> DerivedHashedVersionedSecret<P> {
    pub fn new(
        parent: &P,
        message_digest: MessageDigest,
        salt: &[u8],
        input: &[u8],
        max_version: usize,
    ) -> Result<Self> {
        let secret = derive_secret(parent.secret(), salt, input, message_digest.size())?;
        let previous_parents = parent.previous_versions();
        Ok(DerivedHashedVersionedSecret {
            message_digest,
            secret,
            version: (parent.version(), max_version),

            previous_parents,
            salt: salt.to_vec(),
            input: input.to_vec(),
            max_version,

            previous: RefCell::new(Weak::default()),
        })
    }
}

impl<P: VersionedSecret> VersionedSecret for DerivedHashedVersionedSecret<P> {
    type Version = (P::Version, usize);
    type Previous = Self;

    fn secret(&self) -> &[u8] {
        self.secret.as_ref()
    }

    fn version(&self) -> (P::Version, usize) {
        self.version.clone()
    }

    fn derive_other_version(&self, version: (P::Version, usize)) -> Result<Self> {
        if self.version < version {
            return Err(Error::VersionTooLarge(
                format!("{:?}", &version),
                format!("{:?}", self.version),
            ));
        }
        if self.version == version {
            return Ok(self.clone());
        }
        if self.version.0 == version.0 {
            let mut secret = self.secret.clone();
            for _ in version.1..self.version.1 {
                secret = SecureBlob::from(
                    hash(self.message_digest, iter::once(&secret.as_ref()))?.to_vec(),
                );
            }
            let mut other = self.clone();
            other.secret = secret;
            other.version = version;
            other.previous = RefCell::new(Weak::default());
            return Ok(other);
        }

        let previous = self.previous_parents.get_secret(version.0.clone())?;
        let other = DerivedHashedVersionedSecret::new(
            &previous,
            self.message_digest,
            &self.salt,
            &self.input,
            self.max_version,
        )?;
        other.derive_other_version(version)
    }

    /// Provides a mapping to previous versions without retaining the current version.
    fn previous_versions(&self) -> Rc<Self> {
        if let Some(prev) = self.previous.borrow().deref().upgrade() {
            return prev;
        }

        if self.version.1 > 0 {
            if let Ok(sec) = self.derive_other_version((self.version.0.clone(), self.version.1 - 1))
            {
                let prev = Rc::new(sec);
                self.previous.replace(Rc::downgrade(&prev));
                return prev;
            }
        }

        let mut other = self.clone();
        other.secret.clear();
        let prev = Rc::new(other);
        self.previous.replace(Rc::downgrade(&prev));
        prev
    }
}

impl<P: VersionedSecret> VersionedSecretProvider for DerivedHashedVersionedSecret<P> {
    type Secret = Self;

    fn get_secret(&self, version: (P::Version, usize)) -> Result<Self::Secret> {
        if self.secret.is_empty() {
            return Err(Error::VersionTooLarge(
                format!("{:?}", version),
                "NaN".to_string(),
            ));
        }
        self.derive_other_version(version)
    }

    /// Provides a mapping to previous versions without retaining the current version.
    fn previous_versions(&self) -> Rc<Self> {
        VersionedSecret::previous_versions(self)
    }
}

#[derive(Clone)]
pub struct MixedVersionedSecret<
    V: Clone + Debug + Eq + PartialOrd,
    A: VersionedSecret<Version = V>,
    B: VersionedSecret<Version = V>,
> {
    prev_a: Rc<A::Previous>,
    prev_b: Rc<B::Previous>,
    secret: SecureBlob,
    version: V,

    /// Opportunistic cache of the previous version. This reduces duplicated effort and copies of
    /// the secrets during derivation.
    previous: RefCell<Weak<<Self as VersionedSecret>::Previous>>,
}

impl<
        V: Clone + Debug + Eq + PartialOrd,
        A: VersionedSecret<Version = V>,
        B: VersionedSecret<Version = V>,
    > MixedVersionedSecret<V, A, B>
{
    pub fn new(secret_a: &A, secret_b: &B) -> Result<Self> {
        let ver_a = secret_a.version();
        let ver_b = secret_b.version();
        if ver_a != ver_b {
            return Err(Error::VersionMismatch(
                format!("{:?}", ver_a),
                format!("{:?}", ver_b),
            ));
        }

        let sec_a = secret_a.secret();
        let sec_b = secret_b.secret();

        let secret = derive_secret(sec_a, DEFAULT_SALT, sec_b, sec_a.len().max(sec_b.len()))?;
        let prev_a = secret_a.previous_versions();
        let prev_b = secret_b.previous_versions();
        Ok(MixedVersionedSecret {
            prev_a,
            prev_b,
            secret,
            version: ver_a,

            previous: RefCell::new(Weak::default()),
        })
    }
}

impl<
        V: Clone + Debug + Eq + PartialOrd,
        A: VersionedSecret<Version = V>,
        B: VersionedSecret<Version = V>,
    > VersionedSecret for MixedVersionedSecret<V, A, B>
{
    type Version = V;
    type Previous = MixedVersionedProvider<V, A, B>;

    fn secret(&self) -> &[u8] {
        self.secret.as_ref()
    }

    fn version(&self) -> V {
        self.version.clone()
    }

    fn derive_other_version(&self, version: Self::Version) -> Result<Self> {
        if version == self.version {
            return Ok(self.clone());
        }
        let secret_a: A = self.prev_a.deref().get_secret(version.clone())?;
        let secret_b: B = self.prev_b.deref().get_secret(version)?;
        Self::new(&secret_a, &secret_b)
    }

    /// Provides a mapping to previous versions without retaining the current version.
    fn previous_versions(&self) -> Rc<Self::Previous> {
        if let Some(prev) = self.previous.borrow().deref().upgrade() {
            return prev;
        }

        let prev = Rc::new(MixedVersionedProvider {
            prev_a: self.prev_a.clone(),
            prev_b: self.prev_b.clone(),

            previous: RefCell::new(Weak::default()),
        });
        self.previous.replace(Rc::downgrade(&prev));
        prev
    }
}

#[derive(Clone)]
pub struct MixedVersionedProvider<
    V: Clone + Debug + Eq + PartialOrd,
    A: VersionedSecret<Version = V>,
    B: VersionedSecret<Version = V>,
> {
    prev_a: Rc<A::Previous>,
    prev_b: Rc<B::Previous>,

    /// Opportunistic cache of the previous version. This reduces duplicated effort and copies of
    /// the secrets during derivation.
    previous: RefCell<Weak<Self>>,
}

impl<
        V: Clone + Debug + Eq + PartialOrd,
        A: VersionedSecret<Version = V>,
        B: VersionedSecret<Version = V>,
    > VersionedSecretProvider for MixedVersionedProvider<V, A, B>
{
    type Secret = MixedVersionedSecret<V, A, B>;

    fn get_secret(&self, version: V) -> Result<Self::Secret> {
        let secret_a = self.prev_a.get_secret(version.clone())?;
        let secret_b = self.prev_b.get_secret(version)?;
        MixedVersionedSecret::new(&secret_a, &secret_b)
    }

    /// Provides a mapping to previous versions without retaining the current version.
    fn previous_versions(&self) -> Rc<Self> {
        if let Some(prev) = self.previous.borrow().deref().upgrade() {
            return prev;
        }

        let prev = Rc::new(MixedVersionedProvider {
            prev_a: self.prev_a.previous_versions(),
            prev_b: self.prev_b.previous_versions(),

            previous: RefCell::new(Weak::default()),
        });
        self.previous.replace(Rc::downgrade(&prev));
        prev
    }
}

/// Provides access to low-level secret/key generation.
fn derive_secret(
    key: &[u8],
    salt: &[u8],
    input: &[u8],
    key_size_bytes: usize,
) -> Result<SecureBlob> {
    let mut secret = SecureBlob::from(vec![0; key_size_bytes]);
    let mut ctx = PkeyCtx::new_id(Id::HKDF).map_err(Error::DeriveNew)?;
    ctx.derive_init().map_err(Error::DeriveInit)?;
    ctx.set_hkdf_key(key).map_err(Error::DeriveSetKey)?;
    ctx.set_hkdf_salt(salt).map_err(Error::DeriveSetSalt)?;
    ctx.add_hkdf_info(input).map_err(Error::DeriveSetInfo)?;
    ctx.set_hkdf_md(Md::sha256())
        .map_err(Error::DeriveSetDigest)?;
    if ctx.derive(Some(secret.as_mut())).map_err(Error::Derive)? != secret.len() {
        unreachable!("openssl usage is incorrect.")
    }
    Ok(secret)
}

pub type PlatformSecret = HashedVersionedSecret;
pub type GscSecret = HashedVersionedSecret;
pub type MainSecretVersion = usize;
pub type MainSecret = MixedVersionedSecret<MainSecretVersion, PlatformSecret, GscSecret>;
pub type Intermediate = DerivedHashedVersionedSecret<MainSecret>;
pub type SecretVersion = <Intermediate as VersionedSecret>::Version;

/// Provides key derivation from a main_secret.
pub struct SecretManager {
    intermediates: Map<Vec<u8>, Intermediate>,
}

impl SecretManager {
    pub fn default_hash_function() -> MessageDigest {
        MessageDigest::sha256()
    }

    pub fn new(
        platform_secret: PlatformSecret,
        gsc_secret: GscSecret,
        app_manifest: &AppManifest,
    ) -> Result<Self> {
        let main_secret = MainSecret::new(&platform_secret, &gsc_secret)?;
        let parent_version = main_secret.version();
        let mut intermediates = Map::<Vec<u8>, Intermediate>::new();

        for entry in app_manifest.iter() {
            let app_name = &entry.app_name;
            let salt = hash(
                SecretManager::default_hash_function(),
                iter::once(&app_name.as_bytes()),
            )?;

            if let Some(params) = &entry.secrets_parameters {
                let input =
                    SecretManager::construct_input(&[APP_SECRET_LABEL, app_name.as_bytes()]);
                let intermediate = Intermediate::new(
                    &main_secret,
                    SecretManager::default_hash_function(),
                    salt.as_ref(),
                    &input,
                    MAX_VERSION,
                )?
                .derive_other_version((parent_version, params.encryption_key_version))?;
                intermediates.insert(input, intermediate);
            }

            if let Some(params) = &entry.storage_parameters {
                if let Some(version) = params.encryption_key_version {
                    let input = SecretManager::construct_input(&[
                        STORAGE_SECRET_LABEL,
                        app_name.as_bytes(),
                    ]);
                    let intermediate = Intermediate::new(
                        &main_secret,
                        SecretManager::default_hash_function(),
                        salt.as_ref(),
                        &input,
                        MAX_VERSION,
                    )?
                    .derive_other_version((parent_version, version))?;
                    intermediates.insert(input, intermediate);
                }
            }
        }

        Ok(SecretManager { intermediates })
    }

    /// Construct an unambiguous byte slice from the version and labels.
    ///
    /// The structure is:
    /// * version
    /// * number of labels
    /// * labels:
    ///   * label n length
    ///   * label n
    fn construct_input(labels: &[&[u8]]) -> Vec<u8> {
        let mut input_size = size_of::<usize>() * (labels.len() + 1);
        for label in labels {
            input_size += label.len();
        }

        let mut input = Vec::<u8>::with_capacity(input_size);
        input.extend_from_slice(&labels.len().to_ne_bytes());
        for label in labels {
            input.extend_from_slice(&label.len().to_ne_bytes());
            input.extend_from_slice(label);
        }
        input
    }

    pub fn derive_labeled_secret(
        &self,
        label_prefix: &[u8],
        entry: &AppManifestEntry,
        key_version: SecretVersion,
        salt: &[u8],
        labels: &[&[u8]],
        key_size_bytes: usize,
    ) -> Result<SecureBlob> {
        let lookup_input =
            SecretManager::construct_input(&[label_prefix, entry.app_name.as_bytes()]);

        if let Some(intermediate) = self.intermediates.get(&lookup_input) {
            let input = SecretManager::construct_input(labels);
            let requested_version = intermediate.derive_other_version(key_version)?;
            derive_secret(requested_version.secret(), salt, &input, key_size_bytes)
        } else {
            Err(Error::ApiNotEnabledForApp(entry.app_name.to_string()))
        }
    }

    pub fn get_secret_version(
        &self,
        label_prefix: &[u8],
        entry: &AppManifestEntry,
    ) -> Result<SecretVersion> {
        let lookup_input =
            SecretManager::construct_input(&[label_prefix, entry.app_name.as_bytes()]);

        if let Some(intermediate) = self.intermediates.get(&lookup_input) {
            Ok(intermediate.version)
        } else {
            Err(Error::ApiNotEnabledForApp(entry.app_name.to_string()))
        }
    }

    /// Derive a secret intended to be given to TEE apps.
    pub fn derive_app_secret(
        &self,
        entry: &AppManifestEntry,
        key_version: SecretVersion,
        salt: &[u8],
        labels: &[&[u8]],
        key_size_bytes: usize,
    ) -> Result<SecureBlob> {
        self.derive_labeled_secret(
            APP_SECRET_LABEL,
            entry,
            key_version,
            salt,
            labels,
            key_size_bytes,
        )
    }

    /// Return the highest version available.
    pub fn get_app_secret_version(&self, entry: &AppManifestEntry) -> Result<SecretVersion> {
        self.get_secret_version(APP_SECRET_LABEL, entry)
    }

    /// Provides access to low-level secret/key generation.
    pub fn derive_storage_secret(
        &self,
        entry: &AppManifestEntry,
        key_version: SecretVersion,
        salt: &[u8],
        domain: &str,
        label: &str,
        key_size_bytes: usize,
    ) -> Result<SecureBlob> {
        self.derive_labeled_secret(
            STORAGE_SECRET_LABEL,
            entry,
            key_version,
            salt,
            &[domain.as_bytes(), label.as_bytes()],
            key_size_bytes,
        )
    }

    /// Return the highest version available.
    pub fn get_storage_secret_version(&self, entry: &AppManifestEntry) -> Result<SecretVersion> {
        self.get_secret_version(STORAGE_SECRET_LABEL, entry)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::app_info::ExecutableInfo;
    use crate::app_info::SandboxType;
    use crate::app_info::StdErrBehavior;
    use crate::app_info::StorageParameters;
    use crate::communication::persistence::Scope;

    const TEST_APP_ID: &str = "demo_app";
    const TEST_MAIN_SECRET_VERSION: usize = 1usize;
    const TEST_SALT: &[u8; 64] = &[77u8; 64];
    const TEST_DOMAIN: &str = "test domain";
    const TEST_IDENTIFIER: &str = "test id";
    const TEST_KEY_SIZE_BYTES: usize = 64;

    fn setup_test() -> (SecretManager, AppManifest, SecureBlob) {
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
        let gen = SecretManager::new(platform_secret, gsc_secret, &manifest).unwrap();
        let app_info = manifest.get_app_manifest_entry(TEST_APP_ID).unwrap();
        let version = gen.get_storage_secret_version(app_info).unwrap();
        let key = gen
            .derive_storage_secret(
                app_info,
                version,
                TEST_SALT,
                TEST_DOMAIN,
                TEST_IDENTIFIER,
                TEST_KEY_SIZE_BYTES,
            )
            .unwrap();
        (gen, manifest, key)
    }

    /// Verify the generated secrets remain stable (i.e. prevent code changes from resulting in
    /// different keys being generated breaking users' access to previous data).
    #[test]
    fn check_expected_secret() {
        const EXPECTED: &[u8; 64] = &[
            11, 246, 205, 213, 150, 221, 55, 62, 231, 38, 81, 210, 61, 69, 209, 106, 53, 212, 224,
            235, 169, 115, 84, 150, 26, 22, 60, 249, 89, 32, 30, 80, 139, 216, 242, 108, 1, 15, 55,
            196, 142, 97, 234, 76, 149, 237, 79, 119, 84, 108, 87, 241, 124, 194, 64, 79, 254, 134,
            55, 164, 239, 218, 1, 3,
        ];
        let (_, _, key) = setup_test();

        assert_eq!(key.as_ref(), EXPECTED);
    }

    /// Verify changing the main secret results in different generated secrets.
    #[test]
    fn different_main_secret_version() {
        let (gen, manifest, key1) = setup_test();

        let app_info = manifest.get_app_manifest_entry(TEST_APP_ID).unwrap();
        let mut version = gen.get_storage_secret_version(app_info).unwrap();
        version.0 -= 1;

        let key2 = gen
            .derive_storage_secret(
                app_info,
                version,
                TEST_SALT,
                TEST_DOMAIN,
                TEST_IDENTIFIER,
                TEST_KEY_SIZE_BYTES,
            )
            .unwrap();
        assert_ne!(key1.as_ref(), key2.as_ref());
    }

    /// Verify changing the version results in different generated secrets.
    #[test]
    fn different_key_version() {
        let (gen, manifest, key1) = setup_test();

        let app_info = manifest.get_app_manifest_entry(TEST_APP_ID).unwrap();
        let mut version = gen.get_storage_secret_version(app_info).unwrap();
        version.1 -= 1;

        let key2 = gen
            .derive_storage_secret(
                app_info,
                version,
                TEST_SALT,
                TEST_DOMAIN,
                TEST_IDENTIFIER,
                TEST_KEY_SIZE_BYTES,
            )
            .unwrap();
        assert_ne!(key1.as_ref(), key2.as_ref());
    }

    /// Verify changing the labels results in different generated secrets.
    #[test]
    fn different_label() {
        let (gen, manifest, key1) = setup_test();

        let app_info = manifest.get_app_manifest_entry(TEST_APP_ID).unwrap();
        let version = gen.get_storage_secret_version(app_info).unwrap();

        let key2 = gen
            .derive_storage_secret(
                app_info,
                version,
                TEST_SALT,
                &TEST_DOMAIN[1..],
                TEST_IDENTIFIER,
                TEST_KEY_SIZE_BYTES,
            )
            .unwrap();
        assert_ne!(key1.as_ref(), key2.as_ref());
    }
}
