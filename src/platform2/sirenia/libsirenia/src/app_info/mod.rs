// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! The module that defines the app_manifest.

use std::collections::BTreeMap as Map;
use std::fmt::Debug;
use std::fs::read_dir;
use std::fs::File;
use std::io;
use std::io::BufReader;
use std::io::Read;
use std::ops::Deref;
use std::path::Path;
use std::path::PathBuf;
use std::result::Result as StdResult;

use libchromeos::chromeos::is_dev_mode;
use serde::Deserialize;
use serde::Serialize;
use thiserror::Error as ThisError;

use crate::communication::persistence::Scope;
pub use crate::communication::Digest;

pub const DEFAULT_APP_CONFIG_PATH: &str = "/usr/share/manatee";
pub const JSON_EXTENSION: &str = ".json";
pub const FLEXBUFFER_EXTENSION: &str = ".flex.bin";

#[derive(ThisError, Debug)]
pub enum Error {
    /// Invalid app id.
    #[error("invalid app id: {0}")]
    InvalidAppId(String),
    #[error("failed to open config path: {0}")]
    OpenConfig(#[source] io::Error),
    #[error("failed to open config dir: {0}")]
    OpenConfigDir(#[source] io::Error),
    #[error("failed to read config: {0}")]
    ReadConfig(#[source] io::Error),
    #[error("failed to read config dir: {0}")]
    ReadConfigDir(#[source] io::Error),
    #[error("failed to parse flexbuffer config: {0}")]
    FlexbufferParse(#[source] flexbuffers::DeserializationError),
    #[error("failed to parse json config: {0}")]
    JsonParse(#[source] serde_json::Error),
    #[error("invalid config name: {0:?}")]
    InvalidConfigName(PathBuf),
    #[error("failed to parse json config: {0:?}")]
    UnknownConfigFormat(PathBuf),
}

/// The result of an operation in this crate.
pub type Result<T> = StdResult<T, Error>;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(from = "Vec<AppManifestEntry>", into = "Vec<AppManifestEntry>")]
pub struct AppManifest {
    entries: Map<String, AppManifestEntry>,
}

impl Deref for AppManifest {
    type Target = Map<String, AppManifestEntry>;

    fn deref(&self) -> &Self::Target {
        &self.entries
    }
}

/// Defines the type of isolation given to the TEE app instance.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub enum SandboxType {
    Container,
    DeveloperEnvironment,
    VirtualMachine,
}

/// Defines parameters for use with the storage API.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct StorageParameters {
    pub scope: Scope,
    pub domain: String,
    /// Enables transparent storage encryption.
    pub encryption_key_version: Option<usize>,
}

/// Defines parameters for use with the secrets API.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct SecretsParameters {
    pub encryption_key_version: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub enum ExecutableInfo {
    // Hypervisor initramfs path
    Path(String),
    // Only digest, location unspecified
    Digest(Digest),
    // Host (Chrome OS) path and digest
    CrosPath(String, Option<Digest>),
}

/// Specify how to handle the TEE app instance's stderr.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub enum StdErrBehavior {
    MergeWithStdout,
    Drop,
    Syslog,
}

impl Default for StdErrBehavior {
    fn default() -> Self {
        if is_dev_mode().unwrap_or(false) {
            StdErrBehavior::Syslog
        } else {
            StdErrBehavior::Drop
        }
    }
}

/// The TEE developer will define all of these fields for their app and the
/// manifest will be used when starting up the TEE app.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct AppManifestEntry {
    pub app_name: String,
    // devmode_only is false by default.
    #[serde(default)]
    pub devmode_only: bool,
    pub exec_info: ExecutableInfo,
    pub exec_args: Option<Vec<String>>,
    pub sandbox_type: SandboxType,
    pub secrets_parameters: Option<SecretsParameters>,
    #[serde(default)]
    pub stderr_behavior: StdErrBehavior,
    pub storage_parameters: Option<StorageParameters>,
}

impl AppManifestEntry {
    pub fn app_id(&self) -> &str {
        self.app_name.as_str()
    }

    pub fn cros_path(&self) -> Option<PathBuf> {
        match &self.exec_info {
            ExecutableInfo::CrosPath(p, _) => Some(PathBuf::from(p)),
            ExecutableInfo::Digest(_) | ExecutableInfo::Path(_) => None,
        }
    }
}

/// Provides a lookup for registered AppManifestEntries that represent which
/// TEE apps are recognized.
impl AppManifest {
    pub fn new() -> Self {
        // TODO drop vec! after Rust 1.53 which has an IntoIterator implementation for arrays.
        AppManifest::from(vec![
            // Has a pseudo tty allocated since it is intended for interactive use. The decision is
            // made based on app name since 'shell' is currently the only use case for a tty.
            AppManifestEntry {
                app_name: "shell".to_string(),
                devmode_only: true,
                exec_info: ExecutableInfo::Path("/bin/sh".to_string()),
                exec_args: None,
                sandbox_type: SandboxType::DeveloperEnvironment,
                secrets_parameters: None,
                stderr_behavior: StdErrBehavior::MergeWithStdout,
                storage_parameters: None,
            },
            // Does not receive special treatment and is not allocated a pseudo terminal.
            AppManifestEntry {
                app_name: "shell-notty".to_string(),
                devmode_only: true,
                exec_info: ExecutableInfo::Path("/bin/sh".to_string()),
                exec_args: None,
                sandbox_type: SandboxType::DeveloperEnvironment,
                secrets_parameters: None,
                stderr_behavior: StdErrBehavior::MergeWithStdout,
                storage_parameters: None,
            },
            AppManifestEntry {
                app_name: "sandboxed-shell".to_string(),
                devmode_only: true,
                exec_info: ExecutableInfo::Path("/bin/sh".to_string()),
                exec_args: None,
                sandbox_type: SandboxType::Container,
                secrets_parameters: None,
                stderr_behavior: StdErrBehavior::MergeWithStdout,
                storage_parameters: None,
            },
        ])
    }

    pub fn load_default() -> Result<Self> {
        let mut manifest = AppManifest::new();

        let default_path = Path::new(DEFAULT_APP_CONFIG_PATH);
        if !default_path.exists() {
            return Ok(manifest);
        }

        for entries in entries_from_path(default_path)? {
            manifest.add_app_manifest_entry(entries);
        }
        Ok(manifest)
    }

    pub fn add_app_manifest_entry(&mut self, entry: AppManifestEntry) -> Option<AppManifestEntry> {
        let id = entry.app_name.clone();
        self.entries.insert(id, entry)
    }

    pub fn get_app_manifest_entry(&self, id: &str) -> Result<&AppManifestEntry> {
        match self.entries.get(id) {
            Some(entry) => Ok(entry),
            None => Err(Error::InvalidAppId(id.to_string())),
        }
    }

    pub fn append<I: IntoIterator<Item = AppManifestEntry>>(&mut self, entries: I) {
        for entry in entries.into_iter() {
            self.add_app_manifest_entry(entry);
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &AppManifestEntry> {
        self.entries.iter().map(|kv| kv.1)
    }
}

impl<I: IntoIterator<Item = AppManifestEntry>> From<I> for AppManifest {
    fn from(entries: I) -> Self {
        let mut manifest = AppManifest {
            entries: Map::new(),
        };
        manifest.append(entries);
        manifest
    }
}

impl From<AppManifest> for Vec<AppManifestEntry> {
    fn from(manifest: AppManifest) -> Self {
        manifest.entries.into_values().collect()
    }
}

impl Default for AppManifest {
    fn default() -> Self {
        AppManifest::new()
    }
}

/// Parse AppManifestEntries from configuration(s) at the path. This accepts both files and
/// directories.
pub fn entries_from_path<A: AsRef<Path>>(name: A) -> Result<Vec<AppManifestEntry>> {
    if name.as_ref().is_dir() {
        let mut entries = Vec::<AppManifestEntry>::new();
        for entry in read_dir(name).map_err(Error::OpenConfigDir)? {
            let entry_path = entry.map_err(Error::ReadConfigDir)?.path();
            if !entry_path.is_file() {
                continue;
            }
            entries.append(&mut entries_from_path(entry_path)?);
        }
        Ok(entries)
    } else {
        let lowercase_name = name
            .as_ref()
            .to_str()
            .ok_or_else(|| Error::InvalidConfigName(name.as_ref().to_path_buf()))?
            .to_lowercase();
        let mut file = File::open(name.as_ref()).map_err(Error::OpenConfig)?;
        let entries: Vec<AppManifestEntry> = if lowercase_name.ends_with(JSON_EXTENSION) {
            serde_json::from_reader(BufReader::new(file)).map_err(Error::JsonParse)?
        } else if lowercase_name.ends_with(FLEXBUFFER_EXTENSION) {
            let mut contents = Vec::<u8>::new();
            file.read_to_end(&mut contents).map_err(Error::ReadConfig)?;
            flexbuffers::from_slice(&contents).map_err(Error::FlexbufferParse)?
        } else {
            return Err(Error::UnknownConfigFormat(name.as_ref().to_path_buf()));
        };
        Ok(entries)
    }
}

#[cfg(test)]
pub mod tests {
    use std::io::Write;

    use libchromeos::scoped_path::get_temp_path;
    use libchromeos::scoped_path::ScopedPath;

    use super::*;

    const TEST_MANIFEST_ENTRY_JSON: &str = r#"{
  "app_name": "demo_app",
  "exec_info": {
    "Path": "/usr/bin/demo_app"
  },
  "sandbox_type": "DeveloperEnvironment",
  "secrets_parameters": null,
  "stderr_behavior": "MergeWithStdout",
  "storage_parameters": {
    "scope": "Test",
    "domain": "test",
    "encryption_key_version": 1
  }
}"#;

    fn get_test_manifest_entry() -> AppManifestEntry {
        AppManifestEntry {
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
        }
    }

    fn make_test_app(name: &str) -> (String, AppManifestEntry) {
        let app_json = String::from(TEST_MANIFEST_ENTRY_JSON).replace("demo_app", name);
        let mut app_entry = get_test_manifest_entry();
        app_entry.app_name = name.to_string();
        app_entry.exec_info =
            ExecutableInfo::Path(Path::new("/usr/bin").join(name).display().to_string());
        (app_json, app_entry)
    }

    #[test]
    fn check_deserialization() {
        let test_entry =
            serde_json::from_str::<'_, AppManifestEntry>(TEST_MANIFEST_ENTRY_JSON).unwrap();
        assert_eq!(test_entry, get_test_manifest_entry());
    }

    #[test]
    fn check_load_file() {
        let test_dir =
            ScopedPath::create(get_temp_path(Some("sirenia-app_info-check_load_file"))).unwrap();
        let path = test_dir.join("test.json");
        {
            let mut manifest_file = File::create(&path).unwrap();
            write!(manifest_file, "[{}]", TEST_MANIFEST_ENTRY_JSON).unwrap();
        }
        let entries = entries_from_path(path).unwrap();
        assert_eq!(entries, [get_test_manifest_entry()]);
    }

    #[test]
    fn check_load_file_2apps() {
        let test_dir = ScopedPath::create(get_temp_path(Some(
            "sirenia-app_info-check_load_file_2apps",
        )))
        .unwrap();
        let path = test_dir.join("test.json");
        let (app2_json, app2_entry) = make_test_app("app2");
        {
            let mut manifest_file = File::create(&path).unwrap();
            write!(
                manifest_file,
                "[{},\n{}]",
                TEST_MANIFEST_ENTRY_JSON, app2_json
            )
            .unwrap();
        }
        let entries = entries_from_path(path).unwrap();
        assert_eq!(entries, [get_test_manifest_entry(), app2_entry]);
    }

    #[test]
    fn check_load_dir() {
        let test_dir =
            ScopedPath::create(get_temp_path(Some("sirenia-app_info-check_load_dir"))).unwrap();
        let path1 = test_dir.join("test1.json");
        let path2 = test_dir.join("test2.json");
        let (app2_json, app2_entry) = make_test_app("app2");
        let (app3_json, app3_entry) = make_test_app("app3");
        {
            let mut manifest_file1 = File::create(path1).unwrap();
            write!(manifest_file1, "[{}]", TEST_MANIFEST_ENTRY_JSON).unwrap();

            let mut manifest_file2 = File::create(path2).unwrap();
            write!(manifest_file2, "[{},\n{}]", app2_json, app3_json).unwrap();
        }
        let mut entries = entries_from_path(&test_dir).unwrap();
        entries.sort_by(|a, b| a.app_name.cmp(&b.app_name));
        assert_eq!(entries, [app2_entry, app3_entry, get_test_manifest_entry()]);
    }
}
