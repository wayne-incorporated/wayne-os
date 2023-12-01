// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// ShaderCacheMount represents the specific VM's mesa shader cache. Operations
// are carried on or by it.. This module outlines common operations carried out
// for the VM's mesa shader cache.  *_ops modules group the implementation of
// similar operations of ShaderCacheMount and ShaderCacheMountMap.

mod map;
mod mesa_path_constants;
mod mount_ops;
mod queue_ops;

pub use map::*;

use crate::common::*;
use crate::service;
use mesa_path_constants::*;

use anyhow::{anyhow, Result};
use libchromeos::sys::{debug, error};
use std::collections::HashSet;
use std::ffi::OsString;
use std::fs;
use std::os::unix::prelude::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

const UNINITIALIZED_ERROR: &str = "Mesa cache path not initialized";

#[derive(Debug, Clone)]
pub struct ShaderCacheMount {
    // The Steam application that we want to mount to this directory.
    mount_queue: HashSet<SteamAppId>,
    // Steam app ids to unmount in periodic unmount loop
    unmount_queue: HashSet<SteamAppId>,
    // crosvm render server cache path
    render_server_path: PathBuf,
    // Precompiled cache path
    precompiled_cache_path: PathBuf,
    // After mounting or before unmounting, we need to update foz db list file
    // so that mesa uses or stops using the path.
    foz_blob_db_list_path: PathBuf,
    // Absolute path to bind-mount DLC contents into.
    mount_base_path: Option<PathBuf>,
    // Within gpu cache directory, mesa creates a nested sub directory to store
    // shader cache. |relative_mesa_cache_path| is relative to the
    // render_server's base path within crosvm's gpu cache directory
    relative_mesa_cache_path: Option<PathBuf>,
}

impl ShaderCacheMount {
    pub fn new(vm_gpu_cache_path: PathBuf, vm_id: &VmId) -> Result<ShaderCacheMount> {
        // Render server path is what mesa sees as its base path, so we don't
        // need to worry about paths before that.
        let render_server_path = vm_gpu_cache_path.join(GPU_RENDER_SERVER_PATH);
        let vm_name_encoded = base64::encode_config(&vm_id.vm_name, base64::URL_SAFE);
        let precompiled_cache_path = Path::new(CRYPTO_HOME)
            .join(&vm_id.vm_owner_id)
            .join(PRECOMPILED_CACHE_DIR)
            .join(vm_name_encoded);
        Ok(ShaderCacheMount {
            mount_queue: HashSet::new(),
            unmount_queue: HashSet::new(),
            render_server_path: render_server_path.clone(),
            precompiled_cache_path,
            foz_blob_db_list_path: render_server_path.join(FOZ_DB_LIST_FILE),
            mount_base_path: None,
            relative_mesa_cache_path: None,
        })
    }

    pub fn initialize(&mut self) -> Result<()> {
        if self.mount_base_path.is_none() || self.relative_mesa_cache_path.is_none() {
            let relative_mesa_path = get_mesa_cache_relative_path(&self.render_server_path)?;
            self.mount_base_path = Some(self.render_server_path.join(&relative_mesa_path));
            self.relative_mesa_cache_path = Some(relative_mesa_path);
        }
        Ok(())
    }

    pub async fn setup_mount_destination(
        &self,
        vm_id: &VmId,
        steam_app_id: SteamAppId,
        conn: Arc<dbus::nonblock::SyncConnection>,
    ) -> Result<()> {
        debug!(
            "Setting up mount destination for {:?}, game {}",
            vm_id, steam_app_id
        );
        let dst_path_str = self.get_str_absolute_mount_destination_path(steam_app_id)?;
        let dst_path = Path::new(&dst_path_str);
        if !dst_path.exists() {
            // Attempt to only create the final directory, the parent directory
            // should already exist.
            if let Err(e) = fs::create_dir(dst_path) {
                debug!(
                    "Failed create mount directory: {:?}, retrying after getting permissions",
                    e
                );
                // Retry directory creation once with permissions fix.
                // TODO(endlesspring): consider calling service outside
                // ShaderCacheMount. This detaches this module's dependency
                // on service module. This may involve splitting path creation
                // and setting up permissions.
                service::add_shader_cache_group_permission(vm_id, conn).await?;
                fs::create_dir(dst_path)?;
                debug!("Successfully created mount directory on retry");
            }
            let perm = fs::Permissions::from_mode(0o750);
            if let Err(e) = fs::set_permissions(dst_path, perm) {
                error!("Failed to set permissions for {}: {}", dst_path_str, e);
                fs::remove_dir(dst_path)?;
                return Err(anyhow!("Failed to set permissions: {}", e));
            }
        }

        Ok(())
    }

    fn get_mount_base_path(&self) -> Result<&PathBuf> {
        if let Some(path) = &self.mount_base_path {
            return Ok(path);
        }
        Err(anyhow!(UNINITIALIZED_ERROR))
    }

    fn get_relative_mesa_cache_path(&self) -> Result<&PathBuf> {
        if let Some(path) = &self.relative_mesa_cache_path {
            return Ok(path);
        }
        Err(anyhow!(UNINITIALIZED_ERROR))
    }

    fn get_str_absolute_mount_destination_path(&self, steam_app_id: SteamAppId) -> Result<String> {
        match self
            .get_mount_base_path()?
            .join(steam_app_id.to_string())
            .to_str()
        {
            Some(str) => Ok(String::from(str)),
            None => Err(anyhow!(
                "Failed to get string path for {:?}",
                self.mount_base_path
            )),
        }
    }
}

fn get_mesa_cache_relative_path(render_server_path: &Path) -> Result<PathBuf> {
    // Within gpu cache directory, mesa creates a nested sub directory to store
    // shader cache.
    // This function figures out this relative mount path from GPU cache dir:
    //   <GPU cache dir>/render_server/<mesa_cache_path>/
    // where mesa_cache_path is (usually):
    //   mesa_shader_cache_sf/<mesa_hash>/anv_<gpu device id>
    // or (for AMD):
    //   mesa_shader_cache_sf/<mesa_hash>/<gpu generation name>
    // This mesa_cache_path has the actual binary cache blobs used by mesa,
    // along with the 'foz_blob.foz' and/or 'index' file.
    let mut absolute_path = Path::new(render_server_path)
        .to_path_buf()
        .join(MESA_SINGLE_FILE_DIR);
    let mut relative_path = Path::new(MESA_SINGLE_FILE_DIR).to_path_buf();

    debug!("Getting mesa hash and device id path");

    let mesa_hash = get_single_file(&absolute_path)?;
    absolute_path = absolute_path.join(&mesa_hash);
    relative_path = relative_path.join(&mesa_hash);

    let device_id_path = get_single_file(&absolute_path)?;
    absolute_path = absolute_path.join(&device_id_path);
    relative_path = relative_path.join(&device_id_path);

    if !absolute_path.exists() {
        return Err(anyhow!(
            "{:?} does not exist, report GPU device ID may not match",
            absolute_path
        ));
    }

    // Mesa initializes the cache directory if there was a need to store things
    // into the cache: ex. any GUI app launch, like Steam.
    // When this happens, foz_blob.foz file will always be found.
    //
    // However, on edge cases (ex. manual installation call before Steam
    // launch), foz_blob.foz file may not exist.
    if !has_file(&absolute_path, FOZ_CACHE_FILE_NAME)?
        && !has_file(&absolute_path, INDEX_FILE_NAME)?
    {
        return Err(anyhow!(
            "Invalid mesa cache structure at {:?}",
            absolute_path
        ));
    }

    Ok(relative_path)
}

fn get_single_file(path: &Path) -> Result<OsString> {
    let mut entries = fs::read_dir(path)?;
    let entry = entries.next();
    if entries.next().is_some() {
        return Err(anyhow!("Multiple directories found under: {:?}", path));
    }
    match entry {
        Some(entry) => Ok(entry?.file_name()),
        None => Err(anyhow!("Empty directory: {:?}", path)),
    }
}

fn has_file(path: &Path, file_name: &str) -> Result<bool> {
    let entries = fs::read_dir(path)?;
    for dir_entry in entries {
        if dir_entry?.file_name() == file_name {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::fs;
    use std::path::Path;

    #[test]
    fn test_get_single_file() {
        let temp_dir = env::temp_dir().join("test_get_single_file");
        let _ = fs::remove_dir_all(temp_dir.as_path());

        // single directory present
        fs::create_dir_all(temp_dir.join(Path::new("child"))).unwrap();
        assert_eq!(
            super::get_single_file(temp_dir.as_path())
                .unwrap()
                .to_str()
                .unwrap(),
            "child"
        );

        // multiple directories present
        fs::create_dir(temp_dir.join(Path::new("child2"))).unwrap();
        assert!(super::get_single_file(temp_dir.as_path()).is_err());
    }
}
