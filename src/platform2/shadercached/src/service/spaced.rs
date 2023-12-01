// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    sync::Arc,
};

use super::helper::unsafe_quota::{set_quota_limited, set_quota_normal};
use crate::{
    common::{CRYPTO_HOME, PRECOMPILED_CACHE_DIR},
    shader_cache_mount::{ShaderCacheMountMapPtr, VmId},
};
use dbus::nonblock::SyncConnection;
use libchromeos::sys::{debug, info, warn};

use anyhow::Result;
use system_api::spaced::{StatefulDiskSpaceState, StatefulDiskSpaceUpdate};
use tokio::sync::Mutex;

lazy_static! {
    static ref PURGED: Mutex<bool> = Mutex::new(false);
    static ref LIMITED_QUOTA_PATHS: Mutex<HashSet<PathBuf>> = Mutex::new(HashSet::new());
}

fn delete_all_files(path: &Path) -> Result<()> {
    for dir_entry in (std::fs::read_dir(path)?).flatten() {
        if dir_entry.path().is_dir() {
            std::fs::remove_dir_all(dir_entry.path())?;
        } else {
            std::fs::remove_file(dir_entry.path())?;
        }
    }
    Ok(())
}

fn get_all_precompiled_cache_dir() -> Result<Vec<PathBuf>> {
    let mut dirs: Vec<PathBuf> = vec![];
    for dir_entry in (std::fs::read_dir(CRYPTO_HOME)?).flatten() {
        let user_cryptohome = dir_entry.path();
        dirs.push(user_cryptohome.join(PRECOMPILED_CACHE_DIR))
    }
    Ok(dirs)
}

pub async fn delete_precompiled_cache_all(
    mount_map: ShaderCacheMountMapPtr,
) -> Result<Vec<PathBuf>> {
    let mut dirs_to_clear: Vec<PathBuf> = vec![];
    // TODO(b/271776528): utilize ShaderCacheMount once it is reliable
    // SoT for cryptohome and mounts (even for VMs that are turned off).
    // For now, just get the lock and call get_all_precompiled_cache_dir().
    // This has no runtime differences.
    let _mount_map = mount_map.write().await;

    for local_cache_dir in get_all_precompiled_cache_dir()? {
        for dir_entry in (std::fs::read_dir(local_cache_dir)?).flatten() {
            // For each |local_cache_dir| (which is per user), there are
            // cache directories per VM.
            dirs_to_clear.push(dir_entry.path());
        }
    }

    for local_cache_dir in &dirs_to_clear {
        info!("Deleting all files at {}", local_cache_dir.display());
        delete_all_files(local_cache_dir)?;
    }

    Ok(dirs_to_clear)
}

pub async fn delete_precompiled_cache(
    mount_map: ShaderCacheMountMapPtr,
    vm_id: VmId,
) -> Result<Vec<PathBuf>> {
    let mut dirs_to_clear: Vec<PathBuf> = vec![];
    // TODO(b/271776528): utilize ShaderCacheMount once it is reliable
    // SoT for cryptohome and mounts (even for VMs that are turned off).
    // For now, just get the lock and call get_all_precompiled_cache_dir().
    // This has no runtime differences.
    let _mount_map = mount_map.write().await;

    let encoded_vm_name = base64::encode_config(&vm_id.vm_name, base64::URL_SAFE);
    let path = Path::new(CRYPTO_HOME)
        .join(&vm_id.vm_owner_id)
        .join(PRECOMPILED_CACHE_DIR)
        .join(encoded_vm_name);
    if path.exists() {
        dirs_to_clear.push(path);
    } else {
        info!("No precompiled cache for {:?}", vm_id);
        return Ok(vec![]);
    }

    for local_cache_dir in &dirs_to_clear {
        info!("Deleting all files at {}", local_cache_dir.display());
        delete_all_files(local_cache_dir)?;
    }

    Ok(dirs_to_clear)
}

pub async fn handle_disk_space_update(
    raw_bytes: Vec<u8>,
    mount_map: ShaderCacheMountMapPtr,
    conn: Arc<SyncConnection>,
) -> Result<()> {
    let update_signal: StatefulDiskSpaceUpdate = protobuf::Message::parse_from_bytes(&raw_bytes)
        .map_err(|e| dbus::MethodErr::invalid_arg(&e))?;

    debug!(
        "Spaced status {:?}, free space bytes {}",
        update_signal.state, update_signal.free_space_bytes
    );

    let state = update_signal
        .state
        .enum_value()
        .map_err(|e| dbus::MethodErr::invalid_arg(&e))?;

    let mut is_purged = PURGED.lock().await;
    let mut limited_quota_paths = LIMITED_QUOTA_PATHS.lock().await;

    // Clean things up if low
    // LOW = < 1%
    if state == StatefulDiskSpaceState::LOW || state == StatefulDiskSpaceState::CRITICAL {
        if !*is_purged {
            // In the first attempt, just delete the DLCs and see if disk space
            // recovers.
            info!("Low/critical disk space, removing all shader cache DLCs");
            // Set is_purged  early, so that we do the next step if DLC
            // uninstallation fails.
            *is_purged = true;
            // Purge all shader cache DLCs, only once until recovery
            super::unmount_and_uninstall_all_shader_cache_dlcs(mount_map.clone(), conn.clone())
                .await?;
        } else {
            // spaced will continue sending signals if the disk stays near full.
            // Clean up downloaded shader cache contents.
            delete_precompiled_cache_all(mount_map.clone()).await?;

            // TODO(b/271776528): Ditto as above
            let _mount_map = mount_map.write().await;
            for local_cache_dir in get_all_precompiled_cache_dir()? {
                if !limited_quota_paths.contains(&local_cache_dir) {
                    if let Err(e) = set_quota_limited(&local_cache_dir) {
                        warn!(
                            "Failed to limit quota at {}: {}",
                            local_cache_dir.display(),
                            e
                        );
                    } else {
                        limited_quota_paths.insert(local_cache_dir);
                    }
                }
            }
        }
    } else if state == StatefulDiskSpaceState::NORMAL {
        debug!("Normal disk space, recovering if required");

        if *is_purged {
            *is_purged = false;
        }
        let mut failed = HashSet::new();
        for local_cache_dir in limited_quota_paths.drain() {
            if let Err(e) = set_quota_normal(&local_cache_dir) {
                warn!(
                    "Failed to limit quota at {}: {}",
                    local_cache_dir.display(),
                    e
                );
                failed.insert(local_cache_dir);
            }
        }
        limited_quota_paths.extend(failed);
    }

    Ok(())
}
