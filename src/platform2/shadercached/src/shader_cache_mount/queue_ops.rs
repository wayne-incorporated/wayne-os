// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Collection of ShaderCacheMount methods for adding/removing mount queues,
// which are linked to foz db list operations.

use super::mesa_path_constants::*;
use super::{ShaderCacheMount, ShaderCacheMountMap, VmId};
use crate::common::*;

use anyhow::{anyhow, Result};
use libchromeos::sys::{debug, error, warn};
use regex::Regex;
use std::collections::HashSet;
use std::fs;
use system_api::shadercached::ShaderCacheMountStatus;

impl ShaderCacheMount {
    pub fn add_game_to_db_list(&mut self, steam_app_id: SteamAppId) -> Result<()> {
        // Add game to foz_db_list so that mesa can start using the directory
        // for precompiled cache. Adding game to list must happen after the
        // directory has been created and mounted.
        if !self.foz_blob_db_list_path.exists() {
            return Err(anyhow!("Missing foz blob file"));
        }

        let read_result = fs::read_to_string(&self.foz_blob_db_list_path);
        if let Err(e) = read_result {
            return Err(anyhow!("Failed to read contents: {}", e));
        }

        debug!("Adding {} to foz db list", steam_app_id);
        let mut contents = read_result.unwrap();

        let entry_to_add = format!("{}/{}", steam_app_id, PRECOMPILED_CACHE_FILE_NAME);
        for line in contents.split('\n') {
            if line == entry_to_add {
                debug!("{} already in the entry", steam_app_id);
                return Ok(());
            }
        }

        contents += &entry_to_add;
        contents += "\n";

        fs::write(&self.foz_blob_db_list_path, contents)?;

        self.dequeue_mount(&steam_app_id);

        Ok(())
    }

    pub fn remove_game_from_db_list(&mut self, steam_app_id: SteamAppId) -> Result<bool> {
        // Remove game from foz_db_list so that mesa stops using the precompiled
        // cache in it. Removing the game from list must happen before
        // unmounting and removing the directory.
        if !self.foz_blob_db_list_path.exists() {
            return Err(anyhow!("Missing foz blob file"));
        }
        let read_result = fs::read_to_string(&self.foz_blob_db_list_path);
        if let Err(e) = read_result {
            return Err(anyhow!("Failed to read contents: {}", e));
        }

        debug!("Removing {} from foz db list if it exists", steam_app_id);
        let contents = read_result.unwrap();
        let mut write_contents = String::new();

        let mut found = false;
        let entry_to_remove = format!("{}/{}", steam_app_id, PRECOMPILED_CACHE_FILE_NAME);
        for line in contents.split('\n') {
            // Even the final entry in foz blob db list file has new line, so
            // the last line in contents.split('\n') is empty string
            if line.is_empty() {
                continue;
            }
            if line != entry_to_remove {
                write_contents += line;
                write_contents += "\n";
            } else {
                found = true
            }
        }

        fs::write(&self.foz_blob_db_list_path, write_contents)?;

        if found {
            self.enqueue_unmount(steam_app_id);
        }

        Ok(found)
    }

    pub fn process_unmount_queue(self: &mut ShaderCacheMount) -> Vec<ShaderCacheMountStatus> {
        let mut to_dequeue: Vec<SteamAppId> = vec![];
        let mut mount_statuses: Vec<ShaderCacheMountStatus> = vec![];

        for &steam_app_id in &self.unmount_queue {
            debug!("Attempting to unmount {}", steam_app_id);

            let unmount_result = self.unmount(steam_app_id);

            let mut status = ShaderCacheMountStatus::new();
            status.mounted = unmount_result.is_err();
            status.steam_app_id = steam_app_id;
            if let Err(e) = unmount_result {
                status.error = format!("Unmount failure: {}", e);
                warn!(
                    "Failed to unmount {}, will be retried again: {:?}\n",
                    steam_app_id, e
                );
            } else {
                to_dequeue.push(steam_app_id);
            }
            mount_statuses.push(status);
        }

        self.dequeue_unmount_multi(&to_dequeue);

        mount_statuses
    }

    pub fn is_pending_mount(&self, steam_app_id: &SteamAppId) -> bool {
        self.mount_queue.contains(steam_app_id)
    }

    pub fn enqueue_mount(&mut self, steam_app_id: SteamAppId) -> bool {
        debug!("Enqueue mount {}: {:?}", steam_app_id, self.mount_queue);
        let success = self.mount_queue.insert(steam_app_id);
        self.unmount_queue.remove(&steam_app_id);
        success
    }

    fn reset_foz_db_list(&mut self) -> Result<()> {
        if !self.foz_blob_db_list_path.exists() {
            warn!(
                "Nothing to unmount, specified path does not exist: {:?}",
                self.foz_blob_db_list_path
            );
            return Ok(());
        }

        let mut cleared_games: HashSet<SteamAppId> = HashSet::new();
        let list_string = fs::read_to_string(&self.foz_blob_db_list_path)?;
        // Example foz db list file contents:
        // 620/foz_cache
        // 570/foz_cache
        //
        let path_regex = Regex::new(r"([0-9]+)/.+")?;
        for relative_path in list_string.split('\n') {
            if let Some(capture) = path_regex.captures(relative_path) {
                if let Some(app_id_string) = capture.get(1) {
                    debug!("Converting to int {}", app_id_string.as_str());
                    cleared_games.insert(app_id_string.as_str().parse::<SteamAppId>()?);
                }
            } else {
                debug!("Unexpected path format, ignoring: {}", relative_path);
                warn!("Unexpected path format found for one of the VM foz db list file");
            }
        }

        for entry in fs::read_dir(self.get_mount_base_path()?)? {
            let entry = entry?;
            if entry.path().is_dir() {
                if let Ok(str_entry) = entry.file_name().into_string() {
                    if let Ok(found_id) = str_entry.parse::<SteamAppId>() {
                        if !cleared_games.contains(&found_id) {
                            debug!(
                                "Found unexpected precompiled cache mount for app {}, ignoring",
                                found_id
                            );
                        }
                    }
                }
            }
        }

        fs::write(&self.foz_blob_db_list_path, "")?;

        for game in cleared_games {
            self.enqueue_unmount(game);
        }

        Ok(())
    }

    fn clear_mount_queue(&mut self) {
        debug!("Dequeue all mount");
        self.mount_queue.clear()
    }

    fn dequeue_unmount_multi(&mut self, to_remove: &[SteamAppId]) {
        debug!("Dequeue unmount {:?}: {:?}", to_remove, self.unmount_queue);
        self.unmount_queue
            .retain(|steam_app_id| !to_remove.contains(steam_app_id))
    }

    fn enqueue_unmount(&mut self, steam_app_id: SteamAppId) -> bool {
        debug!("Enqueue unmount {}: {:?}", steam_app_id, self.unmount_queue);
        let success = self.unmount_queue.insert(steam_app_id);
        self.mount_queue.remove(&steam_app_id);
        success
    }

    pub fn dequeue_mount(&mut self, steam_app_id: &SteamAppId) -> bool {
        debug!("Dequeue mount {}: {:?}", steam_app_id, self.mount_queue);
        self.mount_queue.remove(steam_app_id)
    }
}

impl ShaderCacheMountMap {
    pub async fn clear_all_mounts(self: &ShaderCacheMountMap, vm_id: Option<VmId>) -> Result<()> {
        // Queue unmount-everything and clear queued mounts.
        // This function is called on Purge (vm_id is None) and on Borealis exit
        // (vm_id is set).
        let mut mount_map = self.write().await;
        let mut failed_unmounts: HashSet<VmId> = HashSet::new();

        if let Some(vm_id) = vm_id {
            if let Some(shader_cache_mount) = mount_map.get_mut(&vm_id) {
                shader_cache_mount.clear_mount_queue();
                if let Err(e) = shader_cache_mount.reset_foz_db_list() {
                    error!("Failed to queue unmount all for {:?}: {}", vm_id, e);
                    failed_unmounts.insert(vm_id);
                }
            } else {
                failed_unmounts.insert(vm_id);
            }
        } else {
            for (vm_id, shader_cache_mount) in mount_map.iter_mut() {
                shader_cache_mount.clear_mount_queue();
                if let Err(e) = shader_cache_mount.reset_foz_db_list() {
                    error!("Failed to queue unmount all for {:?}: {}", vm_id, e);
                    failed_unmounts.insert(vm_id.clone());
                }
            }
        }

        if failed_unmounts.is_empty() {
            // TODO(b/271776528): Prevent further mounts
            return Ok(());
        }
        Err(anyhow!(
            "Failed to queue unmount for all: {:?}",
            failed_unmounts
        ))
    }
}
