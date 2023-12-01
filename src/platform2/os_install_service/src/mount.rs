// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use anyhow::{Context, Result};
use log::{error, info};
use nix::mount::MsFlags;
use std::path::Path;
use tempfile::TempDir;

/// Mounts a file system on a temporary directory, then unmounts when
/// dropped.
pub struct Mount {
    pub mount_point: TempDir,
}

impl Mount {
    pub fn mount_ext4(source: &Path) -> Result<Self> {
        let data: Option<&Path> = None;
        let flags = MsFlags::MS_NODEV | MsFlags::MS_NOEXEC | MsFlags::MS_NOSUID;
        let mount_point = TempDir::new()?;
        let stateful_partition_mount = Mount { mount_point };
        info!(
            "mounting {} at {} with flags {:?}",
            source.display(),
            stateful_partition_mount.mount_point.path().display(),
            flags
        );
        nix::mount::mount(
            Some(source),
            stateful_partition_mount.mount_point.path(),
            Some("ext4"),
            flags,
            data,
        )
        .with_context(|| {
            format!(
                "failed to mount {} at {}",
                source.display(),
                stateful_partition_mount.mount_point.path().display()
            )
        })?;
        Ok(stateful_partition_mount)
    }

    fn unmount(&self, target: &Path) -> Result<()> {
        info!("unmounting {}", target.display());
        nix::mount::umount(target)
            .with_context(|| format!("failed to unmount {}", target.display()))
    }
}

impl Drop for Mount {
    fn drop(&mut self) {
        if let Err(err) = self.unmount(self.mount_point.path()) {
            // No way to propagate the error from drop(), so just
            // print it.
            error!("unmount failed: {}", err);
        }
    }
}
