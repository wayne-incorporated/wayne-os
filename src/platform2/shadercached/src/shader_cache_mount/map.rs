// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This module creates thread-safe HashMap for ShaderCacheMount, so that each
// ShaderCacheMount can be associated with the VM and user appropriately.

use super::ShaderCacheMount;

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VmId {
    pub vm_name: String,
    pub vm_owner_id: String,
}

#[derive(Debug)]
pub struct ShaderCacheMountMap {
    map: RwLock<HashMap<VmId, ShaderCacheMount>>,
}
// We are not implementing traits directly into ShaderCacheMountPtr because some
// methods (ex. wait_unmount_completed) requires explicitly letting go of locks.
pub type ShaderCacheMountMapPtr = Arc<ShaderCacheMountMap>;

impl ShaderCacheMountMap {
    pub async fn write(
        self: &ShaderCacheMountMap,
    ) -> RwLockWriteGuard<'_, HashMap<VmId, ShaderCacheMount>> {
        self.map.write().await
    }

    pub async fn read(
        self: &ShaderCacheMountMap,
    ) -> RwLockReadGuard<'_, HashMap<VmId, ShaderCacheMount>> {
        self.map.read().await
    }
}

pub fn new_mount_map() -> ShaderCacheMountMapPtr {
    Arc::new(ShaderCacheMountMap {
        map: RwLock::new(HashMap::new()),
    })
}
