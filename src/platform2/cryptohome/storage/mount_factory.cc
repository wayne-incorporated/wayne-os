// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/storage/mount_factory.h"

#include "cryptohome/platform.h"
#include "cryptohome/storage/homedirs.h"
#include "cryptohome/storage/mount.h"

namespace cryptohome {

MountFactory::MountFactory() {}
MountFactory::~MountFactory() {}

Mount* MountFactory::New(Platform* platform,
                         HomeDirs* homedirs,
                         bool legacy_mount,
                         bool bind_mount_downloads,
                         bool use_local_mounter) {
  return new Mount(platform, homedirs, legacy_mount, bind_mount_downloads,
                   use_local_mounter);
}
}  // namespace cryptohome
