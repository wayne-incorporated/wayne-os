// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/lockbox-cache.h"

#include <memory>

#include <base/files/file_path.h>
#include <base/logging.h>

#include "cryptohome/lockbox.h"

namespace cryptohome {
namespace {
// Permissions of cache file (modulo umask).
const mode_t kCacheFilePermissions = 0644;
}  // namespace

bool CacheLockbox(Platform* platform,
                  const base::FilePath& nvram_path,
                  const base::FilePath& lockbox_path,
                  const base::FilePath& cache_path) {
  brillo::SecureBlob nvram;
  if (!platform->ReadFileToSecureBlob(nvram_path, &nvram)) {
    LOG(INFO) << "Failed to read NVRAM contents from " << nvram_path.value();
    return false;
  }
  std::unique_ptr<LockboxContents> lockbox = LockboxContents::New();
  if (!lockbox) {
    LOG(ERROR) << "Unsupported lockbox size!";
    return false;
  }
  if (!lockbox->Decode(nvram)) {
    LOG(ERROR) << "Lockbox failed to decode NVRAM data";
    return false;
  }

  brillo::Blob lockbox_data;
  if (!platform->ReadFile(lockbox_path, &lockbox_data)) {
    LOG(INFO) << "Failed to read lockbox data from " << lockbox_path.value();
    return false;
  }
  if (lockbox->Verify(lockbox_data) !=
      LockboxContents::VerificationResult::kValid) {
    LOG(ERROR) << "Lockbox did not verify!";
    return false;
  }

  // Write atomically (not durably) because cache file resides on tmpfs.
  if (!platform->WriteFileAtomic(cache_path, lockbox_data,
                                 kCacheFilePermissions)) {
    LOG(ERROR) << "Failed to write cache file";
    return false;
  }

  return true;
}

}  // namespace cryptohome
