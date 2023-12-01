// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_STORAGE_ENCRYPTED_CONTAINER_ENCRYPTED_CONTAINER_H_
#define CRYPTOHOME_STORAGE_ENCRYPTED_CONTAINER_ENCRYPTED_CONTAINER_H_

#include <memory>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <brillo/blkdev_utils/device_mapper.h>

#include "cryptohome/platform.h"
#include "cryptohome/storage/encrypted_container/backing_device.h"
#include "cryptohome/storage/encrypted_container/filesystem_key.h"

namespace cryptohome {

// Type of encrypted containers.
enum class EncryptedContainerType {
  kUnknown = 0,
  kEcryptfs,
  kFscrypt,
  kDmcrypt,
  kEphemeral,
  kEcryptfsToFscrypt,
  kEcryptfsToDmcrypt,
  kFscryptToDmcrypt,
};

struct DmcryptConfig {
  BackingDeviceConfig backing_device_config;
  std::string dmcrypt_device_name;
  std::string dmcrypt_cipher;
  bool is_raw_device;
  uint32_t iv_offset;
  std::vector<std::string> mkfs_opts;
  std::vector<std::string> tune2fs_opts;
};

struct EncryptedContainerConfig {
  EncryptedContainerType type;
  base::FilePath backing_dir;
  DmcryptConfig dmcrypt_config;
  std::string backing_file_name;
};

// An encrypted container is an abstract class that represents an encrypted
// backing storage medium. Since encrypted containers can be used in both
// daemons and one-shot calls, the implementation of each encrypted container
// leans towards keeping the container as stateless as possible.
// TODO(dlunev): rename abstraction to VaultContainer.
class EncryptedContainer {
 public:
  virtual ~EncryptedContainer() {}

  // Removes the encrypted container's backing storage.
  virtual bool Purge() = 0;
  // Sets up the encrypted container, including creating the container if
  // needed.
  virtual bool Setup(const FileSystemKey& encryption_key) = 0;
  // Tears down the container, removing the encryption key if it was added.
  virtual bool Teardown() = 0;
  // Checks if the container exists on disk.
  virtual bool Exists() = 0;
  // Gets the type of the encrypted container.
  virtual EncryptedContainerType GetType() const = 0;
  // Resets the backing storage of the container. While Purge removes the
  // entire container, Reset() set the container back to a pristine condition
  // doesn't require the backing storage to be set up again.
  virtual bool Reset() = 0;
  // Marks the container for lazy teardown; once the last reference to the
  // container is dropped, the constructs of the container are automatically
  // torn down and the container can be safely purged afterwards.
  virtual bool SetLazyTeardownWhenUnused() { return false; }
  virtual bool IsLazyTeardownSupported() const { return false; }
  // Returns the backing location if any.
  virtual base::FilePath GetBackingLocation() const = 0;

  static bool IsMigratingType(EncryptedContainerType type) {
    return type == EncryptedContainerType::kEcryptfsToFscrypt ||
           type == EncryptedContainerType::kEcryptfsToDmcrypt ||
           type == EncryptedContainerType::kFscryptToDmcrypt;
  }
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_STORAGE_ENCRYPTED_CONTAINER_ENCRYPTED_CONTAINER_H_
