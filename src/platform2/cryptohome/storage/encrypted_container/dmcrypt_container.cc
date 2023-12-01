// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/storage/encrypted_container/dmcrypt_container.h"

#include <memory>
#include <optional>
#include <string>
#include <tuple>
#include <utility>

#include <absl/cleanup/cleanup.h>
#include <base/files/file_path.h>
#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>

#include "cryptohome/platform.h"
#include "cryptohome/storage/encrypted_container/backing_device.h"
#include "cryptohome/storage/encrypted_container/encrypted_container.h"
#include "cryptohome/storage/encrypted_container/filesystem_key.h"
#include "cryptohome/storage/keyring/keyring.h"
#include "cryptohome/storage/keyring/utils.h"

namespace cryptohome {

namespace {

constexpr uint64_t kSectorSize = 512;
constexpr uint64_t kExt4BlockSize = 4096;

}  // namespace

DmcryptContainer::DmcryptContainer(
    const DmcryptConfig& config,
    std::unique_ptr<BackingDevice> backing_device,
    const FileSystemKeyReference& key_reference,
    Platform* platform,
    Keyring* keyring,
    std::unique_ptr<brillo::DeviceMapper> device_mapper)
    : dmcrypt_device_name_(config.dmcrypt_device_name),
      dmcrypt_cipher_(config.dmcrypt_cipher),
      is_raw_device_(config.is_raw_device),
      iv_offset_(config.iv_offset),
      mkfs_opts_(config.mkfs_opts),
      tune2fs_opts_(config.tune2fs_opts),
      backing_device_(std::move(backing_device)),
      key_reference_(key_reference),
      platform_(platform),
      keyring_(keyring),
      device_mapper_(std::move(device_mapper)) {}

DmcryptContainer::DmcryptContainer(
    const DmcryptConfig& config,
    std::unique_ptr<BackingDevice> backing_device,
    const FileSystemKeyReference& key_reference,
    Platform* platform,
    Keyring* keyring)
    : DmcryptContainer(config,
                       std::move(backing_device),
                       key_reference,
                       platform,
                       keyring,
                       std::make_unique<brillo::DeviceMapper>()) {}

bool DmcryptContainer::Purge() {
  // Stale dm-crypt containers may need an extra teardown before purging the
  // device.
  std::ignore = Teardown();

  return backing_device_->Purge();
}

bool DmcryptContainer::Exists() {
  return backing_device_->Exists();
}

bool DmcryptContainer::Setup(const FileSystemKey& encryption_key) {
  // Check whether the kernel keyring provisioning is supported by the current
  // kernel.
  bool created = false;
  if (!backing_device_->Exists()) {
    if (!backing_device_->Create()) {
      LOG(ERROR) << "Failed to create backing device";
      return false;
    }
    created = true;
  }

  // Ensure that the dm-crypt device or the underlying backing device are
  // not left attached on the failure paths. If the backing device was created
  // during setup, purge it as well.
  absl::Cleanup device_cleanup_runner = [this, created]() {
    if (created) {
      Purge();
    } else {
      Teardown();
    }
  };

  if (!backing_device_->Setup()) {
    LOG(ERROR) << "Failed to setup backing device";
    return false;
  }

  std::optional<base::FilePath> backing_device_path =
      backing_device_->GetPath();
  if (!backing_device_path) {
    LOG(ERROR) << "Failed to get backing device path";
    backing_device_->Teardown();
    return false;
  }

  uint64_t blkdev_size;
  if (!platform_->GetBlkSize(*backing_device_path, &blkdev_size) ||
      blkdev_size < kExt4BlockSize) {
    PLOG(ERROR) << "Failed to get block device size";
    backing_device_->Teardown();
    return false;
  }

  if (!keyring_->AddKey(Keyring::KeyType::kDmcryptKey, encryption_key,
                        &key_reference_)) {
    LOG(ERROR) << "Failed to insert logon key to session keyring.";
    return false;
  }

  // Once the key is inserted, update the key descriptor.
  brillo::SecureBlob key_descriptor = dmcrypt::GenerateDmcryptKeyDescriptor(
      key_reference_.fek_sig, encryption_key.fek.size());

  base::FilePath dmcrypt_device_path =
      base::FilePath("/dev/mapper").Append(dmcrypt_device_name_);
  uint64_t sectors = blkdev_size / kSectorSize;
  brillo::SecureBlob dm_parameters =
      brillo::DevmapperTable::CryptCreateParameters(
          // cipher.
          dmcrypt_cipher_,
          // encryption key descriptor.
          key_descriptor,
          // iv offset.
          iv_offset_,
          // device path.
          *backing_device_path,
          // device offset.
          0,
          // allow discards.
          true);
  brillo::DevmapperTable dm_table(0, sectors, "crypt", dm_parameters);
  if (!device_mapper_->Setup(dmcrypt_device_name_, dm_table)) {
    backing_device_->Teardown();
    LOG(ERROR) << "dm_setup failed";
    return false;
  }

  // Once the key has been used by dm-crypt, remove it from the keyring.
  LOG(INFO) << "Removing provisioned dm-crypt key from kernel keyring.";
  if (!keyring_->RemoveKey(Keyring::KeyType::kDmcryptKey, key_reference_)) {
    LOG(ERROR) << "Failed to remove key";
  }

  // Wait for the dmcrypt device path to show up before continuing to setting
  // up the filesystem.
  if (!platform_->UdevAdmSettle(dmcrypt_device_path, true)) {
    LOG(ERROR) << "udevadm settle failed.";
    return false;
  }

  // Create filesystem, unless we only should provide a raw device.
  if (created && !is_raw_device_ &&
      !platform_->FormatExt4(dmcrypt_device_path, mkfs_opts_, 0)) {
    PLOG(ERROR) << "Failed to format ext4 filesystem";
    return false;
  }

  // Modify features depending on whether we already have the following enabled.
  if (!is_raw_device_ && !tune2fs_opts_.empty() &&
      !platform_->Tune2Fs(dmcrypt_device_path, tune2fs_opts_)) {
    PLOG(ERROR) << "Failed to tune ext4 filesystem";
    return false;
  }

  std::move(device_cleanup_runner).Cancel();
  return true;
}

bool DmcryptContainer::Reset() {
  // Only allow resets for raw devices; discard will otherwise remove the
  // filesystem as well.
  if (!is_raw_device_) {
    LOG(ERROR) << "Attempted to reset a container with a filesystem";
    return false;
  }

  base::FilePath dmcrypt_device_path =
      base::FilePath("/dev/mapper").Append(dmcrypt_device_name_);

  // Discard the entire device.
  if (!platform_->DiscardDevice(dmcrypt_device_path)) {
    LOG(ERROR) << "Failed to discard device";
    return false;
  }

  return true;
}

bool DmcryptContainer::SetLazyTeardownWhenUnused() {
  if (!device_mapper_->Remove(dmcrypt_device_name_, true /* deferred */)) {
    LOG(ERROR) << "Failed to mark the device mapper target for deferred remove";
    return false;
  }

  if (backing_device_->GetType() != BackingDeviceType::kLoopbackDevice) {
    LOG(WARNING) << "Backing device does not support lazy teardown";
    return false;
  }

  if (!backing_device_->Teardown()) {
    LOG(ERROR) << "Failed to lazy teardown backing device";
    return false;
  }

  return true;
}

bool DmcryptContainer::Teardown() {
  if (!device_mapper_->Remove(dmcrypt_device_name_)) {
    LOG(ERROR) << "Failed to teardown device mapper device.";
    return false;
  }

  if (!backing_device_->Teardown()) {
    LOG(ERROR) << "Failed to teardown backing device";
    return false;
  }

  return true;
}

base::FilePath DmcryptContainer::GetBackingLocation() const {
  if (backing_device_ != nullptr && backing_device_->GetPath().has_value()) {
    return *(backing_device_->GetPath());
  }
  return base::FilePath();
}

}  // namespace cryptohome
