// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "bootlockbox/nvram_boot_lockbox.h"

#include <string>
#include <utility>
#include <vector>

#include <base/files/file_util.h>
#include <base/logging.h>
#include <brillo/file_utils.h>
#include <crypto/secure_hash.h>
#include <crypto/sha2.h>
#include <libhwsec-foundation/crypto/sha.h>

#include "bootlockbox/hwsec_space.h"
#include "bootlockbox/hwsec_space_impl.h"

using ::hwsec_foundation::Sha256;

namespace bootlockbox {

NVRamBootLockbox::NVRamBootLockbox(HwsecSpace* hwsec_space)
    : boot_lockbox_filepath_(base::FilePath(kNVRamBootLockboxFilePath)),
      hwsec_space_(hwsec_space) {}

NVRamBootLockbox::NVRamBootLockbox(HwsecSpace* hwsec_space,
                                   const base::FilePath& bootlockbox_file_path)
    : boot_lockbox_filepath_(bootlockbox_file_path),
      hwsec_space_(hwsec_space) {}

NVRamBootLockbox::~NVRamBootLockbox() {}

bool NVRamBootLockbox::Store(const std::string& key,
                             const std::string& digest,
                             BootLockboxErrorCode* error) {
  // Returns nvspace state to client.
  *error = BootLockboxErrorCode::BOOTLOCKBOX_ERROR_NOT_SET;
  if (nvspace_state_ == SpaceState::kSpaceWriteLocked) {
    *error = BootLockboxErrorCode::BOOTLOCKBOX_ERROR_WRITE_LOCKED;
    return false;
  }
  if (nvspace_state_ == SpaceState::kSpaceNeedPowerwash) {
    *error = BootLockboxErrorCode::BOOTLOCKBOX_ERROR_NEED_POWERWASH;
    return false;
  }
  if (nvspace_state_ == SpaceState::kSpaceUndefined) {
    *error = BootLockboxErrorCode::BOOTLOCKBOX_ERROR_NVSPACE_UNDEFINED;
    return false;
  }
  if (nvspace_state_ == SpaceState::kSpaceError) {
    *error = BootLockboxErrorCode::BOOTLOCKBOX_ERROR_NVSPACE_OTHER;
    return false;
  }

  // A temporaray key value map for writing.
  KeyValueMap updated_key_value_map = key_value_store_;
  updated_key_value_map[key] = digest;
  if (!FlushAndUpdate(updated_key_value_map)) {
    LOG(ERROR) << "Store Failed: Cannot flush to file.";
    *error = BootLockboxErrorCode::BOOTLOCKBOX_ERROR_WRITE_FAILED;
    return false;
  }
  return true;
}

bool NVRamBootLockbox::Read(const std::string& key,
                            std::string* digest,
                            BootLockboxErrorCode* error) {
  // Returns nvspace state to client.
  *error = BootLockboxErrorCode::BOOTLOCKBOX_ERROR_NOT_SET;
  if (nvspace_state_ == SpaceState::kSpaceUndefined) {
    *error = BootLockboxErrorCode::BOOTLOCKBOX_ERROR_NVSPACE_UNDEFINED;
    return false;
  }
  if (nvspace_state_ == SpaceState::kSpaceUninitialized) {
    *error = BootLockboxErrorCode::BOOTLOCKBOX_ERROR_NVSPACE_UNINITIALIZED;
    return false;
  }
  if (nvspace_state_ == SpaceState::kSpaceNeedPowerwash) {
    *error = BootLockboxErrorCode::BOOTLOCKBOX_ERROR_NEED_POWERWASH;
    return false;
  }
  if (nvspace_state_ == SpaceState::kSpaceError) {
    *error = BootLockboxErrorCode::BOOTLOCKBOX_ERROR_NVSPACE_OTHER;
    return false;
  }

  KeyValueMap::const_iterator it = key_value_store_.find(key);
  if (it == key_value_store_.end()) {
    *error = BootLockboxErrorCode::BOOTLOCKBOX_ERROR_MISSING_KEY;
    return false;
  }
  *digest = it->second;
  return true;
}

bool NVRamBootLockbox::Finalize() {
  if (nvspace_state_ == SpaceState::kSpaceUndefined) {
    return false;
  }
  if (nvspace_state_ == SpaceState::kSpaceNeedPowerwash) {
    return false;
  }
  if (hwsec_space_->LockSpace()) {
    nvspace_state_ = SpaceState::kSpaceWriteLocked;
    return true;
  }
  nvspace_state_ = SpaceState::kSpaceError;
  return false;
}

bool NVRamBootLockbox::DefineSpace() {
  if (nvspace_state_ != SpaceState::kSpaceUndefined) {
    LOG(INFO)
        << "Trying to define the nvspace, but the nvspace isn't undefined.";
    return false;
  }

  nvspace_state_ = hwsec_space_->DefineSpace();
  if (nvspace_state_ != SpaceState::kSpaceUninitialized) {
    return false;
  }

  LOG(INFO) << "Space defined successfully.";

  return true;
}

bool NVRamBootLockbox::RegisterOwnershipCallback() {
  if (nvspace_state_ != SpaceState::kSpaceUndefined) {
    LOG(ERROR) << "Trying to register the ownership callback, but the nvspace "
                  "isn't undefined.";
    return false;
  }

  if (ownership_callback_registered_) {
    LOG(ERROR) << "Ownership callback had already been registered.";
    return false;
  }

  ownership_callback_registered_ = true;

  // NVRamBootLockbox and HwsecSpace would be destructed in the same time and
  // this callback would disappear after HwsecSpace be destructed, so it is safe
  // to pass `this` into this callback.
  base::OnceClosure callback =
      base::BindRepeating(base::IgnoreResult(&NVRamBootLockbox::DefineSpace),
                          base::Unretained(this));

  hwsec_space_->RegisterOwnershipTakenCallback(std::move(callback));

  return true;
}

bool NVRamBootLockbox::Load() {
  nvspace_state_ = hwsec_space_->ReadSpace(&root_digest_);
  if (nvspace_state_ != SpaceState::kSpaceNormal) {
    LOG(ERROR) << "Failed to read NVRAM space.";
    return false;
  }

  std::string contents;
  if (!base::ReadFileToString(boot_lockbox_filepath_, &contents)) {
    LOG(ERROR) << "Failed to read input file.";
    return false;
  }

  std::string digest = crypto::SHA256HashString(contents);
  if (digest != root_digest_) {
    LOG(ERROR) << "The nvram boot lockbox file verification failed.";
    nvspace_state_ = SpaceState::kSpaceUninitialized;
    return false;
  }

  SerializedKeyValueMap message;
  if (!message.ParseFromString(contents)) {
    LOG(ERROR) << "Failed to parse boot lockbox file.";
    nvspace_state_ = SpaceState::kSpaceUninitialized;
    return false;
  }

  if (!message.has_version() || message.version() != kVersion) {
    LOG(ERROR) << "Unsupported version " << message.version();
    nvspace_state_ = SpaceState::kSpaceUninitialized;
    return false;
  }

  KeyValueMap tmp(message.keyvals().begin(), message.keyvals().end());
  key_value_store_.swap(tmp);
  return true;
}

bool NVRamBootLockbox::FlushAndUpdate(const KeyValueMap& keyvals) {
  SerializedKeyValueMap message;
  message.set_version(kVersion);

  auto mutable_map = message.mutable_keyvals();
  KeyValueMap::const_iterator it;
  for (it = keyvals.begin(); it != keyvals.end(); ++it) {
    (*mutable_map)[it->first] = it->second;
  }

  brillo::Blob content(message.ByteSizeLong());
  message.SerializeWithCachedSizesToArray(content.data());

  brillo::Blob digest_blob = Sha256(content);
  std::string digest(digest_blob.begin(), digest_blob.end());

  // It is hard to make this atomic. In the case the file digest
  // and NVRAM space content are inconsistent, the file is deleted and NVRAM
  // space is updated on write.
  if (!brillo::WriteBlobToFileAtomic(boot_lockbox_filepath_, content, 0600)) {
    LOG(ERROR) << "Failed to write to boot lockbox file";
    return false;
  }
  // Update nvram.
  if (!hwsec_space_->WriteSpace(digest)) {
    LOG(ERROR) << "Failed to write boot lockbox NVRAM space";
    return false;
  }

  brillo::SyncFileOrDirectory(boot_lockbox_filepath_, false /* is directory */,
                              true /* data sync */);
  // Update in memory information.
  key_value_store_ = keyvals;
  root_digest_ = digest;
  nvspace_state_ = SpaceState::kSpaceNormal;
  return true;
}

SpaceState NVRamBootLockbox::GetState() {
  return nvspace_state_;
}

void NVRamBootLockbox::SetState(const SpaceState state) {
  nvspace_state_ = state;
}

}  // namespace bootlockbox
