// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/install_attributes.h"

#include <sys/types.h>

#include <limits>
#include <string>
#include <utility>

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/logging.h>
#include <base/notreached.h>
#include <base/time/time.h>

#include "cryptohome/lockbox.h"

using base::FilePath;
using StorageState = hwsec::CryptohomeFrontend::StorageState;

namespace cryptohome {

// By default, we store this with other cryptohome state.
const char InstallAttributes::kDefaultDataFile[] =
    "/home/.shadow/install_attributes.pb";
const mode_t InstallAttributes::kDataFilePermissions = 0644;
// This is the default location for the cache file.
const char InstallAttributes::kDefaultCacheFile[] =
    "/run/lockbox/install_attributes.pb";
const mode_t InstallAttributes::kCacheFilePermissions = 0644;

InstallAttributes::InstallAttributes(Platform* platform,
                                     const hwsec::CryptohomeFrontend* hwsec)
    : platform_(platform),
      hwsec_(hwsec),
      data_file_(kDefaultDataFile),
      cache_file_(kDefaultCacheFile),
      default_attributes_(new SerializedInstallAttributes()),
      default_lockbox_(new Lockbox(hwsec, hwsec::Space::kInstallAttributes)),
      attributes_(default_attributes_.get()),
      lockbox_(default_lockbox_.get()) {
  CHECK(platform_);
  CHECK(hwsec_);
  version_ = attributes_->version();  // versioning controlled by pb default.
}

InstallAttributes::~InstallAttributes() {}

bool InstallAttributes::IsSecure() {
  if (!USE_TPM_INSECURE_FALLBACK) {
    // We should always enable the hardware protection if we don't enable the
    // fallback feature.
    return true;
  }

  hwsec::StatusOr<bool> is_enabled = hwsec_->IsEnabled();
  if (!is_enabled.ok()) {
    LOG(ERROR) << "Failed to check hwsec is enabled or not: "
               << is_enabled.status();
    return false;
  }
  return is_enabled.value();
}

bool InstallAttributes::Init() {
  // Ensure that if Init() was called and it failed, we can retry cleanly.
  attributes_->Clear();
  status_ = Status::kUnknown;

  // Read the cache file. If it exists, lockbox-cache has successfully
  // verified install attributes during early boot, so use them.
  brillo::Blob blob;
  bool valid_cache = false;
  if (platform_->ReadFile(cache_file_, &blob)) {
    if (!attributes_->ParseFromArray(
            static_cast<google::protobuf::uint8*>(blob.data()), blob.size())) {
      LOG(ERROR) << "Failed to parse data file (" << blob.size() << " bytes)";
      attributes_->Clear();
      status_ = Status::kInvalid;
      return false;
    }
    valid_cache = true;
  }

  if (!IsSecure()) {
    if (valid_cache) {
      LOG(INFO) << "Valid insecure install attributes cache found.";
      status_ = Status::kValid;
    } else {
      // No cache file, so TPM lockbox is either not yet set up or data is
      // invalid.
      LOG(INFO) << "Init() assuming first-time install for TPM-less system.";
      status_ = Status::kFirstInstall;
    }
    return true;
  }

  if (valid_cache) {
    // Ensure the space is defined correctly and removing the owner dependency
    // if necessary.
    hwsec::StatusOr<StorageState> state =
        hwsec_->GetSpaceState(hwsec::Space::kInstallAttributes);
    if (!state.ok()) {
      LOG(ERROR) << "Failed to get install attributes state: "
                 << state.status();
      attributes_->Clear();
      status_ = Status::kInvalid;
      return false;
    }

    if (state->writable) {
      LOG(WARNING) << "Found unfinalized install attributs.";
      status_ = Status::kFirstInstall;
      return true;
    }

    if (state->readable) {
      LOG(INFO) << "Valid secure install attributes cache found.";
      status_ = Status::kValid;
      return true;
    }

    LOG(ERROR) << "Found invalid install attributes. Reinitialize it.";
    attributes_->Clear();
  }

  hwsec::StatusOr<bool> is_ready = hwsec_->IsReady();
  if (!is_ready.ok()) {
    LOG(ERROR) << "Failed to check hwsec is ready or not: "
               << is_ready.status();
    status_ = Status::kInvalid;
    return false;
  }

  // HWSec is not ready yet, i.e. setup after ownership not completed.
  // Init() is supposed to get invoked again once the Hwsec is ready.
  if (!is_ready.value()) {
    // Don't flag invalid here - Chrome verifies that install attributes
    // aren't invalid before locking them as part of enterprise enrollment.
    LOG(ERROR) << "Init() hwsec is not ready, while install "
               << "attributes are missing or invalid.";
    status_ = Status::kTpmNotOwned;
    return false;
  }

  // The TPM is ready and we haven't found valid install attributes. This
  // usually means that we haven't written and locked the lockbox yet, so
  // attempt a reset. The reset may fail in various other edge cases and the
  // error code lets us identify and handle these edge cases correctly.
  LockboxError error_id;
  if (!lockbox()->Reset(&error_id)) {
    switch (error_id) {
      case LockboxError::kNvramInvalid:
        LOG(ERROR) << "Inconsistent install attributes state.";
        status_ = Status::kInvalid;
        return false;
      case LockboxError::kTpmUnavailable:
        NOTREACHED() << "Should never call lockbox when TPM is unavailable.";
        status_ = Status::kInvalid;
        return false;
      case LockboxError::kTpmError:
        LOG(ERROR) << "TPM error on install attributes initialization.";
        status_ = Status::kInvalid;
        return false;
    }
  }

  // Reset succeeded, so we have a writable lockbox now.
  // Delete data file potentially left around from previous installation.
  if (!ClearData()) {
    // ClearData() will log its own error message if it fails.
    return false;
  }

  status_ = Status::kFirstInstall;
  LOG(INFO) << "Install attributes reset back to first install.";
  return true;
}

int InstallAttributes::FindIndexByName(const std::string& name) const {
  std::string name_str(name);
  for (int i = 0; i < attributes_->attributes_size(); ++i) {
    if (attributes_->attributes(i).name().compare(name_str) == 0)
      return i;
  }
  return -1;
}

bool InstallAttributes::Get(const std::string& name,
                            brillo::Blob* value) const {
  int index = FindIndexByName(name);
  if (index == -1)
    return false;
  return GetByIndex(index, NULL, value);
}

bool InstallAttributes::GetByIndex(int index,
                                   std::string* name,
                                   brillo::Blob* value) const {
  if (index < 0 || index >= attributes_->attributes_size()) {
    LOG(ERROR) << "GetByIndex called with invalid index.";
    return false;
  }
  const SerializedInstallAttributes::Attribute* const attr =
      &attributes_->attributes(index);
  if (name) {
    name->assign(attr->name());
  }
  if (value) {
    value->resize(attr->value().length());
    memcpy(&value->at(0), attr->value().c_str(), value->size());
  }
  return true;
}

bool InstallAttributes::Set(const std::string& name,
                            const brillo::Blob& value) {
  if (status_ != Status::kFirstInstall) {
    LOG(ERROR) << "Set() called on immutable attributes.";
    return false;
  }

  if (Count() == std::numeric_limits<int>::max()) {
    LOG(ERROR) << "Set() cannot insert into full attribute store.";
    return false;
  }

  // Clobber an existing entry if it exists.
  int index = FindIndexByName(name);
  if (index != -1) {
    SerializedInstallAttributes::Attribute* attr =
        attributes_->mutable_attributes(index);
    attr->set_value(
        std::string(reinterpret_cast<const char*>(value.data()), value.size()));
    return true;
  }

  SerializedInstallAttributes::Attribute* attr = attributes_->add_attributes();
  if (!attr) {
    LOG(ERROR) << "Failed to add a new attribute.";
    return false;
  }
  attr->set_name(name);
  attr->set_value(
      std::string(reinterpret_cast<const char*>(value.data()), value.size()));
  return true;
}

bool InstallAttributes::Finalize() {
  switch (status_) {
    case Status::kUnknown:
    case Status::kTpmNotOwned:
    case Status::kInvalid:
      LOG(ERROR) << "Finalize() called with invalid/uninitialized data.";
      return false;
    case Status::kValid:
      // Repeated calls to Finalize() are idempotent.
      return true;
    case Status::kFirstInstall:
      break;
    case Status::COUNT:
      NOTREACHED();
  }

  // Restamp the version.
  attributes_->set_version(version_);

  // Serialize the bytestream
  brillo::Blob attr_bytes;
  if (!SerializeAttributes(&attr_bytes)) {
    LOG(ERROR) << "Finalize() failed to serialize the attributes.";
    return false;
  }

  LockboxError error;
  DLOG(INFO) << "Finalizing() " << attr_bytes.size() << " bytes.";
  if (IsSecure() && !lockbox()->Store(attr_bytes, &error)) {
    LOG(ERROR) << "Finalize() failed with Lockbox error: " << error;
    // It may be possible to recover from a failed NVRAM store. So the
    // instance is not marked invalid.
    return false;
  }

  if (!platform_->WriteFileAtomicDurable(data_file_, attr_bytes,
                                         kDataFilePermissions)) {
    LOG(ERROR) << "Finalize() write failed after locking the Lockbox.";
    attributes_->Clear();
    status_ = Status::kInvalid;
    return false;
  }

  // As the cache file is stored on tmpfs, durable write is not required but we
  // need atomicity to be safe in case of concurrent reads.
  if (!platform_->WriteFileAtomic(cache_file_, attr_bytes,
                                  kCacheFilePermissions)) {
    LOG(WARNING) << "Finalize() failed to create cache file.";
  }

  LOG(INFO) << "InstallAttributes have been finalized.";
  status_ = Status::kValid;
  NotifyFinalized();
  return true;
}

int InstallAttributes::Count() const {
  return attributes_->attributes_size();
}

bool InstallAttributes::SerializeAttributes(brillo::Blob* out_bytes) {
  out_bytes->resize(attributes_->ByteSizeLong());
  attributes_->SerializeWithCachedSizesToArray(
      static_cast<google::protobuf::uint8*>(out_bytes->data()));
  return true;
}

bool InstallAttributes::ClearData() {
  if (platform_->FileExists(data_file_) && !platform_->DeleteFile(data_file_)) {
    LOG(ERROR) << "Failed to delete install attributes data file!";
    return false;
  }
  return true;
}

}  // namespace cryptohome
