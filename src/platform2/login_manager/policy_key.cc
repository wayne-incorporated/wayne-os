// Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "login_manager/policy_key.h"

#include <stdint.h>

#include <string>

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <crypto/rsa_private_key.h>

#include "login_manager/nss_util.h"
#include "login_manager/system_utils_impl.h"

namespace login_manager {

PolicyKey::PolicyKey(const base::FilePath& key_file, NssUtil* nss)
    : key_file_(key_file), nss_(nss), utils_(new SystemUtilsImpl) {}

PolicyKey::~PolicyKey() {}

bool PolicyKey::Equals(const std::string& key_der) const {
  return VEquals(std::vector<uint8_t>(key_der.c_str(),
                                      key_der.c_str() + key_der.length()));
}

bool PolicyKey::VEquals(const std::vector<uint8_t>& key_der) const {
  return ((key_.empty() == key_der.empty()) &&
          memcmp(&key_der[0], &key_[0], key_.size()) == 0);
}

bool PolicyKey::HaveCheckedDisk() const {
  return have_checked_disk_;
}

bool PolicyKey::IsPopulated() const {
  return !key_.empty();
}

bool PolicyKey::PopulateFromDiskIfPossible() {
  have_checked_disk_ = true;
  if (!base::PathExists(key_file_)) {
    LOG(INFO) << "No policy key on disk at " << key_file_.value();
    return true;
  }

  int32_t safe_file_size = 0;
  if (!utils_->EnsureAndReturnSafeFileSize(key_file_, &safe_file_size)) {
    LOG(ERROR) << key_file_.value() << " is too large!";
    return false;
  }

  std::vector<uint8_t> buffer(safe_file_size, 0);
  int data_read = base::ReadFile(key_file_, reinterpret_cast<char*>(&buffer[0]),
                                 safe_file_size);
  if (data_read != safe_file_size) {
    PLOG(ERROR) << key_file_.value() << " could not be read in its entirety!";
    return false;
  }

  if (!nss_->CheckPublicKeyBlob(buffer)) {
    LOG(ERROR) << "Policy key " << key_file_.value() << " is corrupted!";
    return false;
  }
  key_.assign(buffer.begin(), buffer.end());
  return true;
}

bool PolicyKey::PopulateFromBuffer(const std::vector<uint8_t>& public_key_der) {
  if (!HaveCheckedDisk()) {
    LOG(WARNING) << "Haven't checked disk for owner key yet!";
    return false;
  }
  // Only get here if we've checked disk already.
  if (IsPopulated()) {
    LOG(ERROR) << "Already have an owner key!";
    return false;
  }
  // Only get here if we've checked disk AND we didn't load a key.
  key_ = public_key_der;
  return true;
}

bool PolicyKey::PopulateFromKeypair(crypto::RSAPrivateKey* pair) {
  std::vector<uint8_t> public_key_der;
  if (pair && pair->ExportPublicKey(&public_key_der))
    return PopulateFromBuffer(public_key_der);
  LOG(ERROR) << "Failed to export public key from key pair";
  return false;
}

bool PolicyKey::Persist() {
  // It is a programming error to call this before checking for the key on disk.
  CHECK(HaveCheckedDisk()) << "Haven't checked disk for owner key yet!";
  if (!have_replaced_ && base::PathExists(key_file_)) {
    LOG(ERROR) << "Tried to overwrite owner key!";
    return false;
  }

  // Remove the key if it has been cleared.
  if (key_.empty()) {
    bool removed = utils_->RemoveFile(key_file_);
    PLOG_IF(ERROR, !removed) << "Failed to delete " << key_file_.value();
    return removed;
  }

  if (!utils_->AtomicFileWrite(key_file_,
                               std::string(key_.begin(), key_.end()))) {
    PLOG(ERROR) << "Could not write data to " << key_file_.value();
    return false;
  }
  DLOG(INFO) << "wrote " << key_.size() << " bytes to " << key_file_.value();
  return true;
}

bool PolicyKey::Rotate(const std::vector<uint8_t>& public_key_der,
                       const std::vector<uint8_t>& signature) {
  if (!IsPopulated()) {
    LOG(ERROR) << "Don't yet have an owner key!";
    return false;
  }
  if (Verify(public_key_der, signature)) {
    key_ = public_key_der;
    have_replaced_ = true;
    return true;
  }
  LOG(ERROR) << "Invalid signature on new key!";
  return false;
}

bool PolicyKey::ClobberCompromisedKey(
    const std::vector<uint8_t>& public_key_der) {
  // It is a programming error to call this before checking for the key on disk.
  CHECK(HaveCheckedDisk()) << "Haven't checked disk for owner key yet!";
  // It is a programming error to call this without a key already loaded.
  CHECK(IsPopulated()) << "Don't yet have an owner key!";

  key_ = public_key_der;
  return have_replaced_ = true;
}

bool PolicyKey::Verify(const std::vector<uint8_t>& data,
                       const std::vector<uint8_t>& signature) {
  if (!nss_->Verify(signature, data, key_)) {
    LOG(ERROR) << "Signature verification failed";
    return false;
  }
  return true;
}

}  // namespace login_manager
