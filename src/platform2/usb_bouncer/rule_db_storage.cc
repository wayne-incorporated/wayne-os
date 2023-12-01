// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "usb_bouncer/rule_db_storage.h"

#include <unistd.h>

#include <string>
#include <vector>

#include <base/files/file_util.h>
#include <base/logging.h>
#include <brillo/files/safe_fd.h>

#include "usb_bouncer/util.h"

using brillo::SafeFD;

namespace usb_bouncer {

namespace {
constexpr size_t kMaxFileSize = 64 * 1024 * 1024;
}  // namespace

RuleDBStorage::RuleDBStorage() {}

RuleDBStorage::RuleDBStorage(const base::FilePath& db_dir) {
  fd_ = OpenStateFile(db_dir.DirName(), db_dir.BaseName().value(),
                      kDefaultDbName, true /* lock */);
  if (fd_.is_valid()) {
    path_ = db_dir.Append(kDefaultDbName);
  }
  Reload();
}

RuleDB& RuleDBStorage::Get() {
  return *val_.get();
}

const RuleDB& RuleDBStorage::Get() const {
  return *val_.get();
}

const base::FilePath& RuleDBStorage::path() const {
  return path_;
}

bool RuleDBStorage::Valid() const {
  return !path_.empty() && fd_.is_valid() && val_ != nullptr;
}

bool RuleDBStorage::Persist() {
  if (!Valid()) {
    LOG(ERROR) << "Called Persist() on invalid RuleDBStorage";
    return false;
  }

  if (lseek(fd_.get(), 0, SEEK_SET) != 0) {
    PLOG(ERROR) << "Failed to rewind DB";
    return false;
  }

  std::string serialized = val_->SerializeAsString();
  if (fd_.Replace(serialized.data(), serialized.size()) !=
      SafeFD::Error::kNoError) {
    PLOG(ERROR) << "Failed to write proto to file!";
    return false;
  }

  return true;
}

bool RuleDBStorage::Reload() {
  val_ = nullptr;

  // Get the file size.
  off_t file_size = lseek(fd_.get(), 0, SEEK_END);
  if (file_size == -1) {
    PLOG(ERROR) << "Failed to get DB size";
    return false;
  }
  if (file_size > kMaxFileSize) {
    LOG(ERROR) << "DB is too big!";
    return false;
  }

  // Read the file.
  if (lseek(fd_.get(), 0, SEEK_SET) != 0) {
    PLOG(ERROR) << "Failed to rewind DB";
    return false;
  }

  SafeFD::Error err;
  std::vector<char> buf;
  std::tie(buf, err) = fd_.ReadContents(kMaxFileSize);
  if (err != SafeFD::Error::kNoError) {
    PLOG(ERROR) << "Failed to read DB";
    return false;
  }

  // Parse the results.
  val_ = std::make_unique<RuleDB>();
  if (!val_->ParseFromArray(buf.data(), buf.size())) {
    LOG(ERROR) << "Error parsing DB. Regenerating...";
    val_ = std::make_unique<RuleDB>();
  }
  return true;
}

}  // namespace usb_bouncer
