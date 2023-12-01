// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "usb_bouncer/entry_manager_test_util.h"

#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file_util.h>
#include <base/logging.h>

#include "usb_bouncer/util.h"

namespace usb_bouncer {

namespace {

constexpr char kUsbguardTestConfigFilename[] = "99-rules.conf";
constexpr char kUsbguardTestConfigFooter[] = "block\n";

bool EntryMapContains(const EntryMap& entries,
                      const std::string& key,
                      const std::string& value) {
  auto entry = entries.find(key);

  if (entry == entries.end()) {
    return false;
  }

  if (entry->second.rules().size() != 1) {
    return false;
  }

  return value == entry->second.rules(0);
}

bool ExpireEntryHelper(EntryMap* entries, const std::string& key) {
  auto entry = entries->find(key);

  if (entry == entries->end()) {
    return false;
  }

  if (entry->second.rules().size() != 1) {
    return false;
  }

  entry->second.mutable_last_used()->clear_seconds();
  return true;
}

}  // namespace

EntryManagerTestUtil::EntryManagerTestUtil() {
  CHECK(scoped_temp_dir_.CreateUniqueTempDir());
  temp_dir_ = scoped_temp_dir_.GetPath();
  CHECK(base::SetPosixFilePermissions(temp_dir_, 0755));

  base::FilePath temp_etc_usbguard =
      CreateTestDir(kUsbguardPolicyDir, true /*force_empty*/);
  CHECK_NE(base::WriteFile(
               temp_etc_usbguard.Append(kUsbguardTestConfigFilename),
               kUsbguardTestConfigFooter, sizeof(kUsbguardTestConfigFooter)),
           -1);

  CreateTestDir(std::string("sys") + kDefaultDevpath, true /*force_empty*/);
  CreateTestDir(kUserDbBaseDir, true /*force_empty*/);

  RecreateEntryManager(base::FilePath() /*userdb_dir*/);
}

EntryManager* EntryManagerTestUtil::Get() {
  return entry_manager_.get();
}

void EntryManagerTestUtil::RefreshDB(bool include_user_db, bool new_db) {
  if (new_db && entry_manager_) {
    if (!base::DeletePathRecursively(entry_manager_->global_db_.path())) {
      LOG(FATAL) << "Unable to delete \""
                 << entry_manager_->global_db_.path().value() << "\"!";
    }
  }
  if (include_user_db) {
    base::FilePath user_db_dir = CreateTestDir(kUserdbDir, new_db);
    CHECK(!user_db_dir.empty());
    RecreateEntryManager(user_db_dir);
  } else {
    RecreateEntryManager(base::FilePath());
  }
}

void EntryManagerTestUtil::ReplaceDB(const RuleDB& replacement) {
  entry_manager_->global_db_.Get() = replacement;
}

void EntryManagerTestUtil::SetUserDBReadOnly(bool user_db_read_only) {
  entry_manager_->user_db_read_only_ = user_db_read_only;
}

void EntryManagerTestUtil::SetIsGuestSession(bool is_guest_session) {
  entry_manager_->is_guest_session_ = is_guest_session;
}

void EntryManagerTestUtil::ExpireEntry(bool expect_user,
                                       const std::string& devpath,
                                       const std::string& rule) {
  CHECK(ExpireEntryHelper(entry_manager_->global_db_.Get().mutable_trash(),
                          Hash(devpath)));

  if (expect_user) {
    CHECK(entry_manager_->user_db_.Valid());
    CHECK(ExpireEntryHelper(entry_manager_->user_db_.Get().mutable_entries(),
                            Hash(rule)));
  }
}

size_t EntryManagerTestUtil::GarbageCollectInternal(bool global_only) {
  return entry_manager_->GarbageCollectInternal(global_only);
}

bool EntryManagerTestUtil::GlobalDBContainsEntry(const std::string& devpath,
                                                 const std::string& rule) {
  return EntryMapContains(entry_manager_->global_db_.Get().entries(),
                          Hash(devpath), rule);
}

bool EntryManagerTestUtil::GlobalTrashContainsEntry(const std::string& devpath,
                                                    const std::string& rule) {
  return EntryMapContains(entry_manager_->global_db_.Get().trash(),
                          Hash(devpath), rule);
}

bool EntryManagerTestUtil::UserDBContainsEntry(const std::string& rule) {
  CHECK(entry_manager_->user_db_.Valid());
  return EntryMapContains(entry_manager_->user_db_.Get().entries(), Hash(rule),
                          rule);
}

base::FilePath EntryManagerTestUtil::CreateTestDir(const std::string& dir,
                                                   bool force_empty) {
  base::FilePath result;
  if (!dir.empty() && dir.front() == '/') {
    result = temp_dir_.Append(dir.substr(1));
  } else {
    result = temp_dir_.Append(dir);
  }
  if (force_empty) {
    if (!base::DeletePathRecursively(result)) {
      LOG(FATAL) << "Unable to clear directory \"" << result.value() << "\"!";
    }
  }
  base::File::Error error;
  if (!base::CreateDirectoryAndGetError(result, &error)) {
    LOG(FATAL) << "Unable to create temp directory \"" << result.value()
               << "\"!";
  }
  return result;
}

void EntryManagerTestUtil::RecreateEntryManager(
    const base::FilePath& userdb_dir) {
  // Make sure old entry_manager_ is cleaned up before creating another to
  // release the file lock.
  entry_manager_.reset();
  // std::make_unique was not used because a private constructor was needed.
  entry_manager_.reset(
      new EntryManager(temp_dir_.value(), userdb_dir,
                       false /*user_db_read_only*/, false /*is_guest_session*/,
                       [](const std::string& devpath) -> std::string {
                         if (devpath.empty()) {
                           return "";
                         }
                         return kDefaultRule;
                       }));
  CHECK(entry_manager_->global_db_.Valid());
}

}  // namespace usb_bouncer
