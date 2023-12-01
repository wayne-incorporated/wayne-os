// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef USB_BOUNCER_RULE_DB_STORAGE_H_
#define USB_BOUNCER_RULE_DB_STORAGE_H_

#include <memory>

#include <base/files/file_path.h>
#include <brillo/files/safe_fd.h>

#include "usb_bouncer/usb_bouncer.pb.h"

namespace usb_bouncer {

// Handles file related operations for a RuleDB.
//
// The state on disk is read during construction and can be read again to
// replace the current state provided by Get() using Reload().
//
// Once the desired changes are to be finalized Persist() will write the changes
// to disk.
//
// Only one RuleDBStorage instance should be created for a unique path at any
// time otherwise some instances will block until the file lock is released.
class RuleDBStorage {
 public:
  // The default constructor makes an invalid RuleDBStorage() instance. This
  // supports the case where a user isn't signed in so EntryManager::user_db_ is
  // invalid.
  RuleDBStorage();
  explicit RuleDBStorage(const base::FilePath& db_dir);

  // Allow safe assignment and moving so the value can be changed after the
  // initial member construction (e.g. a default constructed RuleDBStorage can
  // be replaced at a later time once the db_dir is known).
  RuleDBStorage(RuleDBStorage&&) = default;
  RuleDBStorage(const RuleDBStorage&) = delete;
  RuleDBStorage& operator=(const RuleDBStorage&) = delete;

  RuleDBStorage& operator=(RuleDBStorage&&) = default;

  RuleDB& Get();
  const RuleDB& Get() const;
  const base::FilePath& path() const;

  bool Valid() const;

  bool Persist();
  bool Reload();

 private:
  base::FilePath path_;
  brillo::SafeFD fd_;
  std::unique_ptr<RuleDB> val_;
};

}  // namespace usb_bouncer

#endif  // USB_BOUNCER_RULE_DB_STORAGE_H_
