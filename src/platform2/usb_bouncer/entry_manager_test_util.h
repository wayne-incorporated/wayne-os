// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef USB_BOUNCER_ENTRY_MANAGER_TEST_UTIL_H_
#define USB_BOUNCER_ENTRY_MANAGER_TEST_UTIL_H_

#include <memory>
#include <string>

#include <base/files/file_path.h>
#include <base/files/scoped_temp_dir.h>

#include "usb_bouncer/entry_manager.h"

namespace usb_bouncer {

constexpr char kDefaultRule[] =
    "allow id 046d:c31c serial \"\" name \"USB Keyboard\" hash "
    "\"eqf7n/3rlMr5be7CI8RRr3PAT41/67nSG7TO4oyXBKQ=\" with-interface "
    "{ 03:01:01 03:00:00 }";

constexpr char kDefaultDevpath[] = "/devices/pci0000:00/0000:00:00.0/usb1/1-0";

constexpr char kUserdbDir[] =
    "run/daemon-store/usb_bouncer/0000000000000000000000000000000000000000/";

class EntryManagerTestUtil {
 public:
  EntryManagerTestUtil();

  EntryManager* Get();

  void RefreshDB(bool include_user_db, bool new_db);

  void ReplaceDB(const RuleDB& replacement);

  void SetUserDBReadOnly(bool user_db_read_only);

  void SetIsGuestSession(bool is_guest_session);

  void ExpireEntry(bool expect_user,
                   const std::string& devpath,
                   const std::string& rule);

  size_t GarbageCollectInternal(bool global_only);

  bool GlobalDBContainsEntry(const std::string& devpath,
                             const std::string& rule);

  bool GlobalTrashContainsEntry(const std::string& devpath,
                                const std::string& rule);

  bool UserDBContainsEntry(const std::string& rule);

 private:
  base::FilePath CreateTestDir(const std::string& dir, bool force_empty);
  void RecreateEntryManager(const base::FilePath& userdb_dir);

  std::unique_ptr<EntryManager> entry_manager_;
  base::ScopedTempDir scoped_temp_dir_;
  base::FilePath temp_dir_;
};

}  // namespace usb_bouncer

#endif  // USB_BOUNCER_ENTRY_MANAGER_TEST_UTIL_H_
