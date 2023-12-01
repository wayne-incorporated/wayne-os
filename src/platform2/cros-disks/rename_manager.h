// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CROS_DISKS_RENAME_MANAGER_H_
#define CROS_DISKS_RENAME_MANAGER_H_

#include <map>
#include <string>

#include <base/memory/weak_ptr.h>
#include <brillo/process/process_reaper.h>
#include <chromeos/dbus/service_constants.h>
#include <gtest/gtest_prod.h>

#include "cros-disks/sandboxed_process.h"

namespace cros_disks {

class Platform;
class RenameManagerObserverInterface;

class RenameManager {
 public:
  RenameManager(Platform* platform, brillo::ProcessReaper* process_reaper);
  RenameManager(const RenameManager&) = delete;
  RenameManager& operator=(const RenameManager&) = delete;

  ~RenameManager();

  // Starts a renaming process of a given device.
  RenameError StartRenaming(const std::string& device_path,
                            const std::string& device_file,
                            const std::string& volume_name,
                            const std::string& filesystem_type);

  void set_observer(RenameManagerObserverInterface* observer) {
    observer_ = observer;
  }

 private:
  FRIEND_TEST(RenameManagerTest, CanRename);

  void OnRenameProcessTerminated(const std::string& device_path,
                                 const siginfo_t& info);

  // Returns true if renaming |source_path| is supported.
  bool CanRename(const std::string& source_path) const;

  // Platform service
  Platform* platform_;

  brillo::ProcessReaper* process_reaper_;

  // A list of outstanding renaming processes indexed by device path.
  std::map<std::string, SandboxedProcess> rename_process_;

  RenameManagerObserverInterface* observer_;

  base::WeakPtrFactory<RenameManager> weak_ptr_factory_;
};

}  // namespace cros_disks

#endif  // CROS_DISKS_RENAME_MANAGER_H_
