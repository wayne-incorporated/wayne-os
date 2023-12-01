// Copyright 2011 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CROS_DISKS_FORMAT_MANAGER_H_
#define CROS_DISKS_FORMAT_MANAGER_H_

#include <map>
#include <string>
#include <vector>

#include <base/memory/weak_ptr.h>
#include <brillo/process/process_reaper.h>
#include <chromeos/dbus/service_constants.h>
#include <gtest/gtest_prod.h>

#include "cros-disks/sandboxed_process.h"

namespace cros_disks {

class Platform;

class FormatManagerObserverInterface;

class FormatManager {
 public:
  explicit FormatManager(Platform* platform,
                         brillo::ProcessReaper* process_reaper);
  FormatManager(const FormatManager&) = delete;
  FormatManager& operator=(const FormatManager&) = delete;

  ~FormatManager();

  // Starts a formatting process of a given device.
  FormatError StartFormatting(const std::string& device_path,
                              const std::string& device_file,
                              const std::string& filesystem,
                              const std::vector<std::string>& options);

  void set_observer(FormatManagerObserverInterface* observer) {
    observer_ = observer;
  }

 private:
  FRIEND_TEST(FormatManagerTest, GetFormatProgramPath);
  FRIEND_TEST(FormatManagerTest, IsFilesystemSupported);

  void OnFormatProcessTerminated(const std::string& device_path,
                                 const siginfo_t& info);

  // Returns the full path of an external formatting program if it is
  // found in some predefined locations. Otherwise, an empty string is
  // returned.
  std::string GetFormatProgramPath(const std::string& filesystem) const;

  // Returns true if formatting a given file system is supported.
  bool IsFilesystemSupported(const std::string& filesystem) const;

  // Platform service.
  Platform* const platform_;

  brillo::ProcessReaper* process_reaper_;

  // A list of outstanding formatting processes indexed by device path.
  std::map<std::string, SandboxedProcess> format_process_;

  FormatManagerObserverInterface* observer_;

  base::WeakPtrFactory<FormatManager> weak_ptr_factory_;
};

}  // namespace cros_disks

#endif  // CROS_DISKS_FORMAT_MANAGER_H_
