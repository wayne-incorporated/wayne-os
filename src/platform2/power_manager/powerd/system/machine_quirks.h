// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_SYSTEM_MACHINE_QUIRKS_H_
#define POWER_MANAGER_POWERD_SYSTEM_MACHINE_QUIRKS_H_

#include <string>

#include <base/files/file_path.h>

namespace power_manager {

class PrefsInterface;

namespace system {

// Abstraction layer that allows us to mock MachineQuirks when testing.
class MachineQuirksInterface {
 public:
  virtual ~MachineQuirksInterface() = default;
  virtual void Init(PrefsInterface* prefs) = 0;
  // When a machine quirk is found, set the corresponding pref to 1
  virtual void ApplyQuirksToPrefs() = 0;
  // Checks if the machine quirk indicates that
  // the suspend should be blocked.
  virtual bool IsSuspendBlocked() = 0;
  // Checks if the machine quirk indicates that
  // the suspend should be allowed but only to
  // Idle (freeze).
  virtual bool IsSuspendToIdle() = 0;
};

// Check for machine specific quirks from the running machine.
// When broken devices are discovered in testing, they get added
// to lists in the /usr/share/power_manager directory on the device.
// This class uses those lists to make decisions.
// Some machines and configurations have broken behavior
// and certain power_manager actions must be avoided.
class MachineQuirks : public MachineQuirksInterface {
 public:
  MachineQuirks();
  MachineQuirks(const MachineQuirks&) = delete;
  MachineQuirks& operator=(const MachineQuirks&) = delete;

  ~MachineQuirks() override = default;

  void Init(PrefsInterface* prefs) override;
  // When a machine quirk is found, set the corresponding pref to 1
  void ApplyQuirksToPrefs() override;

  // Determine if the machine is blocked from suspending.
  // These workarounds are required due to certain models
  // being unable to suspend and resume properly.
  bool IsSuspendBlocked() override;

  // Determine if the machine should use suspend-to-idle
  // instead of suspending.
  // This quirk is for machines which do not return from a suspend-to-ram
  // case. They do work if the system is suspend-to-idle. (freeze)
  bool IsSuspendToIdle() override;

  // Return true if field_name is found in list_file
  bool IsQuirkMatch(std::string field_name, std::string list_file);

  // Functions used to pass in mock directories for unit tests
  void set_dmi_id_dir_for_test(const base::FilePath& dir) { dmi_id_dir_ = dir; }

 private:
  base::FilePath dmi_id_dir_;

  PrefsInterface* prefs_ = nullptr;  // non-owned
};

}  // namespace system
}  // namespace power_manager

#endif  // POWER_MANAGER_POWERD_SYSTEM_MACHINE_QUIRKS_H_
