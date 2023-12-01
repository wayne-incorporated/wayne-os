// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_SYSTEM_DARK_RESUME_INTERFACE_H_
#define POWER_MANAGER_POWERD_SYSTEM_DARK_RESUME_INTERFACE_H_

namespace base {
class TimeDelta;
}  // namespace base

namespace power_manager::system {

// Returns information related to "dark resume", a mode where the system wakes
// without user interaction to display notifications, or to show alarms.
class DarkResumeInterface {
 public:
  DarkResumeInterface() = default;
  virtual ~DarkResumeInterface() = default;

  // Reads the system state to see if it's in a dark resume.
  virtual void HandleSuccessfulResume(bool from_hibernate) = 0;

  // Returns true if the system is currently in dark resume.
  virtual bool InDarkResume() = 0;

  // Returns true if dark resume is enabled on the system.
  virtual bool IsEnabled() = 0;

  // Exits dark resume so that the system can transition to fully resumed.
  virtual void ExitDarkResume() = 0;
};

}  // namespace power_manager::system

#endif  // POWER_MANAGER_POWERD_SYSTEM_DARK_RESUME_INTERFACE_H_
