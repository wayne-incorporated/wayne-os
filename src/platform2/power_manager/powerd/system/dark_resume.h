// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_SYSTEM_DARK_RESUME_H_
#define POWER_MANAGER_POWERD_SYSTEM_DARK_RESUME_H_

#include <string>

#include "power_manager/common/prefs_observer.h"
#include "power_manager/powerd/system/dark_resume_interface.h"

namespace power_manager {

class PrefsInterface;

namespace system {

class WakeupSourceIdentifierInterface;

// Newer implementation of dark resume. Uses per device (peripheral) wakeup
// count to identify the wake source.
class DarkResume : public DarkResumeInterface, public PrefsObserver {
 public:
  DarkResume() = default;
  DarkResume(const DarkResume&) = delete;
  DarkResume& operator=(const DarkResume&) = delete;

  ~DarkResume() override = default;

  // Reads preferences on whether dark resume is enabled.
  void Init(PrefsInterface* prefs,
            WakeupSourceIdentifierInterface* wakeup_source_identifier);

  // DarkResumeInterface implementation:
  void HandleSuccessfulResume(bool from_hibernate) override;
  bool InDarkResume() override;
  bool IsEnabled() override;
  void ExitDarkResume() override;

  // PrefsInterface::Observer implementation:
  void OnPrefChanged(const std::string& pref_name) override;

 private:
  void ReadDarkResumePref();

  // Are we currently in dark resume?
  bool in_dark_resume_ = false;

  // Is dark resume enabled?
  bool enabled_ = false;

  PrefsInterface* prefs_;  // weak

  WakeupSourceIdentifierInterface* wakeup_source_identifier_;  // weak
};

}  // namespace system
}  // namespace power_manager

#endif  // POWER_MANAGER_POWERD_SYSTEM_DARK_RESUME_H_
