// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_SYSTEM_DARK_RESUME_STUB_H_
#define POWER_MANAGER_POWERD_SYSTEM_DARK_RESUME_STUB_H_

#include <base/time/time.h>
#include <base/timer/timer.h>

#include "power_manager/powerd/system/dark_resume_interface.h"

namespace power_manager::system {

// Stub implementation of DarkResumeInterface for tests.
class DarkResumeStub : public DarkResumeInterface {
 public:
  DarkResumeStub() = default;
  DarkResumeStub(const DarkResumeStub&) = delete;
  DarkResumeStub& operator=(const DarkResumeStub&) = delete;

  ~DarkResumeStub() override = default;

  void set_in_dark_resume(bool in_dark_resume) {
    in_dark_resume_ = in_dark_resume;
  }
  void set_enabled(bool enabled) { enabled_ = enabled; }

  // DarkResumeInterface implementation:
  void HandleSuccessfulResume(bool from_hibernate) override;
  bool InDarkResume() override;
  bool IsEnabled() override;
  void ExitDarkResume() override{};

 private:
  // Values to return.
  bool in_dark_resume_ = false;
  bool enabled_ = false;
};

}  // namespace power_manager::system

#endif  // POWER_MANAGER_POWERD_SYSTEM_DARK_RESUME_STUB_H_
