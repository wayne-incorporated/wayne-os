// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/dark_resume.h"

#include <string>

#include "power_manager/common/power_constants.h"
#include "power_manager/common/prefs.h"
#include "power_manager/powerd/system/wakeup_source_identifier_interface.h"

#include <base/check.h>
#include <base/logging.h>

namespace power_manager::system {

void DarkResume::Init(
    PrefsInterface* prefs,
    WakeupSourceIdentifierInterface* wakeup_source_identifier) {
  DCHECK(prefs);
  DCHECK(wakeup_source_identifier);

  prefs_ = prefs;
  wakeup_source_identifier_ = wakeup_source_identifier;

  ReadDarkResumePref();
  prefs_->AddObserver(this);
}

void DarkResume::HandleSuccessfulResume(bool from_hibernate) {
  in_dark_resume_ = false;

  if (wakeup_source_identifier_->InputDeviceCausedLastWake()) {
    LOG(INFO) << "User triggered wake";
  } else {
    // Resumes from hibernate do not have a wake reason, so
    // look a lot to powerd like dark resume. Assume any resume
    // from hibernate is a user-initiated resume to avoid going
    // straight back down into suspend.
    if (from_hibernate) {
      LOG(INFO) << "Resumed from hibernate";
    } else {
      LOG(INFO) << "Wake not triggered by user";
      if (enabled_) {
        LOG(INFO) << "In dark resume";
        in_dark_resume_ = true;
      }
    }
  }
}

bool DarkResume::InDarkResume() {
  return in_dark_resume_;
}

bool DarkResume::IsEnabled() {
  return enabled_;
}

void DarkResume::ExitDarkResume() {
  if (in_dark_resume_)
    LOG(INFO) << "Transitioning from dark resume to full resume";
  in_dark_resume_ = false;
}

void DarkResume::OnPrefChanged(const std::string& pref_name) {
  if (pref_name != kDisableDarkResumePref)
    return;
  ReadDarkResumePref();
}

void DarkResume::ReadDarkResumePref() {
  bool disable = false;
  enabled_ = (!prefs_->GetBool(kDisableDarkResumePref, &disable) || !disable);
  LOG(INFO) << "Dark resume " << (enabled_ ? "enabled" : "disabled");
}

}  // namespace power_manager::system
