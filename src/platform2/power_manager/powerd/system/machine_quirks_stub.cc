// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include "power_manager/powerd/system/machine_quirks_stub.h"

#include <base/logging.h>
#include <base/notreached.h>

#include "power_manager/common/power_constants.h"
#include "power_manager/common/prefs.h"

namespace power_manager::system {

MachineQuirksStub::MachineQuirksStub() {
  ResetQuirks();
}

void MachineQuirksStub::Init(PrefsInterface* prefs) {
  DCHECK(prefs);
  prefs_ = prefs;
}

void MachineQuirksStub::ApplyQuirksToPrefs() {
  if (IsSuspendBlocked()) {
    prefs_->SetInt64(kDisableIdleSuspendPref, 1);
  }

  if (IsSuspendToIdle()) {
    prefs_->SetInt64(kSuspendToIdlePref, 1);
  }
}

bool MachineQuirksStub::IsSuspendToIdle() {
  return force_idle_;
}

bool MachineQuirksStub::IsSuspendBlocked() {
  return block_suspend_;
}

void MachineQuirksStub::ResetQuirks() {
  force_idle_ = false;
  block_suspend_ = false;
}

void MachineQuirksStub::SetSuspendToIdleQuirkDetected(bool value) {
  force_idle_ = value;
}

void MachineQuirksStub::SetSuspendBlockedQuirkDetected(bool value) {
  block_suspend_ = value;
}

}  // namespace power_manager::system
