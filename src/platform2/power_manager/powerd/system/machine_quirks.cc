// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/machine_quirks.h"

#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/pattern.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>

#include "power_manager/common/power_constants.h"
#include "power_manager/common/prefs.h"
#include "power_manager/common/util.h"

namespace power_manager::system {

namespace {
// Default DMI ID directory
const base::FilePath kDefaultDmiIdDir("/sys/class/dmi/id/");

// Name of product name file for special suspend workarounds.
const base::FilePath kDefaultProductNameFile("product_name");

// File containing the product names that require suspend-to-idle.
const base::FilePath kPowerManagerSuspendToIdleFile("suspend_to_idle_models");

// File containing the product names that require suspend blocking.
const base::FilePath kPowerManagerSuspendPreventionFile(
    "suspend_prevention_models");
}  // namespace

MachineQuirks::MachineQuirks() : dmi_id_dir_(kDefaultDmiIdDir) {}

void MachineQuirks::Init(PrefsInterface* prefs) {
  DCHECK(prefs);
  prefs_ = prefs;
}

void MachineQuirks::ApplyQuirksToPrefs() {
  DCHECK(prefs_) << "MachineQuirks::Init() wasn't called";
  bool machine_quirks_enabled = false;
  prefs_->GetBool(kHasMachineQuirksPref, &machine_quirks_enabled);
  if (!machine_quirks_enabled) {
    return;
  }

  if (IsSuspendBlocked()) {
    prefs_->SetInt64(kDisableIdleSuspendPref, 1);
    LOG(INFO) << "Disable Idle Suspend Pref set to enabled";
  }

  if (IsSuspendToIdle()) {
    prefs_->SetInt64(kSuspendToIdlePref, 1);
    LOG(INFO) << "Suspend to Idle Pref set to enabled";
  }
}

bool MachineQuirks::IsSuspendBlocked() {
  DCHECK(prefs_) << "MachineQuirks::Init() wasn't called";

  std::string suspend_prevention_list;
  // Read suspend prevention list from pref.
  if (!prefs_->GetString(kSuspendPreventionListPref, &suspend_prevention_list))
    return false;

  std::string product_name;
  // If the product name is unavailable do not block.
  base::FilePath product_name_file =
      base::FilePath(dmi_id_dir_.Append(kDefaultProductNameFile));
  if (!util::ReadStringFile(product_name_file, &product_name))
    return false;

  if (IsQuirkMatch(product_name, suspend_prevention_list)) {
    LOG(INFO) << "Product name " << product_name
              << " is in power_manager's suspend-prevention list.";
    return true;
  }

  // Do not interfere.
  return false;
}

bool MachineQuirks::IsSuspendToIdle() {
  CHECK(prefs_) << "MachineQuirks::Init() wasn't called";

  std::string suspend_to_idle_list;
  // Read suspend prevention list from pref.
  if (!prefs_->GetString(kSuspendToIdleListPref, &suspend_to_idle_list))
    return false;

  std::string product_name;
  // If the product name is unreadable, assume no.
  base::FilePath product_name_file =
      base::FilePath(dmi_id_dir_.Append(kDefaultProductNameFile));
  if (!util::ReadStringFile(product_name_file, &product_name))
    return false;

  if (IsQuirkMatch(product_name, suspend_to_idle_list)) {
    LOG(INFO) << "Product name " << product_name
              << " is in power_manager's suspend-to-idle list.";
    return true;
  }

  // Normal case, no quirk is required.
  return false;
}

bool MachineQuirks::IsQuirkMatch(std::string field_name,
                                 std::string list_file) {
  // The file should be a list of product names and product versions
  // separated by '\n'. One line for each machine that should
  // be skipped.
  base::TrimWhitespaceASCII(field_name, base::TRIM_ALL, &field_name);
  for (const auto& quirk_indice : base::SplitString(
           list_file, "\n", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY)) {
    if (base::MatchPattern(field_name, quirk_indice)) {
      // Force suspend-to-idle for matching hardware.
      return true;
    }
  }
  return false;
}

}  // namespace power_manager::system
