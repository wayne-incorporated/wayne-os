// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/wakeup_device.h"

#include <string>
#include <utility>

#include <base/check.h>
#include <base/files/file_enumerator.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_util.h>
#include <base/strings/string_number_conversions.h>

#include "power_manager/common/power_constants.h"

namespace {

// Regex that looks for wakeupN directory under |kWakeupDir| of a given
// device.
char kWakeupSysDirPattern[] = "wakeup*";

}  // namespace

namespace power_manager::system {

// static
std::unique_ptr<WakeupDeviceInterface> WakeupDevice::CreateWakeupDevice(
    const base::FilePath& path) {
  const base::FilePath wakeup_path = path.Append(kPowerWakeup);
  if (!base::PathExists(wakeup_path)) {
    // This can happen when the device is not wake capable.
    return nullptr;
  }
  return std::unique_ptr<WakeupDevice>(new WakeupDevice(path));
}

// static
const char WakeupDevice::kWakeupDir[] = "wakeup";
const char WakeupDevice::kPowerEventCountPath[] = "event_count";

WakeupDevice::WakeupDevice(const base::FilePath& path) : sys_path_(path) {}

void WakeupDevice::PrepareForSuspend() {
  // This can happen when the device is no more a wake source (if power/wakeup
  // is disabled).
  was_pre_suspend_read_successful_ =
      ReadEventCount(&event_count_before_suspend_);
}

void WakeupDevice::HandleResume() {
  caused_last_wake_ = false;
  if (!was_pre_suspend_read_successful_) {
    return;
  }

  uint64_t event_count_after_resume = 0;

  // This can happen when the device is no more a wake source (if power/wakeup
  // is disabled).
  if (!ReadEventCount(&event_count_after_resume))
    return;

  if (event_count_after_resume != event_count_before_suspend_) {
    LOG(INFO) << "Device " << sys_path_.value() << " had event_count "
              << event_count_before_suspend_ << " before suspend and "
              << event_count_after_resume << " after resume";
    caused_last_wake_ = true;
  }
}

bool WakeupDevice::CausedLastWake() const {
  return caused_last_wake_;
}

bool WakeupDevice::ReadEventCount(uint64_t* event_count_out) {
  DCHECK(event_count_out);
  std::string event_count_str;

  auto wakeup_dir = sys_path_.Append(kWakeupDir);
  // For power_supply devices, 'wakeup*' is directly below device's root dir.
  if (sys_path_.value().find("/power_supply/") != std::string::npos)
    wakeup_dir = sys_path_;

  // event_count lies under wakeup/wakeupN directory. Thus look for wakeupN
  // directory under |wakeup_dir|.
  base::FileEnumerator events_count_dir(
      wakeup_dir, /*recursive=*/false,
      base::FileEnumerator::DIRECTORIES | base::FileEnumerator::SHOW_SYM_LINKS,
      kWakeupSysDirPattern);

  auto events_count_dir_path = events_count_dir.Next();
  // This can happen if the device is not wake capable anymore.
  if (events_count_dir_path.empty())
    return false;

  if (!events_count_dir.Next().empty()) {
    LOG(ERROR) << "More than one wakeupN dir found in " << wakeup_dir.value();
    return false;
  }

  const base::FilePath event_count_path =
      events_count_dir_path.Append(kPowerEventCountPath);

  // This can happen if the device is not wake enabled anymore.
  if (!base::PathExists(event_count_path))
    return false;

  if (!base::ReadFileToString(event_count_path, &event_count_str)) {
    PLOG(ERROR) << "Unable to read event count for " << sys_path_.value();
    return false;
  }

  // Some drivers leave the event_count empty initially.
  if (event_count_str.empty()) {
    *event_count_out = 0;
    return true;
  }
  base::TrimWhitespaceASCII(event_count_str, base::TRIM_TRAILING,
                            &event_count_str);
  if (base::StringToUint64(event_count_str, event_count_out))
    return true;

  LOG(ERROR) << "Could not parse event_count sysattr for " << sys_path_.value();
  return false;
}

}  // namespace power_manager::system
