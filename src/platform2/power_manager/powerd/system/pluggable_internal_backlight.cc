// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/pluggable_internal_backlight.h"

#include <base/check.h>
#include <base/check_op.h>
#include <base/logging.h>
#include <base/strings/pattern.h>

#include "power_manager/powerd/system/backlight_observer.h"
#include "power_manager/powerd/system/internal_backlight.h"
#include "power_manager/powerd/system/udev.h"

namespace power_manager::system {

PluggableInternalBacklight::~PluggableInternalBacklight() {
  if (udev_)
    udev_->RemoveSubsystemObserver(udev_subsystem_, this);
}

void PluggableInternalBacklight::Init(UdevInterface* udev,
                                      const std::string& udev_subsystem,
                                      const base::FilePath& base_path,
                                      const std::string& pattern) {
  DCHECK(udev);
  udev_ = udev;
  udev_subsystem_ = udev_subsystem;
  base_path_ = base_path;
  pattern_ = pattern;

  udev_->AddSubsystemObserver(udev_subsystem_, this);
  UpdateDevice();
}

void PluggableInternalBacklight::AddObserver(BacklightObserver* observer) {
  DCHECK(observer);
  observers_.AddObserver(observer);
}

void PluggableInternalBacklight::RemoveObserver(BacklightObserver* observer) {
  DCHECK(observer);
  observers_.RemoveObserver(observer);
}

bool PluggableInternalBacklight::DeviceExists() const {
  return device_ != nullptr;
}

int64_t PluggableInternalBacklight::GetMaxBrightnessLevel() {
  return device_ ? device_->GetMaxBrightnessLevel() : -1;
}

int64_t PluggableInternalBacklight::GetCurrentBrightnessLevel() {
  return device_ ? device_->GetCurrentBrightnessLevel() : -1;
}

bool PluggableInternalBacklight::SetBrightnessLevel(int64_t level,
                                                    base::TimeDelta interval) {
  return device_ ? device_->SetBrightnessLevel(level, interval) : false;
}

BacklightInterface::BrightnessScale
PluggableInternalBacklight::GetBrightnessScale() {
  return BrightnessScale::kUnknown;
}

bool PluggableInternalBacklight::TransitionInProgress() const {
  return device_ ? device_->TransitionInProgress() : false;
}

void PluggableInternalBacklight::UpdateDevice() {
  device_ = std::make_unique<InternalBacklight>();
  if (!device_->Init(base_path_, pattern_)) {
    LOG(INFO) << "No backlight found under " << base_path_.value()
              << " matching pattern " << pattern_;
    device_.reset();
  } else {
    LOG(INFO) << "Found backlight at " << device_->device_path().value();
  }
  for (BacklightObserver& observer : observers_)
    observer.OnBacklightDeviceChanged(this);
}

void PluggableInternalBacklight::OnUdevEvent(const UdevEvent& event) {
  DCHECK_EQ(event.device_info.subsystem, udev_subsystem_);
  if ((event.action == UdevEvent::Action::ADD ||
       event.action == UdevEvent::Action::REMOVE) &&
      base::MatchPattern(event.device_info.sysname, pattern_)) {
    LOG(INFO) << "Got udev "
              << (event.action == UdevEvent::Action::ADD ? "add" : "remove")
              << " event for " << event.device_info.sysname << " on subsystem "
              << event.device_info.subsystem;
    UpdateDevice();
  }
}

}  // namespace power_manager::system
