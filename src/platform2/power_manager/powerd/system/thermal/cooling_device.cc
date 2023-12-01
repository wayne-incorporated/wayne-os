// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/thermal/cooling_device.h"

#include <string>
#include <unordered_map>
#include <unordered_set>

#include <base/check.h>
#include <base/files/file_enumerator.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>

#include "power_manager/common/util.h"
#include "power_manager/powerd/system/thermal/device_thermal_state.h"

namespace power_manager::system {

namespace {

// File name of cooling device type in sysfs.
const char kTypeFileName[] = "type";

// File name of cooling device maximum state in sysfs.
const char kMaxStateFileName[] = "max_state";

// File name of cooling device current state in sysfs.
const char kCurStateFileName[] = "cur_state";

// Proportion of current state compare to max state to have device thermal
// state at Fair/Serious/Critical for each cooling device type. Number > 1.0
// means this cooling device won't make device reach that state.
typedef struct CoolingStateScale {
  double fair;
  double serious;
  double critical;
} CoolingStateScale;

// Fan and charger .critical = 2.0 indicates no critical state for that type.
const std::unordered_map<ThermalDeviceType, CoolingStateScale> kScale = {
    {ThermalDeviceType::kProcessorCooling,
     {.fair = 0.1, .serious = 0.5, .critical = 0.8}},
    {ThermalDeviceType::kFanCooling,
     {.fair = 0.5, .serious = 1.0, .critical = 2.0}},
    {ThermalDeviceType::kChargerCooling,
     {.fair = 0.7, .serious = 1.0, .critical = 2.0}},
    {ThermalDeviceType::kOtherCooling,
     {.fair = 0.5, .serious = 0.8, .critical = 1.0}},
};

// List of strings in |kTypeFileName| for each cooling device type.
const std::unordered_set<std::string> kProcessorTypes = {
    "Processor",
    "thermal-cpu-freq",
};
const std::unordered_set<std::string> kFanTypes = {"TFN1"};
const std::unordered_set<std::string> kChargerTypes = {"TCHG"};

}  // namespace

bool CoolingDevice::InitSysfsFile() {
  if (!base::PathExists(device_path_)) {
    LOG(ERROR) << "Nonexistent path: " << device_path_;
    return false;
  }

  base::FilePath max_state_path = device_path_.Append(kMaxStateFileName);
  int64_t max_state;
  if (!util::ReadInt64File(max_state_path, &max_state))
    return false;

  if (max_state == 0) {
    LOG(INFO) << "Ignore max_state = 0 cooling device: " << device_path_;
    return false;
  }

  base::FilePath type_path = device_path_.Append(kTypeFileName);
  std::string type;
  if (!util::ReadStringFile(type_path, &type))
    type = "Unknown";

  base::FilePath cur_state_path = device_path_.Append(kCurStateFileName);
  int64_t cur_state;
  if (!util::ReadInt64File(cur_state_path, &cur_state))
    return false;

  // DCHECK since it would be an unlikely kernel bug if this happened.
  DCHECK(cur_state <= max_state);

  max_state_ = max_state;
  polling_path_ = cur_state_path;
  if (kProcessorTypes.find(type) != kProcessorTypes.end()) {
    LOG(INFO) << "Found processor cooling device: " << device_path_;
    type_ = ThermalDeviceType::kProcessorCooling;
  } else if (kFanTypes.find(type) != kFanTypes.end()) {
    LOG(INFO) << "Found fan cooling device: " << device_path_;
    type_ = ThermalDeviceType::kFanCooling;
  } else if (kChargerTypes.find(type) != kChargerTypes.end()) {
    LOG(INFO) << "Found charger cooling device: " << device_path_;
    type_ = ThermalDeviceType::kChargerCooling;
  } else {
    LOG(INFO) << "Found other (" << type
              << ") cooling device: " << device_path_;
    type_ = ThermalDeviceType::kOtherCooling;
  }
  threshold_fair_ =
      ceil(static_cast<double>(max_state) * kScale.at(type_).fair);
  threshold_serious_ =
      ceil(static_cast<double>(max_state) * kScale.at(type_).serious);
  threshold_critical_ =
      ceil(static_cast<double>(max_state) * kScale.at(type_).critical);

  polling_file_.Init(polling_path_);
  return true;
}

DeviceThermalState CoolingDevice::CalculateThermalState(int sysfs_data) {
  if (sysfs_data < 0 || sysfs_data > max_state_) {
    LOG(ERROR) << "Invalid value: " << sysfs_data << " at " << polling_path_;
    return DeviceThermalState::kUnknown;
  }
  if (max_state_ == 0) {
    return DeviceThermalState::kUnknown;
  }
  if (sysfs_data >= threshold_critical_)
    return DeviceThermalState::kCritical;
  if (sysfs_data >= threshold_serious_)
    return DeviceThermalState::kSerious;
  if (sysfs_data >= threshold_fair_)
    return DeviceThermalState::kFair;
  return DeviceThermalState::kNominal;
}

}  // namespace power_manager::system
