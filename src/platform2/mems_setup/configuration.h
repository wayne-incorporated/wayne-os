// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MEMS_SETUP_CONFIGURATION_H_
#define MEMS_SETUP_CONFIGURATION_H_

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/values.h>

#include <libmems/iio_device.h>
#include "mems_setup/delegate.h"
#include "mems_setup/sensor_kind.h"

namespace mems_setup {

class Configuration {
 public:
  Configuration(libmems::IioContext* context,
                libmems::IioDevice* sensor,
                Delegate* delegate);
  Configuration(const Configuration&) = delete;
  Configuration& operator=(const Configuration&) = delete;

  bool Configure();

  const char* GetGroupNameForSysfs();

 private:
  bool ConfigureOnKind();

  bool ConfigGyro();
  bool ConfigAccelerometer();
  bool ConfigIlluminance();
  bool ConfigProximity();

  bool IsIioActivitySensor(const std::string& sys_path);

  bool GetDevlinks(const std::string& syspath, std::vector<std::string>* out);

  bool SetIioRisingFallingValue(const base::Value::Dict& config_dict,
                                const std::string& config_postfix,
                                const std::string& path_prefix,
                                const std::string& postfix);

  bool CopyImuCalibationFromVpd(int max_value);
  bool CopyImuCalibationFromVpd(int max_value, const std::string& location);

  bool CopyLightCalibrationFromVpd();

  bool AddSysfsTrigger(int sysfs_trigger_id);

  bool EnableAccelScanElements();

  bool EnableBuffer();

  bool EnableKeyboardAngle();

  bool EnableCalibration(bool enable);

  bool SetupPermissions();
  bool SetReadPermissionAndOwnership(base::FilePath file_path);
  bool SetWritePermissionAndOwnership(base::FilePath file_path);

  Delegate* delegate_;  // non-owned
  SensorKind kind_;
  libmems::IioDevice* sensor_;    // non-owned
  libmems::IioContext* context_;  // non-owned

  std::optional<gid_t> iioservice_gid_ = std::nullopt;
};

}  // namespace mems_setup

#endif  // MEMS_SETUP_CONFIGURATION_H_
