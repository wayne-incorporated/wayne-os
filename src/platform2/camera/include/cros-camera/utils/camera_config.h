/* Copyright 2018 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_INCLUDE_CROS_CAMERA_UTILS_CAMERA_CONFIG_H_
#define CAMERA_INCLUDE_CROS_CAMERA_UTILS_CAMERA_CONFIG_H_

#include <memory>
#include <string>
#include <vector>

#include "cros-camera/constants.h"
#include "cros-camera/export.h"

namespace cros {

// Read config from camera configure file.
// Reference for all options from: include/cros-camera/constants.h
//
// Example usage:
//
// #include "cros-camera/utils/camera_config.h"
// std::unique_ptr<CameraConfig> camera_config =
//     CameraConfig::Create(SOME_CONFIG_PATH);
// if (!camera_config) {
//   /* Error handling */
// }
// // Or let process crash by SIGSEGV and fix Create() error. It should be json
// // syntax error.
// bool bool_val = camera_config->GetBoolean(BooleanKey, false);
// int int_val = camera_config->GetInteger(IntegerKey, 999);
// std::string string_val = camera_config->GetString(StringKey, "default");
class CROS_CAMERA_EXPORT CameraConfig {
 public:
  static std::unique_ptr<CameraConfig> Create(
      const std::string& config_path_string);

  virtual ~CameraConfig() {}

  // Return true if key present in test config.
  virtual bool HasKey(const std::string& key) const = 0;

  // Return value of |path| in config file. In case that path is not present in
  // test config or any error occurred, return default_value instead.
  virtual bool GetBoolean(const std::string& path,
                          bool default_value) const = 0;

  // Return value of |path| in config file. In case that path is not present in
  // test config or any error occurred, return default_value instead.
  virtual int GetInteger(const std::string& path, int default_value) const = 0;

  // Return value of |path| in config file. In case that path is not present in
  // test config or any error occurred, return default_value instead.
  virtual std::string GetString(const std::string& path,
                                const std::string& default_value) const = 0;

  // Return value of |path| in config file. In case that path is not present in
  // test config or any error occurred, return default_value instead.
  virtual std::vector<std::string> GetStrings(
      const std::string& path,
      const std::vector<std::string>& default_value) const = 0;
};

}  // namespace cros

#endif  // CAMERA_INCLUDE_CROS_CAMERA_UTILS_CAMERA_CONFIG_H_
