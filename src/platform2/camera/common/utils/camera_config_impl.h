/* Copyright 2018 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_COMMON_UTILS_CAMERA_CONFIG_IMPL_H_
#define CAMERA_COMMON_UTILS_CAMERA_CONFIG_IMPL_H_

#include <memory>
#include <string>
#include <vector>

#include <base/values.h>
#include <base/memory/ptr_util.h>

#include "cros-camera/utils/camera_config.h"

namespace cros {

// Read config from camera configure file.
// Reference for all options from: include/cros-camera/constants.h
class CameraConfigImpl : public CameraConfig {
 public:
  ~CameraConfigImpl() override;

  bool HasKey(const std::string& key) const override;

  bool GetBoolean(const std::string& path, bool default_value) const override;

  int GetInteger(const std::string& path, int default_value) const override;

  std::string GetString(const std::string& path,
                        const std::string& default_value) const override;

  std::vector<std::string> GetStrings(
      const std::string& path,
      const std::vector<std::string>& default_value) const override;

 private:
  explicit CameraConfigImpl(base::Value::Dict config);
  friend std::unique_ptr<CameraConfig> CameraConfig::Create(
      const std::string& config_path_string);

  base::Value::Dict config_;
};

}  // namespace cros

#endif  // CAMERA_COMMON_UTILS_CAMERA_CONFIG_IMPL_H_
