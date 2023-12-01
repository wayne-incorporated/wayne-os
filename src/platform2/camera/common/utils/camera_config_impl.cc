/* Copyright 2018 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <iomanip>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/json/json_reader.h>
#include <base/values.h>

#include "common/utils/camera_config_impl.h"
#include "cros-camera/common.h"

namespace cros {

// static
std::unique_ptr<CameraConfig> CameraConfig::Create(
    const std::string& config_path_string) {
  const base::FilePath config_path(config_path_string);

  if (!base::PathExists(config_path)) {
    // If there is no config file it means that all are default values.
    return base::WrapUnique(new CameraConfigImpl(base::Value::Dict()));
  }

  std::string content;
  if (!base::ReadFileToString(config_path, &content)) {
    LOGF(ERROR) << "Failed to read camera configuration file:"
                << config_path_string;
    return nullptr;
  }

  auto result = base::JSONReader::ReadAndReturnValueWithError(content, 0);
  if (!result.has_value()) {
    LOGF(ERROR) << "Invalid JSON format of camera configuration file:"
                << result.error().message;
    return nullptr;
  }

  if (!result->is_dict()) {
    LOGF(ERROR) << "value of JSON result is not a dictionary";
    return nullptr;
  }

  return base::WrapUnique(new CameraConfigImpl(std::move(result->GetDict())));
}

CameraConfigImpl::CameraConfigImpl(base::Value::Dict config) {
  config_ = std::move(config);
}

CameraConfigImpl::~CameraConfigImpl() {}

bool CameraConfigImpl::HasKey(const std::string& key) const {
  return config_.Find(key) != nullptr;
}

bool CameraConfigImpl::GetBoolean(const std::string& path,
                                  bool default_value) const {
  return config_.FindBoolByDottedPath(path).value_or(default_value);
}

int CameraConfigImpl::GetInteger(const std::string& path,
                                 int default_value) const {
  return config_.FindIntByDottedPath(path).value_or(default_value);
}

std::string CameraConfigImpl::GetString(
    const std::string& path, const std::string& default_value) const {
  const std::string* result = config_.FindStringByDottedPath(path);
  return (result != nullptr) ? *result : default_value;
}

std::vector<std::string> CameraConfigImpl::GetStrings(
    const std::string& path,
    const std::vector<std::string>& default_value) const {
  const base::Value::List* values = config_.FindListByDottedPath(path);
  if (values == nullptr)
    return default_value;

  std::vector<std::string> result;
  for (const auto& s : *values) {
    CHECK(s.is_string());
    result.push_back(s.GetString());
  }

  return result;
}

}  // namespace cros
