// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rmad/utils/cros_config_utils_impl.h"

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <base/files/file_path.h>
#include <base/files/file_enumerator.h>
#include <base/files/file_util.h>
#include <base/json/json_reader.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/stringprintf.h>
#include <chromeos-config/libcros_config/cros_config.h>

#include "rmad/utils/json_store.h"

namespace rmad {

namespace {

// TODO(genechang): We should build the configuration ourselves to
// prevent possible changes to the configuration file in the future.
const std::string kChromeosConfigsRootPath(
    "/run/chromeos-config/private/v1/chromeos/configs");

// cros_config root path.
constexpr char kCrosRootPath[] = "/";
constexpr char kCrosModelNameKey[] = "name";

// cros_config identity path.
constexpr char kCrosIdentityPath[] = "identity";
constexpr char kCrosIdentitySkuKey[] = "sku-id";
constexpr char kCrosIdentityCustomLabelTagKey[] = "custom-label-tag";

// cros_config rmad path.
constexpr char kCrosRmadPath[] = "/rmad";
constexpr char kCrosRmadEnabledKey[] = "enabled";
constexpr char kCrosRmadHasCbiKey[] = "has-cbi";

// cros_config rmad/ssfc path.
constexpr char kCrosRmadSsfcPath[] = "/rmad/ssfc";
constexpr char kCrosRmadSsfcMaskKey[] = "mask";
constexpr char kCrosRmadSsfcComponentTypeConfigsPath[] =
    "/rmad/ssfc/component-type-configs";
constexpr char kCrosRmadSsfcComponentTypeKey[] = "component-type";
constexpr char kCrosRmadSsfcDefaultValueKey[] = "default-value";
constexpr char kCrosRmadSsfcProbeableComponentsRelPath[] =
    "probeable-components";
constexpr char kCrosRmadSsfcIdentifierKey[] = "identifier";
constexpr char kCrosRmadSsfcValueKey[] = "value";
constexpr int kMaxSsfcComponentTypeNum = 32;
constexpr int kMaxSsfcProbeableComponentNum = 1024;

constexpr char kTrueStr[] = "true";
constexpr char kUndefinedComponentType[] = "undefined_component_type";

}  // namespace

CrosConfigUtilsImpl::CrosConfigUtilsImpl()
    : configs_root_path_(kChromeosConfigsRootPath) {
  cros_config_ = std::make_unique<brillo::CrosConfig>();
}

CrosConfigUtilsImpl::CrosConfigUtilsImpl(
    const std::string& configs_root_path,
    std::unique_ptr<brillo::CrosConfigInterface> cros_config)
    : configs_root_path_(configs_root_path),
      cros_config_(std::move(cros_config)) {}

bool CrosConfigUtilsImpl::GetRmadConfig(RmadConfig* config) const {
  DCHECK(config);

  config->enabled =
      GetBooleanWithDefault(kCrosRmadPath, kCrosRmadEnabledKey, false);
  config->has_cbi =
      GetBooleanWithDefault(kCrosRmadPath, kCrosRmadHasCbiKey, false);
  config->ssfc = GetSsfc();

  return true;
}

bool CrosConfigUtilsImpl::GetModelName(std::string* model_name) const {
  DCHECK(model_name);

  return cros_config_->GetString(kCrosRootPath, kCrosModelNameKey, model_name);
}

bool CrosConfigUtilsImpl::GetSkuId(uint64_t* sku_id) const {
  DCHECK(sku_id);

  std::string sku_id_str;
  if (!cros_config_->GetString(
          std::string(kCrosRootPath) + std::string(kCrosIdentityPath),
          kCrosIdentitySkuKey, &sku_id_str)) {
    return false;
  }

  return base::StringToUint64(sku_id_str, sku_id);
}

bool CrosConfigUtilsImpl::GetCustomLabelTag(
    std::string* custom_label_tag) const {
  DCHECK(custom_label_tag);

  return cros_config_->GetString(
      std::string(kCrosRootPath) + std::string(kCrosIdentityPath),
      kCrosIdentityCustomLabelTagKey, custom_label_tag);
}

bool CrosConfigUtilsImpl::GetSkuIdList(
    std::vector<uint64_t>* sku_id_list) const {
  DCHECK(sku_id_list);

  std::vector<std::string> values;
  if (!GetMatchedItemsFromCategory(kCrosIdentityPath, kCrosIdentitySkuKey,
                                   &values)) {
    return false;
  }

  sku_id_list->clear();
  for (auto& value : values) {
    uint64_t sku_id;
    if (!base::StringToUint64(value, &sku_id)) {
      LOG(ERROR) << "Failed to convert " << value << " to uint64_t";
      return false;
    }

    sku_id_list->push_back(sku_id);
  }

  sort(sku_id_list->begin(), sku_id_list->end());
  return true;
}

bool CrosConfigUtilsImpl::GetCustomLabelTagList(
    std::vector<std::string>* custom_label_tag_list) const {
  DCHECK(custom_label_tag_list);

  std::vector<std::string> values;
  if (!GetMatchedItemsFromCategory(kCrosIdentityPath,
                                   kCrosIdentityCustomLabelTagKey, &values)) {
    return false;
  }

  custom_label_tag_list->clear();
  for (auto& value : values) {
    custom_label_tag_list->push_back(value);
  }

  sort(custom_label_tag_list->begin(), custom_label_tag_list->end());
  return true;
}

bool CrosConfigUtilsImpl::GetMatchedItemsFromCategory(
    const std::string& category,
    const std::string& key,
    std::vector<std::string>* list) const {
  DCHECK(list);

  std::string model_name;
  if (!GetModelName(&model_name)) {
    LOG(ERROR) << "Failed to get model name for comparison";
    return false;
  }

  std::vector<std::string> items;
  base::FileEnumerator directories(base::FilePath(configs_root_path_), false,
                                   base::FileEnumerator::FileType::DIRECTORIES);
  for (base::FilePath path = directories.Next(); !path.empty();
       path = directories.Next()) {
    base::FilePath model_name_path = path.Append(kCrosModelNameKey);
    std::string model_name_str;
    if (!base::ReadFileToString(model_name_path, &model_name_str)) {
      LOG(WARNING) << "Failed to read model name from "
                   << model_name_path.value();
    }
    if (model_name != model_name_str) {
      continue;
    }

    base::FilePath key_path = path.Append(category).Append(key);
    std::string key_str;
    if (!base::ReadFileToString(key_path, &key_str)) {
      LOG(WARNING) << "Failed to read key from " << key_path.value();
      continue;
    }
    items.push_back(key_str);
  }

  *list = std::move(items);
  return true;
}

std::string CrosConfigUtilsImpl::GetStringWithDefault(
    const std::string& path,
    const std::string& key,
    const std::string& default_value) const {
  std::string ret = default_value;
  cros_config_->GetString(path, key, &ret);
  return ret;
}

bool CrosConfigUtilsImpl::GetBooleanWithDefault(const std::string& path,
                                                const std::string& key,
                                                bool default_value) const {
  bool ret = default_value;
  if (std::string value_str; cros_config_->GetString(path, key, &value_str)) {
    ret = (value_str == kTrueStr);
  }
  return ret;
}

uint32_t CrosConfigUtilsImpl::GetUintWithDefault(const std::string& path,
                                                 const std::string& key,
                                                 uint32_t default_value) const {
  uint32_t ret = default_value;
  if (std::string value_str; cros_config_->GetString(path, key, &value_str)) {
    if (uint32_t value; base::StringToUint(value_str, &value)) {
      ret = value;
    }
  }
  return ret;
}

SsfcConfig CrosConfigUtilsImpl::GetSsfc() const {
  SsfcConfig ssfc;
  ssfc.mask = GetUintWithDefault(kCrosRmadSsfcPath, kCrosRmadSsfcMaskKey, 0);
  ssfc.component_type_configs = GetSsfcComponentTypeConfigs();
  // SSFC config integrity check. No component should set the bits in the mask.
  for (const auto& component_type_config : ssfc.component_type_configs) {
    for (const auto& [identifier, value] :
         component_type_config.probeable_components) {
      if (value & ssfc.mask) {
        LOG(WARNING) << "Component " << identifier << " has SSFC value "
                     << value << " which conflicts with SSFC mask "
                     << ssfc.mask;
      }
    }
  }
  return ssfc;
}

std::vector<SsfcComponentTypeConfig>
CrosConfigUtilsImpl::GetSsfcComponentTypeConfigs() const {
  std::vector<SsfcComponentTypeConfig> component_type_configs;
  for (int i = 0; i < kMaxSsfcComponentTypeNum; ++i) {
    const std::string path =
        base::StringPrintf("%s/%d", kCrosRmadSsfcComponentTypeConfigsPath, i);
    SsfcComponentTypeConfig component_type_config =
        GetSsfcComponentTypeConfig(path);
    if (component_type_config.probeable_components.size()) {
      component_type_configs.emplace_back(std::move(component_type_config));
    } else {
      break;
    }
  }
  return component_type_configs;
}

SsfcComponentTypeConfig CrosConfigUtilsImpl::GetSsfcComponentTypeConfig(
    const std::string& path) const {
  SsfcComponentTypeConfig config;
  config.component_type = GetStringWithDefault(
      path, kCrosRmadSsfcComponentTypeKey, kUndefinedComponentType);
  config.default_value =
      GetUintWithDefault(path, kCrosRmadSsfcDefaultValueKey, 0);
  config.probeable_components = GetSsfcProbeableComponents(path);
  return config;
}

std::map<std::string, uint32_t> CrosConfigUtilsImpl::GetSsfcProbeableComponents(
    const std::string& path) const {
  std::map<std::string, uint32_t> components;
  for (int i = 0; i < kMaxSsfcProbeableComponentNum; ++i) {
    const std::string component_path = base::StringPrintf(
        "%s/%s/%d", path.c_str(), kCrosRmadSsfcProbeableComponentsRelPath, i);
    std::string identifier, value_str;
    uint32_t value;
    if (cros_config_->GetString(component_path, kCrosRmadSsfcIdentifierKey,
                                &identifier) &&
        cros_config_->GetString(component_path, kCrosRmadSsfcValueKey,
                                &value_str) &&
        base::StringToUint(value_str, &value)) {
      components[identifier] = value;
    } else {
      break;
    }
  }
  return components;
}

}  // namespace rmad
