// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_UTILS_CROS_CONFIG_UTILS_IMPL_H_
#define RMAD_UTILS_CROS_CONFIG_UTILS_IMPL_H_

#include "rmad/utils/cros_config_utils.h"

#include <map>
#include <memory>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/values.h>
#include <chromeos-config/libcros_config/cros_config_interface.h>

namespace rmad {

class CrosConfigUtilsImpl : public CrosConfigUtils {
 public:
  CrosConfigUtilsImpl();
  explicit CrosConfigUtilsImpl(
      const std::string& configs_root_path,
      std::unique_ptr<brillo::CrosConfigInterface> cros_config);
  ~CrosConfigUtilsImpl() override = default;

  bool GetRmadConfig(RmadConfig* config) const override;
  bool GetModelName(std::string* model_name) const override;
  bool GetSkuId(uint64_t* sku) const override;
  bool GetCustomLabelTag(std::string* custom_label_tag) const override;
  bool GetSkuIdList(std::vector<uint64_t>* sku_list) const override;
  bool GetCustomLabelTagList(
      std::vector<std::string>* custom_label_tag_list) const override;

 private:
  bool GetMatchedItemsFromCategory(const std::string& category,
                                   const std::string& key,
                                   std::vector<std::string>* list) const;
  std::string GetStringWithDefault(const std::string& path,
                                   const std::string& key,
                                   const std::string& default_value) const;
  bool GetBooleanWithDefault(const std::string& path,
                             const std::string& key,
                             bool default_value) const;
  uint32_t GetUintWithDefault(const std::string& path,
                              const std::string& key,
                              uint32_t default_value) const;

  SsfcConfig GetSsfc() const;
  std::vector<SsfcComponentTypeConfig> GetSsfcComponentTypeConfigs() const;
  SsfcComponentTypeConfig GetSsfcComponentTypeConfig(
      const std::string& path) const;
  std::map<std::string, uint32_t> GetSsfcProbeableComponents(
      const std::string& path) const;

  std::string configs_root_path_;
  std::unique_ptr<brillo::CrosConfigInterface> cros_config_;
};

}  // namespace rmad

#endif  // RMAD_UTILS_CROS_CONFIG_UTILS_IMPL_H_
