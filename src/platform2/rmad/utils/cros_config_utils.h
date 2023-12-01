// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_UTILS_CROS_CONFIG_UTILS_H_
#define RMAD_UTILS_CROS_CONFIG_UTILS_H_

#include <map>
#include <string>
#include <vector>

namespace rmad {

// Rmad config and SSFC config structures defined in cros_config.
// See platform2/chromeos-config/README.md#rmad for more details.
struct SsfcComponentTypeConfig {
  std::string component_type;
  uint32_t default_value;
  std::map<std::string, uint32_t> probeable_components;
};

struct SsfcConfig {
  uint32_t mask;
  std::vector<SsfcComponentTypeConfig> component_type_configs;
};

struct RmadConfig {
  bool enabled;
  bool has_cbi;
  SsfcConfig ssfc;
};

class CrosConfigUtils {
 public:
  CrosConfigUtils() = default;
  virtual ~CrosConfigUtils() = default;

  virtual bool GetRmadConfig(RmadConfig* config) const = 0;
  virtual bool GetModelName(std::string* model_name) const = 0;
  virtual bool GetCustomLabelTag(std::string* custom_label_tag) const = 0;
  virtual bool GetSkuId(uint64_t* sku_id) const = 0;
  virtual bool GetCustomLabelTagList(
      std::vector<std::string>* custom_label_tag_list) const = 0;
  virtual bool GetSkuIdList(std::vector<uint64_t>* sku_id_list) const = 0;

  bool IsCustomLabel() const;
};

}  // namespace rmad

#endif  // RMAD_UTILS_CROS_CONFIG_UTILS_H_
