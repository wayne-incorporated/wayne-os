// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rmad/utils/cros_config_utils.h"

#include <string>
#include <vector>

namespace rmad {

bool CrosConfigUtils::IsCustomLabel() const {
  std::vector<std::string> custom_label_tag_list;
  return GetCustomLabelTagList(&custom_label_tag_list) &&
         !custom_label_tag_list.empty();
}

}  // namespace rmad
