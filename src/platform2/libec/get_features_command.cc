// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libec/get_features_command.h"

namespace ec {

GetFeaturesCommand::GetFeaturesCommand() : EcCommand(EC_CMD_GET_FEATURES) {}

bool GetFeaturesCommand::IsFeatureSupported(enum ec_feature_code code) const {
  if (code < 32 && (EC_FEATURE_MASK_0(code) & Resp()->flags[0])) {
    return true;
  }
  if (code >= 32 && (EC_FEATURE_MASK_1(code) & Resp()->flags[1])) {
    return true;
  }
  return false;
}

}  // namespace ec
