// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gtest/gtest.h>

#include "debugd/src/helpers/typec_connector_class_helper_utils.h"

using debugd::typec_connector_class_helper::kPD20IDHeaderVDO;
using debugd::typec_connector_class_helper::kPD20ProductVDO;
using debugd::typec_connector_class_helper::kPD30IDHeaderVDO;
using debugd::typec_connector_class_helper::kPD30ProductVDO;
using debugd::typec_connector_class_helper::kPD31IDHeaderVDO;
using debugd::typec_connector_class_helper::kPD31ProductVDO;
using debugd::typec_connector_class_helper::VdoField;

// Check that ID Header VDOs will not masks bits 0-15.
TEST(TypecConnectorClassHelperTest, CheckIDHeaderMask) {
  std::vector<std::vector<VdoField>> id_header_vdos = {
      kPD20IDHeaderVDO,
      kPD30IDHeaderVDO,
      kPD31IDHeaderVDO,
  };

  for (auto id_header : id_header_vdos) {
    for (auto field : id_header)
      ASSERT_FALSE(field.mask & 0xffff);
  }
}

// Check that Product VDOs will not masks the bits 16-31.
TEST(TypecConnectorClassHelperTest, CheckProductMask) {
  std::vector<std::vector<VdoField>> product_vdos = {
      kPD20ProductVDO,
      kPD30ProductVDO,
      kPD31ProductVDO,
  };

  for (auto product : product_vdos) {
    for (auto field : product)
      ASSERT_FALSE(field.mask & 0xffff0000);
  }
}
