// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/cellular/mock_mobile_operator_mapper.h"

#include <gmock/gmock.h>

using testing::_;
using testing::Return;
using testing::ReturnRef;

namespace shill {

MockMobileOperatorMapper::MockMobileOperatorMapper(
    EventDispatcher* dispatcher, const std::string& info_owner)
    : MobileOperatorMapper(dispatcher, info_owner) {
  ON_CALL(*this, IsMobileNetworkOperatorKnown()).WillByDefault(Return(false));
  ON_CALL(*this, mccmnc()).WillByDefault(ReturnRef(empty_mccmnc_));
  ON_CALL(*this, apn_list()).WillByDefault(ReturnRef(empty_apn_list_));
  ON_CALL(*this, olp_list()).WillByDefault(ReturnRef(empty_olp_list_));
  ON_CALL(*this, operator_name())
      .WillByDefault(ReturnRef(empty_operator_name_));
  ON_CALL(*this, country()).WillByDefault(ReturnRef(empty_country_));
  ON_CALL(*this, uuid()).WillByDefault(ReturnRef(empty_uuid_));
  ON_CALL(*this, gid1()).WillByDefault(ReturnRef(empty_gid1_));
  ON_CALL(*this, RequiresRoamingOnOperator(_)).WillByDefault(Return(false));
}

MockMobileOperatorMapper::~MockMobileOperatorMapper() = default;

}  // namespace shill
