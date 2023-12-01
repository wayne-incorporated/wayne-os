// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/cellular/mock_mobile_operator_info.h"

#include <gmock/gmock.h>

using testing::Return;
using testing::ReturnRef;

namespace shill {

MockMobileOperatorInfo::MockMobileOperatorInfo(EventDispatcher* dispatcher,
                                               const std::string& info_owner)
    : MobileOperatorInfo(dispatcher, info_owner) {
  ON_CALL(*this, IsMobileNetworkOperatorKnown()).WillByDefault(Return(false));
  ON_CALL(*this, mccmnc()).WillByDefault(ReturnRef(empty_mccmnc_));
  ON_CALL(*this, apn_list()).WillByDefault(ReturnRef(empty_apn_list_));
  ON_CALL(*this, olp_list()).WillByDefault(ReturnRef(empty_olp_list_));
  ON_CALL(*this, operator_name())
      .WillByDefault(ReturnRef(empty_operator_name_));
  ON_CALL(*this, country()).WillByDefault(ReturnRef(empty_country_));
  ON_CALL(*this, uuid()).WillByDefault(ReturnRef(empty_uuid_));
  ON_CALL(*this, serving_country())
      .WillByDefault(ReturnRef(empty_serving_country_));
  ON_CALL(*this, serving_mccmnc())
      .WillByDefault(ReturnRef(empty_serving_mccmnc_));
  ON_CALL(*this, serving_operator_name())
      .WillByDefault(ReturnRef(empty_serving_operator_name_));
  ON_CALL(*this, serving_uuid()).WillByDefault(ReturnRef(empty_serving_uuid_));
}

MockMobileOperatorInfo::~MockMobileOperatorInfo() = default;

}  // namespace shill
