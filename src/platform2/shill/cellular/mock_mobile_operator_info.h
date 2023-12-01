// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_CELLULAR_MOCK_MOBILE_OPERATOR_INFO_H_
#define SHILL_CELLULAR_MOCK_MOBILE_OPERATOR_INFO_H_

#include <memory>
#include <string>
#include <vector>

#include <gmock/gmock.h>

#include "shill/cellular/mobile_operator_info.h"
#include "shill/cellular/mobile_operator_mapper.h"

namespace shill {

class MockMobileOperatorInfo : public MobileOperatorInfo {
 public:
  MockMobileOperatorInfo(EventDispatcher* dispatcher,
                         const std::string& info_owner);
  ~MockMobileOperatorInfo() override;

  MOCK_METHOD(bool, IsMobileNetworkOperatorKnown, (), (const, override));
  MOCK_METHOD(bool, IsServingMobileNetworkOperatorKnown, (), (const, override));

  MOCK_METHOD(const std::string&, mccmnc, (), (const, override));
  MOCK_METHOD(const std::vector<MobileOperatorMapper::MobileAPN>&,
              apn_list,
              (),
              (const, override));
  MOCK_METHOD(const std::vector<MobileOperatorMapper::OnlinePortal>&,
              olp_list,
              (),
              (const, override));
  MOCK_METHOD(const std::string&, operator_name, (), (const, override));
  MOCK_METHOD(const std::string&, country, (), (const, override));
  MOCK_METHOD(const std::string&, uuid, (), (const, override));
  MOCK_METHOD(const std::string&, serving_mccmnc, (), (const, override));
  MOCK_METHOD(const std::string&, serving_operator_name, (), (const, override));
  MOCK_METHOD(const std::string&, serving_country, (), (const, override));
  MOCK_METHOD(const std::string&, serving_uuid, (), (const, override));

  MOCK_METHOD(std::string, friendly_operator_name, (bool), (const, override));
  MOCK_METHOD(void, UpdateMCCMNC, (const std::string&), (override));
  MOCK_METHOD(void, UpdateIMSI, (const std::string&), (override));
  MOCK_METHOD(void, UpdateOperatorName, (const std::string&), (override));
  MOCK_METHOD(void, UpdateServingMCCMNC, (const std::string&), (override));
  MOCK_METHOD(void,
              UpdateServingOperatorName,
              (const std::string&),
              (override));

 private:
  std::string empty_mccmnc_;
  std::vector<MobileOperatorMapper::MobileAPN> empty_apn_list_;
  std::vector<MobileOperatorMapper::OnlinePortal> empty_olp_list_;
  std::string empty_operator_name_;
  std::string empty_country_;
  std::string empty_uuid_;
  std::string empty_serving_country_;
  std::string empty_serving_mccmnc_;
  std::string empty_serving_operator_name_;
  std::string empty_serving_uuid_;
};

}  // namespace shill

#endif  // SHILL_CELLULAR_MOCK_MOBILE_OPERATOR_INFO_H_
