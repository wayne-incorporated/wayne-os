// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_CELLULAR_MOCK_MOBILE_OPERATOR_MAPPER_H_
#define SHILL_CELLULAR_MOCK_MOBILE_OPERATOR_MAPPER_H_

#include <memory>
#include <string>
#include <vector>

#include <gmock/gmock.h>

#include "shill/cellular/mobile_operator_mapper.h"

namespace shill {

class MockMobileOperatorMapper : public MobileOperatorMapper {
 public:
  explicit MockMobileOperatorMapper(EventDispatcher* dispatcher,
                                    const std::string& info_owner);
  MockMobileOperatorMapper(const MockMobileOperatorMapper&) = delete;
  MockMobileOperatorMapper& operator=(const MockMobileOperatorMapper&) = delete;

  ~MockMobileOperatorMapper() override;

  MOCK_METHOD(void, AddDatabasePath, (const base::FilePath&), (override));
  MOCK_METHOD(void, ClearDatabasePaths, (), (override));
  MOCK_METHOD(bool,
              Init,
              (MobileOperatorMapperOnOperatorChangedCallback),
              (override));
  MOCK_METHOD(void, Reset, (), (override));

  MOCK_METHOD(bool, IsMobileNetworkOperatorKnown, (), (const, override));

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
  MOCK_METHOD(const std::string&, gid1, (), (const, override));
  MOCK_METHOD(bool, requires_roaming, (), (const, override));
  MOCK_METHOD(bool, tethering_allowed, (), (const, override));
  MOCK_METHOD(bool, use_dun_apn_as_default, (), (const, override));
  MOCK_METHOD(const MobileOperatorMapper::EntitlementConfig&,
              entitlement_config,
              (),
              (override));

  MOCK_METHOD(void, UpdateMCCMNC, (const std::string&), (override));
  MOCK_METHOD(void, UpdateIMSI, (const std::string&), (override));
  MOCK_METHOD(void, UpdateOperatorName, (const std::string&), (override));

  MOCK_METHOD(bool,
              RequiresRoamingOnOperator,
              (const MobileOperatorMapper*),
              (const, override));

 private:
  std::string empty_mccmnc_;
  std::vector<MobileOperatorMapper::MobileAPN> empty_apn_list_;
  std::vector<MobileOperatorMapper::OnlinePortal> empty_olp_list_;
  std::string empty_operator_name_;
  std::string empty_country_;
  std::string empty_uuid_;
  std::string empty_gid1_;
};

}  // namespace shill

#endif  // SHILL_CELLULAR_MOCK_MOBILE_OPERATOR_MAPPER_H_
