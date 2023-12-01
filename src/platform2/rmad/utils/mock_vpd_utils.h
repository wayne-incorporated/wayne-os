// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_UTILS_MOCK_VPD_UTILS_H_
#define RMAD_UTILS_MOCK_VPD_UTILS_H_

#include "rmad/utils/vpd_utils.h"

#include <map>
#include <string>
#include <vector>

#include <gmock/gmock.h>

namespace rmad {

class MockVpdUtils : public VpdUtils {
 public:
  MockVpdUtils() = default;
  ~MockVpdUtils() override = default;

  MOCK_METHOD(bool, GetSerialNumber, (std::string*), (const, override));
  MOCK_METHOD(bool, GetCustomLabelTag, (std::string*, bool), (const, override));
  MOCK_METHOD(bool, GetRegion, (std::string*), (const, override));
  MOCK_METHOD(bool,
              GetCalibbias,
              (const std::vector<std::string>&, std::vector<int>*),
              (const, override));
  MOCK_METHOD(bool,
              GetRegistrationCode,
              (std::string*, std::string*),
              (const, override));
  MOCK_METHOD(bool, GetStableDeviceSecret, (std::string*), (const, override));
  MOCK_METHOD(bool, SetSerialNumber, (const std::string&), (override));
  MOCK_METHOD(bool, SetCustomLabelTag, (const std::string&, bool), (override));
  MOCK_METHOD(bool, SetRegion, (const std::string&), (override));
  MOCK_METHOD(bool,
              SetCalibbias,
              ((const std::map<std::string, int>&)),
              (override));
  MOCK_METHOD(bool,
              SetRegistrationCode,
              (const std::string&, const std::string&),
              (override));
  MOCK_METHOD(bool, SetStableDeviceSecret, (const std::string&), (override));
  MOCK_METHOD(bool, RemoveCustomLabelTag, (), (override));
  MOCK_METHOD(bool, FlushOutRoVpdCache, (), (override));
  MOCK_METHOD(bool, FlushOutRwVpdCache, (), (override));
  MOCK_METHOD(void, ClearRoVpdCache, (), (override));
  MOCK_METHOD(void, ClearRwVpdCache, (), (override));
};

}  // namespace rmad

#endif  // RMAD_UTILS_MOCK_VPD_UTILS_H_
