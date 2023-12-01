// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DLCSERVICE_LVM_MOCK_LVMD_PROXY_WRAPPER_H_
#define DLCSERVICE_LVM_MOCK_LVMD_PROXY_WRAPPER_H_

#include "dlcservice/lvm/lvmd_proxy_wrapper.h"

#include <string>
#include <vector>

#include <gmock/gmock.h>

namespace dlcservice {

class MockLvmdProxyWrapper : public LvmdProxyWrapperInterface {
 public:
  MockLvmdProxyWrapper() = default;
  MockLvmdProxyWrapper(const MockLvmdProxyWrapper&) = delete;
  MockLvmdProxyWrapper& operator=(const MockLvmdProxyWrapper&) = delete;

  MOCK_METHOD(bool,
              CreateLogicalVolumes,
              (const std::vector<lvmd::LogicalVolumeConfiguration>&),
              (override));
  MOCK_METHOD(bool,
              RemoveLogicalVolumes,
              (const std::vector<std::string>&),
              (override));
  MOCK_METHOD(bool, ActivateLogicalVolume, (const std::string&), (override));
  MOCK_METHOD(std::string,
              GetLogicalVolumePath,
              (const std::string&),
              (override));
  MOCK_METHOD(bool,
              GetPhysicalVolume,
              (const std::string&, lvmd::PhysicalVolume*),
              (override));
};

}  // namespace dlcservice

#endif  // DLCSERVICE_LVM_MOCK_LVMD_PROXY_WRAPPER_H_
