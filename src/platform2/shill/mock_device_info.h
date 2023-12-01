// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_MOCK_DEVICE_INFO_H_
#define SHILL_MOCK_DEVICE_INFO_H_

#include <string>
#include <vector>

#include <gmock/gmock.h>

#include "shill/device.h"
#include "shill/device_info.h"

namespace shill {

class ByteString;
class IPAddress;
class Manager;

class MockDeviceInfo : public DeviceInfo {
 public:
  explicit MockDeviceInfo(Manager* manager);
  MockDeviceInfo(const MockDeviceInfo&) = delete;
  MockDeviceInfo& operator=(const MockDeviceInfo&) = delete;

  ~MockDeviceInfo() override;

  MOCK_METHOD(bool, IsDeviceBlocked, (const std::string&), (override));
  MOCK_METHOD(void, BlockDevice, (const std::string&), (override));
  MOCK_METHOD(void, AllowDevice, (const std::string&), (override));
  MOCK_METHOD(DeviceRefPtr, GetDevice, (int), (const, override));
  MOCK_METHOD(int, GetIndex, (const std::string&), (const, override));
  MOCK_METHOD(bool, GetMacAddress, (int, ByteString*), (const, override));
  MOCK_METHOD(ByteString, GetMacAddressFromKernel, (int), (const, override));
  MOCK_METHOD(bool,
              GetByteCounts,
              (int, uint64_t*, uint64_t*),
              (const, override));
  MOCK_METHOD(bool, GetFlags, (int, unsigned int*), (const, override));
  MOCK_METHOD(bool, CreateTunnelInterface, (LinkReadyCallback), (override));

  MOCK_METHOD(bool,
              CreateWireGuardInterface,
              (const std::string&, LinkReadyCallback, base::OnceClosure),
              (override));
  MOCK_METHOD(
      bool,
      CreateXFRMInterface,
      (const std::string&, int, int, LinkReadyCallback, base::OnceClosure),
      (override));
  MOCK_METHOD(VirtualDevice*,
              CreatePPPDevice,
              (Manager*, const std::string&, int),
              (override));
  MOCK_METHOD(void,
              AddVirtualInterfaceReadyCallback,
              (const std::string&, LinkReadyCallback),
              (override));
  MOCK_METHOD(int,
              OpenTunnelInterface,
              (const std::string&),
              (const, override));
  MOCK_METHOD(bool, DeleteInterface, (int), (const, override));
  MOCK_METHOD(void, RegisterDevice, (const DeviceRefPtr&), (override));
};

}  // namespace shill

#endif  // SHILL_MOCK_DEVICE_INFO_H_
