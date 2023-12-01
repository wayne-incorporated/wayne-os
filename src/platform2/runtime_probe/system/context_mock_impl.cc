// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "runtime_probe/system/context_mock_impl.h"

#include <memory>
#include <utility>

#include <dbus/shill/dbus-constants.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <shill/dbus-proxies.h>
#include <shill/dbus-proxy-mocks.h>

namespace runtime_probe {
ContextMockImpl::ContextMockImpl()
    : fake_crossystem_(std::make_unique<crossystem::fake::CrossystemFake>()) {
  CHECK(temp_dir_.CreateUniqueTempDir());
  root_dir_ = temp_dir_.GetPath();
}

ContextMockImpl::~ContextMockImpl() = default;

std::unique_ptr<org::chromium::flimflam::DeviceProxyInterface>
ContextMockImpl::CreateShillDeviceProxy(const dbus::ObjectPath& path) {
  auto device = std::make_unique<
      ::testing::NiceMock<org::chromium::flimflam::DeviceProxyMock>>();

  auto properties = mock_shill_device_properties_.at(path.value());
  ON_CALL(*device, GetProperties)
      .WillByDefault(::testing::DoAll(::testing::SetArgPointee<0>(properties),
                                      ::testing::Return(true)));

  return device;
}

void ContextMockImpl::SetShillProxies(
    const std::map<std::string, brillo::VariantDictionary>& shill_devices) {
  // Set up shill devices properties returned by the shill device proxy.
  mock_shill_device_properties_ = shill_devices;

  // Set up paths of shill devices returned by the shill manager proxy.
  std::vector<dbus::ObjectPath> device_paths;
  for (const auto& [path, properties] : shill_devices) {
    const dbus::ObjectPath device_path(path);
    device_paths.push_back(device_path);
  }
  brillo::VariantDictionary manager_props = {
      {shill::kDevicesProperty, device_paths}};
  auto shill_manager = mock_shill_manager_proxy();
  ON_CALL(*shill_manager, GetProperties)
      .WillByDefault(::testing::DoAll(
          ::testing::SetArgPointee<0>(manager_props), ::testing::Return(true)));
}

}  // namespace runtime_probe
