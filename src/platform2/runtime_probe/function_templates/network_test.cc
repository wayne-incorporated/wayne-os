// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <map>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <base/containers/span.h>
#include <base/files/file_path.h>
#include <base/strings/stringprintf.h>
#include <brillo/variant_dictionary.h>
#include <dbus/shill/dbus-constants.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "runtime_probe/function_templates/network.h"
#include "runtime_probe/utils/function_test_utils.h"
#include "shill/dbus-constants.h"

namespace runtime_probe {
namespace {

using ::testing::_;
using ::testing::Eq;
using ::testing::Pointee;
using ::testing::Return;

class MockNetworkFunction : public NetworkFunction {
  using NetworkFunction::NetworkFunction;

 public:
  NAME_PROBE_FUNCTION("mock_network");

  MOCK_METHOD(std::optional<std::string>,
              GetNetworkType,
              (),
              (const, override));
};

class NetworkFunctionTest : public BaseFunctionTest {
 protected:
  void SetNetworkDevice(const std::string& dev_name,
                        const std::string& network_type) {
    const std::string bus_dev =
        "/sys/devices/pci0000:00/0000:00:08.1" + dev_name;
    const std::string bus_dev_relative_to_sys = "../../../";
    SetSymbolicLink(bus_dev, {"/sys/class/net", dev_name, "device"});
    // The symbolic link is for getting the bus type.
    SetSymbolicLink({bus_dev_relative_to_sys, "bus", "pci"},
                    {bus_dev, "subsystem"});
    SetFile({bus_dev, "device"}, "0x1111");
    SetFile({bus_dev, "vendor"}, "0x2222");

    shill_devices_["/dev/" + dev_name] = {{shill::kInterfaceProperty, dev_name},
                                          {shill::kTypeProperty, network_type}};
    mock_context()->SetShillProxies(shill_devices_);
  }

  std::map<std::string, brillo::VariantDictionary> shill_devices_;
};

TEST_F(NetworkFunctionTest, ProbeNetwork) {
  SetNetworkDevice("wlan0", shill::kTypeWifi);
  auto probe_function = CreateProbeFunction<NetworkFunction>();

  auto result = probe_function->Eval();
  EXPECT_EQ(result.size(), 1);
  EXPECT_TRUE(result[0].GetDict().FindString("path"));
  EXPECT_TRUE(result[0].GetDict().FindString("bus_type"));
}

TEST_F(NetworkFunctionTest, ProbeNetworkByType) {
  SetNetworkDevice("wlan0", shill::kTypeWifi);
  SetNetworkDevice("eth0", shill::kTypeEthernet);
  SetNetworkDevice("wwan0", shill::kTypeCellular);
  const std::set<std::string> expected_types{
      shill::kTypeWifi, shill::kTypeEthernet, shill::kTypeCellular};

  // Probe all.
  {
    auto probe_function = CreateProbeFunction<NetworkFunction>();
    auto result = probe_function->Eval();
    std::set<std::string> result_types;
    for (const auto& each_result : result) {
      auto* type = each_result.GetDict().FindString("type");
      if (type) {
        result_types.insert(*type);
      }
    }
    EXPECT_EQ(result_types, expected_types);
  }
  // Filter by each type.
  for (const auto& expected_type : expected_types) {
    base::Value::Dict arg;
    arg.Set("device_type", expected_type);
    auto probe_function = CreateProbeFunction<NetworkFunction>(arg);
    auto result = probe_function->Eval();
    EXPECT_EQ(result.size(), 1);
    EXPECT_THAT(result[0].GetDict().FindString("type"),
                Pointee(Eq(expected_type)));
  }

  // TODO(b/269822306): The below two do the same thing as the above, but use
  // the old interface to pass the type. Remove this after we done the
  // migration.
  // Probe all.
  {
    auto probe_function = CreateProbeFunction<MockNetworkFunction>();
    EXPECT_CALL(*probe_function, GetNetworkType())
        .WillOnce(Return(std::nullopt));
    auto result = probe_function->Eval();
    std::set<std::string> result_types;
    for (const auto& each_result : result) {
      auto* type = each_result.GetDict().FindString("type");
      if (type) {
        result_types.insert(*type);
      }
    }
    EXPECT_EQ(result_types, expected_types);
  }
  // Filter by each type.
  for (const auto& expected_type : expected_types) {
    auto probe_function = CreateProbeFunction<MockNetworkFunction>();
    EXPECT_CALL(*probe_function, GetNetworkType())
        .WillOnce(Return(expected_type));
    auto result = probe_function->Eval();
    EXPECT_EQ(result.size(), 1);
    EXPECT_THAT(result[0].GetDict().FindString("type"),
                Pointee(Eq(expected_type)));
  }
}

TEST_F(NetworkFunctionTest, CreateNetworkFunctionFailed) {
  base::Value::Dict arg;
  arg.Set("device_type", "unknown_type");
  auto probe_function = CreateProbeFunction<NetworkFunction>(arg);
  EXPECT_FALSE(probe_function);
}

}  // namespace
}  // namespace runtime_probe
