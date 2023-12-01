// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "runtime_probe/utils/bus_utils.h"
#include "runtime_probe/utils/file_test_utils.h"

namespace runtime_probe {
namespace {

using ::testing::Eq;
using ::testing::Pointee;

constexpr char kFakeSysClassDir[] = "/sys/class/fake_class";

base::Value MakeValue(std::vector<std::pair<std::string, std::string>> data) {
  return base::Value(base::Value::Dict(std::make_move_iterator(data.begin()),
                                       std::make_move_iterator(data.end())));
}

class BusUtilsTest : public BaseFileTest {
 protected:
  void SetUp() override { CreateTestRoot(); }

  // Returns the string of fake pci bus device.
  std::string SetFakePciDevice(const std::string& dev_name) {
    const std::string bus_dev = "/sys/devices/pci0000:00/0000:00:08.1";
    const std::string bus_dev_relative_to_sys = "../../../";
    SetSymbolicLink(bus_dev, {kFakeSysClassDir, dev_name, "device"});
    // The symbolic link is for getting the bus type.
    SetSymbolicLink({bus_dev_relative_to_sys, "bus", "pci"},
                    {bus_dev, "subsystem"});
    SetFile({bus_dev, "device"}, "0x1111");
    SetFile({bus_dev, "vendor"}, "0x2222");

    return bus_dev;
  }
};

TEST_F(BusUtilsTest, ProbePci) {
  const std::string dev_name = "dev_name";
  const std::string bus_dev = SetFakePciDevice(dev_name);
  SetFile({bus_dev, "device"}, "0x1111");
  SetFile({bus_dev, "vendor"}, "0x2222");
  SetFile({bus_dev, "revision"}, "0x01");
  auto ans = MakeValue({
      {"bus_type", "pci"},
      {"pci_device_id", "0x1111"},
      {"pci_vendor_id", "0x2222"},
      {"pci_revision", "0x01"},
      {"path", GetPathUnderRoot({kFakeSysClassDir, dev_name}).value()},
  });
  auto result = GetDeviceBusDataFromSysfsNode(
      GetPathUnderRoot({kFakeSysClassDir, dev_name}));
  EXPECT_EQ(result, ans);
}

TEST_F(BusUtilsTest, ProbePciRevisionOldKernel) {
  const std::string dev_name = "dev_name";
  const std::string bus_dev = SetFakePciDevice(dev_name);
  // The revision is at offset 8 of the binary file.
  std::vector<uint8_t> config_buffer{0x00, 0x01, 0x02, 0x03, 0x04,
                                     0x05, 0x06, 0x07, 0x08, 0x09};
  UnsetPath({bus_dev, "revision"});
  SetFile({bus_dev, "config"}, base::span<uint8_t>(config_buffer));

  auto result = GetDeviceBusDataFromSysfsNode(
      GetPathUnderRoot({kFakeSysClassDir, dev_name}));
  EXPECT_TRUE(result);
  EXPECT_THAT(result->GetDict().FindString("pci_revision"),
              Pointee(Eq("0x08")));
}

TEST_F(BusUtilsTest, ProbePciRevisionOldKernelFailed) {
  const std::string dev_name = "dev_name";
  const std::string bus_dev = SetFakePciDevice(dev_name);
  // File too small.
  std::vector<uint8_t> config_buffer{0x00, 0x01, 0x02, 0x03, 0x04};
  UnsetPath({bus_dev, "revision"});
  SetFile({bus_dev, "config"}, base::span<uint8_t>(config_buffer));

  auto result = GetDeviceBusDataFromSysfsNode(
      GetPathUnderRoot({kFakeSysClassDir, dev_name}));
  EXPECT_TRUE(result);
  EXPECT_FALSE(result->GetDict().FindString("pci_revision"));
}

TEST_F(BusUtilsTest, ProbeUsb) {
  const std::string dev_name = "dev_name";
  const std::string bus_dev =
      "/sys/devices/pci0000:00/0000:00:08.1/0000:03:00.3/usb2/2-3";
  const std::string bus_dev_relative_to_sys = "../../../../../../";
  const std::string interface_name = "2-3:1.0";
  SetSymbolicLink({bus_dev, interface_name},
                  {kFakeSysClassDir, dev_name, "device"});
  // The symbolic link is for getting the bus type.
  SetSymbolicLink({bus_dev_relative_to_sys, "bus", "usb"},
                  {bus_dev, interface_name, "subsystem"});
  SetFile({bus_dev, "idProduct"}, "0x1111");
  SetFile({bus_dev, "idVendor"}, "0x2222");
  auto ans = MakeValue({
      {"bus_type", "usb"},
      {"usb_product_id", "0x1111"},
      {"usb_vendor_id", "0x2222"},
      {"path", GetPathUnderRoot({kFakeSysClassDir, dev_name}).value()},
  });

  auto result = GetDeviceBusDataFromSysfsNode(
      GetPathUnderRoot({kFakeSysClassDir, dev_name}));
  EXPECT_EQ(result, ans);
}

TEST_F(BusUtilsTest, ProbeSdio) {
  const std::string dev_name = "dev_name";
  const std::string bus_dev = "/sys/devices/fake_sdio";
  const std::string bus_dev_relative_to_sys = "../../";
  SetSymbolicLink(bus_dev, {kFakeSysClassDir, dev_name, "device"});
  // The symbolic link is for getting the bus type.
  SetSymbolicLink({bus_dev_relative_to_sys, "bus", "sdio"},
                  {bus_dev, "subsystem"});
  SetFile({bus_dev, "device"}, "0x1111");
  SetFile({bus_dev, "vendor"}, "0x2222");
  auto ans = MakeValue({
      {"bus_type", "sdio"},
      {"sdio_device_id", "0x1111"},
      {"sdio_vendor_id", "0x2222"},
      {"path", GetPathUnderRoot({kFakeSysClassDir, dev_name}).value()},
  });

  auto result = GetDeviceBusDataFromSysfsNode(
      GetPathUnderRoot({kFakeSysClassDir, dev_name}));
  EXPECT_EQ(result, ans);
}

TEST_F(BusUtilsTest, ProbePlatform) {
  const std::string dev_name = "dev_name";
  const std::string bus_dev = "/sys/devices/platform/AMDI0040:00";
  const std::string bus_dev_relative_to_sys = "../../../";
  SetSymbolicLink(bus_dev, {kFakeSysClassDir, dev_name, "device"});
  // The symbolic link is for getting the bus type.
  SetSymbolicLink({bus_dev_relative_to_sys, "bus", "platform"},
                  {bus_dev, "subsystem"});

  auto result = GetDeviceBusDataFromSysfsNode(
      GetPathUnderRoot({kFakeSysClassDir, dev_name}));
  EXPECT_EQ(result, std::nullopt);
}

TEST_F(BusUtilsTest, ProbeUnknown) {
  const std::string dev_name = "dev_name";
  const std::string bus_dev = "/sys/devices/unknown_device";
  const std::string bus_dev_relative_to_sys = "../../";
  SetSymbolicLink(bus_dev, {kFakeSysClassDir, dev_name, "device"});
  // The symbolic link is for getting the bus type.
  SetSymbolicLink({bus_dev_relative_to_sys, "bus", "unknown"},
                  {bus_dev, "subsystem"});

  auto result = GetDeviceBusDataFromSysfsNode(
      GetPathUnderRoot({kFakeSysClassDir, dev_name}));
  EXPECT_EQ(result, std::nullopt);
}

}  // namespace
}  // namespace runtime_probe
