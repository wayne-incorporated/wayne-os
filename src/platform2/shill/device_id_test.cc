// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/device_id.h"

#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <gtest/gtest.h>

namespace shill {

TEST(DeviceIdTest, MatchByBusType) {
  constexpr DeviceId kDeviceId{DeviceId::BusType::kUsb};
  constexpr DeviceId kPattern{DeviceId::BusType::kUsb};
  EXPECT_TRUE(kDeviceId.Match(kPattern))
      << kDeviceId << " does not match " << kPattern;
}

TEST(DeviceIdTest, NotMatchByBusType) {
  constexpr DeviceId kDeviceId{DeviceId::BusType::kUsb};
  constexpr DeviceId kPattern{DeviceId::BusType::kPci};
  EXPECT_FALSE(kDeviceId.Match(kPattern))
      << kDeviceId << " matches " << kPattern;
}

TEST(DeviceIdTest, MatchByVendor) {
  constexpr DeviceId kDeviceId{DeviceId::BusType::kUsb, 1234};
  constexpr DeviceId kPattern{DeviceId::BusType::kUsb, 1234};
  EXPECT_TRUE(kDeviceId.Match(kPattern))
      << kDeviceId << " does not match " << kPattern;
}

TEST(DeviceIdTest, MatchByAnyVendor) {
  constexpr DeviceId kDeviceId{DeviceId::BusType::kPci, 4567};
  constexpr DeviceId kPattern{DeviceId::BusType::kPci};
  EXPECT_TRUE(kDeviceId.Match(kPattern))
      << kDeviceId << " does not match " << kPattern;
}

TEST(DeviceIdTest, SpecificVendorNotMatchByVendor) {
  constexpr DeviceId kDeviceId{DeviceId::BusType::kPci, 9988};
  constexpr DeviceId kPattern{DeviceId::BusType::kPci, 456};
  EXPECT_FALSE(kDeviceId.Match(kPattern))
      << kDeviceId << " matches " << kPattern;
}

TEST(DeviceIdTest, AnyVendorNotMatchByVendor) {
  constexpr DeviceId kDeviceId{DeviceId::BusType::kUsb};
  constexpr DeviceId kPattern{DeviceId::BusType::kUsb, 3123};
  EXPECT_FALSE(kDeviceId.Match(kPattern))
      << kDeviceId << " matches " << kPattern;
}

TEST(DeviceIdTest, MatchByProduct) {
  constexpr DeviceId kDeviceId{DeviceId::BusType::kUsb, 453, 15};
  constexpr DeviceId kPattern{DeviceId::BusType::kUsb, 453, 15};
  EXPECT_TRUE(kDeviceId.Match(kPattern))
      << kDeviceId << " does not match " << kPattern;
}

TEST(DeviceIdTest, MatchByAnyProduct) {
  constexpr DeviceId kDeviceId{DeviceId::BusType::kPci, 782, 578};
  constexpr DeviceId kPattern{DeviceId::BusType::kPci, 782};
  EXPECT_TRUE(kDeviceId.Match(kPattern))
      << kDeviceId << " does not match " << kPattern;
}

TEST(DeviceIdTest, SpecificProductNotMatchByProduct) {
  constexpr DeviceId kDeviceId{DeviceId::BusType::kUsb, 4633, 213};
  constexpr DeviceId kPattern{DeviceId::BusType::kUsb, 4633, 3999};
  EXPECT_FALSE(kDeviceId.Match(kPattern))
      << kDeviceId << " matches " << kPattern;
}

TEST(DeviceIdTest, AnyProductNotMatchByProduct) {
  constexpr DeviceId kDeviceId{DeviceId::BusType::kUsb, 9721};
  constexpr DeviceId kPattern{DeviceId::BusType::kUsb, 9721, 4647};
  EXPECT_FALSE(kDeviceId.Match(kPattern))
      << kDeviceId << " matches " << kPattern;
}

TEST(DeviceIdTest, MatchByLocationTypeExternal) {
  constexpr DeviceId kDeviceId{DeviceId::BusType::kPci,
                               DeviceId::LocationType::kExternal};
  constexpr DeviceId kPattern{DeviceId::BusType::kPci,
                              DeviceId::LocationType::kExternal};
  EXPECT_TRUE(kDeviceId.Match(kPattern))
      << kDeviceId << " does not match " << kPattern;
}

TEST(DeviceIdTest, NotMatchByLocationTypeExternalAndInternal) {
  constexpr DeviceId kDeviceId{DeviceId::BusType::kPci,
                               DeviceId::LocationType::kInternal};
  constexpr DeviceId kPattern{DeviceId::BusType::kPci,
                              DeviceId::LocationType::kExternal};
  EXPECT_FALSE(kDeviceId.Match(kPattern))
      << kDeviceId << " matches " << kPattern;
}

TEST(DeviceIdTest, NotMatchByLocationTypeExternalAndUnknown) {
  constexpr DeviceId kDeviceId{DeviceId::BusType::kPci};
  constexpr DeviceId kPattern{DeviceId::BusType::kPci,
                              DeviceId::LocationType::kExternal};
  EXPECT_FALSE(kDeviceId.Match(kPattern))
      << kDeviceId << " matches " << kPattern;
}

TEST(DeviceIdTest, MatchByNoLocationTypeInternal) {
  constexpr DeviceId kDeviceId{DeviceId::BusType::kPci,
                               DeviceId::LocationType::kInternal};
  constexpr DeviceId kPattern{DeviceId::BusType::kPci};
  EXPECT_TRUE(kDeviceId.Match(kPattern))
      << kDeviceId << " does not match " << kPattern;
}

TEST(DeviceIdTest, MatchByNoLocationTypeExternal) {
  constexpr DeviceId kDeviceId{DeviceId::BusType::kPci,
                               DeviceId::LocationType::kExternal};
  constexpr DeviceId kPattern{DeviceId::BusType::kPci};
  EXPECT_TRUE(kDeviceId.Match(kPattern))
      << kDeviceId << " does not match " << kPattern;
}

TEST(DeviceIdTest, MatchByNoLocationType) {
  constexpr DeviceId kDeviceId{DeviceId::BusType::kPci};
  constexpr DeviceId kPattern{DeviceId::BusType::kPci};
  EXPECT_TRUE(kDeviceId.Match(kPattern))
      << kDeviceId << " does not match " << kPattern;
}

namespace {

class DeviceIdFromSysfsTest : public testing::Test {
 public:
  void SetUp() override { ASSERT_TRUE(temp_dir_.CreateUniqueTempDir()); }

  void CreateDeviceSysfs(const std::string& device_name,
                         const std::string& subsystem_name) const {
    base::FilePath temp_dir_path = temp_dir_.GetPath();
    base::FilePath device_path = temp_dir_path.Append(device_name);
    base::FilePath subsystem_path = temp_dir_path.Append(subsystem_name);

    ASSERT_TRUE(base::CreateDirectory(device_path));
    ASSERT_TRUE(base::CreateDirectory(subsystem_path));
    ASSERT_TRUE(base::CreateSymbolicLink(subsystem_path,
                                         device_path.Append("subsystem")));
  }

  void CreateDeviceSysfsFile(const std::string& device_name,
                             const std::string& file_name,
                             const std::string& data) const {
    base::FilePath file_path =
        temp_dir_.GetPath().Append(device_name).Append(file_name);
    ASSERT_EQ(base::WriteFile(file_path, data.c_str(), data.length()),
              data.length());
  }

  base::FilePath GetDevicePath(const std::string& device_name) const {
    return temp_dir_.GetPath().Append(device_name);
  }

  void ExpectDeviceId(const std::string& device_name,
                      const DeviceId& expected_device_id) const {
    const auto device_id =
        DeviceId::CreateFromSysfs(GetDevicePath(device_name));
    ASSERT_TRUE(device_id);
    EXPECT_TRUE(device_id->Match(expected_device_id))
        << *device_id << " does not match " << expected_device_id;
  }

 protected:
  static const char kPciBusName[];
  static const char kUsbBusName[];

  static const char kDeviceName0[];
  static const char kDeviceName1[];

 private:
  base::ScopedTempDir temp_dir_;
};

const char DeviceIdFromSysfsTest::kPciBusName[] = "pci";
const char DeviceIdFromSysfsTest::kUsbBusName[] = "usb";

const char DeviceIdFromSysfsTest::kDeviceName0[] = "eth0";
const char DeviceIdFromSysfsTest::kDeviceName1[] = "eth1";

}  // namespace

TEST_F(DeviceIdFromSysfsTest, UnknownSubsystem) {
  CreateDeviceSysfs(kDeviceName1, "unknown_subsystem");
  EXPECT_FALSE(DeviceId::CreateFromSysfs(GetDevicePath(kDeviceName1)));
}

TEST_F(DeviceIdFromSysfsTest, PciDevice) {
  CreateDeviceSysfs(kDeviceName1, kPciBusName);
  CreateDeviceSysfsFile(kDeviceName1, "vendor", "0x97ba");
  CreateDeviceSysfsFile(kDeviceName1, "device", "0x6012");
  ExpectDeviceId(kDeviceName1, {DeviceId::BusType::kPci, 0x97ba, 0x6012});
}

TEST_F(DeviceIdFromSysfsTest, PciDeviceWithAnyProductId) {
  CreateDeviceSysfs(kDeviceName0, kPciBusName);
  CreateDeviceSysfsFile(kDeviceName0, "vendor", "0x6480");
  ExpectDeviceId(kDeviceName0, {DeviceId::BusType::kPci, 0x6480});
}

TEST_F(DeviceIdFromSysfsTest, PciDeviceWithAnyVendorId) {
  CreateDeviceSysfs(kDeviceName0, kPciBusName);
  ExpectDeviceId(kDeviceName0, DeviceId{DeviceId::BusType::kPci});
}

TEST_F(DeviceIdFromSysfsTest, ExternalPciDeviceWithAnyVendorId) {
  CreateDeviceSysfs(kDeviceName0, kPciBusName);
  CreateDeviceSysfsFile(kDeviceName0, "untrusted", "1");
  ExpectDeviceId(kDeviceName0, DeviceId{DeviceId::BusType::kPci,
                                        DeviceId::LocationType::kExternal});
}

TEST_F(DeviceIdFromSysfsTest, InternalPciDeviceWithAnyVendorId) {
  CreateDeviceSysfs(kDeviceName0, kPciBusName);
  CreateDeviceSysfsFile(kDeviceName0, "untrusted", "0");
  ExpectDeviceId(kDeviceName0, DeviceId{DeviceId::BusType::kPci,
                                        DeviceId::LocationType::kInternal});
}

TEST_F(DeviceIdFromSysfsTest, InternalPciDeviceWithAnyVendorIdTrailingNewline) {
  CreateDeviceSysfs(kDeviceName0, kPciBusName);
  CreateDeviceSysfsFile(kDeviceName0, "untrusted", "0\n");
  ExpectDeviceId(kDeviceName0, DeviceId{DeviceId::BusType::kPci,
                                        DeviceId::LocationType::kInternal});
}

TEST_F(DeviceIdFromSysfsTest, UsbDevice) {
  CreateDeviceSysfs(kDeviceName1, kUsbBusName);
  CreateDeviceSysfsFile(kDeviceName1, "idVendor", "af36");
  CreateDeviceSysfsFile(kDeviceName1, "idProduct", "98ed");
  ExpectDeviceId(kDeviceName1, {DeviceId::BusType::kUsb, 0xaf36, 0x98ed});
}

TEST_F(DeviceIdFromSysfsTest, UsbDeviceWithAnyProductId) {
  CreateDeviceSysfs(kDeviceName0, kUsbBusName);
  CreateDeviceSysfsFile(kDeviceName0, "idVendor", "ff00");
  ExpectDeviceId(kDeviceName0, {DeviceId::BusType::kUsb, 0xff00});
}

TEST_F(DeviceIdFromSysfsTest, UsbDeviceWithAnyVendorId) {
  CreateDeviceSysfs(kDeviceName1, kUsbBusName);
  ExpectDeviceId(kDeviceName1, DeviceId{DeviceId::BusType::kUsb});
}

TEST_F(DeviceIdFromSysfsTest, UsbDeviceByString) {
  const std::string kDeviceIdString = "usb:2cb7:01a0";
  CreateDeviceSysfs(kDeviceName1, kUsbBusName);
  CreateDeviceSysfsFile(kDeviceName1, "idVendor", "2cb7");
  CreateDeviceSysfsFile(kDeviceName1, "idProduct", "01a0");
  // In the cellular code(modemfwd), the manifests for the firmwares and the
  // helpers match against the DeviceID string exported over D-Bus.
  // We need to ensure that the following string doesn't change over time.
  const auto device_id = DeviceId::CreateFromSysfs(GetDevicePath(kDeviceName1));
  ASSERT_TRUE(device_id);
  EXPECT_TRUE(device_id->AsString() == kDeviceIdString)
      << device_id->AsString() << " does not match " << kDeviceIdString;
}

}  // namespace shill
