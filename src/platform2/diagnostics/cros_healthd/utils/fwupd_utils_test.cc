// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/utils/fwupd_utils.h"

#include <optional>

#include <base/strings/stringprintf.h>
#include <brillo/variant_dictionary.h>
#include <gtest/gtest.h>
#include <libfwupd/fwupd-enums.h>

namespace diagnostics {
namespace fwupd_utils {
namespace {

using FwupdVersionFormat = ::ash::cros_healthd::mojom::FwupdVersionFormat;

TEST(FwupdUtilsTest, DeviceContainsVendorId) {
  auto device_info = DeviceInfo();
  device_info.joined_vendor_id = "USB:0x1234|PCI:0x5678";

  EXPECT_TRUE(ContainsVendorId(device_info, "USB:0x1234"));
  EXPECT_TRUE(ContainsVendorId(device_info, "PCI:0x5678"));

  EXPECT_FALSE(ContainsVendorId(device_info, "USB:0x4321"));
}

TEST(FwupdUtilsTest, DeviceContainsVendorIdWrongFormat) {
  auto device_info = DeviceInfo();
  device_info.joined_vendor_id = "USB:0x1234|PCI:0x5678";

  EXPECT_FALSE(ContainsVendorId(device_info, "1234"));
}

TEST(FwupdUtilsTest, DeviceContainsVendorIdNull) {
  auto device_info = DeviceInfo();

  EXPECT_FALSE(ContainsVendorId(device_info, "USB:0x1234"));
  EXPECT_FALSE(ContainsVendorId(device_info, ""));
}

TEST(FwupdUtilsTest, InstanceIdToGuid) {
  EXPECT_EQ(InstanceIdToGuid("USB\\VID_0A5C&PID_6412&REV_0001"),
            "52fd36dc-5904-5936-b114-d98e9d410b25");
  EXPECT_EQ(InstanceIdToGuid("USB\\VID_0A5C&PID_6412"),
            "7a1ba7b9-6bcd-54a4-8a36-d60cc5ee935c");
  EXPECT_EQ(InstanceIdToGuid("USB\\VID_0A5C"),
            "ddfc8e56-df0d-582e-af12-c7fa171233dc");
}

TEST(FwupdUtilsTest, InstanceIdToGuidConversionFails) {
  EXPECT_EQ(InstanceIdToGuid(""), std::nullopt);
}

TEST(FwupdUtilsTest, ParseDbusFwupdDeviceInfo) {
  std::vector<std::string> guids{"GUID_1", "GUID_2"};
  std::vector<std::string> instance_ids{"INSTNACE_ID1", "INSTNACE_ID2"};
  std::string product_name("product_name");
  std::string serial("serial");
  std::string version("version");
  std::string joined_vendor_id("USB:0x1234|PCI:0x5678");

  brillo::VariantDictionary dbus_response_entry;
  dbus_response_entry.emplace(kFwupdResultKeyName, product_name);
  dbus_response_entry.emplace(kFwupdReusltKeyGuid, guids);
  dbus_response_entry.emplace(kFwupdResultKeyInstanceIds, instance_ids);
  dbus_response_entry.emplace(kFwupdResultKeySerial, serial);
  dbus_response_entry.emplace(kFwupdResultKeyVendorId, joined_vendor_id);
  dbus_response_entry.emplace(kFwupdResultKeyVersion, version);
  dbus_response_entry.emplace(
      kFwupdResultKeyVersionFormat,
      static_cast<uint32_t>(FWUPD_VERSION_FORMAT_PLAIN));

  DeviceInfo device_info = ParseDbusFwupdDeviceInfo(dbus_response_entry);

  EXPECT_EQ(device_info.name, product_name);
  EXPECT_EQ(device_info.guids, guids);
  EXPECT_EQ(device_info.instance_ids, instance_ids);
  EXPECT_EQ(device_info.serial, serial);
  EXPECT_EQ(device_info.version, version);
  EXPECT_EQ(device_info.version_format, FwupdVersionFormat::kPlain);
  EXPECT_EQ(device_info.joined_vendor_id, joined_vendor_id);
}

TEST(FwupdUtilsTest, ParseDbusFwupdDeviceInfoMissingKeys) {
  // For std::vector<std::string>, fill guids but not instance_ids.
  // For std::optional<std::string>, fill product_name but not serial.
  std::vector<std::string> guids{"GUID_1", "GUID_2"};
  std::string product_name("product_name");

  brillo::VariantDictionary dbus_response_entry;
  dbus_response_entry.emplace(kFwupdResultKeyName, product_name);
  dbus_response_entry.emplace(kFwupdReusltKeyGuid, guids);

  DeviceInfo device_info = ParseDbusFwupdDeviceInfo(dbus_response_entry);

  EXPECT_EQ(device_info.name, product_name);
  EXPECT_EQ(device_info.guids, guids);
  EXPECT_EQ(device_info.instance_ids.size(), 0);
  EXPECT_EQ(device_info.serial, std::nullopt);
  EXPECT_EQ(device_info.version, std::nullopt);
  EXPECT_EQ(device_info.version_format, FwupdVersionFormat::kUnknown);
  EXPECT_EQ(device_info.joined_vendor_id, std::nullopt);
}

TEST(FwupdUtilsTest, MatchUsbBySerials) {
  // Tell apart different instances by their serial numbers.
  DeviceInfo device1{
      .name = "product_name",
      .instance_ids = std::vector<std::string>{"USB\\VID_1234&PID_5678"},
      .serial = "serial1",
      .version = "version1",
      .version_format = FwupdVersionFormat::kPlain,
      .joined_vendor_id = "USB:0x1234",
  };
  if (auto guid = InstanceIdToGuid("USB\\VID_1234&PID_5678");
      guid.has_value()) {
    device1.guids.push_back(guid.value());
  }

  DeviceInfo device2 = device1;
  device2.serial = "serial2";
  device2.version = "version2";

  std::vector<DeviceInfo> device_infos{device1, device2};

  auto usb_device_filter = UsbDeviceFilter{
      .vendor_id = 0x1234,
      .product_id = 0x5678,
      .serial = "serial1",
  };

  auto res = FetchUsbFirmwareVersion(device_infos, usb_device_filter);
  EXPECT_EQ(res->version, "version1");
  EXPECT_EQ(res->version_format, FwupdVersionFormat::kPlain);
}

TEST(FwupdUtilsTest, UsbProductNotMatched) {
  // Only the vendor id and the product name are matched but no product id and
  // no serial. This kind of matchingness is too weak.
  DeviceInfo device{
      .name = "product_name",
      .version = "version",
      .version_format = FwupdVersionFormat::kPlain,
      .joined_vendor_id = "USB:0x1234",
  };

  std::vector<DeviceInfo> device_infos{device};

  auto usb_device_filter = UsbDeviceFilter{
      .vendor_id = 0x1234,
      .product_id = 0x5678,
  };

  auto res = FetchUsbFirmwareVersion(device_infos, usb_device_filter);
  EXPECT_EQ(res.get(), nullptr);
}

TEST(FwupdUtilsTest, MultipleUsbMatchedWithACommonVersion) {
  // Multiple devices matches the VID:PID and the target serial number is
  // absent.
  DeviceInfo device{
      .name = "device name",
      .instance_ids = std::vector<std::string>{"USB\\VID_1234&PID_5678"},
      .version = "version",
      .version_format = FwupdVersionFormat::kPlain,
      .joined_vendor_id = "USB:0x1234",
  };
  if (auto guid = InstanceIdToGuid("USB\\VID_1234&PID_5678");
      guid.has_value()) {
    device.guids.push_back(guid.value());
  }

  std::vector<DeviceInfo> device_infos{device, device};

  auto usb_device_filter = UsbDeviceFilter{
      .vendor_id = 0x1234,
      .product_id = 0x5678,
  };

  auto res = FetchUsbFirmwareVersion(device_infos, usb_device_filter);
  EXPECT_EQ(res->version, "version");
  EXPECT_EQ(res->version_format, FwupdVersionFormat::kPlain);
}

TEST(FwupdUtilsTest, MultipleUsbMatchedButDifferentVersions) {
  // Multiple matches but they have different versions.
  DeviceInfo device1{
      .name = "device name",
      .instance_ids = std::vector<std::string>{"USB\\VID_1234&PID_5678"},
      .version = "version",
      .version_format = FwupdVersionFormat::kPlain,
      .joined_vendor_id = "USB:0x1234",
  };
  if (auto guid = InstanceIdToGuid("USB\\VID_1234&PID_5678");
      guid.has_value()) {
    device1.guids.push_back(guid.value());
  }

  DeviceInfo device2 = device1;
  device2.version = "version2";

  std::vector<DeviceInfo> device_infos{device1, device2};

  auto usb_device_filter = UsbDeviceFilter{
      .vendor_id = 0x1234,
      .product_id = 0x5678,
  };

  auto res = FetchUsbFirmwareVersion(device_infos, usb_device_filter);
  EXPECT_EQ(res.get(), nullptr);
}

}  // namespace
}  // namespace fwupd_utils
}  // namespace diagnostics
