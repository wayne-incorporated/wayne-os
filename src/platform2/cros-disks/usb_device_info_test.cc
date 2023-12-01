// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cros-disks/usb_device_info.h"

#include <base/files/file_util.h>
#include <gtest/gtest.h>

namespace cros_disks {

class USBDeviceInfoTest : public ::testing::Test {
 public:
  void SetUp() override {
    info_file_ = CreateTestDataFile(
        "# This is a comment line\n"
        " \n"
        "\n"
        "18d1:4e11 mobile\n"
        "0bda:0138 sd\n");
    ASSERT_FALSE(info_file_.empty());

    ids_file_ = CreateTestDataFile(
        "#\n"
        "#\tList of USB ID's\n"
        "#\n"
        "\n"
        "# Syntax:\n"
        "# vendor  vendor_name\n"
        "\tdevice  device_name\n"
        "#\t\tinterface  interface_name\n"
        "  \n"
        "0123  Vendor A\n"
        "\tab01  Product 1\n"
        "\tab02  Product 2\n"
        "\tab03  Product 3\n"
        "  \n"
        "5678  Vendor with no product IDs\n"
        "abcd  Vendor B\n"
        "\t0004  Product X\n"
        "\t\n"
        "  \n"
        "# comment\n"
        "\t0005  Product Y\n"
        "\t0006  Product Z\n"
        "\n"
        "C 00  Class 0\n");
    ASSERT_FALSE(ids_file_.empty());
  }

  void TearDown() override {
    ASSERT_TRUE(base::DeleteFile(base::FilePath(info_file_)));
    ASSERT_TRUE(base::DeleteFile(base::FilePath(ids_file_)));
  }

 protected:
  std::string CreateTestDataFile(const std::string& content) const {
    base::FilePath temp_file;
    if (base::CreateTemporaryFile(&temp_file) &&
        (static_cast<size_t>(base::WriteFile(
             temp_file, content.c_str(), content.size())) == content.size())) {
      return temp_file.value();
    }
    return std::string();
  }

  std::string info_file_;
  std::string ids_file_;
  USBDeviceInfo info_;
};

TEST_F(USBDeviceInfoTest, GetDeviceMediaType) {
  EXPECT_EQ(DeviceType::kUSB, info_.GetDeviceMediaType("0bda", "0138"));

  EXPECT_TRUE(info_.RetrieveFromFile(info_file_));
  EXPECT_EQ(DeviceType::kMobile, info_.GetDeviceMediaType("18d1", "4e11"));
  EXPECT_EQ(DeviceType::kSD, info_.GetDeviceMediaType("0bda", "0138"));
  EXPECT_EQ(DeviceType::kUSB, info_.GetDeviceMediaType("1234", "5678"));
}

TEST_F(USBDeviceInfoTest, RetrieveFromFile) {
  EXPECT_TRUE(info_.RetrieveFromFile(info_file_));
}

TEST_F(USBDeviceInfoTest, GetVendorAndProductName) {
  std::string vendor_name, product_name;

  EXPECT_FALSE(info_.GetVendorAndProductName("nonexistent-path", "0123", "ab01",
                                             &vendor_name, &product_name));
  EXPECT_FALSE(info_.GetVendorAndProductName(ids_file_, "1234", "ab01",
                                             &vendor_name, &product_name));

  EXPECT_TRUE(info_.GetVendorAndProductName(ids_file_, "0123", "0000",
                                            &vendor_name, &product_name));
  EXPECT_EQ("Vendor A", vendor_name);
  EXPECT_EQ("", product_name);

  EXPECT_TRUE(info_.GetVendorAndProductName(ids_file_, "0123", "ab03",
                                            &vendor_name, &product_name));
  EXPECT_EQ("Vendor A", vendor_name);
  EXPECT_EQ("Product 3", product_name);

  EXPECT_TRUE(info_.GetVendorAndProductName(ids_file_, "5678", "0005",
                                            &vendor_name, &product_name));
  EXPECT_EQ("Vendor with no product IDs", vendor_name);
  EXPECT_EQ("", product_name);

  EXPECT_TRUE(info_.GetVendorAndProductName(ids_file_, "abcd", "0005",
                                            &vendor_name, &product_name));
  EXPECT_EQ("Vendor B", vendor_name);
  EXPECT_EQ("Product Y", product_name);
}

TEST_F(USBDeviceInfoTest, ConvertToDeviceMediaType) {
  EXPECT_EQ(DeviceType::kMobile, info_.ConvertToDeviceMediaType("mobile"));
  EXPECT_EQ(DeviceType::kSD, info_.ConvertToDeviceMediaType("sd"));
  EXPECT_EQ(DeviceType::kUSB, info_.ConvertToDeviceMediaType("usb"));
  EXPECT_EQ(DeviceType::kUSB, info_.ConvertToDeviceMediaType(""));
  EXPECT_EQ(DeviceType::kUSB, info_.ConvertToDeviceMediaType("foo"));
}

TEST_F(USBDeviceInfoTest, ExtractIdAndName) {
  std::string id, name;
  EXPECT_FALSE(info_.ExtractIdAndName("", &id, &name));
  EXPECT_FALSE(info_.ExtractIdAndName("0123  ", &id, &name));
  EXPECT_FALSE(info_.ExtractIdAndName("012  test device", &id, &name));
  EXPECT_FALSE(info_.ExtractIdAndName("0123 test device", &id, &name));
  EXPECT_FALSE(info_.ExtractIdAndName("x123  test device", &id, &name));
  EXPECT_FALSE(info_.ExtractIdAndName("0x23  test device", &id, &name));
  EXPECT_FALSE(info_.ExtractIdAndName("01x3  test device", &id, &name));
  EXPECT_FALSE(info_.ExtractIdAndName("012x  test device", &id, &name));
  EXPECT_FALSE(info_.ExtractIdAndName("01234 test device", &id, &name));

  EXPECT_TRUE(info_.ExtractIdAndName("0123  test device", &id, &name));
  EXPECT_EQ("0123", id);
  EXPECT_EQ("test device", name);

  EXPECT_TRUE(info_.ExtractIdAndName("ABCD  T", &id, &name));
  EXPECT_EQ("abcd", id);
  EXPECT_EQ("T", name);
}

TEST_F(USBDeviceInfoTest, IsLineSkippable) {
  EXPECT_TRUE(info_.IsLineSkippable(""));
  EXPECT_TRUE(info_.IsLineSkippable("  "));
  EXPECT_TRUE(info_.IsLineSkippable("\t"));
  EXPECT_TRUE(info_.IsLineSkippable("#"));
  EXPECT_TRUE(info_.IsLineSkippable("# this is a comment"));
  EXPECT_TRUE(info_.IsLineSkippable(" # this is a comment"));
  EXPECT_TRUE(info_.IsLineSkippable("# this is a comment "));
  EXPECT_TRUE(info_.IsLineSkippable("\t#this is a comment"));
  EXPECT_FALSE(info_.IsLineSkippable("this is not a comment"));
}

}  // namespace cros_disks
