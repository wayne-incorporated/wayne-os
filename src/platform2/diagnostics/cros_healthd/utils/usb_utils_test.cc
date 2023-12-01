// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <string>
#include <utility>

#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <brillo/udev/mock_udev_device.h>

#include "diagnostics/base/file_test_utils.h"
#include "diagnostics/cros_healthd/utils/usb_utils.h"
#include "diagnostics/cros_healthd/utils/usb_utils_constants.h"

#include "diagnostics/mojom/public/cros_healthd_probe.mojom.h"

namespace diagnostics {
namespace {

using ::testing::Return;
namespace mojom = ::ash::cros_healthd::mojom;

constexpr char kFakePathUsb[] = "sys/devices/pci0000:00/0000:00:14.0";
constexpr char kFakeUsbVendorName[] = "Usb Vendor";
constexpr auto kFakeUsbProductName = "Usb Product";
constexpr auto kFakeUsbFallbackVendorName = "Fallback Vendor Name";
constexpr auto kFakeUsbFallbackProductName = "Fallback Product Name";
constexpr auto kFakeUsbPropertieProduct = "47f/430c/1093";
constexpr uint16_t kFakeUsbVid = 0x47f;
constexpr uint16_t kFakeUsbPid = 0x430c;

class UsbUtilsTest : public BaseFileTest {
 public:
  UsbUtilsTest() = default;
  UsbUtilsTest(const UsbUtilsTest&) = delete;
  UsbUtilsTest& operator=(const UsbUtilsTest&) = delete;
  ~UsbUtilsTest() = default;

  void SetUp() override {
    dev_ = std::make_unique<brillo::MockUdevDevice>();
    CreateUsbDevice(/*layer=*/0);
  }

  // Create a usb device at a specific layer.
  // The device path is "{kFakePathUsb}/0/1/.../{layer}/".
  //
  // Note: Multiple call of this function will override the following member
  // variables:
  //   - fake_dev_relative_path_
  //   - fake_dev_path_
  void CreateUsbDevice(uint8_t layer) {
    fake_dev_relative_path_ = base::FilePath(kFakePathUsb);
    for (int i = 0; i <= layer; ++i) {
      fake_dev_relative_path_ =
          fake_dev_relative_path_.Append(base::NumberToString(i));
    }
    fake_dev_path_ = GetPathUnderRoot(fake_dev_relative_path_);

    SetFile(fake_dev_relative_path_.Append(kFileUsbManufacturerName),
            kFakeUsbFallbackVendorName);
    SetFile(fake_dev_relative_path_.Append(kFileUsbProductName),
            kFakeUsbFallbackProductName);
    auto product_tokens =
        base::SplitString(std::string(kFakeUsbPropertieProduct), "/",
                          base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);
    EXPECT_EQ(product_tokens.size(), 3);
    SetFile(fake_dev_relative_path_.Append(kFileUsbVendor), product_tokens[0]);
    SetFile(fake_dev_relative_path_.Append(kFileUsbProduct), product_tokens[1]);
  }

  // Set the property of the usb device at a specific layer.
  void SetUsbProp(uint8_t layer,
                  const std::string& file,
                  const std::string& content) {
    auto target = base::FilePath(kFakePathUsb);
    for (int i = 0; i <= layer; ++i) {
      target = target.Append(base::NumberToString(i));
    }
    EXPECT_TRUE(target == fake_dev_relative_path_ ||
                target.IsParent(fake_dev_relative_path_));

    SetFile(target.Append(file), content);
  }

  brillo::MockUdevDevice& mock_dev() {
    return *reinterpret_cast<brillo::MockUdevDevice*>(dev_.get());
  }

 protected:
  std::unique_ptr<brillo::UdevDevice> dev_;
  // Absolute path from root.
  base::FilePath fake_dev_path_;

 private:
  // Relative path to root.
  base::FilePath fake_dev_relative_path_;
};

TEST_F(UsbUtilsTest, TestFetchVendor) {
  EXPECT_CALL(mock_dev(), GetPropertyValue(kPropertieVendorFromDB))
      .WillOnce(Return(kFakeUsbVendorName));
  EXPECT_EQ(GetUsbVendorName(dev_), kFakeUsbVendorName);
}

TEST_F(UsbUtilsTest, TestFetchProduct) {
  EXPECT_CALL(mock_dev(), GetPropertyValue(kPropertieModelFromDB))
      .WillOnce(Return(kFakeUsbProductName));
  EXPECT_EQ(GetUsbProductName(dev_), kFakeUsbProductName);
}

TEST_F(UsbUtilsTest, TestFetchVendorFallback) {
  EXPECT_CALL(mock_dev(), GetPropertyValue(kPropertieVendorFromDB))
      .WillOnce(Return(nullptr));
  EXPECT_CALL(mock_dev(), GetSysPath())
      .WillOnce(Return(fake_dev_path_.value().c_str()));
  EXPECT_EQ(GetUsbVendorName(dev_), kFakeUsbFallbackVendorName);
}

TEST_F(UsbUtilsTest, TestFetchProductFallback) {
  EXPECT_CALL(mock_dev(), GetPropertyValue(kPropertieModelFromDB))
      .WillOnce(Return(nullptr));
  EXPECT_CALL(mock_dev(), GetSysPath())
      .WillOnce(Return(fake_dev_path_.value().c_str()));
  EXPECT_EQ(GetUsbProductName(dev_), kFakeUsbFallbackProductName);
}

TEST_F(UsbUtilsTest, TestFetchVidPid) {
  EXPECT_CALL(mock_dev(), GetPropertyValue(kPropertieProduct))
      .WillOnce(Return(kFakeUsbPropertieProduct));
  EXPECT_EQ(GetUsbVidPid(dev_), std::make_pair(kFakeUsbVid, kFakeUsbPid));
}

TEST_F(UsbUtilsTest, TestFetchVidPidFallback) {
  EXPECT_CALL(mock_dev(), GetPropertyValue(kPropertieProduct))
      .WillOnce(Return(nullptr));
  EXPECT_CALL(mock_dev(), GetSysPath())
      .WillOnce(Return(fake_dev_path_.value().c_str()));
  EXPECT_EQ(GetUsbVidPid(dev_), std::make_pair(kFakeUsbVid, kFakeUsbPid));
}

TEST_F(UsbUtilsTest, TestDetermineUsbVersionRootHub) {
  SetUsbProp(/*layer=*/0, kFileUsbVendor, kLinuxFoundationVendorId);
  SetUsbProp(/*layer=*/0, kFileUsbProduct, "1");
  EXPECT_EQ(DetermineUsbVersion(fake_dev_path_), mojom::UsbVersion::kUsb1);

  SetUsbProp(/*layer=*/0, kFileUsbProduct, "2");
  EXPECT_EQ(DetermineUsbVersion(fake_dev_path_), mojom::UsbVersion::kUsb2);

  SetUsbProp(/*layer=*/0, kFileUsbProduct, "3");
  EXPECT_EQ(DetermineUsbVersion(fake_dev_path_), mojom::UsbVersion::kUsb3);
}

TEST_F(UsbUtilsTest, TestDetermineUsbVersionRootHubUnexpectedProductId) {
  SetUsbProp(/*layer=*/0, kFileUsbVendor, kLinuxFoundationVendorId);
  SetUsbProp(/*layer=*/0, kFileUsbProduct, "4");
  EXPECT_EQ(DetermineUsbVersion(fake_dev_path_), mojom::UsbVersion::kUnknown);
}

TEST_F(UsbUtilsTest, TestDetermineUsbVersionRootHubUnexpectedVendorId) {
  SetUsbProp(/*layer=*/0, kFileUsbVendor, "1234");
  SetUsbProp(/*layer=*/0, kFileUsbProduct, "3");
  EXPECT_EQ(DetermineUsbVersion(fake_dev_path_), mojom::UsbVersion::kUnknown);
}

TEST_F(UsbUtilsTest, TestDetermineUsbVersionDevice) {
  const int max_layer = 5;
  CreateUsbDevice(/*layer=*/max_layer);

  // Set up non linux root hub property for layer 1~4.
  for (int i = 1; i < max_layer; ++i) {
    SetUsbProp(/*layer=*/i, kFileUsbVendor, "1234");
    SetUsbProp(/*layer=*/i, kFileUsbProduct, "2");
  }

  SetUsbProp(/*layer=*/0, kFileUsbVendor, kLinuxFoundationVendorId);
  SetUsbProp(/*layer=*/0, kFileUsbProduct, "1");
  EXPECT_EQ(DetermineUsbVersion(fake_dev_path_), mojom::UsbVersion::kUsb1);

  SetUsbProp(/*layer=*/0, kFileUsbProduct, "2");
  EXPECT_EQ(DetermineUsbVersion(fake_dev_path_), mojom::UsbVersion::kUsb2);

  SetUsbProp(/*layer=*/0, kFileUsbProduct, "3");
  EXPECT_EQ(DetermineUsbVersion(fake_dev_path_), mojom::UsbVersion::kUsb3);
}

TEST_F(UsbUtilsTest, TestGetUsbSpecSpeed) {
  SetUsbProp(/*layer=*/0, kFileUsbSpeed, "Unknown");
  EXPECT_EQ(GetUsbSpecSpeed(fake_dev_path_), mojom::UsbSpecSpeed::kUnknown);

  SetUsbProp(/*layer=*/0, kFileUsbSpeed, "1.5");
  EXPECT_EQ(GetUsbSpecSpeed(fake_dev_path_), mojom::UsbSpecSpeed::k1_5Mbps);

  SetUsbProp(/*layer=*/0, kFileUsbSpeed, "12");
  EXPECT_EQ(GetUsbSpecSpeed(fake_dev_path_), mojom::UsbSpecSpeed::k12Mbps);

  SetUsbProp(/*layer=*/0, kFileUsbSpeed, "480");
  EXPECT_EQ(GetUsbSpecSpeed(fake_dev_path_), mojom::UsbSpecSpeed::k480Mbps);

  SetUsbProp(/*layer=*/0, kFileUsbSpeed, "5000");
  EXPECT_EQ(GetUsbSpecSpeed(fake_dev_path_), mojom::UsbSpecSpeed::k5Gbps);

  SetUsbProp(/*layer=*/0, kFileUsbSpeed, "10000");
  EXPECT_EQ(GetUsbSpecSpeed(fake_dev_path_), mojom::UsbSpecSpeed::k10Gbps);

  SetUsbProp(/*layer=*/0, kFileUsbSpeed, "20000");
  EXPECT_EQ(GetUsbSpecSpeed(fake_dev_path_), mojom::UsbSpecSpeed::k20Gbps);
}

}  // namespace
}  // namespace diagnostics
