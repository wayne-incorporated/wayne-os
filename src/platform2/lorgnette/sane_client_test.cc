// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "lorgnette/sane_client_impl.h"

#include <iostream>
#include <memory>
#include <optional>
#include <vector>

#include <chromeos/dbus/service_constants.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <lorgnette/proto_bindings/lorgnette_service.pb.h>

#include "lorgnette/manager.h"
#include "lorgnette/test_util.h"

using ::testing::ElementsAre;

namespace lorgnette {

class SaneDeviceImplTest : public testing::Test {
 protected:
  void SetUp() override {
    client_ = SaneClientImpl::Create();
    device_ = client_->ConnectToDevice(nullptr, nullptr, "test");
    EXPECT_TRUE(device_);
  }

  void ReloadOptions() {
    dynamic_cast<SaneDeviceImpl*>(device_.get())->LoadOptions(nullptr);
  }

  std::unique_ptr<SaneClient> client_;
  std::unique_ptr<SaneDevice> device_;
};

// Check that GetValidOptionValues returns correct values for the test backend.
TEST_F(SaneDeviceImplTest, GetValidOptionValuesSuccess) {
  std::optional<ValidOptionValues> values =
      device_->GetValidOptionValues(nullptr);
  EXPECT_TRUE(values.has_value());
  ASSERT_EQ(values->resolutions.size(), 1200);
  for (int i = 0; i < 1200; i++)
    EXPECT_EQ(values->resolutions[i], i + 1);

  std::vector<ColorMode> color_modes = {MODE_GRAYSCALE, MODE_COLOR};
  std::vector<uint32_t> resolutions = {75, 100, 150, 200, 300, 600};
  EXPECT_THAT(values->sources,
              ElementsAre(EqualsDocumentSource(CreateDocumentSource(
                              "Flatbed", SOURCE_PLATEN, 200.0, 200.0,
                              resolutions, color_modes)),
                          EqualsDocumentSource(CreateDocumentSource(
                              "Automatic Document Feeder", SOURCE_ADF_SIMPLEX,
                              200.0, 200.0, resolutions, color_modes))));

  EXPECT_THAT(values->color_modes,
              ElementsAre(kScanPropertyModeGray, kScanPropertyModeColor));
}

// Check that SetScanResolution works for all valid values.
TEST_F(SaneDeviceImplTest, SetResolution) {
  std::optional<ValidOptionValues> values =
      device_->GetValidOptionValues(nullptr);
  EXPECT_TRUE(values.has_value());

  for (int resolution : values->resolutions)
    EXPECT_TRUE(device_->SetScanResolution(nullptr, resolution));
}

// Check the SetDocumentSource rejects invalid values and works properly for all
// valid values. Also check that GetDocumentSource returns that correct value
// after SetDocumentSource, even if we force-reload option values from scanner.
TEST_F(SaneDeviceImplTest, SetSource) {
  EXPECT_FALSE(device_->SetDocumentSource(nullptr, "invalid source"));

  std::optional<ValidOptionValues> values =
      device_->GetValidOptionValues(nullptr);
  EXPECT_TRUE(values.has_value());

  // Test both with and without reloading options after setting option, since
  // it can surface different bugs.
  for (bool reload_options : {true, false}) {
    LOG(INFO) << "Testing " << (reload_options ? "with" : "without")
              << " option reloading.";
    for (const DocumentSource& source : values->sources) {
      EXPECT_TRUE(device_->SetDocumentSource(nullptr, source.name()));
      if (reload_options) {
        ReloadOptions();
      }

      std::optional<std::string> scanner_value =
          device_->GetDocumentSource(nullptr);
      EXPECT_TRUE(scanner_value.has_value());
      EXPECT_EQ(scanner_value.value(), source.name());
    }
  }
}

// Check that SetColorMode rejects invalid values, and accepts all valid values.
// Also check that GetColorMode returns the correct value after SetColorMode,
// even if we force-reload option values from the scanner.
TEST_F(SaneDeviceImplTest, SetColorMode) {
  EXPECT_FALSE(device_->SetColorMode(nullptr, MODE_UNSPECIFIED));

  std::optional<ValidOptionValues> values =
      device_->GetValidOptionValues(nullptr);
  EXPECT_TRUE(values.has_value());

  // Test both with and without reloading options after setting option, since
  // it can surface different bugs.
  for (bool reload_options : {true, false}) {
    LOG(INFO) << "Testing " << (reload_options ? "with" : "without")
              << " option reloading.";
    for (const std::string& mode_string : values->color_modes) {
      ColorMode mode = impl::ColorModeFromSaneString(mode_string);
      EXPECT_NE(mode, MODE_UNSPECIFIED)
          << "Unexpected ColorMode string " << mode_string;
      EXPECT_TRUE(device_->SetColorMode(nullptr, mode));

      if (reload_options) {
        ReloadOptions();
      }

      std::optional<ColorMode> scanner_value = device_->GetColorMode(nullptr);
      EXPECT_TRUE(scanner_value.has_value());
      EXPECT_EQ(scanner_value.value(), mode);
    }
  }
}

// Check that Scan Region can be set without problems from justification with
// all source types.
TEST_F(SaneDeviceImplTest, SetScanRegionWithJustification) {
  ReloadOptions();
  const double width = 187;  /* mm */
  const double height = 123; /* mm */

  ScanRegion region;
  region.set_top_left_x(0);
  region.set_top_left_y(0);
  region.set_bottom_right_x(width);
  region.set_bottom_right_y(height);

  std::optional<ValidOptionValues> values =
      device_->GetValidOptionValues(nullptr);
  EXPECT_TRUE(values.has_value());

  for (const DocumentSource& source : values->sources) {
    EXPECT_TRUE(device_->SetDocumentSource(nullptr, source.name()));
    EXPECT_TRUE(device_->SetScanRegion(nullptr, region));
  }
}

// Check that extra calls to StartScan fail properly.
TEST_F(SaneDeviceImplTest, DuplicateStartScan) {
  EXPECT_EQ(device_->StartScan(nullptr), SANE_STATUS_GOOD);
  EXPECT_EQ(device_->StartScan(nullptr), SANE_STATUS_DEVICE_BUSY);
}

// Check that GetScanParameters returns the correct values corresponding to the
// input resolution and scan region.
TEST_F(SaneDeviceImplTest, GetScanParameters) {
  const int resolution = 100; /* dpi */
  EXPECT_TRUE(device_->SetScanResolution(nullptr, resolution));

  const double width = 187;  /* mm */
  const double height = 123; /* mm */

  ScanRegion region;
  region.set_top_left_x(0);
  region.set_top_left_y(0);
  region.set_bottom_right_x(width);
  region.set_bottom_right_y(height);
  EXPECT_TRUE(device_->SetScanRegion(nullptr, region));

  std::optional<ScanParameters> params = device_->GetScanParameters(nullptr);
  EXPECT_TRUE(params.has_value());
  EXPECT_TRUE(params->format == kGrayscale);

  const double mms_per_inch = 25.4;
  EXPECT_EQ(params->bytes_per_line,
            static_cast<int>(width / mms_per_inch * resolution));
  EXPECT_EQ(params->pixels_per_line,
            static_cast<int>(width / mms_per_inch * resolution));
  EXPECT_EQ(params->lines,
            static_cast<int>(height / mms_per_inch * resolution));
  EXPECT_EQ(params->depth, 8);
}

// Check that ReadScanData fails when we haven't started a scan.
TEST_F(SaneDeviceImplTest, ReadScanDataWhenNotStarted) {
  std::vector<uint8_t> buf(8192);
  size_t read = 0;

  EXPECT_EQ(device_->ReadScanData(nullptr, buf.data(), buf.size(), &read),
            SANE_STATUS_INVAL);
}

// Check that ReadScanData fails with invalid input pointers.
TEST_F(SaneDeviceImplTest, ReadScanDataBadPointers) {
  std::vector<uint8_t> buf(8192);
  size_t read = 0;

  EXPECT_EQ(device_->StartScan(nullptr), SANE_STATUS_GOOD);
  EXPECT_EQ(device_->ReadScanData(nullptr, nullptr, buf.size(), &read),
            SANE_STATUS_INVAL);
  EXPECT_EQ(device_->ReadScanData(nullptr, buf.data(), buf.size(), nullptr),
            SANE_STATUS_INVAL);
}

// Check that we can successfully run a scan to completion.
TEST_F(SaneDeviceImplTest, RunScan) {
  std::vector<uint8_t> buf(8192);
  size_t read = 0;

  EXPECT_EQ(device_->StartScan(nullptr), SANE_STATUS_GOOD);
  SANE_Status status = SANE_STATUS_GOOD;
  do {
    status = device_->ReadScanData(nullptr, buf.data(), buf.size(), &read);
  } while (status == SANE_STATUS_GOOD && read != 0);
  EXPECT_EQ(read, 0);
  EXPECT_EQ(status, SANE_STATUS_EOF);
}

class SaneClientTest : public testing::Test {
 protected:
  void SetUp() override {
    dev_ = CreateTestDevice();
    dev_two_ = CreateTestDevice();
  }

  static SANE_Device CreateTestDevice() {
    SANE_Device dev;
    dev.name = "Test Name";
    dev.vendor = "Test Vendor";
    dev.model = "Test Model";
    dev.type = "film scanner";

    return dev;
  }

  SANE_Device dev_;
  SANE_Device dev_two_;
  const SANE_Device* empty_devices_[1] = {NULL};
  const SANE_Device* one_device_[2] = {&dev_, NULL};
  const SANE_Device* two_devices_[3] = {&dev_, &dev_two_, NULL};
};

TEST_F(SaneClientTest, ScannerInfoFromDeviceListInvalidParameters) {
  EXPECT_FALSE(SaneClientImpl::DeviceListToScannerInfo(NULL).has_value());
}

TEST_F(SaneClientTest, ScannerInfoFromDeviceListNoDevices) {
  std::optional<std::vector<ScannerInfo>> info =
      SaneClientImpl::DeviceListToScannerInfo(empty_devices_);
  EXPECT_TRUE(info.has_value());
  EXPECT_EQ(info->size(), 0);
}

TEST_F(SaneClientTest, ScannerInfoFromDeviceListOneDevice) {
  std::optional<std::vector<ScannerInfo>> opt_info =
      SaneClientImpl::DeviceListToScannerInfo(one_device_);
  EXPECT_TRUE(opt_info.has_value());
  std::vector<ScannerInfo> info = opt_info.value();
  ASSERT_EQ(info.size(), 1);
  EXPECT_EQ(info[0].name(), dev_.name);
  EXPECT_EQ(info[0].manufacturer(), dev_.vendor);
  EXPECT_EQ(info[0].model(), dev_.model);
  EXPECT_EQ(info[0].type(), dev_.type);
}

TEST_F(SaneClientTest, ScannerInfoFromDeviceListNullFields) {
  dev_ = CreateTestDevice();
  dev_.name = NULL;
  std::optional<std::vector<ScannerInfo>> opt_info =
      SaneClientImpl::DeviceListToScannerInfo(one_device_);
  EXPECT_TRUE(opt_info.has_value());
  EXPECT_EQ(opt_info->size(), 0);

  dev_ = CreateTestDevice();
  dev_.vendor = NULL;
  opt_info = SaneClientImpl::DeviceListToScannerInfo(one_device_);
  EXPECT_TRUE(opt_info.has_value());
  std::vector<ScannerInfo> info = opt_info.value();
  ASSERT_EQ(info.size(), 1);
  EXPECT_EQ(info[0].name(), dev_.name);
  EXPECT_EQ(info[0].manufacturer(), "");
  EXPECT_EQ(info[0].model(), dev_.model);
  EXPECT_EQ(info[0].type(), dev_.type);

  dev_ = CreateTestDevice();
  dev_.model = NULL;
  opt_info = SaneClientImpl::DeviceListToScannerInfo(one_device_);
  EXPECT_TRUE(opt_info.has_value());
  info = opt_info.value();
  ASSERT_EQ(info.size(), 1);
  EXPECT_EQ(info[0].name(), dev_.name);
  EXPECT_EQ(info[0].manufacturer(), dev_.vendor);
  EXPECT_EQ(info[0].model(), "");
  EXPECT_EQ(info[0].type(), dev_.type);

  dev_ = CreateTestDevice();
  dev_.type = NULL;
  opt_info = SaneClientImpl::DeviceListToScannerInfo(one_device_);
  EXPECT_TRUE(opt_info.has_value());
  info = opt_info.value();
  ASSERT_EQ(info.size(), 1);
  EXPECT_EQ(info[0].name(), dev_.name);
  EXPECT_EQ(info[0].manufacturer(), dev_.vendor);
  EXPECT_EQ(info[0].model(), dev_.model);
  EXPECT_EQ(info[0].type(), "");
}

TEST_F(SaneClientTest, ScannerInfoFromDeviceListMultipleDevices) {
  std::optional<std::vector<ScannerInfo>> opt_info =
      SaneClientImpl::DeviceListToScannerInfo(two_devices_);
  EXPECT_FALSE(opt_info.has_value());

  dev_two_.name = "Test Device 2";
  dev_two_.vendor = "Test Vendor 2";
  opt_info = SaneClientImpl::DeviceListToScannerInfo(two_devices_);
  EXPECT_TRUE(opt_info.has_value());
  std::vector<ScannerInfo> info = opt_info.value();
  ASSERT_EQ(info.size(), 2);
  EXPECT_EQ(info[0].name(), dev_.name);
  EXPECT_EQ(info[0].manufacturer(), dev_.vendor);
  EXPECT_EQ(info[0].model(), dev_.model);
  EXPECT_EQ(info[0].type(), dev_.type);

  EXPECT_EQ(info[1].name(), dev_two_.name);
  EXPECT_EQ(info[1].manufacturer(), dev_two_.vendor);
  EXPECT_EQ(info[1].model(), dev_two_.model);
  EXPECT_EQ(info[1].type(), dev_two_.type);
}

namespace {

SANE_Option_Descriptor CreateDescriptor(const char* name,
                                        SANE_Value_Type type,
                                        int size) {
  SANE_Option_Descriptor desc;
  desc.name = name;
  desc.type = type;
  desc.constraint_type = SANE_CONSTRAINT_NONE;
  desc.size = size;
  return desc;
}

}  // namespace

TEST(SaneOptionIntTest, SetIntSucceeds) {
  SaneOption option(
      CreateDescriptor("Test Name", SANE_TYPE_INT, sizeof(SANE_Word)), 7);
  EXPECT_TRUE(option.Set(54));
  EXPECT_EQ(*static_cast<SANE_Int*>(option.GetPointer()), 54);
}

TEST(SaneOptionIntTest, SetDoubleSucceeds) {
  SaneOption option(
      CreateDescriptor("Test Name", SANE_TYPE_INT, sizeof(SANE_Word)), 7);
  // Should round towards 0.
  EXPECT_TRUE(option.Set(295.7));
  EXPECT_EQ(option.Get<int>().value(), 295);
}

TEST(SaneOptionIntTest, SetStringFails) {
  SaneOption option(
      CreateDescriptor("Test Name", SANE_TYPE_INT, sizeof(SANE_Word)), 7);
  EXPECT_TRUE(option.Set(17));
  EXPECT_FALSE(option.Set("test"));
  EXPECT_EQ(option.Get<int>().value(), 17);
}

TEST(SaneOptionIntTest, GetIndex) {
  SaneOption option(
      CreateDescriptor("Test Name", SANE_TYPE_INT, sizeof(SANE_Word)), 7);
  EXPECT_EQ(option.GetIndex(), 7);
}

TEST(SaneOptionIntTest, GetName) {
  SaneOption option(
      CreateDescriptor("Test Name", SANE_TYPE_INT, sizeof(SANE_Word)), 7);
  EXPECT_EQ(option.GetName(), "Test Name");
}

TEST(SaneOptionIntTest, DisplayValue) {
  SaneOption option(
      CreateDescriptor("Test Name", SANE_TYPE_INT, sizeof(SANE_Word)), 2);
  EXPECT_TRUE(option.Set(247));
  EXPECT_EQ(option.DisplayValue(), "247");
}

TEST(SaneOptionIntTest, CopiesDoNotAlias) {
  SaneOption option(
      CreateDescriptor("Test Name", SANE_TYPE_INT, sizeof(SANE_Word)), 2);
  EXPECT_TRUE(option.Set(88));
  EXPECT_EQ(option.DisplayValue(), "88");

  SaneOption option_two = option;
  EXPECT_TRUE(option_two.Set(9));
  EXPECT_EQ(option_two.DisplayValue(), "9");
  EXPECT_EQ(option.DisplayValue(), "88");
}

TEST(SaneOptionFixedTest, SetIntSucceeds) {
  SaneOption option(
      CreateDescriptor("Test Name", SANE_TYPE_FIXED, sizeof(SANE_Word)), 7);
  EXPECT_TRUE(option.Set(54));
  SANE_Fixed f = *static_cast<SANE_Fixed*>(option.GetPointer());
  EXPECT_EQ(static_cast<int>(SANE_UNFIX(f)), 54);
}

TEST(SaneOptionFixedTest, SetDoubleSucceeds) {
  SaneOption option(
      CreateDescriptor("Test Name", SANE_TYPE_FIXED, sizeof(SANE_Word)), 7);
  EXPECT_TRUE(option.Set(436.2));
  SANE_Fixed f = *static_cast<SANE_Fixed*>(option.GetPointer());
  EXPECT_FLOAT_EQ(SANE_UNFIX(f), 436.2);
}

TEST(SaneOptionFixedTest, SetStringFails) {
  SaneOption option(
      CreateDescriptor("Test Name", SANE_TYPE_FIXED, sizeof(SANE_Word)), 7);
  EXPECT_TRUE(option.Set(17));
  EXPECT_FALSE(option.Set("test"));
  SANE_Fixed f = *static_cast<SANE_Fixed*>(option.GetPointer());
  EXPECT_EQ(static_cast<int>(SANE_UNFIX(f)), 17);
}

TEST(SaneOptionFixedTest, GetIndex) {
  SaneOption option(
      CreateDescriptor("Test Name", SANE_TYPE_FIXED, sizeof(SANE_Word)), 7);
  EXPECT_EQ(option.GetIndex(), 7);
}

TEST(SaneOptionFixedTest, GetName) {
  SaneOption option(
      CreateDescriptor("Test Name", SANE_TYPE_FIXED, sizeof(SANE_Word)), 7);
  EXPECT_EQ(option.GetName(), "Test Name");
}

TEST(SaneOptionFixedTest, DisplayValue) {
  SaneOption option(
      CreateDescriptor("Test Name", SANE_TYPE_FIXED, sizeof(SANE_Word)), 2);
  EXPECT_TRUE(option.Set(247));
  EXPECT_EQ(option.DisplayValue(), "247");
}

TEST(SaneOptionFixedTest, CopiesDoNotAlias) {
  SaneOption option(
      CreateDescriptor("Test Name", SANE_TYPE_FIXED, sizeof(SANE_Word)), 2);
  EXPECT_TRUE(option.Set(88));
  EXPECT_EQ(option.DisplayValue(), "88");

  SaneOption option_two = option;
  EXPECT_TRUE(option_two.Set(9));
  EXPECT_EQ(option_two.DisplayValue(), "9");
  EXPECT_EQ(option.DisplayValue(), "88");
}

TEST(SaneOptionStringTest, SetStringSucceeds) {
  SaneOption option(CreateDescriptor("Test Name", SANE_TYPE_STRING, 8), 7);
  EXPECT_TRUE(option.Set("test"));
  EXPECT_STREQ(static_cast<char*>(option.GetPointer()), "test");

  // Longest string that fits (with null terminator).
  EXPECT_TRUE(option.Set("1234567"));
  EXPECT_STREQ(static_cast<char*>(option.GetPointer()), "1234567");
}

TEST(SaneOptionStringTest, SetStringTooLongFails) {
  SaneOption option(CreateDescriptor("Test Name", SANE_TYPE_STRING, 8), 7);
  EXPECT_TRUE(option.Set("test"));

  // String that is exactly one character too long.
  EXPECT_FALSE(option.Set("12345678"));

  // String that is many characters too long.
  EXPECT_FALSE(option.Set("This is a much longer string than can fit."));
  EXPECT_STREQ(static_cast<char*>(option.GetPointer()), "test");
}

TEST(SaneOptionStringTest, SetIntFails) {
  SaneOption option(CreateDescriptor("Test Name", SANE_TYPE_STRING, 32), 7);
  EXPECT_TRUE(option.Set("test"));
  EXPECT_FALSE(option.Set(54));
  EXPECT_STREQ(static_cast<char*>(option.GetPointer()), "test");
}

TEST(SaneOptionStringTest, GetIndex) {
  SaneOption option(CreateDescriptor("Test Name", SANE_TYPE_STRING, 32), 7);
  EXPECT_EQ(option.GetIndex(), 7);
}

TEST(SaneOptionStringTest, GetName) {
  SaneOption option(CreateDescriptor("Test Name", SANE_TYPE_STRING, 32), 7);
  EXPECT_EQ(option.GetName(), "Test Name");
}

TEST(SaneOptionStringTest, DisplayValue) {
  SaneOption option(CreateDescriptor("Test Name", SANE_TYPE_STRING, 32), 2);
  EXPECT_TRUE(option.Set("test string"));
  EXPECT_EQ(option.DisplayValue(), "test string");
}

TEST(SaneOptionStringTest, CopiesDoNotAlias) {
  SaneOption option(CreateDescriptor("Test Name", SANE_TYPE_STRING, 32), 2);
  EXPECT_TRUE(option.Set("test string"));
  EXPECT_EQ(option.DisplayValue(), "test string");

  SaneOption option_two = option;
  EXPECT_TRUE(option_two.Set("other value"));
  EXPECT_EQ(option.DisplayValue(), "test string");
  EXPECT_EQ(option_two.DisplayValue(), "other value");
}

TEST(ValidOptionValues, InvalidDescriptorWordList) {
  SANE_Option_Descriptor desc;
  desc.constraint_type = SANE_CONSTRAINT_STRING_LIST;
  desc.type = SANE_TYPE_INT;
  std::vector<SANE_String_Const> valid_values = {nullptr};
  desc.constraint.string_list = valid_values.data();

  std::optional<std::vector<uint32_t>> values =
      SaneDeviceImpl::GetValidIntOptionValues(nullptr, desc);
  EXPECT_FALSE(values.has_value());
}

TEST(ValidOptionValues, EmptyWordList) {
  SANE_Option_Descriptor desc;
  desc.constraint_type = SANE_CONSTRAINT_WORD_LIST;
  desc.type = SANE_TYPE_INT;
  std::vector<SANE_Word> valid_values = {0};
  desc.constraint.word_list = valid_values.data();

  std::optional<std::vector<uint32_t>> values =
      SaneDeviceImpl::GetValidIntOptionValues(nullptr, desc);
  EXPECT_TRUE(values.has_value());
  EXPECT_EQ(values.value().size(), 0);
}

TEST(ValidOptionValues, NonEmptyWordListFixed) {
  SANE_Option_Descriptor desc;
  desc.constraint_type = SANE_CONSTRAINT_WORD_LIST;
  desc.type = SANE_TYPE_FIXED;
  std::vector<SANE_Word> valid_values = {4, SANE_FIX(0), SANE_FIX(729.0),
                                         SANE_FIX(3682.34), SANE_FIX(15)};
  desc.constraint.word_list = valid_values.data();

  std::optional<std::vector<uint32_t>> values =
      SaneDeviceImpl::GetValidIntOptionValues(nullptr, desc);
  EXPECT_TRUE(values.has_value());
  EXPECT_EQ(values.value().size(), 4);
  EXPECT_EQ(values.value(), std::vector<uint32_t>({0, 729, 3682, 15}));
}

TEST(ValidOptionValues, NonEmptyWordListInt) {
  SANE_Option_Descriptor desc;
  desc.constraint_type = SANE_CONSTRAINT_WORD_LIST;
  desc.type = SANE_TYPE_INT;
  std::vector<SANE_Word> valid_values = {4, 0, 729, 368234, 15};
  desc.constraint.word_list = valid_values.data();

  std::optional<std::vector<uint32_t>> values =
      SaneDeviceImpl::GetValidIntOptionValues(nullptr, desc);
  EXPECT_TRUE(values.has_value());
  EXPECT_EQ(values.value().size(), 4);
  EXPECT_EQ(values.value(), std::vector<uint32_t>({0, 729, 368234, 15}));
}

TEST(ValidOptionValues, InvalidDescriptorRangeList) {
  SANE_Option_Descriptor desc;
  desc.constraint_type = SANE_CONSTRAINT_RANGE;
  desc.type = SANE_TYPE_INT;
  SANE_Range range;
  desc.constraint.range = &range;

  std::optional<std::vector<std::string>> values =
      SaneDeviceImpl::GetValidStringOptionValues(nullptr, desc);
  EXPECT_FALSE(values.has_value());
}

TEST(ValidOptionValues, EmptyRangeList) {
  SANE_Option_Descriptor desc;
  desc.constraint_type = SANE_CONSTRAINT_RANGE;
  desc.type = SANE_TYPE_INT;
  SANE_Range range;
  range.min = 5;
  range.max = 4;
  range.quant = 1;
  desc.constraint.range = &range;

  std::optional<std::vector<uint32_t>> values =
      SaneDeviceImpl::GetValidIntOptionValues(nullptr, desc);
  EXPECT_TRUE(values.has_value());
  EXPECT_EQ(values.value().size(), 0);
}

TEST(ValidOptionValues, SingleStepRangeListFixed) {
  SANE_Option_Descriptor desc;
  desc.constraint_type = SANE_CONSTRAINT_RANGE;
  desc.type = SANE_TYPE_FIXED;
  SANE_Range range;
  range.min = SANE_FIX(5);
  range.max = SANE_FIX(11);
  range.quant = SANE_FIX(1.2);
  desc.constraint.range = &range;

  std::optional<std::vector<uint32_t>> values =
      SaneDeviceImpl::GetValidIntOptionValues(nullptr, desc);
  EXPECT_TRUE(values.has_value());
  EXPECT_EQ(values.value(), std::vector<uint32_t>({5, 6, 7, 8, 9, 10}));
}

TEST(ValidOptionValues, SingleStepRangeListInt) {
  SANE_Option_Descriptor desc;
  desc.constraint_type = SANE_CONSTRAINT_RANGE;
  desc.type = SANE_TYPE_INT;
  SANE_Range range;
  range.min = 5;
  range.max = 11;
  range.quant = 1;
  desc.constraint.range = &range;

  std::optional<std::vector<uint32_t>> values =
      SaneDeviceImpl::GetValidIntOptionValues(nullptr, desc);
  EXPECT_TRUE(values.has_value());
  EXPECT_EQ(values.value(), std::vector<uint32_t>({5, 6, 7, 8, 9, 10, 11}));
}

TEST(ValidOptionValues, FourStepRangeListFixed) {
  SANE_Option_Descriptor desc;
  desc.constraint_type = SANE_CONSTRAINT_RANGE;
  desc.type = SANE_TYPE_FIXED;
  SANE_Range range;
  range.min = SANE_FIX(13);
  range.max = SANE_FIX(28);
  range.quant = SANE_FIX(4);
  desc.constraint.range = &range;

  std::optional<std::vector<uint32_t>> values =
      SaneDeviceImpl::GetValidIntOptionValues(nullptr, desc);
  EXPECT_TRUE(values.has_value());
  EXPECT_EQ(values.value(), std::vector<uint32_t>({13, 17, 21, 25}));
}

TEST(ValidOptionValues, FourStepRangeListInt) {
  SANE_Option_Descriptor desc;
  desc.constraint_type = SANE_CONSTRAINT_RANGE;
  desc.type = SANE_TYPE_INT;
  SANE_Range range;
  range.min = 13;
  range.max = 28;
  range.quant = 4;
  desc.constraint.range = &range;

  std::optional<std::vector<uint32_t>> values =
      SaneDeviceImpl::GetValidIntOptionValues(nullptr, desc);
  EXPECT_TRUE(values.has_value());
  EXPECT_EQ(values.value(), std::vector<uint32_t>({13, 17, 21, 25}));
}

TEST(ValidOptionValues, InvalidDescriptorStringList) {
  SANE_Option_Descriptor desc;
  desc.constraint_type = SANE_CONSTRAINT_WORD_LIST;
  std::vector<SANE_Word> valid_values = {4, 0, 729, 368234, 15};
  desc.constraint.word_list = valid_values.data();

  std::optional<std::vector<std::string>> values =
      SaneDeviceImpl::GetValidStringOptionValues(nullptr, desc);
  EXPECT_FALSE(values.has_value());
}

TEST(ValidOptionValues, EmptyStringList) {
  SANE_Option_Descriptor desc;
  desc.constraint_type = SANE_CONSTRAINT_STRING_LIST;
  std::vector<SANE_String_Const> valid_values = {nullptr};
  desc.constraint.string_list = valid_values.data();

  std::optional<std::vector<std::string>> values =
      SaneDeviceImpl::GetValidStringOptionValues(nullptr, desc);
  EXPECT_TRUE(values.has_value());
  EXPECT_EQ(values.value().size(), 0);
}

TEST(ValidOptionValues, NonEmptyStringList) {
  SANE_Option_Descriptor desc;
  desc.constraint_type = SANE_CONSTRAINT_STRING_LIST;
  std::vector<SANE_String_Const> valid_values = {"Color", "Gray", "Lineart",
                                                 nullptr};
  desc.constraint.string_list = valid_values.data();

  std::optional<std::vector<std::string>> values =
      SaneDeviceImpl::GetValidStringOptionValues(nullptr, desc);
  desc.constraint.string_list = valid_values.data();
  values = SaneDeviceImpl::GetValidStringOptionValues(nullptr, desc);
  EXPECT_TRUE(values.has_value());
  EXPECT_EQ(values.value().size(), 3);
  EXPECT_EQ(values.value(),
            std::vector<std::string>({"Color", "Gray", "Lineart"}));
}

TEST(GetOptionRange, InvalidConstraint) {
  SANE_Option_Descriptor desc;
  desc.name = "Test";
  desc.constraint_type = SANE_CONSTRAINT_WORD_LIST;

  EXPECT_FALSE(SaneDeviceImpl::GetOptionRange(nullptr, desc).has_value());

  desc.constraint_type = SANE_CONSTRAINT_NONE;
  EXPECT_FALSE(SaneDeviceImpl::GetOptionRange(nullptr, desc).has_value());
}

TEST(GetOptionRange, InvalidType) {
  SANE_Option_Descriptor desc;
  desc.name = "Test";
  desc.constraint_type = SANE_CONSTRAINT_RANGE;
  SANE_Range range;
  range.min = 13;
  range.max = 28;
  range.quant = 4;
  desc.constraint.range = &range;

  desc.type = SANE_TYPE_STRING;
  EXPECT_FALSE(SaneDeviceImpl::GetOptionRange(nullptr, desc).has_value());

  desc.type = SANE_TYPE_BOOL;
  EXPECT_FALSE(SaneDeviceImpl::GetOptionRange(nullptr, desc).has_value());
}

TEST(GetOptionRange, ValidFixedValue) {
  SANE_Option_Descriptor desc;
  desc.name = "Test";
  desc.constraint_type = SANE_CONSTRAINT_RANGE;
  SANE_Range range;
  range.min = SANE_FIX(2.3);
  range.max = SANE_FIX(4.9);
  range.quant = SANE_FIX(0.1);
  desc.constraint.range = &range;
  desc.type = SANE_TYPE_FIXED;

  std::optional<OptionRange> range_result =
      SaneDeviceImpl::GetOptionRange(nullptr, desc);
  EXPECT_TRUE(range_result.has_value());
  EXPECT_NEAR(range_result.value().start, 2.3, 1e-4);
  EXPECT_NEAR(range_result.value().size, 2.6, 1e-4);
}

TEST(GetOptionRange, ValidIntValue) {
  SANE_Option_Descriptor desc;
  desc.name = "Test";
  desc.constraint_type = SANE_CONSTRAINT_RANGE;
  SANE_Range range;
  range.min = 3;
  range.max = 27;
  range.quant = 1;
  desc.constraint.range = &range;
  desc.type = SANE_TYPE_INT;

  std::optional<OptionRange> range_result =
      SaneDeviceImpl::GetOptionRange(nullptr, desc);
  EXPECT_TRUE(range_result.has_value());
  EXPECT_NEAR(range_result.value().start, 3, 1e-4);
  EXPECT_NEAR(range_result.value().size, 24, 1e-4);
}

}  // namespace lorgnette
