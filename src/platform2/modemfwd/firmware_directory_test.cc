// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "modemfwd/firmware_directory.h"

#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <gtest/gtest.h>

namespace {

constexpr char kDeviceId[] = "device-id";

constexpr char kMainFirmwareFile1[] = "NAND_10.20.30.40.fls";
constexpr char kMainFirmwareVersion1[] = "10.20.30.40";

constexpr char kMainFirmwareFile2[] = "NAND_10.20.30.45.fls";
constexpr char kMainFirmwareVersion2[] = "10.20.30.45";

constexpr char kOemFirmwareFile1[] = "OEM_cust.11.22.33.44.fls";
constexpr char kOemFirmwareVersion1[] = "11.22.33.44";

constexpr char kOemFirmwareFile2[] = "OEM_cust.11.22.33.45.fls";
constexpr char kOemFirmwareVersion2[] = "11.22.33.45";

constexpr char kCarrierA[] = "CarrierA";
constexpr char kCarrierFirmwareFile1[] = "CarrierA_40.30.20.10.fls";
constexpr char kCarrierFirmwareVersion1[] = "40.30.20.10";

constexpr char kCarrierB[] = "CarrierB";
constexpr char kCarrierFirmwareFile2[] = "Custom_B_50_60.fls";
constexpr char kCarrierFirmwareVersion2[] = "50.60.70.80";

constexpr char kCarrierC[] = "CarrierC";

constexpr char kGenericCarrierFirmwareFile[] = "Generic_V1.59.3.fls";
constexpr char kGenericCarrierFirmwareVersion[] = "V1.59.3";

// Associated payloads
constexpr char kApFirmwareTag[] = "ap";
constexpr char kApFirmwarePath[] = "ap_firmware";
constexpr char kApFirmwareVersion[] = "abc.a40";

constexpr char kDevFirmwareTag[] = "dev";
constexpr char kDevFirmwarePath[] = "dev_firmware";
constexpr char kDevFirmwareVersion[] = "000.012";

}  // namespace

namespace modemfwd {

class FirmwareDirectoryTest : public ::testing::Test {
 public:
  FirmwareDirectoryTest() { CHECK(temp_dir_.CreateUniqueTempDir()); }
  ~FirmwareDirectoryTest() override = default;

 protected:
  void SetUpDirectory(const base::FilePath& manifest,
                      bool manifest_is_valid = true) {
    base::FilePath manifest_in_dir =
        temp_dir_.GetPath().Append("firmware_manifest.prototxt");
    CHECK(base::CopyFile(manifest, manifest_in_dir));
    std::map<std::string, Dlc> dlc_per_variant;
    std::unique_ptr<FirmwareIndex> index =
        ParseFirmwareManifestV2(manifest_in_dir, dlc_per_variant);
    ASSERT_EQ(!!index, manifest_is_valid);
    firmware_directory_ =
        CreateFirmwareDirectory(std::move(index), temp_dir_.GetPath(), "");
  }

  std::unique_ptr<FirmwareDirectory> firmware_directory_;

 private:
  base::ScopedTempDir temp_dir_;
};

TEST_F(FirmwareDirectoryTest, NoFirmwareForDevice) {
  const base::FilePath kManifest("/dev/null");
  SetUpDirectory(kManifest);

  std::string carrier_a(kCarrierA);
  FirmwareDirectory::Files res =
      firmware_directory_->FindFirmware(kDeviceId, &carrier_a);

  EXPECT_FALSE(res.main_firmware.has_value());
  EXPECT_FALSE(res.carrier_firmware.has_value());
}

// ----------------------- MANIFEST V2 TESTS ----------------------------------

TEST_F(FirmwareDirectoryTest, FindFirmwareV2) {
  const base::FilePath kManifest("test_protos/find_firmware_v2.prototxt");
  SetUpDirectory(kManifest);

  std::string carrier_a(kCarrierA);
  FirmwareDirectory::Files res =
      firmware_directory_->FindFirmware(kDeviceId, &carrier_a);

  EXPECT_TRUE(res.main_firmware.has_value());
  const FirmwareFileInfo& main_info = res.main_firmware.value();
  EXPECT_EQ(kMainFirmwareFile1,
            base::FilePath(main_info.firmware_path).BaseName().value());
  EXPECT_EQ(kMainFirmwareVersion1, main_info.version);

  EXPECT_TRUE(res.carrier_firmware.has_value());
  const FirmwareFileInfo& carrier_info = res.carrier_firmware.value();
  EXPECT_EQ(kCarrierA, carrier_a);
  EXPECT_EQ(kCarrierFirmwareFile1,
            base::FilePath(carrier_info.firmware_path).BaseName().value());
  EXPECT_EQ(kCarrierFirmwareVersion1, carrier_info.version);

  EXPECT_FALSE(res.oem_firmware.has_value());
}

TEST_F(FirmwareDirectoryTest, FindFirmwareWithOemV2) {
  const base::FilePath kManifest(
      "test_protos/find_firmware_with_oem_v2.prototxt");
  SetUpDirectory(kManifest);

  std::string carrier_a(kCarrierA);
  FirmwareDirectory::Files res =
      firmware_directory_->FindFirmware(kDeviceId, &carrier_a);

  EXPECT_TRUE(res.main_firmware.has_value());
  const FirmwareFileInfo& main_info = res.main_firmware.value();
  EXPECT_EQ(kMainFirmwareFile1,
            base::FilePath(main_info.firmware_path).BaseName().value());
  EXPECT_EQ(kMainFirmwareVersion1, main_info.version);

  EXPECT_TRUE(res.carrier_firmware.has_value());
  const FirmwareFileInfo& carrier_info = res.carrier_firmware.value();
  EXPECT_EQ(kCarrierA, carrier_a);
  EXPECT_EQ(kCarrierFirmwareFile1,
            base::FilePath(carrier_info.firmware_path).BaseName().value());
  EXPECT_EQ(kCarrierFirmwareVersion1, carrier_info.version);

  EXPECT_TRUE(res.oem_firmware.has_value());
  const FirmwareFileInfo& oem_info = res.oem_firmware.value();
  EXPECT_EQ(kOemFirmwareFile1,
            base::FilePath(oem_info.firmware_path).BaseName().value());
  EXPECT_EQ(kOemFirmwareVersion1, oem_info.version);
}

TEST_F(FirmwareDirectoryTest, FirmwareForDifferentCarrierV2) {
  const base::FilePath kManifest("test_protos/find_firmware_v2.prototxt");
  SetUpDirectory(kManifest);

  std::string carrier_b(kCarrierB);
  FirmwareDirectory::Files res =
      firmware_directory_->FindFirmware(kDeviceId, &carrier_b);
  EXPECT_FALSE(res.carrier_firmware.has_value());
}

TEST_F(FirmwareDirectoryTest, FirmwareForDifferentDeviceV2) {
  const base::FilePath kManifest(
      "test_protos/firmware_for_different_device_v2.prototxt");
  SetUpDirectory(kManifest);

  FirmwareDirectory::Files res =
      firmware_directory_->FindFirmware(kDeviceId, nullptr);
  EXPECT_FALSE(res.main_firmware.has_value());
}

TEST_F(FirmwareDirectoryTest, MultipleCarrierFirmwareV2) {
  const base::FilePath kManifest(
      "test_protos/multiple_carrier_firmware_v2.prototxt");
  SetUpDirectory(kManifest);

  std::string carrier_a(kCarrierA);
  FirmwareDirectory::Files res =
      firmware_directory_->FindFirmware(kDeviceId, &carrier_a);
  EXPECT_TRUE(res.carrier_firmware.has_value());
  const FirmwareFileInfo& info_a = res.carrier_firmware.value();
  EXPECT_EQ(kCarrierA, carrier_a);
  EXPECT_EQ(kCarrierFirmwareFile1,
            base::FilePath(info_a.firmware_path).BaseName().value());
  EXPECT_EQ(kCarrierFirmwareVersion1, info_a.version);

  std::string carrier_b(kCarrierB);
  res = firmware_directory_->FindFirmware(kDeviceId, &carrier_b);
  EXPECT_TRUE(res.carrier_firmware.has_value());
  const FirmwareFileInfo& info_b = res.carrier_firmware.value();
  EXPECT_EQ(kCarrierB, carrier_b);
  EXPECT_EQ(kCarrierFirmwareFile2,
            base::FilePath(info_b.firmware_path).BaseName().value());
  EXPECT_EQ(kCarrierFirmwareVersion2, info_b.version);
}

TEST_F(FirmwareDirectoryTest, GenericFirmwareV2) {
  const base::FilePath kManifest("test_protos/generic_firmware_v2.prototxt");
  SetUpDirectory(kManifest);

  std::string carrier_a(kCarrierA);
  FirmwareDirectory::Files res =
      firmware_directory_->FindFirmware(kDeviceId, &carrier_a);
  EXPECT_TRUE(res.carrier_firmware.has_value());
  const FirmwareFileInfo& info = res.carrier_firmware.value();
  EXPECT_EQ(FirmwareDirectory::kGenericCarrierId, carrier_a);
  EXPECT_EQ(kGenericCarrierFirmwareFile,
            base::FilePath(info.firmware_path).BaseName().value());
  EXPECT_EQ(kGenericCarrierFirmwareVersion, info.version);

  EXPECT_TRUE(res.oem_firmware.has_value());
  const FirmwareFileInfo& oem_info = res.oem_firmware.value();
  EXPECT_EQ(kOemFirmwareFile1,
            base::FilePath(oem_info.firmware_path).BaseName().value());
  EXPECT_EQ(kOemFirmwareVersion1, oem_info.version);
}

TEST_F(FirmwareDirectoryTest, FirmwareSupportsTwoCarriersV2) {
  const base::FilePath kManifest(
      "test_protos/two_carrier_firmware_v2.prototxt");
  SetUpDirectory(kManifest);

  std::string carrier_a(kCarrierA);
  FirmwareDirectory::Files res =
      firmware_directory_->FindFirmware(kDeviceId, &carrier_a);
  EXPECT_TRUE(res.carrier_firmware.has_value());
  const FirmwareFileInfo& info_a = res.carrier_firmware.value();
  EXPECT_EQ(kCarrierA, carrier_a);
  EXPECT_EQ(kCarrierFirmwareFile1,
            base::FilePath(info_a.firmware_path).BaseName().value());
  EXPECT_EQ(kCarrierFirmwareVersion1, info_a.version);

  std::string carrier_b(kCarrierB);
  res = firmware_directory_->FindFirmware(kDeviceId, &carrier_b);
  EXPECT_TRUE(res.carrier_firmware.has_value());
  const FirmwareFileInfo& info_b = res.carrier_firmware.value();
  EXPECT_EQ(kCarrierB, carrier_b);
  EXPECT_EQ(kCarrierFirmwareFile1,
            base::FilePath(info_b.firmware_path).BaseName().value());
  EXPECT_EQ(kCarrierFirmwareVersion1, info_b.version);

  std::string carrier_c(kCarrierC);
  res = firmware_directory_->FindFirmware(kDeviceId, &carrier_c);
  EXPECT_FALSE(res.carrier_firmware.has_value());
}

TEST_F(FirmwareDirectoryTest, SpecificBeforeGenericV2) {
  const base::FilePath kManifest(
      "test_protos/specific_before_generic_v2.prototxt");
  SetUpDirectory(kManifest);

  std::string carrier_a(kCarrierA);
  FirmwareDirectory::Files res =
      firmware_directory_->FindFirmware(kDeviceId, &carrier_a);
  EXPECT_TRUE(res.carrier_firmware.has_value());
  const FirmwareFileInfo& info = res.carrier_firmware.value();
  EXPECT_EQ(kCarrierA, carrier_a);
  EXPECT_EQ(kCarrierFirmwareFile1,
            base::FilePath(info.firmware_path).BaseName().value());
  EXPECT_EQ(kCarrierFirmwareVersion1, info.version);
}

TEST_F(FirmwareDirectoryTest, MainFirmwareDefault) {
  const base::FilePath kManifest("test_protos/main_firmware_default.prototxt");
  SetUpDirectory(kManifest);

  std::string carrier_a(kCarrierA);
  FirmwareDirectory::Files res =
      firmware_directory_->FindFirmware(kDeviceId, &carrier_a);

  EXPECT_TRUE(res.main_firmware.has_value());
  const FirmwareFileInfo& main_info = res.main_firmware.value();
  EXPECT_EQ(kMainFirmwareFile1,
            base::FilePath(main_info.firmware_path).BaseName().value());
  EXPECT_EQ(kMainFirmwareVersion1, main_info.version);

  EXPECT_TRUE(res.carrier_firmware.has_value());
  const FirmwareFileInfo& info_a = res.carrier_firmware.value();
  EXPECT_EQ(kCarrierA, carrier_a);
  EXPECT_EQ(kCarrierFirmwareFile1,
            base::FilePath(info_a.firmware_path).BaseName().value());
  EXPECT_EQ(kCarrierFirmwareVersion1, info_a.version);

  EXPECT_TRUE(res.oem_firmware.has_value());
  const FirmwareFileInfo& oem_info = res.oem_firmware.value();
  EXPECT_EQ(kOemFirmwareFile1,
            base::FilePath(oem_info.firmware_path).BaseName().value());
  EXPECT_EQ(kOemFirmwareVersion1, oem_info.version);
}

TEST_F(FirmwareDirectoryTest, MainFirmwareDefaultForGeneric) {
  const base::FilePath kManifest("test_protos/main_firmware_default.prototxt");
  SetUpDirectory(kManifest);

  // The default main firmware should also apply to the generic/no carrier
  // case.
  FirmwareDirectory::Files res =
      firmware_directory_->FindFirmware(kDeviceId, nullptr);

  EXPECT_TRUE(res.main_firmware.has_value());
  const FirmwareFileInfo& main_info_2 = res.main_firmware.value();
  EXPECT_EQ(kMainFirmwareFile1,
            base::FilePath(main_info_2.firmware_path).BaseName().value());
  EXPECT_EQ(kMainFirmwareVersion1, main_info_2.version);

  EXPECT_TRUE(res.oem_firmware.has_value());
  const FirmwareFileInfo& oem_info = res.oem_firmware.value();
  EXPECT_EQ(kOemFirmwareFile1,
            base::FilePath(oem_info.firmware_path).BaseName().value());
  EXPECT_EQ(kOemFirmwareVersion1, oem_info.version);
}

TEST_F(FirmwareDirectoryTest, MainFirmwareSwitching) {
  const base::FilePath kManifest(
      "test_protos/main_firmware_switching.prototxt");
  SetUpDirectory(kManifest);

  std::string carrier_a(kCarrierA);
  FirmwareDirectory::Files res =
      firmware_directory_->FindFirmware(kDeviceId, &carrier_a);

  EXPECT_TRUE(res.main_firmware.has_value());
  const FirmwareFileInfo& main_info = res.main_firmware.value();
  EXPECT_EQ(kMainFirmwareFile1,
            base::FilePath(main_info.firmware_path).BaseName().value());
  EXPECT_EQ(kMainFirmwareVersion1, main_info.version);

  EXPECT_TRUE(res.carrier_firmware.has_value());
  const FirmwareFileInfo& info_a = res.carrier_firmware.value();
  EXPECT_EQ(kCarrierA, carrier_a);
  EXPECT_EQ(kCarrierFirmwareFile1,
            base::FilePath(info_a.firmware_path).BaseName().value());
  EXPECT_EQ(kCarrierFirmwareVersion1, info_a.version);

  EXPECT_TRUE(res.oem_firmware.has_value());
  const FirmwareFileInfo& oem_info = res.oem_firmware.value();
  EXPECT_EQ(kOemFirmwareFile1,
            base::FilePath(oem_info.firmware_path).BaseName().value());
  EXPECT_EQ(kOemFirmwareVersion1, oem_info.version);

  // Carrier B calls for different main firmware. This can only be encoded
  // in manifest v2.
  std::string carrier_b(kCarrierB);
  res = firmware_directory_->FindFirmware(kDeviceId, &carrier_b);

  EXPECT_TRUE(res.main_firmware.has_value());
  const FirmwareFileInfo& main_info_2 = res.main_firmware.value();
  EXPECT_EQ(kMainFirmwareFile2,
            base::FilePath(main_info_2.firmware_path).BaseName().value());
  EXPECT_EQ(kMainFirmwareVersion2, main_info_2.version);

  EXPECT_TRUE(res.carrier_firmware.has_value());
  const FirmwareFileInfo& info_b = res.carrier_firmware.value();
  EXPECT_EQ(kCarrierB, carrier_b);
  EXPECT_EQ(kCarrierFirmwareFile2,
            base::FilePath(info_b.firmware_path).BaseName().value());
  EXPECT_EQ(kCarrierFirmwareVersion2, info_b.version);

  EXPECT_TRUE(res.oem_firmware.has_value());
  const FirmwareFileInfo& oem_info_2 = res.oem_firmware.value();
  EXPECT_EQ(kOemFirmwareFile2,
            base::FilePath(oem_info_2.firmware_path).BaseName().value());
  EXPECT_EQ(kOemFirmwareVersion2, oem_info_2.version);
}

TEST_F(FirmwareDirectoryTest, MainFirmwareFullySpecified) {
  const base::FilePath kManifest(
      "test_protos/main_firmware_specified.prototxt");
  SetUpDirectory(kManifest);

  std::string carrier_a(kCarrierA);
  FirmwareDirectory::Files res =
      firmware_directory_->FindFirmware(kDeviceId, &carrier_a);

  EXPECT_TRUE(res.main_firmware.has_value());
  const FirmwareFileInfo& main_info = res.main_firmware.value();
  EXPECT_EQ(kMainFirmwareFile1,
            base::FilePath(main_info.firmware_path).BaseName().value());
  EXPECT_EQ(kMainFirmwareVersion1, main_info.version);

  EXPECT_TRUE(res.carrier_firmware.has_value());
  const FirmwareFileInfo& info_a = res.carrier_firmware.value();
  EXPECT_EQ(kCarrierA, carrier_a);
  EXPECT_EQ(kCarrierFirmwareFile1,
            base::FilePath(info_a.firmware_path).BaseName().value());
  EXPECT_EQ(kCarrierFirmwareVersion1, info_a.version);

  EXPECT_TRUE(res.oem_firmware.has_value());
  const FirmwareFileInfo& oem_info = res.oem_firmware.value();
  EXPECT_EQ(kOemFirmwareFile1,
            base::FilePath(oem_info.firmware_path).BaseName().value());
  EXPECT_EQ(kOemFirmwareVersion1, oem_info.version);

  // Carrier B uses the generic firmware, which specifies its own main firmware.
  std::string carrier_b(kCarrierB);
  res = firmware_directory_->FindFirmware(kDeviceId, &carrier_b);

  EXPECT_TRUE(res.main_firmware.has_value());
  const FirmwareFileInfo& main_info_2 = res.main_firmware.value();
  EXPECT_EQ(kMainFirmwareFile2,
            base::FilePath(main_info_2.firmware_path).BaseName().value());
  EXPECT_EQ(kMainFirmwareVersion2, main_info_2.version);

  EXPECT_TRUE(res.carrier_firmware.has_value());
  const FirmwareFileInfo& info_b = res.carrier_firmware.value();
  EXPECT_EQ(FirmwareDirectory::kGenericCarrierId, carrier_b);
  EXPECT_EQ(kGenericCarrierFirmwareFile,
            base::FilePath(info_b.firmware_path).BaseName().value());
  EXPECT_EQ(kGenericCarrierFirmwareVersion, info_b.version);

  EXPECT_TRUE(res.oem_firmware.has_value());
  const FirmwareFileInfo& oem_info_2 = res.oem_firmware.value();
  EXPECT_EQ(kOemFirmwareFile2,
            base::FilePath(oem_info_2.firmware_path).BaseName().value());
  EXPECT_EQ(kOemFirmwareVersion2, oem_info_2.version);
}

TEST_F(FirmwareDirectoryTest, MainFirmwareFullySpecifiedNoGeneric) {
  // If each carrier directly specifies a present main firmware but there's no
  // generic firmware, we can't flash anything for unknown carriers.
  const base::FilePath kManifest(
      "test_protos/main_firmware_specified_no_generic.prototxt");
  SetUpDirectory(kManifest, false);
}

TEST_F(FirmwareDirectoryTest, CarrierSpecifiesAbsentMainFirmware) {
  const base::FilePath kManifest(
      "test_protos/carrier_specifies_absent_main.prototxt");
  SetUpDirectory(kManifest, false);
}

TEST_F(FirmwareDirectoryTest, MalformedDeviceEntry) {
  const base::FilePath kManifest("test_protos/malformed_device_entry.prototxt");
  SetUpDirectory(kManifest, false);
}

TEST_F(FirmwareDirectoryTest, MalformedMainEntryV2) {
  const base::FilePath kManifest(
      "test_protos/malformed_main_firmware_v2.prototxt");
  SetUpDirectory(kManifest, false);
}

TEST_F(FirmwareDirectoryTest, MalformedOemEntryV2) {
  const base::FilePath kManifest(
      "test_protos/malformed_oem_firmware_v2.prototxt");
  SetUpDirectory(kManifest, false);
}

TEST_F(FirmwareDirectoryTest, MalformedCarrierEntryV2) {
  const base::FilePath kManifest(
      "test_protos/malformed_carrier_firmware_v2.prototxt");
  SetUpDirectory(kManifest, false);
}

TEST_F(FirmwareDirectoryTest, AbsolutePathInFilenameV2) {
  const base::FilePath kManifest(
      "test_protos/absolute_path_in_filename_v2.prototxt");
  SetUpDirectory(kManifest, false);
}

TEST_F(FirmwareDirectoryTest, AssocEntryParsingV2) {
  const base::FilePath kManifest(
      "test_protos/single_assoc_firmware_v2.prototxt");
  SetUpDirectory(kManifest);

  FirmwareDirectory::Files res =
      firmware_directory_->FindFirmware(kDeviceId, nullptr);

  EXPECT_TRUE(res.main_firmware.has_value());
  const FirmwareFileInfo& main_info = res.main_firmware.value();
  EXPECT_EQ(kMainFirmwareFile1,
            base::FilePath(main_info.firmware_path).BaseName().value());
  EXPECT_EQ(kMainFirmwareVersion1, main_info.version);

  // Check ap payload is present and has correct path and version
  auto ap_it = res.assoc_firmware.find(kApFirmwareTag);
  EXPECT_FALSE(ap_it == res.assoc_firmware.end());
  EXPECT_EQ(ap_it->second.firmware_path, kApFirmwarePath);
  EXPECT_EQ(ap_it->second.version, kApFirmwareVersion);

  // Check dev payload is present and has correct path and version
  auto dev_it = res.assoc_firmware.find(kDevFirmwareTag);
  EXPECT_FALSE(dev_it == res.assoc_firmware.end());
  EXPECT_EQ(dev_it->second.firmware_path, kDevFirmwarePath);
  EXPECT_EQ(dev_it->second.version, kDevFirmwareVersion);
}

}  // namespace modemfwd
