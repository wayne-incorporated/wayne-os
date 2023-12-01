// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <utility>

#include <base/files/file_path.h>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "diagnostics/cros_healthd/fetchers/storage/device_info.h"
#include "diagnostics/cros_healthd/fetchers/storage/mock/mock_platform.h"
#include "diagnostics/mojom/public/cros_healthd_probe.mojom.h"

namespace diagnostics {
namespace {

namespace mojom = ::ash::cros_healthd::mojom;
using ::testing::ReturnPointee;
using ::testing::StrictMock;

constexpr char kFakeDevnode[] = "dev/node/path";
constexpr char kFakeSubsystemMmc[] = "block:mmc";
constexpr char kFakeSubsystemNvme[] = "block:nvme";
constexpr char kFakeSubsystemUfs[] = "block:scsi:scsi:scsi:pci";
constexpr char kFakeSubsystemSata[] = "block:scsi:pci";
constexpr uint64_t kFakeSize = 16 * 1024;
constexpr uint64_t kFakeBlockSize = 512;
constexpr mojom::StorageDevicePurpose kFakePurpose =
    mojom::StorageDevicePurpose::kSwapDevice;

class StorageDeviceInfoTest : public ::testing::Test {
 protected:
  std::unique_ptr<StrictMock<MockPlatform>> CreateMockPlatform() {
    auto mock_platform = std::make_unique<StrictMock<MockPlatform>>();
    EXPECT_CALL(*mock_platform,
                GetDeviceSizeBytes(base::FilePath(kFakeDevnode)))
        .WillOnce(ReturnPointee(&kFakeSize));
    EXPECT_CALL(*mock_platform,
                GetDeviceBlockSizeBytes(base::FilePath(kFakeDevnode)))
        .WillOnce(ReturnPointee(&kFakeBlockSize));
    return mock_platform;
  }
};

TEST_F(StorageDeviceInfoTest, FetchEmmcTest) {
  constexpr char kPath[] =
      "cros_healthd/fetchers/storage/testdata/sys/block/mmcblk0";
  auto mock_platform = CreateMockPlatform();
  auto dev_info = StorageDeviceInfo::Create(
      base::FilePath(kPath), base::FilePath(kFakeDevnode), kFakeSubsystemMmc,
      kFakePurpose, mock_platform.get());
  EXPECT_NE(nullptr, dev_info);

  auto info_result = dev_info->FetchDeviceInfo();
  EXPECT_TRUE(info_result.has_value());

  auto info = std::move(info_result.value());
  EXPECT_EQ(kFakeDevnode, info->path);
  EXPECT_EQ(kFakeSubsystemMmc, info->type);
  EXPECT_EQ(kFakeSize, info->size);
  EXPECT_EQ(184, info->read_time_seconds_since_last_boot);
  EXPECT_EQ(13849, info->write_time_seconds_since_last_boot);
  EXPECT_EQ((uint64_t)84710472 * kFakeBlockSize,
            info->bytes_read_since_last_boot);
  EXPECT_EQ((uint64_t)7289304 * kFakeBlockSize,
            info->bytes_written_since_last_boot);
  EXPECT_EQ(7392, info->io_time_seconds_since_last_boot);
  EXPECT_TRUE(info->discard_time_seconds_since_last_boot.is_null());
  EXPECT_EQ(0x5050, info->vendor_id->get_emmc_oemid());
  EXPECT_EQ(0x4D4E504D4E50, info->product_id->get_emmc_pnm());
  EXPECT_EQ(0x8, info->revision->get_emmc_prv());
  EXPECT_EQ("PNMPNM", info->name);
  EXPECT_EQ("0x1223344556677889", info->firmware_string);
  EXPECT_EQ(0x1223344556677889, info->firmware_version->get_emmc_fwrev());
  EXPECT_TRUE(info->device_info->is_emmc_device_info());
  EXPECT_EQ(0xA5, info->device_info->get_emmc_device_info()->manfid);
  EXPECT_EQ(0x4D4E504D4E50, info->device_info->get_emmc_device_info()->pnm);
  EXPECT_EQ(0x8, info->device_info->get_emmc_device_info()->prv);
  EXPECT_EQ(0x1223344556677889,
            info->device_info->get_emmc_device_info()->fwrev);
  EXPECT_EQ(kFakePurpose, info->purpose);
  EXPECT_EQ(0xA5, info->manufacturer_id);
  EXPECT_EQ(0x1EAFBED5, info->serial);
}

TEST_F(StorageDeviceInfoTest, FetchEmmcTestWithOldMmc) {
  constexpr char kPath[] =
      "cros_healthd/fetchers/storage/testdata/sys/block/mmcblk2";
  auto mock_platform = CreateMockPlatform();
  auto dev_info = StorageDeviceInfo::Create(
      base::FilePath(kPath), base::FilePath(kFakeDevnode), kFakeSubsystemMmc,
      kFakePurpose, mock_platform.get());
  EXPECT_NE(nullptr, dev_info);

  auto info_result = dev_info->FetchDeviceInfo();
  EXPECT_TRUE(info_result.has_value());

  auto info = std::move(info_result.value());
  EXPECT_EQ(kFakeDevnode, info->path);
  EXPECT_EQ(kFakeSubsystemMmc, info->type);
  EXPECT_EQ(kFakeSize, info->size);
  EXPECT_EQ(184, info->read_time_seconds_since_last_boot);
  EXPECT_EQ(13849, info->write_time_seconds_since_last_boot);
  EXPECT_EQ((uint64_t)84710472 * kFakeBlockSize,
            info->bytes_read_since_last_boot);
  EXPECT_EQ((uint64_t)7289304 * kFakeBlockSize,
            info->bytes_written_since_last_boot);
  EXPECT_EQ(7392, info->io_time_seconds_since_last_boot);
  EXPECT_TRUE(info->discard_time_seconds_since_last_boot.is_null());
  EXPECT_EQ(0x5050, info->vendor_id->get_emmc_oemid());
  EXPECT_EQ(0x4D4E504D4E50, info->product_id->get_emmc_pnm());
  EXPECT_EQ(0x4, info->revision->get_emmc_prv());
  EXPECT_EQ("PNMPNM", info->name);
  EXPECT_EQ("0x1223344556677889", info->firmware_string);
  EXPECT_EQ(0x1223344556677889, info->firmware_version->get_emmc_fwrev());
  EXPECT_TRUE(info->device_info->is_emmc_device_info());
  EXPECT_EQ(0xA5, info->device_info->get_emmc_device_info()->manfid);
  EXPECT_EQ(0x4D4E504D4E50, info->device_info->get_emmc_device_info()->pnm);
  EXPECT_EQ(0x4, info->device_info->get_emmc_device_info()->prv);
  EXPECT_EQ(0x1223344556677889,
            info->device_info->get_emmc_device_info()->fwrev);
  EXPECT_EQ(kFakePurpose, info->purpose);
  EXPECT_EQ(0xA5, info->manufacturer_id);
  EXPECT_EQ(0x1EAFBED5, info->serial);
}

TEST_F(StorageDeviceInfoTest, FetchEmmcTestWithNoData) {
  constexpr char kPath[] =
      "cros_healthd/fetchers/storage/testdata/sys/block/mmcblk1";
  auto mock_platform = std::make_unique<StrictMock<MockPlatform>>();
  auto dev_info = StorageDeviceInfo::Create(
      base::FilePath(kPath), base::FilePath(kFakeDevnode), kFakeSubsystemMmc,
      kFakePurpose, mock_platform.get());
  EXPECT_EQ(nullptr, dev_info);
}

TEST_F(StorageDeviceInfoTest, FetchNvmeTest) {
  constexpr char kPath[] =
      "cros_healthd/fetchers/storage/testdata/sys/block/nvme0n1";
  auto mock_platform = CreateMockPlatform();
  auto dev_info = StorageDeviceInfo::Create(
      base::FilePath(kPath), base::FilePath(kFakeDevnode), kFakeSubsystemNvme,
      kFakePurpose, mock_platform.get());
  EXPECT_NE(nullptr, dev_info);

  auto info_result = dev_info->FetchDeviceInfo();
  EXPECT_TRUE(info_result.has_value());

  auto info = std::move(info_result.value());
  EXPECT_EQ(kFakeDevnode, info->path);
  EXPECT_EQ(kFakeSubsystemNvme, info->type);
  EXPECT_EQ(kFakeSize, info->size);
  EXPECT_EQ(144, info->read_time_seconds_since_last_boot);
  EXPECT_EQ(22155, info->write_time_seconds_since_last_boot);
  EXPECT_EQ((uint64_t)35505772 * kFakeBlockSize,
            info->bytes_read_since_last_boot);
  EXPECT_EQ((uint64_t)665648234 * kFakeBlockSize,
            info->bytes_written_since_last_boot);
  EXPECT_EQ(4646, info->io_time_seconds_since_last_boot);
  EXPECT_EQ(200, info->discard_time_seconds_since_last_boot->value);
  EXPECT_EQ(0x1812, info->vendor_id->get_nvme_subsystem_vendor());
  EXPECT_EQ(0x3243, info->product_id->get_nvme_subsystem_device());
  EXPECT_EQ(0x13, info->revision->get_nvme_pcie_rev());
  EXPECT_EQ("test_nvme_model", info->name);
  EXPECT_EQ("TEST_REV", info->firmware_string);
  EXPECT_EQ(0x5645525F54534554,
            info->firmware_version->get_nvme_firmware_rev());
  EXPECT_TRUE(info->device_info->is_nvme_device_info());
  EXPECT_EQ(0x1812,
            info->device_info->get_nvme_device_info()->subsystem_vendor);
  EXPECT_EQ(0x3243,
            info->device_info->get_nvme_device_info()->subsystem_device);
  EXPECT_EQ(0x13, info->device_info->get_nvme_device_info()->pcie_rev);
  EXPECT_EQ(0x5645525F54534554,
            info->device_info->get_nvme_device_info()->firmware_rev);
  EXPECT_EQ(kFakePurpose, info->purpose);
  EXPECT_EQ(0, info->manufacturer_id);
  EXPECT_EQ(0, info->serial);
}

TEST_F(StorageDeviceInfoTest, FetchNvmeTestWithLegacyRevision) {
  constexpr char kPath[] =
      "cros_healthd/fetchers/storage/testdata/sys/block/missing_revision";
  auto mock_platform = CreateMockPlatform();
  auto dev_info = StorageDeviceInfo::Create(
      base::FilePath(kPath), base::FilePath(kFakeDevnode), kFakeSubsystemNvme,
      kFakePurpose, mock_platform.get());
  EXPECT_NE(nullptr, dev_info);

  auto info_result = dev_info->FetchDeviceInfo();
  EXPECT_TRUE(info_result.has_value());

  auto info = std::move(info_result.value());
  EXPECT_EQ(kFakeDevnode, info->path);
  EXPECT_EQ(kFakeSubsystemNvme, info->type);
  EXPECT_EQ(kFakeSize, info->size);
  EXPECT_EQ(144, info->read_time_seconds_since_last_boot);
  EXPECT_EQ(22155, info->write_time_seconds_since_last_boot);
  EXPECT_EQ((uint64_t)35505772 * kFakeBlockSize,
            info->bytes_read_since_last_boot);
  EXPECT_EQ((uint64_t)665648234 * kFakeBlockSize,
            info->bytes_written_since_last_boot);
  EXPECT_EQ(4646, info->io_time_seconds_since_last_boot);
  EXPECT_EQ(200, info->discard_time_seconds_since_last_boot->value);
  EXPECT_EQ(0x1812, info->vendor_id->get_nvme_subsystem_vendor());
  EXPECT_EQ(0x3243, info->product_id->get_nvme_subsystem_device());
  EXPECT_EQ(0x17, info->revision->get_nvme_pcie_rev());
  EXPECT_EQ("test_nvme_model", info->name);
  EXPECT_EQ("TEST_REV", info->firmware_string);
  EXPECT_EQ(0x5645525F54534554,
            info->firmware_version->get_nvme_firmware_rev());
  EXPECT_TRUE(info->device_info->is_nvme_device_info());
  EXPECT_EQ(0x1812,
            info->device_info->get_nvme_device_info()->subsystem_vendor);
  EXPECT_EQ(0x3243,
            info->device_info->get_nvme_device_info()->subsystem_device);
  EXPECT_EQ(0x17, info->device_info->get_nvme_device_info()->pcie_rev);
  EXPECT_EQ(0x5645525F54534554,
            info->device_info->get_nvme_device_info()->firmware_rev);
  EXPECT_EQ(kFakePurpose, info->purpose);
  EXPECT_EQ(0, info->manufacturer_id);
  EXPECT_EQ(0, info->serial);
}

TEST_F(StorageDeviceInfoTest, FetchNvmeTestWithNoData) {
  constexpr char kPath[] =
      "cros_healthd/fetchers/storage/testdata/sys/block/nvme0n2";
  auto mock_platform = std::make_unique<StrictMock<MockPlatform>>();
  auto dev_info = StorageDeviceInfo::Create(
      base::FilePath(kPath), base::FilePath(kFakeDevnode), kFakeSubsystemNvme,
      kFakePurpose, mock_platform.get());
  EXPECT_EQ(nullptr, dev_info);
}

TEST_F(StorageDeviceInfoTest, FetchUFSTest) {
  constexpr char kPath[] =
      "cros_healthd/fetchers/storage/testdata/sys/block/sda";
  auto mock_platform = CreateMockPlatform();
  auto dev_info = StorageDeviceInfo::Create(
      base::FilePath(kPath), base::FilePath(kFakeDevnode), kFakeSubsystemUfs,
      kFakePurpose, mock_platform.get());
  EXPECT_NE(nullptr, dev_info);

  auto info_result = dev_info->FetchDeviceInfo();
  EXPECT_TRUE(info_result.has_value());

  auto info = std::move(info_result.value());
  EXPECT_EQ(kFakeDevnode, info->path);
  EXPECT_EQ(kFakeSubsystemUfs, info->type);
  EXPECT_EQ(kFakeSize, info->size);
  EXPECT_EQ(198, info->read_time_seconds_since_last_boot);
  EXPECT_EQ(89345, info->write_time_seconds_since_last_boot);
  EXPECT_EQ((uint64_t)14995718 * kFakeBlockSize,
            info->bytes_read_since_last_boot);
  EXPECT_EQ((uint64_t)325649111 * kFakeBlockSize,
            info->bytes_written_since_last_boot);
  EXPECT_EQ(7221, info->io_time_seconds_since_last_boot);
  EXPECT_EQ(194, info->discard_time_seconds_since_last_boot->value);
  EXPECT_EQ(0x1337, info->vendor_id->get_jedec_manfid());
  EXPECT_EQ(0, info->product_id->get_other());
  EXPECT_EQ(0, info->revision->get_other());
  EXPECT_EQ("MYUFS", info->name);
  EXPECT_EQ("2022", info->firmware_string);
  EXPECT_EQ(0x32323032, info->firmware_version->get_ufs_fwrev());
  EXPECT_TRUE(info->device_info->is_ufs_device_info());
  EXPECT_EQ(0x1337, info->device_info->get_ufs_device_info()->jedec_manfid);
  EXPECT_EQ(0x32323032, info->device_info->get_ufs_device_info()->fwrev);
  EXPECT_EQ(kFakePurpose, info->purpose);
  EXPECT_EQ(0, info->manufacturer_id);
  EXPECT_EQ(0, info->serial);
}

TEST_F(StorageDeviceInfoTest, FetchUFSTestWithNoData) {
  constexpr char kPath[] =
      "cros_healthd/fetchers/storage/testdata/sys/block/sdb";
  auto mock_platform = std::make_unique<StrictMock<MockPlatform>>();
  auto dev_info = StorageDeviceInfo::Create(
      base::FilePath(kPath), base::FilePath(kFakeDevnode), kFakeSubsystemUfs,
      kFakePurpose, mock_platform.get());
  EXPECT_EQ(nullptr, dev_info);
}

TEST_F(StorageDeviceInfoTest, FetchSataTest) {
  constexpr char kPath[] =
      "cros_healthd/fetchers/storage/testdata/sys/block/sdc";
  auto mock_platform = CreateMockPlatform();
  auto dev_info = StorageDeviceInfo::Create(
      base::FilePath(kPath), base::FilePath(kFakeDevnode), kFakeSubsystemSata,
      kFakePurpose, mock_platform.get());
  EXPECT_NE(nullptr, dev_info);

  auto info_result = dev_info->FetchDeviceInfo();
  EXPECT_TRUE(info_result.has_value());

  auto info = std::move(info_result.value());
  EXPECT_EQ(kFakeDevnode, info->path);
  EXPECT_EQ(kFakeSubsystemSata, info->type);
  EXPECT_EQ(kFakeSize, info->size);
  EXPECT_EQ(4, info->read_time_seconds_since_last_boot);
  EXPECT_EQ(162, info->write_time_seconds_since_last_boot);
  EXPECT_EQ((uint64_t)1011383 * kFakeBlockSize,
            info->bytes_read_since_last_boot);
  EXPECT_EQ((uint64_t)1242744 * kFakeBlockSize,
            info->bytes_written_since_last_boot);
  EXPECT_EQ(38, info->io_time_seconds_since_last_boot);
  EXPECT_EQ(0, info->discard_time_seconds_since_last_boot->value);
  EXPECT_EQ(0, info->vendor_id->get_other());
  EXPECT_EQ(0, info->product_id->get_other());
  EXPECT_EQ(0, info->revision->get_other());
  EXPECT_EQ("BAR SATA", info->name);
  EXPECT_EQ("", info->firmware_string);
  EXPECT_EQ(0, info->firmware_version->get_other());
  EXPECT_TRUE(info->device_info.is_null());
  EXPECT_EQ(kFakePurpose, info->purpose);
  EXPECT_EQ(0, info->manufacturer_id);
  EXPECT_EQ(0, info->serial);
}

}  // namespace
}  // namespace diagnostics
