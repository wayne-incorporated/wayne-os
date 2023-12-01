// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/files/scoped_temp_dir.h>
#include <memory>
#include <gmock/gmock.h>

#include "pciguard/sysfs_utils.h"

using base::CreateDirectory;
using base::CreateSymbolicLink;
using base::FilePath;
using base::WriteFile;

namespace pciguard {

namespace {

constexpr char kMockTestDevice1[] =
    "/sys/devices/pci0000:00/0000:00:0d.2/domain0/0-0/0-1";
constexpr char kMockTestDevice2[] =
    "/sys/devices/pci0000:00/0000:00:0d.2/domain0/0-0/0-2";
constexpr char kMockPciDevice[] = "/sys/bus/pci/devices/0000:04:00.0";
constexpr char kBusThunderboltPath[] = "/sys/bus/thunderbolt";

}  // namespace

class SysfsUtilsTest : public ::testing::Test {
 protected:
  void SetUp() override {
    // Create a "fake root"
    ASSERT_TRUE(root_dir_.CreateUniqueTempDir());
    auto root_path = root_dir_.GetPath();
    root_ = root_path.value();

    // Create SysfsUtils and make it use the fake root.
    utils_ = std::make_unique<SysfsUtils>(root_path);

    // Setup fake sysfs in the fake root
    ASSERT_TRUE(base::CreateDirectory(utils_->tbt_devices_path_));

    // Create thunderbolt dev 1
    auto dev = FilePath(root_ + kMockTestDevice1);
    ASSERT_TRUE(CreateDirectory(dev));
    ASSERT_TRUE(WriteFile(dev.Append("authorized"), "0"));
    ASSERT_TRUE(CreateSymbolicLink(FilePath(root_ + kBusThunderboltPath),
                                   dev.Append("subsystem")));
    ASSERT_TRUE(CreateSymbolicLink(
        dev, FilePath(root_ + "/sys/bus/thunderbolt/devices/0-1")));

    // Create thunderbolt dev 2
    dev = FilePath(root_ + kMockTestDevice2);
    ASSERT_TRUE(CreateDirectory(dev));
    ASSERT_TRUE(WriteFile(dev.Append("authorized"), "0"));
    ASSERT_TRUE(CreateSymbolicLink(FilePath(root_ + kBusThunderboltPath),
                                   dev.Append("subsystem")));
    ASSERT_TRUE(CreateSymbolicLink(
        dev, FilePath(root_ + "/sys/bus/thunderbolt/devices/0-2")));

    // Create PCI dev
    dev = base::FilePath(root_ + kMockPciDevice);
    ASSERT_TRUE(base::CreateDirectory(dev));
    ASSERT_TRUE(WriteFile(dev.Append("removable"), "removable"));
    ASSERT_TRUE(WriteFile(dev.Append("remove"), "0"));

    ASSERT_TRUE(base::WriteFile(utils_->pci_lockdown_path_, "1"));
  }

  std::string root_;
  base::ScopedTempDir root_dir_;
  std::unique_ptr<SysfsUtils> utils_;
};

TEST_F(SysfsUtilsTest, CheckAuthorizeThunderboltDev) {
  // Set authorized to 0 for device 1
  auto dev1 = FilePath(root_ + kMockTestDevice1);
  auto file1 = dev1.Append("authorized");
  ASSERT_TRUE(WriteFile(file1, "0"));

  // This should set it to "1"
  utils_->AuthorizeThunderboltDev(dev1);

  // Verify
  std::string data = "0";
  ASSERT_TRUE(ReadFileToString(file1, &data));
  EXPECT_EQ(data, "1");

  // Set authorized to 0 to device 2
  auto dev2 = FilePath(root_ + kMockTestDevice2);
  auto file2 = dev2.Append("authorized");
  ASSERT_TRUE(WriteFile(file2, "0"));

  // This should set it to "1"
  utils_->AuthorizeThunderboltDev(dev2);

  // Verify
  data = "0";
  ASSERT_TRUE(ReadFileToString(file2, &data));
  EXPECT_EQ(data, "1");
}

TEST_F(SysfsUtilsTest, CheckDenyNewDevices) {
  // Intialize lockdown with "0"
  ASSERT_TRUE(base::WriteFile(utils_->pci_lockdown_path_, "0"));

  // This should set it to "1"
  utils_->DenyNewDevices();

  // Verify
  std::string data = "0";
  ASSERT_TRUE(ReadFileToString(utils_->pci_lockdown_path_, &data));
  EXPECT_EQ(data, "1");
}

TEST_F(SysfsUtilsTest, CheckAuthorizeAllDevices) {
  // Intialize lockdown with "1""
  ASSERT_TRUE(WriteFile(utils_->pci_lockdown_path_, "1"));

  // Intialize rescan with "1""
  ASSERT_TRUE(WriteFile(utils_->pci_rescan_path_, "0"));

  // Set authorized to 0 for device 1
  auto file1 = FilePath(root_ + kMockTestDevice1 + "/authorized");
  ASSERT_TRUE(WriteFile(file1, "0"));

  // Set authorized to 0 for device 2
  auto file2 = FilePath(root_ + kMockTestDevice2 + "/authorized");
  ASSERT_TRUE(WriteFile(file1, "0"));

  utils_->AuthorizeAllDevices();

  // Verify lockdown = 0
  std::string data = "1";
  ASSERT_TRUE(ReadFileToString(utils_->pci_lockdown_path_, &data));
  EXPECT_EQ(data, "0");

  // Verify rescan = 1
  data = "0";
  ASSERT_TRUE(ReadFileToString(utils_->pci_rescan_path_, &data));
  EXPECT_EQ(data, "1");

  // Verify file 1 is authorized
  data = "0";
  ASSERT_TRUE(ReadFileToString(file1, &data));
  EXPECT_EQ(data, "1");

  // Verify file 2 is authorized
  data = "0";
  ASSERT_TRUE(ReadFileToString(file2, &data));
  EXPECT_EQ(data, "1");
}

TEST_F(SysfsUtilsTest, CheckDeauthorizeAllDevices) {
  // Intialize lockdown with "0"
  ASSERT_TRUE(base::WriteFile(utils_->pci_lockdown_path_, "0"));

  auto remove = FilePath(root_ + kMockPciDevice + "/remove");
  ASSERT_TRUE(base::WriteFile(remove, "0"));

  // Set authorized to 1 for device 1
  auto file1 = FilePath(root_ + kMockTestDevice1 + "/authorized");
  ASSERT_TRUE(WriteFile(file1, "1"));

  // Set authorized to 1 for device 2
  auto file2 = FilePath(root_ + kMockTestDevice2 + "/authorized");
  ASSERT_TRUE(WriteFile(file2, "1"));

  utils_->DeauthorizeAllDevices();

  // Verify
  std::string data = "0";
  ASSERT_TRUE(ReadFileToString(utils_->pci_lockdown_path_, &data));
  EXPECT_EQ(data, "1");

  data = "0";
  ASSERT_TRUE(ReadFileToString(remove, &data));
  EXPECT_EQ(data, "1");

  // Verify file 1 is deauthorized
  data = "1";
  ASSERT_TRUE(ReadFileToString(file1, &data));
  EXPECT_EQ(data, "0");

  // Verify file 2 is deauthorized
  data = "1";
  ASSERT_TRUE(ReadFileToString(file2, &data));
  EXPECT_EQ(data, "0");
}

}  // namespace pciguard
