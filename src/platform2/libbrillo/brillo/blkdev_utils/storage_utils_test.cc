// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "brillo/blkdev_utils/storage_utils.h"

#include <map>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <brillo/blkdev_utils/storage_device.h>
#include <brillo/file_utils.h>
#include <gtest/gtest.h>

namespace brillo {

class MockStorageUtils : public StorageUtils {
 public:
  void SetAbsPathReturnValue(
      std::map<base::FilePath, base::FilePath>& abs_path_map) {
    abs_path_map_ = abs_path_map;
  }

 protected:
  base::FilePath GetAbsPath(const base::FilePath& path) override {
    return abs_path_map_[path];
  }

  std::map<base::FilePath, base::FilePath> abs_path_map_;
};

TEST(NvmeTest, GetStorageTypeTest) {
  base::FilePath root("/");
  base::FilePath root_disk = root.Append("dev/nvme0n1");
  MockStorageUtils storage_utils_mock = MockStorageUtils();
  EXPECT_EQ(StorageType::nvme,
            storage_utils_mock.GetStorageType(root, root_disk));
}

TEST(EmmcTest, GetStorageTypeTest) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  base::FilePath root = temp_dir.GetPath();
  base::FilePath root_disk = root.Append("dev/mmcblk0");
  base::FilePath type_file_path = root.Append("sys/block/mmcblk0/device/type");
  std::map<base::FilePath, base::FilePath> abs_path_map{
      {type_file_path,
       base::FilePath(
           "/sys/devices/pci0000:00/0000:00:1a.0/mmc_host/mmc1/mmc1:0001")},
  };
  MockStorageUtils storage_utils_mock = MockStorageUtils();
  storage_utils_mock.SetAbsPathReturnValue(abs_path_map);
  EXPECT_EQ(StorageType::emmc,
            storage_utils_mock.GetStorageType(root, root_disk));
}

TEST(UsbTest, GetStorageTypeTest) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  base::FilePath root = temp_dir.GetPath();
  base::FilePath root_disk = root.Append("dev/sda");
  base::FilePath type_file_path = root.Append("sys/block/sda/device/type");
  std::map<base::FilePath, base::FilePath> abs_path_map{
      {type_file_path,
       base::FilePath(
           "/sys/devices/pci0000:00/0000:00:14.0/usb4/4-1/4-1:1.0/host1/"
           "target1:0:0/1:0:0:0")},
  };
  MockStorageUtils storage_utils_mock = MockStorageUtils();
  storage_utils_mock.SetAbsPathReturnValue(abs_path_map);
  EXPECT_EQ(StorageType::usb,
            storage_utils_mock.GetStorageType(root, root_disk));
}

TEST(UfsTest, GetStorageTypeTest) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  base::FilePath root = temp_dir.GetPath();
  base::FilePath root_disk = root.Append("dev/sda");
  base::FilePath type_file_path = root.Append("sys/block/sda/device/type");
  std::map<base::FilePath, base::FilePath> abs_path_map{
      {type_file_path,
       base::FilePath(
           "/sys/devices/pci0000:00/0000:00:12.7/host0/ufs0:0:0/0:0:0:0")},
  };
  MockStorageUtils storage_utils_mock = MockStorageUtils();
  storage_utils_mock.SetAbsPathReturnValue(abs_path_map);
  EXPECT_EQ(StorageType::ufs,
            storage_utils_mock.GetStorageType(root, root_disk));
}

TEST(UfsDriverTest, GetStorageTypeTest) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  base::FilePath root = temp_dir.GetPath();
  base::FilePath root_disk = root.Append("dev/sda");
  base::FilePath dev_node = root.Append("sys/block/sda/device");
  base::FilePath type_file_path = dev_node.Append("type");
  base::FilePath vendor_file = dev_node.Append("vendor");
  base::FilePath driver_path = dev_node.Append("../../../driver");
  ASSERT_TRUE(brillo::WriteStringToFile(vendor_file, ""));
  std::map<base::FilePath, base::FilePath> abs_path_map{
      {type_file_path,
       base::FilePath(
           "/sys/devices/pci0000:00/0000:00:12.7/host0/target0:0:0/0:0:0:0")},
      {driver_path, root.Append("sys/bus/pci/drivers/ufshcd")},
  };
  MockStorageUtils storage_utils_mock = MockStorageUtils();
  storage_utils_mock.SetAbsPathReturnValue(abs_path_map);
  EXPECT_EQ(StorageType::ufs,
            storage_utils_mock.GetStorageType(root, root_disk));
}

TEST(AtaTest, GetStorageTypeTest) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  base::FilePath root = temp_dir.GetPath();
  base::FilePath root_disk = root.Append("dev/sda");
  base::FilePath dev_node = root.Append("sys/block/sda/device");
  base::FilePath type_file_path = dev_node.Append("type");
  base::FilePath vendor_file = dev_node.Append("vendor");
  ASSERT_TRUE(brillo::WriteStringToFile(vendor_file, "ATA vendor"));
  std::map<base::FilePath, base::FilePath> abs_path_map{
      {type_file_path,
       base::FilePath(
           "/sys/devices/pci0000:00/0000:00:12.7/host0/target0:0:0/0:0:0:0")}};
  MockStorageUtils storage_utils_mock = MockStorageUtils();
  storage_utils_mock.SetAbsPathReturnValue(abs_path_map);
  EXPECT_EQ(StorageType::ata,
            storage_utils_mock.GetStorageType(root, root_disk));
}

TEST(OthersTest, GetStorageTypeTest) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());
  base::FilePath root = temp_dir.GetPath();
  base::FilePath root_disk = root.Append("dev/sda");
  base::FilePath type_file_path = root.Append("sys/block/sda/device/type");
  std::map<base::FilePath, base::FilePath> abs_path_map{
      {type_file_path,
       base::FilePath(
           "/sys/devices/pci0000:00/0000:00:12.7/host0/other0:0:0/0:0:0:0")}};
  MockStorageUtils storage_utils_mock = MockStorageUtils();
  storage_utils_mock.SetAbsPathReturnValue(abs_path_map);
  EXPECT_EQ(StorageType::others,
            storage_utils_mock.GetStorageType(root, root_disk));
}

TEST(StorageUtils, AppendPartition) {
  EXPECT_EQ(AppendPartition(base::FilePath("/dev/sda"), 12),
            base::FilePath("/dev/sda12"));
  EXPECT_EQ(AppendPartition(base::FilePath("/dev/nvme0n1"), 12),
            base::FilePath("/dev/nvme0n1p12"));
}

}  // namespace brillo
