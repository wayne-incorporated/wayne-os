// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "brillo/blkdev_utils/storage_utils.h"

#include <memory>
#include <string>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/memory/free_deleter.h>
#include <base/strings/string_util.h>
#include <brillo/blkdev_utils/emmc.h>
#include <brillo/blkdev_utils/storage_device.h>
#include <brillo/blkdev_utils/ufs.h>
#include <brillo/strings/string_utils.h>

namespace brillo {

base::FilePath StorageUtils::GetAbsPath(const base::FilePath& path) {
  base::FilePath abs_path = base::MakeAbsoluteFilePath(path);
  if (abs_path.empty()) {
    PLOG(ERROR) << "Failed to get the absolute path for: " << path;
  }
  return abs_path;
}

StorageType StorageUtils::GetStorageType(const base::FilePath& root,
                                         const base::FilePath& root_disk) {
  base::FilePath basename = root_disk.BaseName();
  if (base::StartsWith(basename.value(), "nvme")) {
    return StorageType::nvme;
  }

  base::FilePath sys_dev = root.Append("sys/block").Append(basename);
  base::FilePath dev_node = sys_dev.Append("device");
  base::FilePath type_file_abs_path = GetAbsPath(dev_node.Append("type"));
  if (type_file_abs_path.empty()) {
    return StorageType::others;
  }

  std::string type_file_str = type_file_abs_path.value();
  if (type_file_str.find("mmc") != std::string::npos) {
    return StorageType::emmc;
  }
  if (type_file_str.find("usb") != std::string::npos) {
    return StorageType::usb;
  }
  if (type_file_str.find("ufs") != std::string::npos) {
    return StorageType::ufs;
  }
  if (type_file_str.find("target") != std::string::npos) {
    base::FilePath vendor = dev_node.Append("vendor");
    std::string vendor_str;
    if (!base::ReadFileToString(vendor, &vendor_str)) {
      PLOG(ERROR) << "Fail to read " << vendor.value();
    } else {
      if (string_utils::SplitAtFirst(vendor_str, " ", true).first == "ATA") {
        return StorageType::ata;
      }
      // Check if it is UFS device on PCIe bus. The dev node points to the
      // /sys/devices and '..' on a link will get parents of the target. We
      // aim to find the driver node of a SCSI device, which should point to
      // ufshcd driver.
      base::FilePath driver_abs_path =
          GetAbsPath(dev_node.Append("../../../driver"));
      if (driver_abs_path.BaseName().value() == "ufshcd") {
        return StorageType::ufs;
      }
    }
  }

  return StorageType::others;
}

std::string StorageTypeToString(StorageType type) {
  switch (type) {
    case StorageType::ata:
      return "ata";
    case StorageType::emmc:
      return "emmc";
    case StorageType::nvme:
      return "nvme";
    case StorageType::ufs:
      return "ufs";
    case StorageType::usb:
      return "usb";
    case StorageType::others:
      return "others";
  }
}

std::unique_ptr<StorageDevice> GetStorageDevice(
    const base::FilePath& root_disk) {
  StorageType type =
      StorageUtils().GetStorageType(base::FilePath("/"), root_disk);
  LOG(INFO) << "DUT is using storage: " << StorageTypeToString(type);
  // So far only UFS and eMMC implemented storage specific operations.
  switch (type) {
    case StorageType::ufs: {
      return std::make_unique<Ufs>();
    }
    case StorageType::emmc: {
      return std::make_unique<Emmc>();
    }
    default: {
      return std::make_unique<StorageDevice>();
    }
  }
}

base::FilePath AppendPartition(const base::FilePath& device, int partition) {
  CHECK(!device.empty());
  CHECK_GE(partition, 1);

  std::string value = device.value();
  if (base::IsAsciiDigit(value.back())) {
    value += 'p';
  }
  return base::FilePath(value + std::to_string(partition));
}

}  // namespace brillo
