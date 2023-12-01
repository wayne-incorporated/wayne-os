// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/fetchers/storage/device_info.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/types/expected.h>
#include <brillo/blkdev_utils/disk_iostat.h>
#include <brillo/blkdev_utils/ufs.h>

#include "diagnostics/base/file_utils.h"
#include "diagnostics/cros_healthd/fetchers/storage/device_info_constants.h"
#include "diagnostics/cros_healthd/utils/error_utils.h"
#include "diagnostics/mojom/public/cros_healthd_probe.mojom.h"

namespace diagnostics {

namespace {

namespace mojom = ::ash::cros_healthd::mojom;

template <typename T>
bool ReadIntegerAndLogError(const base::FilePath& directory,
                            const std::string& filename,
                            bool (*StringToInteger)(base::StringPiece, T*),
                            T* out) {
  if (!ReadInteger(directory, filename, StringToInteger, out)) {
    LOG(ERROR) << "Failed to read " << directory.Append(filename);
    return false;
  }
  return true;
}

template <typename StringType>
bool ReadAndTrimStringAndLogError(const base::FilePath& directory,
                                  const std::string& filename,
                                  StringType* out) {
  if (!ReadAndTrimString(directory.Append(filename), out)) {
    LOG(ERROR) << "Failed to read " << directory.Append(filename);
    return false;
  }
  return true;
}

mojom::NonRemovableBlockDeviceInfoPtr FetchDefaultImmutableBlockDeviceInfo(
    const base::FilePath& dev_sys_path) {
  // This piece is for compatibility and will be replaced with a simple
  // return ""; when all the devices are covered properly.
  std::string model;
  if (!ReadAndTrimString(dev_sys_path, kDefaultModelFile, &model)) {
    if (!ReadAndTrimString(dev_sys_path, kDefaultAltModelFile, &model)) {
      LOG(ERROR) << "Failed to read " << dev_sys_path.Append(kDefaultModelFile)
                 << " and " << dev_sys_path.Append(kDefaultAltModelFile);
      return nullptr;
    }
  }

  auto block_device_info = mojom::NonRemovableBlockDeviceInfo::New();
  block_device_info->name = model;
  block_device_info->vendor_id = mojom::BlockDeviceVendor::NewOther(0);
  block_device_info->product_id = mojom::BlockDeviceProduct::NewOther(0);
  block_device_info->revision = mojom::BlockDeviceRevision::NewOther(0);
  block_device_info->firmware_version = mojom::BlockDeviceFirmware::NewOther(0);
  block_device_info->firmware_string = "";
  return block_device_info;
}

mojom::NonRemovableBlockDeviceInfoPtr FetchEmmcImmutableBlockDeviceInfo(
    const base::FilePath& dev_sys_path) {
  std::string model;
  uint32_t oem_id;
  uint32_t manfid;
  uint64_t fwrev;
  std::string fwrev_str;
  if (!ReadAndTrimString(dev_sys_path, kEmmcNameFile, &model) ||
      !ReadIntegerAndLogError(dev_sys_path, kEmmcManfIdFile,
                              &base::HexStringToUInt, &manfid) ||
      !ReadIntegerAndLogError(dev_sys_path, kEmmcOemIdFile,
                              &base::HexStringToUInt, &oem_id) ||
      !ReadIntegerAndLogError(dev_sys_path, kEmmcFirmwareVersionFile,
                              &base::HexStringToUInt64, &fwrev) ||
      !ReadAndTrimStringAndLogError(dev_sys_path, kEmmcFirmwareVersionFile,
                                    &fwrev_str)) {
    return nullptr;
  }

  // TODO(b/259401555): Revisit the necessity of casting it to uint64_t.
  // "pnm", having the same content as |model|, is an 6 ASCII characters long
  // string, so it cannot be parsed with base::HexStringToUInt64 directly.
  char bytes[sizeof(uint64_t)] = {0};
  memcpy(bytes, model.c_str(), std::min(model.length(), sizeof(uint64_t)));
  uint64_t pnm = *reinterpret_cast<uint64_t*>(bytes);

  uint32_t prv;
  if (!ReadInteger(dev_sys_path, kEmmcRevisionFile, &base::HexStringToUInt,
                   &prv)) {
    // Older eMMC devices may not have prv, but they should have hwrev.
    if (!ReadInteger(dev_sys_path, kEmmcAltRevisionFile, &base::HexStringToUInt,
                     &prv)) {
      LOG(ERROR) << "Failed to read " << dev_sys_path.Append(kEmmcRevisionFile)
                 << " and " << dev_sys_path.Append(kEmmcAltRevisionFile);
      return nullptr;
    }
  }

  auto block_device_info = mojom::NonRemovableBlockDeviceInfo::New();
  block_device_info->name = model;
  block_device_info->vendor_id = mojom::BlockDeviceVendor::NewEmmcOemid(oem_id);
  block_device_info->product_id = mojom::BlockDeviceProduct::NewEmmcPnm(pnm);
  block_device_info->revision = mojom::BlockDeviceRevision::NewEmmcPrv(prv);
  block_device_info->firmware_version =
      mojom::BlockDeviceFirmware::NewEmmcFwrev(fwrev);
  block_device_info->firmware_string = fwrev_str;
  block_device_info->device_info = mojom::BlockDeviceInfo::NewEmmcDeviceInfo(
      mojom::EmmcDeviceInfo::New(manfid, pnm, prv, fwrev));
  return block_device_info;
}

mojom::NonRemovableBlockDeviceInfoPtr FetchNvmeImmutableBlockDeviceInfo(
    const base::FilePath& dev_sys_path) {
  std::string model;
  uint32_t subsystem_vendor;
  uint64_t subsystem_device;
  if (!ReadAndTrimStringAndLogError(dev_sys_path, kNvmeModelFile, &model) ||
      !ReadIntegerAndLogError(dev_sys_path, kNvmeVendorIdFile,
                              &base::HexStringToUInt, &subsystem_vendor) ||
      !ReadIntegerAndLogError(dev_sys_path, kNvmeProductIdFile,
                              &base::HexStringToUInt64, &subsystem_device)) {
    return nullptr;
  }

  uint32_t pcie_rev;
  if (base::PathExists(dev_sys_path.Append(kNvmeRevisionFile))) {
    if (!ReadIntegerAndLogError(dev_sys_path, kNvmeRevisionFile,
                                &base::HexStringToUInt, &pcie_rev)) {
      return nullptr;
    }
  } else {
    // Try legacy method if the revision file is missing.
    std::vector<char> bytes;
    bytes.resize(sizeof(pci_config_space));

    int read = base::ReadFile(dev_sys_path.Append(kNvmeConfigFile),
                              bytes.data(), bytes.size());

    // Failed to read the file.
    if (read < 0) {
      LOG(ERROR) << "Failed to read " << dev_sys_path.Append(kNvmeConfigFile);
      return nullptr;
    }

    // File present, but the config space is truncated, assume revision == 0.
    if (read < sizeof(pci_config_space)) {
      pcie_rev = 0;
    } else {
      pci_config_space* pci = reinterpret_cast<pci_config_space*>(bytes.data());
      pcie_rev = pci->revision;
    }
  }

  std::string str_firmware_rev;
  auto path = dev_sys_path.Append(kNvmeFirmwareVersionFile);
  if (!ReadAndTrimStringAndLogError(dev_sys_path, kNvmeFirmwareVersionFile,
                                    &str_firmware_rev)) {
    LOG(ERROR) << "Failed to read " << path;
    return nullptr;
  }

  char bytes[sizeof(uint64_t)] = {0};
  memcpy(bytes, str_firmware_rev.c_str(),
         std::min(str_firmware_rev.length(), sizeof(uint64_t)));
  uint64_t firmware_rev = *reinterpret_cast<uint64_t*>(bytes);

  auto block_device_info = mojom::NonRemovableBlockDeviceInfo::New();
  block_device_info->name = model;
  block_device_info->vendor_id =
      mojom::BlockDeviceVendor::NewNvmeSubsystemVendor(subsystem_vendor);
  block_device_info->product_id =
      mojom::BlockDeviceProduct::NewNvmeSubsystemDevice(subsystem_device);
  block_device_info->revision =
      mojom::BlockDeviceRevision::NewNvmePcieRev(pcie_rev);
  block_device_info->firmware_version =
      mojom::BlockDeviceFirmware::NewNvmeFirmwareRev(firmware_rev);
  block_device_info->firmware_string = str_firmware_rev;
  block_device_info->device_info =
      mojom::BlockDeviceInfo::NewNvmeDeviceInfo(mojom::NvmeDeviceInfo::New(
          subsystem_vendor, subsystem_device, pcie_rev, firmware_rev));
  return block_device_info;
}

mojom::NonRemovableBlockDeviceInfoPtr FetchUfsImmutableBlockDeviceInfo(
    const base::FilePath& dev_sys_path) {
  std::string model;
  if (!ReadAndTrimStringAndLogError(dev_sys_path, kUfsModelFile, &model)) {
    return nullptr;
  }

  base::FilePath controller_node =
      brillo::UfsSysfsToControllerNode(dev_sys_path);
  if (controller_node.empty()) {
    LOG(ERROR) << "Failed to get controller node for " << dev_sys_path;
    return nullptr;
  }
  uint32_t manfid;
  if (!ReadIntegerAndLogError(controller_node, kUfsManfidFile,
                              &base::HexStringToUInt, &manfid)) {
    return nullptr;
  }

  std::string str_fwrev;
  if (!ReadAndTrimString(dev_sys_path, kUfsFirmwareVersionFile, &str_fwrev)) {
    LOG(ERROR) << "Failed to read "
               << dev_sys_path.Append(kUfsFirmwareVersionFile);
    return nullptr;
  }

  // This is not entirely correct. UFS exports revision as 4 2-byte unicode
  // characters. But Linux's UFS subsystem converts it to a raw ascii string.
  // This is a temporary fixture to provide meaningful info on this aspect.
  // TODO(dlunev): use raw representation, either through ufs-utils, or create
  // a new kernel's node.
  char bytes[sizeof(uint64_t)] = {0};
  memcpy(bytes, str_fwrev.c_str(),
         std::min(str_fwrev.length(), sizeof(uint64_t)));
  uint64_t fwrev = *reinterpret_cast<uint64_t*>(bytes);

  auto block_device_info = mojom::NonRemovableBlockDeviceInfo::New();
  block_device_info->name = model;
  block_device_info->vendor_id =
      mojom::BlockDeviceVendor::NewJedecManfid(manfid);
  block_device_info->product_id = mojom::BlockDeviceProduct::NewOther(0);
  block_device_info->revision = mojom::BlockDeviceRevision::NewOther(0);
  block_device_info->firmware_version =
      mojom::BlockDeviceFirmware::NewUfsFwrev(fwrev);
  block_device_info->firmware_string = str_fwrev;
  block_device_info->device_info = mojom::BlockDeviceInfo::NewUfsDeviceInfo(
      mojom::UfsDeviceInfo::New(/*jedec_manfid=*/manfid, fwrev));
  return block_device_info;
}

mojom::NonRemovableBlockDeviceInfoPtr FetchImmutableBlockDeviceInfo(
    const base::FilePath& dev_sys_path,
    const base::FilePath& dev_node_path,
    const std::string& subsystem,
    mojom::StorageDevicePurpose purpose,
    const Platform* platform) {
  mojom::NonRemovableBlockDeviceInfoPtr block_device_info;

  // A particular device has a chain of subsystems it belongs to. We pass them
  // here in a colon-separated format (e.g. "block:mmc:mmc_host:pci"). We expect
  // that the root subsystem is "block", and the type of the block device
  // immediately follows it.
  auto subs = base::SplitString(subsystem, ":", base::KEEP_WHITESPACE,
                                base::SPLIT_WANT_NONEMPTY);

  if (subs.size() < kMinComponentLength ||
      subs[kBlockSubsystemIndex] != kBlockSubsystem)
    return nullptr;

  if (subs[kBlockTypeSubsystemIndex] == kNvmeSubsystem) {
    block_device_info = FetchNvmeImmutableBlockDeviceInfo(dev_sys_path);
  } else if (subs[kBlockTypeSubsystemIndex] == kMmcSubsystem) {
    block_device_info = FetchEmmcImmutableBlockDeviceInfo(dev_sys_path);
  } else if (brillo::IsUfs(dev_sys_path)) {
    block_device_info = FetchUfsImmutableBlockDeviceInfo(dev_sys_path);
  } else {
    // TODO(b/259401854): Revisit the necessity of default storage type.
    block_device_info = FetchDefaultImmutableBlockDeviceInfo(dev_sys_path);
  }

  if (block_device_info) {
    block_device_info->path = dev_node_path.value();
    block_device_info->type = subsystem;
    block_device_info->purpose = purpose;

    if (auto size_result = platform->GetDeviceSizeBytes(dev_node_path);
        size_result.has_value()) {
      block_device_info->size = size_result.value();
    } else {
      return nullptr;
    }

    // Fetch legacy device info.
    // Not all devices in sysfs have a serial, so ignore the return code.
    ReadInteger(dev_sys_path, kLegacySerialFile, &base::HexStringToUInt,
                &block_device_info->serial);

    // |manfid| (manufacturer_id) is a legacy field for backward compatibility
    // only, so no need to return nullptr when not found.
    uint64_t manfid = 0;
    if (ReadInteger(dev_sys_path, kLegacyManfidFile, &base::HexStringToUInt64,
                    &manfid)) {
      if (manfid > 0xFF) {
        LOG(ERROR)
            << "manfid is expected to be less than or equal to 0xFF, got: "
            << manfid;
        return nullptr;
      }
      block_device_info->manufacturer_id = manfid;
    }
  }

  return block_device_info;
}

}  // namespace

StorageDeviceInfo::StorageDeviceInfo(
    const base::FilePath& dev_sys_path,
    const base::FilePath& dev_node_path,
    mojom::NonRemovableBlockDeviceInfoPtr immutable_block_device_info,
    const Platform* platform)
    : dev_sys_path_(dev_sys_path),
      dev_node_path_(dev_node_path),
      platform_(platform),
      iostat_(dev_sys_path),
      immutable_block_device_info_(std::move(immutable_block_device_info)) {}

std::unique_ptr<StorageDeviceInfo> StorageDeviceInfo::Create(
    const base::FilePath& dev_sys_path,
    const base::FilePath& dev_node_path,
    const std::string& subsystem,
    mojom::StorageDevicePurpose purpose,
    const Platform* platform) {
  auto immutable_block_device_info = FetchImmutableBlockDeviceInfo(
      dev_sys_path, dev_node_path, subsystem, purpose, platform);
  if (!immutable_block_device_info)
    return nullptr;
  return std::unique_ptr<StorageDeviceInfo>(
      new StorageDeviceInfo(dev_sys_path, dev_node_path,
                            std::move(immutable_block_device_info), platform));
}

base::expected<mojom::NonRemovableBlockDeviceInfoPtr, mojom::ProbeErrorPtr>
StorageDeviceInfo::FetchDeviceInfo() {
  auto output_info = immutable_block_device_info_.Clone();
  std::optional<brillo::DiskIoStat::Snapshot> iostat_snapshot =
      iostat_.GetSnapshot();
  if (!iostat_snapshot.has_value()) {
    return base::unexpected(CreateAndLogProbeError(
        mojom::ErrorType::kFileReadError, "Failed retrieving iostat"));
  }

  uint64_t sector_size;
  if (auto sector_size_result =
          platform_->GetDeviceBlockSizeBytes(dev_node_path_);
      sector_size_result.has_value()) {
    sector_size = sector_size_result.value();
  } else {
    return base::unexpected(sector_size_result.error()->Clone());
  }

  output_info->read_time_seconds_since_last_boot =
      static_cast<uint64_t>(iostat_snapshot->GetReadTime().InSeconds());
  output_info->write_time_seconds_since_last_boot =
      static_cast<uint64_t>(iostat_snapshot->GetWriteTime().InSeconds());
  output_info->io_time_seconds_since_last_boot =
      static_cast<uint64_t>(iostat_snapshot->GetIoTime().InSeconds());

  auto discard_time = iostat_snapshot->GetDiscardTime();
  if (discard_time.has_value()) {
    output_info->discard_time_seconds_since_last_boot =
        mojom::NullableUint64::New(
            static_cast<uint64_t>(discard_time.value().InSeconds()));
  }

  // Convert from sectors to bytes.
  output_info->bytes_written_since_last_boot =
      sector_size * iostat_snapshot->GetWrittenSectors();
  output_info->bytes_read_since_last_boot =
      sector_size * iostat_snapshot->GetReadSectors();

  return base::ok(std::move(output_info));
}

}  // namespace diagnostics
