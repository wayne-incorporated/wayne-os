// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_FETCHERS_STORAGE_DEVICE_INFO_CONSTANTS_H_
#define DIAGNOSTICS_CROS_HEALTHD_FETCHERS_STORAGE_DEVICE_INFO_CONSTANTS_H_

#include <cstdint>

namespace diagnostics {
// Constants for determining storage device type.
inline constexpr char kBlockSubsystem[] = "block";
inline constexpr char kNvmeSubsystem[] = "nvme";
inline constexpr char kMmcSubsystem[] = "mmc";
inline constexpr int kBlockSubsystemIndex = 0;
inline constexpr int kBlockTypeSubsystemIndex = 1;
inline constexpr int kMinComponentLength = 2;

// Constants for fetching legacy device info.
inline constexpr char kLegacySerialFile[] = "device/serial";
inline constexpr char kLegacyManfidFile[] = "device/manfid";

// Constants for fetching default device info.
inline constexpr char kDefaultModelFile[] = "device/model";
// The alternative file for reading model name, for backward compatibility.
inline constexpr char kDefaultAltModelFile[] = "device/name";

// Constants for fetching eMMC device info.
inline constexpr char kEmmcOemIdFile[] = "device/oemid";
inline constexpr char kEmmcManfIdFile[] = "device/manfid";
inline constexpr char kEmmcRevisionFile[] = "device/rev";
// The alternative file for reading revision, for backward compatibility.
inline constexpr char kEmmcAltRevisionFile[] = "device/hwrev";
// `device/name` is also used as pnm_id.
inline constexpr char kEmmcNameFile[] = "device/name";
inline constexpr char kEmmcFirmwareVersionFile[] = "device/fwrev";

// Constants for fetching NVMe device info.
inline constexpr char kNvmeVendorIdFile[] = "device/device/subsystem_vendor";
inline constexpr char kNvmeProductIdFile[] = "device/device/subsystem_device";
inline constexpr char kNvmeRevisionFile[] = "device/device/revision";
inline constexpr char kNvmeConfigFile[] = "device/device/config";
inline constexpr char kNvmeModelFile[] = "device/model";
inline constexpr char kNvmeFirmwareVersionFile[] = "device/firmware_rev";

// Extract from PCI local bus spec 2.2 from December 18, 1998
// (page 191, figure 6-1)
struct pci_config_space {
  uint16_t notrequired[4];
  uint8_t revision;
  char rest[0];
} __attribute__((packed));

// Constants for fetching UFS device info.
inline constexpr char kUfsManfidFile[] = "device_descriptor/manufacturer_id";
inline constexpr char kUfsModelFile[] = "device/model";
inline constexpr char kUfsFirmwareVersionFile[] = "device/rev";

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_FETCHERS_STORAGE_DEVICE_INFO_CONSTANTS_H_
