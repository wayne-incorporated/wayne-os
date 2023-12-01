// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_STRUCTURES_IFX_INFO_H_
#define LIBHWSEC_STRUCTURES_IFX_INFO_H_

#include <cstdint>

namespace hwsec {

// Holds status information pertaining to TPM firmware updates for Infineon
// TPMs.
struct IFXFieldUpgradeInfo {
  // Describes status of a firmware package.
  struct FirmwarePackage {
    uint32_t package_id;
    uint32_t version;
    uint32_t stale_version;
  };

  // Chunk size for transmitting the firmware update.
  uint16_t max_data_size;
  // Version numbers of the bootloader in ROM.
  FirmwarePackage bootloader;
  // Version numbers for the two writable firmware slots.
  FirmwarePackage firmware[2];
  // Status of the TPM - 0x5a3c indicates bootloader mode, i.e. no running
  // TPM firmware.
  uint16_t status;
  // Version numbers of the firmware for which installation has started, but
  // not completed.
  FirmwarePackage process_fw;
  // Total number of updates the TPM has installed in its entire lifetime.
  uint16_t field_upgrade_counter;
};

}  // namespace hwsec

#endif  // LIBHWSEC_STRUCTURES_IFX_INFO_H_
