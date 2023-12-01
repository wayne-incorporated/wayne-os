// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_BACKEND_VENDOR_H_
#define LIBHWSEC_BACKEND_VENDOR_H_

#include <cstdint>

#include <brillo/secure_blob.h>

#include "libhwsec/status.h"
#include "libhwsec/structures/ifx_info.h"

namespace hwsec {

// Vendor provide the vendor specific commands.
class Vendor {
 public:
  struct RwVersion {
    uint32_t epoch;
    uint32_t major;
    uint32_t minor;
  };

  // Gets the family.
  virtual StatusOr<uint32_t> GetFamily() = 0;

  // Gets the spec level.
  virtual StatusOr<uint64_t> GetSpecLevel() = 0;

  // Gets the manufacturer.
  virtual StatusOr<uint32_t> GetManufacturer() = 0;

  // Gets the TPM model.
  virtual StatusOr<uint32_t> GetTpmModel() = 0;

  // Gets the TPM firmware version.
  virtual StatusOr<uint64_t> GetFirmwareVersion() = 0;

  // Gets the vendor specific string.
  virtual StatusOr<brillo::Blob> GetVendorSpecific() = 0;

  // Gets the TPM fingerprint.
  virtual StatusOr<int32_t> GetFingerprint() = 0;

  // Is the SRK ROCA vulnerable or not.
  virtual StatusOr<bool> IsSrkRocaVulnerable() = 0;

  // Gets the lookup key for Remote Server Unlock.
  virtual StatusOr<brillo::Blob> GetRsuDeviceId() = 0;

  // Gets the IFX upgrade information.
  virtual StatusOr<IFXFieldUpgradeInfo> GetIFXFieldUpgradeInfo() = 0;

  // Declares the TPM firmware is stable.
  virtual Status DeclareTpmFirmwareStable() = 0;

  // Gets the GSC RW version.
  virtual StatusOr<RwVersion> GetRwVersion() = 0;

  // Sends the raw |command|.
  virtual StatusOr<brillo::Blob> SendRawCommand(
      const brillo::Blob& command) = 0;

 protected:
  Vendor() = default;
  ~Vendor() = default;
};

}  // namespace hwsec

#endif  // LIBHWSEC_BACKEND_VENDOR_H_
