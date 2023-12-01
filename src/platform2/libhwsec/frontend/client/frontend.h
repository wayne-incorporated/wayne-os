// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FRONTEND_CLIENT_FRONTEND_H_
#define LIBHWSEC_FRONTEND_CLIENT_FRONTEND_H_

#include <optional>
#include <vector>

#include <brillo/secure_blob.h>

#include "libhwsec/frontend/frontend.h"
#include "libhwsec/status.h"
#include "libhwsec/structures/ifx_info.h"

namespace hwsec {

class ClientFrontend : public Frontend {
 public:
  ~ClientFrontend() override = default;

  // Generates random blob with |size|.
  virtual StatusOr<brillo::Blob> GetRandomBlob(size_t size) const = 0;

  // Is the SRK ROCA vulnerable or not.
  virtual StatusOr<bool> IsSrkRocaVulnerable() const = 0;

  // Gets the family.
  virtual StatusOr<uint32_t> GetFamily() const = 0;

  // Gets the spec level.
  virtual StatusOr<uint64_t> GetSpecLevel() const = 0;

  // Gets the manufacturer.
  virtual StatusOr<uint32_t> GetManufacturer() const = 0;

  // Gets the TPM model.
  virtual StatusOr<uint32_t> GetTpmModel() const = 0;

  // Gets the TPM firmware version.
  virtual StatusOr<uint64_t> GetFirmwareVersion() const = 0;

  // Gets the vendor specific string.
  virtual StatusOr<brillo::Blob> GetVendorSpecific() const = 0;

  // Gets the IFX upgrade information.
  virtual StatusOr<IFXFieldUpgradeInfo> GetIFXFieldUpgradeInfo() const = 0;
};

}  // namespace hwsec

#endif  // LIBHWSEC_FRONTEND_CLIENT_FRONTEND_H_
