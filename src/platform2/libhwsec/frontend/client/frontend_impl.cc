// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec/frontend/client/frontend_impl.h"

#include <optional>
#include <utility>
#include <vector>

#include <brillo/secure_blob.h>

#include "libhwsec/backend/backend.h"
#include "libhwsec/middleware/middleware.h"
#include "libhwsec/status.h"

using hwsec_foundation::status::MakeStatus;

namespace hwsec {

StatusOr<brillo::Blob> ClientFrontendImpl::GetRandomBlob(size_t size) const {
  return middleware_.CallSync<&Backend::Random::RandomBlob>(size);
}

StatusOr<bool> ClientFrontendImpl::IsSrkRocaVulnerable() const {
  return middleware_.CallSync<&Backend::Vendor::IsSrkRocaVulnerable>();
}

StatusOr<uint32_t> ClientFrontendImpl::GetFamily() const {
  return middleware_.CallSync<&Backend::Vendor::GetFamily>();
}

StatusOr<uint64_t> ClientFrontendImpl::GetSpecLevel() const {
  return middleware_.CallSync<&Backend::Vendor::GetSpecLevel>();
}

StatusOr<uint32_t> ClientFrontendImpl::GetManufacturer() const {
  return middleware_.CallSync<&Backend::Vendor::GetManufacturer>();
}

StatusOr<uint32_t> ClientFrontendImpl::GetTpmModel() const {
  return middleware_.CallSync<&Backend::Vendor::GetTpmModel>();
}

StatusOr<uint64_t> ClientFrontendImpl::GetFirmwareVersion() const {
  return middleware_.CallSync<&Backend::Vendor::GetFirmwareVersion>();
}

StatusOr<brillo::Blob> ClientFrontendImpl::GetVendorSpecific() const {
  return middleware_.CallSync<&Backend::Vendor::GetVendorSpecific>();
}

StatusOr<IFXFieldUpgradeInfo> ClientFrontendImpl::GetIFXFieldUpgradeInfo()
    const {
  return middleware_.CallSync<&Backend::Vendor::GetIFXFieldUpgradeInfo>();
}

}  // namespace hwsec
