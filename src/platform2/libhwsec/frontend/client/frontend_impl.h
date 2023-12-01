// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FRONTEND_CLIENT_FRONTEND_IMPL_H_
#define LIBHWSEC_FRONTEND_CLIENT_FRONTEND_IMPL_H_

#include <optional>
#include <vector>

#include <brillo/secure_blob.h>

#include "libhwsec/frontend/client/frontend.h"
#include "libhwsec/frontend/frontend_impl.h"
#include "libhwsec/status.h"
#include "libhwsec/structures/operation_policy.h"

namespace hwsec {

class ClientFrontendImpl : public ClientFrontend, public FrontendImpl {
 public:
  using FrontendImpl::FrontendImpl;
  ~ClientFrontendImpl() override = default;

  StatusOr<brillo::Blob> GetRandomBlob(size_t size) const override;
  StatusOr<bool> IsSrkRocaVulnerable() const override;
  StatusOr<uint32_t> GetFamily() const override;
  StatusOr<uint64_t> GetSpecLevel() const override;
  StatusOr<uint32_t> GetManufacturer() const override;
  StatusOr<uint32_t> GetTpmModel() const override;
  StatusOr<uint64_t> GetFirmwareVersion() const override;
  StatusOr<brillo::Blob> GetVendorSpecific() const override;
  StatusOr<IFXFieldUpgradeInfo> GetIFXFieldUpgradeInfo() const override;
};

}  // namespace hwsec

#endif  // LIBHWSEC_FRONTEND_CLIENT_FRONTEND_IMPL_H_
