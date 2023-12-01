// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_BACKEND_TPM1_VENDOR_H_
#define LIBHWSEC_BACKEND_TPM1_VENDOR_H_

#include <cstdint>
#include <optional>

#include <brillo/secure_blob.h>
#include <tpm_manager/proto_bindings/tpm_manager.pb.h>

#include "libhwsec/backend/tpm1/key_management.h"
#include "libhwsec/backend/tpm1/tss_helper.h"
#include "libhwsec/backend/vendor.h"
#include "libhwsec/proxy/proxy.h"
#include "libhwsec/status.h"
#include "libhwsec/structures/ifx_info.h"

namespace hwsec {

class VendorTpm1 : public Vendor {
 public:
  explicit VendorTpm1(overalls::Overalls& overalls,
                      TssHelper& tss_helper,
                      org::chromium::TpmManagerProxyInterface& tpm_manager,
                      KeyManagementTpm1& key_management)
      : overalls_(overalls),
        tss_helper_(tss_helper),
        tpm_manager_(tpm_manager),
        key_management_(key_management) {}

  StatusOr<uint32_t> GetFamily() override;
  StatusOr<uint64_t> GetSpecLevel() override;
  StatusOr<uint32_t> GetManufacturer() override;
  StatusOr<uint32_t> GetTpmModel() override;
  StatusOr<uint64_t> GetFirmwareVersion() override;
  StatusOr<brillo::Blob> GetVendorSpecific() override;
  StatusOr<int32_t> GetFingerprint() override;
  StatusOr<bool> IsSrkRocaVulnerable() override;
  StatusOr<brillo::Blob> GetRsuDeviceId() override;
  StatusOr<IFXFieldUpgradeInfo> GetIFXFieldUpgradeInfo() override;
  Status DeclareTpmFirmwareStable() override;
  StatusOr<RwVersion> GetRwVersion() override;
  StatusOr<brillo::Blob> SendRawCommand(const brillo::Blob& command) override;

 private:
  Status EnsureVersionInfo();

  overalls::Overalls& overalls_;
  TssHelper& tss_helper_;
  org::chromium::TpmManagerProxyInterface& tpm_manager_;
  KeyManagementTpm1& key_management_;

  std::optional<tpm_manager::GetVersionInfoReply> version_info_;
};

}  // namespace hwsec

#endif  // LIBHWSEC_BACKEND_TPM1_VENDOR_H_
