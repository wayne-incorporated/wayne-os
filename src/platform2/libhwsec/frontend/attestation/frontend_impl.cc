// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec/frontend/attestation/frontend_impl.h"

#include <attestation/proto_bindings/attestation_ca.pb.h>
#include <brillo/secure_blob.h>
#include <libhwsec-foundation/status/status_chain_macros.h>

#include "libhwsec/backend/backend.h"
#include "libhwsec/middleware/middleware.h"
#include "libhwsec/status.h"
#include "libhwsec/structures/key.h"
#include "libhwsec/structures/operation_policy.h"

namespace hwsec {

StatusOr<brillo::SecureBlob> AttestationFrontendImpl::Unseal(
    const brillo::Blob& sealed_data) const {
  return middleware_.CallSync<&Backend::Sealing::Unseal>(
      OperationPolicy{
          .device_configs =
              DeviceConfigs{
                  DeviceConfig::kBootMode,
              },
      },
      sealed_data, Sealing::UnsealOptions{});
}

StatusOr<brillo::Blob> AttestationFrontendImpl::Seal(
    const brillo::SecureBlob& unsealed_data) const {
  return middleware_.CallSync<&Backend::Sealing::Seal>(
      OperationPolicySetting{
          .device_config_settings =
              DeviceConfigSettings{
                  .boot_mode =
                      DeviceConfigSettings::BootModeSetting{
                          .mode = std::nullopt,
                      },
              },
      },
      unsealed_data);
}

StatusOr<attestation::Quote> AttestationFrontendImpl::Quote(
    DeviceConfig device_config, const brillo::Blob& key_blob) const {
  ASSIGN_OR_RETURN(
      ScopedKey key,
      middleware_.CallSync<&Backend::KeyManagement::LoadKey>(
          OperationPolicy{}, key_blob,
          Backend::KeyManagement::LoadKeyOptions{.auto_reload = true}));

  return middleware_.CallSync<&Backend::Attestation::Quote>(
      DeviceConfigs{device_config}, key.GetKey());
}

StatusOr<bool> AttestationFrontendImpl::IsQuoted(
    DeviceConfig device_config, const attestation::Quote& quote) const {
  return middleware_.CallSync<&Backend::Attestation::IsQuoted>(
      DeviceConfigs{device_config}, quote);
}

StatusOr<DeviceConfigSettings::BootModeSetting::Mode>
AttestationFrontendImpl::GetCurrentBootMode() const {
  return middleware_.CallSync<&Backend::Config::GetCurrentBootMode>();
}

}  // namespace hwsec
