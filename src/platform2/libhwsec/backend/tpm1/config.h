// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_BACKEND_TPM1_CONFIG_H_
#define LIBHWSEC_BACKEND_TPM1_CONFIG_H_

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <brillo/secure_blob.h>
#include <libcrossystem/crossystem.h>

#include "libhwsec/backend/config.h"
#include "libhwsec/backend/tpm1/tss_helper.h"
#include "libhwsec/proxy/proxy.h"
#include "libhwsec/status.h"
#include "libhwsec/structures/key.h"
#include "libhwsec/structures/operation_policy.h"

namespace hwsec {

extern const int kCurrentUserPcrTpm1;

class ConfigTpm1 : public Config {
 public:
  ConfigTpm1(overalls::Overalls& overalls,
             TssHelper& tss_helper,
             crossystem::Crossystem& crossystem)
      : overalls_(overalls), tss_helper_(tss_helper), crossystem_(crossystem) {}

  StatusOr<OperationPolicy> ToOperationPolicy(
      const OperationPolicySetting& policy) override;
  Status SetCurrentUser(const std::string& current_user) override;
  StatusOr<bool> IsCurrentUserSet() override;
  StatusOr<DeviceConfigSettings::BootModeSetting::Mode> GetCurrentBootMode()
      override;

  using PcrMap = std::map<uint32_t, brillo::Blob>;

  // Converts a device config usage into a PCR map.
  StatusOr<PcrMap> ToPcrMap(const DeviceConfigs& device_config);

  // Converts a device config usage into a PCR map, and fill the value with
  // real PCR value.
  StatusOr<PcrMap> ToCurrentPcrValueMap(const DeviceConfigs& device_config);

  // Converts a device config setting into a PCR map.
  StatusOr<PcrMap> ToSettingsPcrMap(const DeviceConfigSettings& settings);

  // Creates the PCR selection from |device_configs|.
  StatusOr<ScopedTssPcrs> ToPcrSelection(const DeviceConfigs& device_configs);

  // Reads the PCR value in |pcr_index|.
  StatusOr<brillo::Blob> ReadPcr(uint32_t pcr_index);

  // Gets Hardware ID.
  StatusOr<std::string> GetHardwareID();

 private:
  overalls::Overalls& overalls_;
  TssHelper& tss_helper_;
  crossystem::Crossystem& crossystem_;
};

}  // namespace hwsec

#endif  // LIBHWSEC_BACKEND_TPM1_CONFIG_H_
