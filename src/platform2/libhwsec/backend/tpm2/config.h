// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_BACKEND_TPM2_CONFIG_H_
#define LIBHWSEC_BACKEND_TPM2_CONFIG_H_

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <brillo/secure_blob.h>
#include <libcrossystem/crossystem.h>
#include <trunks/command_transceiver.h>
#include <trunks/trunks_factory.h>

#include "libhwsec/backend/config.h"
#include "libhwsec/backend/tpm2/session_management.h"
#include "libhwsec/backend/tpm2/trunks_context.h"
#include "libhwsec/status.h"
#include "libhwsec/structures/key.h"
#include "libhwsec/structures/operation_policy.h"

namespace hwsec {

class ConfigTpm2 : public Config {
 public:
  ConfigTpm2(TrunksContext& context,
             SessionManagementTpm2& session_management,
             crossystem::Crossystem& crossystem)
      : context_(context),
        session_management_(session_management),
        crossystem_(crossystem) {}

  StatusOr<OperationPolicy> ToOperationPolicy(
      const OperationPolicySetting& policy) override;
  Status SetCurrentUser(const std::string& current_user) override;
  StatusOr<bool> IsCurrentUserSet() override;
  StatusOr<DeviceConfigSettings::BootModeSetting::Mode> GetCurrentBootMode()
      override;

  using PcrMap = std::map<uint32_t, std::string>;

  struct TrunksSession {
    using InnerSession = std::unique_ptr<trunks::PolicySession>;

    // The inner session should not be used directly in most of the case, and it
    // may not contain anything.
    InnerSession session;

    trunks::AuthorizationDelegate* delegate;
  };

  // Defines a set of PCR indexes (in bitmask) and the digest that is valid
  // after computation of sha256 of concatenation of PCR values included in
  // bitmask.
  struct PcrValue {
    // The set of PCR indexes that have to pass the validation.
    uint8_t bitmask[2];
    // The hash digest of the PCR values contained in the bitmask.
    std::string digest;
  };

  // Converts a device config usage into a PCR map.
  StatusOr<PcrMap> ToPcrMap(const DeviceConfigs& device_config);

  // Converts a device config setting into a PCR map.
  StatusOr<PcrMap> ToSettingsPcrMap(const DeviceConfigSettings& settings);

  // Creates a trunks policy session from |policy|, and PolicyOR the
  // |extra_policy_digests| if it's not empty.
  StatusOr<std::unique_ptr<trunks::PolicySession>> GetTrunksPolicySession(
      const OperationPolicy& policy,
      const std::vector<std::string>& extra_policy_digests,
      bool salted,
      bool enable_encryption);

  // Creates a unified session from |policy|.
  StatusOr<TrunksSession> GetTrunksSession(const OperationPolicy& policy,
                                           SessionSecuritySetting setting);

  // Creates the PCR value for PinWeaver digest.
  StatusOr<PcrValue> ToPcrValue(const DeviceConfigSettings& settings);

  // Creates the PCR selection from |device_configs|.
  StatusOr<trunks::TPMS_PCR_SELECTION> ToPcrSelection(
      const DeviceConfigs& device_configs);

  // Gets the policy digest from operation policy setting. Returns empty string
  // if the the policy can be satisfied by HMAC session.
  StatusOr<std::string> GetPolicyDigest(const OperationPolicySetting& policy);

  // Reads the PCR value in |pcr_index|.
  StatusOr<std::string> ReadPcr(uint32_t pcr_index);

  // Gets Hardware ID.
  StatusOr<std::string> GetHardwareID();

 private:
  TrunksContext& context_;
  SessionManagementTpm2& session_management_;
  crossystem::Crossystem& crossystem_;
};

}  // namespace hwsec

#endif  // LIBHWSEC_BACKEND_TPM2_CONFIG_H_
