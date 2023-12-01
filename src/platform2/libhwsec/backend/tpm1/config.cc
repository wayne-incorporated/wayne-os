// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec/backend/tpm1/config.h"

#include <cstdint>
#include <map>
#include <string>

#include <base/containers/contains.h>
#include <base/hash/sha1.h>
#include <base/no_destructor.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/stringprintf.h>
#include <crypto/sha2.h>
#include <libhwsec-foundation/crypto/sha.h>
#include <libhwsec-foundation/status/status_chain_macros.h>
#include <openssl/sha.h>

#include "libhwsec/error/tpm1_error.h"
#include "libhwsec/overalls/overalls.h"
#include "libhwsec/status.h"

using brillo::BlobFromString;
using brillo::BlobToString;
using hwsec_foundation::Sha1;
using hwsec_foundation::status::MakeStatus;
using Mode = hwsec::DeviceConfigSettings::BootModeSetting::Mode;

namespace hwsec {

const int kCurrentUserPcrTpm1 = USE_TPM_DYNAMIC ? 11 : 4;

namespace {

constexpr int kBootModePcr = 0;
constexpr int kDeviceModelPcr = 1;

constexpr DeviceConfig kSupportConfigs[] = {
    DeviceConfig::kBootMode,
    DeviceConfig::kDeviceModel,
    DeviceConfig::kCurrentUser,
};

StatusOr<int> DeviceConfigToPcr(DeviceConfig config) {
  switch (config) {
    case DeviceConfig::kBootMode:
      return kBootModePcr;
    case DeviceConfig::kDeviceModel:
      return kDeviceModelPcr;
    case DeviceConfig::kCurrentUser:
      return kCurrentUserPcrTpm1;
  }
  return MakeStatus<TPMError>("Unknown device config",
                              TPMRetryAction::kNoRetry);
}

brillo::Blob GetPCRValueForMode(const Mode& mode) {
  char boot_modes[3] = {mode.developer_mode, mode.recovery_mode,
                        mode.verified_firmware};
  std::string mode_str(std::begin(boot_modes), std::end(boot_modes));
  const std::string mode_digest = base::SHA1HashString(mode_str);

  // PCR0 value immediately after power on.
  const std::string pcr_initial_value(base::kSHA1Length, 0);

  return BlobFromString(base::SHA1HashString(pcr_initial_value + mode_digest));
}

// The mapping that maps pcr value to corresponding boot mode.
const std::map<brillo::Blob, Mode>& BootModeMapping() {
  static const base::NoDestructor<std::map<brillo::Blob, Mode>> mapping([] {
    std::map<brillo::Blob, Mode> mapping;
    // 3-byte boot mode:
    //  - byte 0: 1 if in developer mode, 0 otherwise,
    //  - byte 1: 1 if in recovery mode, 0 otherwise,
    //  - byte 2: 1 if verified firmware, 0 if developer firmware.
    // Iterating through all possible combination of modes.
    for (int i = 0; i < (1 << 3); ++i) {
      Mode mode = {
          .developer_mode = i & 1,
          .recovery_mode = i & 2,
          .verified_firmware = i & 4,
      };
      mapping.emplace(GetPCRValueForMode(mode), mode);
    }
    return mapping;
  }());
  return *mapping;
}

}  // namespace

StatusOr<OperationPolicy> ConfigTpm1::ToOperationPolicy(
    const OperationPolicySetting& policy) {
  DeviceConfigs configs;
  const DeviceConfigSettings& settings = policy.device_config_settings;
  if (settings.boot_mode.has_value()) {
    configs[DeviceConfig::kBootMode] = true;
  }

  if (settings.device_model.has_value()) {
    configs[DeviceConfig::kDeviceModel] = true;
  }

  if (settings.current_user.has_value()) {
    configs[DeviceConfig::kCurrentUser] = true;
  }

  return OperationPolicy{
      .device_configs = configs,
      .permission = policy.permission,
  };
}

Status ConfigTpm1::SetCurrentUser(const std::string& current_user) {
  ASSIGN_OR_RETURN(TSS_HCONTEXT context, tss_helper_.GetTssContext());

  ASSIGN_OR_RETURN(TSS_HTPM tpm_handle, tss_helper_.GetUserTpmHandle());

  brillo::Blob extention = Sha1(brillo::BlobFromString(current_user));

  uint32_t new_pcr_value_length = 0;
  ScopedTssMemory new_pcr_value(overalls_, context);

  RETURN_IF_ERROR(
      MakeStatus<TPM1Error>(overalls_.Ospi_TPM_PcrExtend(
          tpm_handle, kCurrentUserPcrTpm1, extention.size(), extention.data(),
          nullptr, &new_pcr_value_length, new_pcr_value.ptr())))
      .WithStatus<TPMError>("Failed to call Ospi_TPM_PcrExtend");

  return OkStatus();
}

StatusOr<bool> ConfigTpm1::IsCurrentUserSet() {
  ASSIGN_OR_RETURN(brillo::Blob && value, ReadPcr(kCurrentUserPcrTpm1),
                   _.WithStatus<TPMError>("Failed to read current user PCR"));

  return value != brillo::Blob(SHA_DIGEST_LENGTH, 0);
}

StatusOr<Mode> ConfigTpm1::GetCurrentBootMode() {
  const std::map<brillo::Blob, Mode>& mapping = BootModeMapping();
  ASSIGN_OR_RETURN(const brillo::Blob& value, ReadPcr(kBootModePcr),
                   _.WithStatus<TPMError>("Failed to read boot mode PCR"));

  if (auto it = mapping.find(value); it != mapping.end()) {
    return it->second;
  }
  return MakeStatus<TPMError>("Encountered invalid boot mode value: " +
                                  base::HexEncode(value.data(), value.size()),
                              TPMRetryAction::kNoRetry);
}

StatusOr<ConfigTpm1::PcrMap> ConfigTpm1::ToPcrMap(
    const DeviceConfigs& device_config) {
  PcrMap result;
  for (DeviceConfig config : kSupportConfigs) {
    if (device_config[config]) {
      ASSIGN_OR_RETURN(int pcr, DeviceConfigToPcr(config),
                       _.WithStatus<TPMError>("Failed to convert to PCR"));
      result[pcr] = brillo::Blob();
    }
  }
  return result;
}

StatusOr<ConfigTpm1::PcrMap> ConfigTpm1::ToCurrentPcrValueMap(
    const DeviceConfigs& device_config) {
  PcrMap result;
  for (DeviceConfig config : kSupportConfigs) {
    if (device_config[config]) {
      ASSIGN_OR_RETURN(int pcr, DeviceConfigToPcr(config),
                       _.WithStatus<TPMError>("Failed to convert to PCR"));

      ASSIGN_OR_RETURN(result[pcr], ReadPcr(pcr),
                       _.WithStatus<TPMError>(base::StringPrintf(
                           "Failed to read PCR %d value", pcr)));
    }
  }
  return result;
}

StatusOr<brillo::Blob> ConfigTpm1::ReadPcr(uint32_t pcr_index) {
  ASSIGN_OR_RETURN(TSS_HCONTEXT context, tss_helper_.GetTssContext());

  ASSIGN_OR_RETURN(TSS_HTPM tpm_handle, tss_helper_.GetUserTpmHandle());

  uint32_t length = 0;
  ScopedTssMemory buffer(overalls_, context);

  RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls_.Ospi_TPM_PcrRead(
                      tpm_handle, pcr_index, &length, buffer.ptr())))
      .WithStatus<TPMError>("Failed to call Ospi_TPM_PcrRead");

  return brillo::Blob(buffer.value(), buffer.value() + length);
}

StatusOr<ConfigTpm1::PcrMap> ConfigTpm1::ToSettingsPcrMap(
    const DeviceConfigSettings& settings) {
  PcrMap result;

  if (settings.boot_mode.has_value()) {
    const auto& mode = settings.boot_mode->mode;
    if (mode.has_value()) {
      result[kBootModePcr] = GetPCRValueForMode(*mode);
    } else {
      ASSIGN_OR_RETURN(brillo::Blob && value, ReadPcr(kBootModePcr),
                       _.WithStatus<TPMError>("Failed to read boot mode PCR"));
      result[kBootModePcr] = std::move(value);
    }
  }

  if (settings.device_model.has_value()) {
    const auto& hardware_id = settings.device_model->hardware_id;
    if (hardware_id.has_value()) {
      return MakeStatus<TPMError>("Unsupported settings",
                                  TPMRetryAction::kNoRetry);
    } else {
      ASSIGN_OR_RETURN(
          brillo::Blob && value, ReadPcr(kDeviceModelPcr),
          _.WithStatus<TPMError>("Failed to read device model PCR"));
      result[kDeviceModelPcr] = std::move(value);
    }
  }

  if (settings.current_user.has_value()) {
    const auto& username = settings.current_user->username;
    brillo::Blob digest_value(SHA_DIGEST_LENGTH, 0);
    if (username.has_value()) {
      digest_value = Sha1(brillo::CombineBlobs(
          {digest_value, Sha1(BlobFromString(username.value()))}));
    }
    result[kCurrentUserPcrTpm1] = digest_value;
  }

  return result;
}

StatusOr<ScopedTssPcrs> ConfigTpm1::ToPcrSelection(
    const DeviceConfigs& device_configs) {
  ASSIGN_OR_RETURN(const PcrMap& pcr_map, ToPcrMap(device_configs));

  ASSIGN_OR_RETURN(TSS_HCONTEXT context, tss_helper_.GetTssContext());
  ScopedTssPcrs pcrs(overalls_, context);
  RETURN_IF_ERROR(
      MakeStatus<TPM1Error>(overalls_.Ospi_Context_CreateObject(
          context, TSS_OBJECT_TYPE_PCRS, TSS_PCRS_STRUCT_INFO, pcrs.ptr())))
      .WithStatus<TPMError>("Failed to call Ospi_Context_CreateObject");

  for (const PcrMap::value_type& pcr : pcr_map) {
    RETURN_IF_ERROR(
        MakeStatus<TPM1Error>(
            overalls_.Ospi_PcrComposite_SelectPcrIndex(pcrs, pcr.first)))
        .WithStatus<TPMError>(
            "Failed to call Ospi_PcrComposite_SelectPcrIndex");
  }
  return pcrs;
}

StatusOr<std::string> ConfigTpm1::GetHardwareID() {
  auto property = crossystem_.VbGetSystemPropertyString("hwid");
  if (!property.has_value()) {
    return MakeStatus<TPMError>("Failed to read hwid property",
                                TPMRetryAction::kNoRetry);
  }
  return *property;
}

}  // namespace hwsec
