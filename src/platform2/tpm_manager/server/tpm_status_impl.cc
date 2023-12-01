// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tpm_manager/server/tpm_status_impl.h"

#include <algorithm>
#include <optional>
#include <vector>

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <brillo/file_utils.h>
#include <tpm_manager/server/tpm_util.h>
#include <trousers/trousers.h>
#include <trousers/tss.h>

namespace {

// Minimum size of TPM_DA_INFO struct.
constexpr size_t kMinimumDaInfoSize = 21;

// Minimum size of TPM_CAP_VERSION_INFO struct.
constexpr size_t kMinimumVersionInfoSize = 15;

// The TPM manufacturer code of Infineon.
constexpr uint32_t kInfineonManufacturerCode = 0x49465800;

// The Infineon-specific DA info sub-capability flag.
constexpr uint32_t kInfineonMfrSubCapability = 0x00000802;

// The offset of DA counter in the Infineon-specific DA info data.
constexpr size_t kInfineonDACounterOffset = 9;

// The flag that tells if the tpm is full initialized.
constexpr char kTpmFullyInitializedPath[] =
    "/mnt/stateful_partition/unencrypted/tpm_manager/tpm_owned";

bool TouchTpmFullyInitializedPath() {
  return brillo::WriteBlobToFile<std::vector<char>>(
      base::FilePath(kTpmFullyInitializedPath), {});
}

bool SetNoSrkAuth(tpm_manager::LocalDataStore* local_data_store, bool value) {
  tpm_manager::LocalData local_data;
  if (!local_data_store->Read(&local_data)) {
    LOG(ERROR) << __func__ << ": Failed to read local data.";
    return false;
  }
  local_data.set_no_srk_auth(value);
  if (!local_data_store->Write(local_data)) {
    LOG(ERROR) << __func__ << ": Failed to write local data change.";
    return false;
  }
  return true;
}

bool GetNoSrkAuth(tpm_manager::LocalDataStore* local_data_store) {
  tpm_manager::LocalData local_data;
  if (!local_data_store->Read(&local_data)) {
    LOG(ERROR) << __func__ << ": Failed to read local data.";
    return false;
  }
  return local_data.no_srk_auth();
}

}  // namespace

namespace tpm_manager {

TpmStatusImpl::TpmStatusImpl(LocalDataStore* local_data_store)
    : local_data_store_(local_data_store) {}

bool TpmStatusImpl::IsTpmEnabled() {
  if (!is_enable_initialized_) {
    RefreshOwnedEnabledInfo();
  }
  return is_enabled_;
}

bool TpmStatusImpl::GetTpmOwned(TpmStatus::TpmOwnershipStatus* status) {
  CHECK(status);
  if (kTpmOwned == ownership_status_) {
    *status = ownership_status_;
    return true;
  }

  if (!is_owned_) {
    // update is_owned_
    RefreshOwnedEnabledInfo();
  }

  if (!is_owned_) {
    if (!base::DeleteFile(base::FilePath(kTpmFullyInitializedPath))) {
      LOG(WARNING) << __func__ << ": Failed to delete "
                   << kTpmFullyInitializedPath;
    }
    if (!SetNoSrkAuth(local_data_store_, false)) {
      LOG(WARNING) << __func__ << ": Failed to set no_srk_auth";
    }
    // We even haven't tried to take ownership yet.
    ownership_status_ = kTpmUnowned;
    *status = ownership_status_;
    return true;
  }

  const std::optional<TpmStatus::TpmOwnershipStatus> owner_password_status =
      TestTpmWithDefaultOwnerPassword();
  if (!owner_password_status.has_value()) {
    LOG(ERROR) << __func__ << ": Failed to test default owner password.";
    return false;
  }

  if (*owner_password_status == TpmStatus::kTpmPreOwned ||
      *owner_password_status == TpmStatus::kTpmDisabled) {
    ownership_status_ = *owner_password_status;
    *status = ownership_status_;
    return true;
  }

  const std::optional<bool> is_default_srk_auth = TestTpmSrkWithDefaultAuth();
  if (!is_default_srk_auth.has_value()) {
    LOG(ERROR) << __func__ << ": Failed to test default SRK auth.";
    return false;
  }
  if (!*is_default_srk_auth) {
    LOG(WARNING) << __func__ << ": Failed to use SRK with default auth.";
    ownership_status_ = kTpmSrkNoAuth;
    *status = ownership_status_;
    return true;
  }

  ownership_status_ = kTpmOwned;

  *status = ownership_status_;
  return true;
}

bool TpmStatusImpl::GetDictionaryAttackInfo(uint32_t* counter,
                                            uint32_t* threshold,
                                            bool* lockout,
                                            uint32_t* seconds_remaining) {
  CHECK(counter);
  CHECK(threshold);
  CHECK(lockout);
  CHECK(seconds_remaining);
  std::vector<uint8_t> capability_data;
  if (!GetCapability(TSS_TPMCAP_DA_LOGIC, TPM_ET_KEYHANDLE, &capability_data,
                     nullptr) ||
      capability_data.size() < kMinimumDaInfoSize) {
    LOG(ERROR) << "Error getting tpm capability data for DA info.";
    return false;
  }
  if (static_cast<uint16_t>(capability_data[1]) == TPM_TAG_DA_INFO) {
    TPM_DA_INFO da_info;
    uint64_t offset = 0;
    if (Trspi_UnloadBlob_DA_INFO_s(&offset, capability_data.data(),
                                   capability_data.size(), &da_info)) {
      LOG(ERROR) << "Trspi_UnloadBlob_DA_INFO_s failed.";
      return false;
    }
    *counter = da_info.currentCount;
    *threshold = da_info.thresholdCount;
    *lockout = (da_info.state == TPM_DA_STATE_ACTIVE);
    *seconds_remaining = da_info.actionDependValue;
  }

  // For Infineon, pulls the counter out of vendor-specific data and checks if
  // it matches the value in DA_INFO.

  if (!GetCapability(TSS_TPMCAP_PROPERTY, TSS_TPMCAP_PROP_MANUFACTURER,
                     &capability_data, nullptr) ||
      capability_data.size() != sizeof(uint32_t)) {
    LOG(WARNING) << "Failed to query TSS_TPMCAP_PROP_MANUFACTURER. "
                    "Using the DA info from TSS_TPMCAP_DA_LOGIC.";
    return true;
  }

  uint32_t manufacturer;
  uint64_t offset = 0;
  if (Trspi_UnloadBlob_UINT32_s(&offset, &manufacturer, capability_data.data(),
                                capability_data.size())) {
    LOG(ERROR) << "Trspi_UnloadBlob_UINT32_s failed.";
    return false;
  }
  if (manufacturer != kInfineonManufacturerCode) {
    return true;
  }

  if (!GetCapability(TSS_TPMCAP_MFR, kInfineonMfrSubCapability,
                     &capability_data, nullptr)) {
    LOG(WARNING) << "Failed to query Infineon MFR capability. "
                    "Using the DA info from TSS_TPMCAP_DA_LOGIC.";
    return true;
  }

  if (capability_data.size() <= kInfineonDACounterOffset) {
    LOG(WARNING) << "Couldn't read DA counter from Infineon's MFR "
                    "capability. Using the DA info from TSS_TPMCAP_DA_LOGIC.";
    return true;
  }

  uint32_t vendor_da_counter =
      static_cast<uint32_t>(capability_data[kInfineonDACounterOffset]);
  if (*counter != vendor_da_counter) {
    LOG(WARNING) << "DA counter mismatch for Infineon: " << *counter << " vs. "
                 << vendor_da_counter << ". Using the larger one.";
    *counter = std::max(*counter, vendor_da_counter);
  }
  return true;
}

bool TpmStatusImpl::IsDictionaryAttackMitigationEnabled(bool* is_enabled) {
  // For TPM1.2, it is always enabled.
  *is_enabled = true;
  return true;
}

bool TpmStatusImpl::GetVersionInfo(uint32_t* family,
                                   uint64_t* spec_level,
                                   uint32_t* manufacturer,
                                   uint32_t* tpm_model,
                                   uint64_t* firmware_version,
                                   std::vector<uint8_t>* vendor_specific) {
  CHECK(family);
  CHECK(spec_level);
  CHECK(manufacturer);
  CHECK(tpm_model);
  CHECK(firmware_version);
  CHECK(vendor_specific);

  std::vector<uint8_t> capability_data;
  if (!GetCapability(TSS_TPMCAP_VERSION_VAL, 0, &capability_data, nullptr) ||
      capability_data.size() < kMinimumVersionInfoSize ||
      static_cast<uint16_t>(capability_data[1]) != TPM_TAG_CAP_VERSION_INFO) {
    LOG(ERROR) << "Error getting TPM version capability data.";
    return false;
  }

  TPM_CAP_VERSION_INFO tpm_version;
  uint64_t offset = 0;
  if (Trspi_UnloadBlob_CAP_VERSION_INFO_s(&offset, capability_data.data(),
                                          capability_data.size(),
                                          &tpm_version)) {
    LOG(ERROR) << "Trspi_UnloadBlob_CAP_VERSION_INFO_s failed.";
    return false;
  }
  *family = 0x312e3200;
  *spec_level = (static_cast<uint64_t>(tpm_version.specLevel) << 32) |
                tpm_version.errataRev;
  *manufacturer =
      (tpm_version.tpmVendorID[0] << 24) | (tpm_version.tpmVendorID[1] << 16) |
      (tpm_version.tpmVendorID[2] << 8) | (tpm_version.tpmVendorID[3] << 0);
  // There's no generic model field in the spec. Model information might be
  // present in the vendor-specific data returned by CAP_VERSION_INFO, so if
  // we ever require to know the model, we'll need to check with hardware
  // vendors for the best way to determine it.
  *tpm_model = ~0;
  *firmware_version =
      (tpm_version.version.revMajor << 8) | tpm_version.version.revMinor;
  const uint8_t* data =
      reinterpret_cast<const uint8_t*>(tpm_version.vendorSpecific);
  vendor_specific->assign(data, data + tpm_version.vendorSpecificSize);
  free(tpm_version.vendorSpecific);
  return true;
}

std::optional<TpmStatus::TpmOwnershipStatus>
TpmStatusImpl::TestTpmWithDefaultOwnerPassword() {
  if (base::PathExists(base::FilePath(kTpmFullyInitializedPath))) {
    owner_password_status_ = TpmStatus::kTpmOwned;
  }

  if (owner_password_status_.has_value()) {
    return owner_password_status_;
  }

  TpmConnection connection(GetDefaultOwnerPassword());
  TSS_HTPM tpm_handle = connection.GetTpm();
  if (tpm_handle == 0) {
    return std::nullopt;
  }

  // Call Tspi_TPM_GetStatus to test the default owner password.
  TSS_BOOL current_status = false;
  TSS_RESULT result =
      Tspi_TPM_GetStatus(tpm_handle, TSS_TPMSTATUS_DISABLED, &current_status);

  if (result == TPM_SUCCESS) {
    owner_password_status_ = TpmStatus::kTpmPreOwned;
  } else if (result == TPM_ERROR(TPM_E_AUTHFAIL)) {
    owner_password_status_ = TpmStatus::kTpmOwned;
    if (!TouchTpmFullyInitializedPath()) {
      LOG(WARNING) << __func__ << ": Failed to touch "
                   << kTpmFullyInitializedPath;
    }
  } else if (result == TPM_ERROR(TPM_E_DISABLED)) {
    is_enable_initialized_ = true;
    is_enabled_ = false;
    owner_password_status_ = TpmStatus::kTpmDisabled;
    LOG(WARNING) << __func__ << ": TPM is disabled.";
  } else {
    TPM_LOG(ERROR, result) << "Unexpected error calling |Tspi_TPM_GetStatus|.";
  }
  return owner_password_status_;
}

std::optional<bool> TpmStatusImpl::TestTpmSrkWithDefaultAuth() {
  if (GetNoSrkAuth(local_data_store_)) {
    is_srk_auth_default_ = false;
  }

  if (is_srk_auth_default_.has_value()) {
    return is_srk_auth_default_;
  }

  TpmConnection connection;
  TSS_RESULT result;
  trousers::ScopedTssKey srk_handle(connection.GetContext());
  TSS_UUID SRK_UUID = TSS_UUID_SRK;
  if (TPM_ERROR(result = Tspi_Context_LoadKeyByUUID(
                    connection.GetContext(), TSS_PS_TYPE_SYSTEM, SRK_UUID,
                    srk_handle.ptr()))) {
    if (ERROR_CODE(result) == TSS_E_PS_KEY_NOTFOUND) {
      LOG(WARNING) << "SRK not found. This is normal on a pre-owned device.";
      return false;
    }
    TPM_LOG(ERROR, result) << "Error calling Tspi_Context_LoadKeyByUUID";
    return std::nullopt;
  }

  // Check if the SRK wants a password
  UINT32 srk_authusage;
  if (TPM_ERROR(result = Tspi_GetAttribUint32(
                    srk_handle, TSS_TSPATTRIB_KEY_INFO,
                    TSS_TSPATTRIB_KEYINFO_AUTHUSAGE, &srk_authusage))) {
    TPM_LOG(ERROR, result) << "Error calling Tspi_GetAttribUint32";
    return std::nullopt;
  }

  if (!srk_authusage) {
    is_srk_auth_default_ = true;
    return is_srk_auth_default_;
  }

  // Give it the password if needed
  TSS_HPOLICY srk_usage_policy;
  if (TPM_ERROR(result = Tspi_GetPolicyObject(srk_handle, TSS_POLICY_USAGE,
                                              &srk_usage_policy))) {
    TPM_LOG(ERROR, result) << "Error calling Tspi_GetPolicyObject";
    return std::nullopt;
  }
  BYTE default_auth[0];
  result = Tspi_Policy_SetSecret(srk_usage_policy, TSS_SECRET_MODE_PLAIN, 0,
                                 default_auth);
  if (result != TPM_SUCCESS) {
    TPM_LOG(ERROR, result)
        << "Unexpected error calling |Tspi_Policy_SetSecret|.";
    return std::nullopt;
  }

  unsigned public_srk_size;
  trousers::ScopedTssMemory public_srk_bytes(connection.GetContext());
  result =
      Tspi_Key_GetPubKey(srk_handle, &public_srk_size, public_srk_bytes.ptr());
  if (result == TPM_SUCCESS) {
    is_srk_auth_default_ = true;
  } else if (ERROR_CODE(result) == TPM_E_AUTHFAIL) {
    is_srk_auth_default_ = false;
    if (!SetNoSrkAuth(local_data_store_, true)) {
      LOG(WARNING) << __func__ << ": Failed to set no_srk_auth";
    }
  } else {
    TPM_LOG(ERROR, result) << "Unexpected error calling |Tspi_Key_GetPubKey|.";
    return std::nullopt;
  }
  return is_srk_auth_default_;
}

void TpmStatusImpl::RefreshOwnedEnabledInfo() {
  TSS_RESULT result;
  std::vector<uint8_t> capability_data;
  if (!GetCapability(TSS_TPMCAP_PROPERTY, TSS_TPMCAP_PROP_OWNER,
                     &capability_data, &result)) {
    if (ERROR_CODE(result) == TPM_E_DISABLED) {
      is_enable_initialized_ = true;
      is_enabled_ = false;
      return;
    }
  } else {
    // |capability_data| should be populated with a TSS_BOOL which is true iff
    // the Tpm is owned.
    if (capability_data.size() != sizeof(TSS_BOOL)) {
      LOG(ERROR) << "Error refreshing Tpm ownership information.";
      is_enable_initialized_ = true;
      is_enabled_ = true;
      is_owned_ = false;
      return;
    }
    is_owned_ = (capability_data[0] != 0);
    if (!is_owned_) {
      trousers::ScopedTssKey local_key_handle(tpm_connection_.GetContext());
      TSS_RESULT result = Tspi_TPM_GetPubEndorsementKey(
          tpm_connection_.GetTpm(), false, nullptr, local_key_handle.ptr());
      if (TPM_ERROR(result) == TPM_E_DISABLED) {
        is_enable_initialized_ = true;
        is_enabled_ = false;
        return;
      }
    }
    is_enable_initialized_ = true;
    is_enabled_ = true;
    return;
  }
}

bool TpmStatusImpl::GetCapability(uint32_t capability,
                                  uint32_t sub_capability,
                                  std::vector<uint8_t>* data,
                                  TSS_RESULT* tpm_result) {
  CHECK(data);
  TSS_HTPM tpm_handle = tpm_connection_.GetTpm();
  if (tpm_handle == 0) {
    if (tpm_result) {
      *tpm_result = TSS_E_COMM_FAILURE;
    }
    return false;
  }
  uint32_t length = 0;
  trousers::ScopedTssMemory buf(tpm_connection_.GetContext());
  TSS_RESULT result = Tspi_TPM_GetCapability(
      tpm_handle, capability, sizeof(uint32_t),
      reinterpret_cast<BYTE*>(&sub_capability), &length, buf.ptr());
  if (tpm_result) {
    *tpm_result = result;
  }
  if (TPM_ERROR(result)) {
    LOG(ERROR) << "Error getting TPM capability data.";
    return false;
  }
  data->assign(buf.value(), buf.value() + length);
  return true;
}

void TpmStatusImpl::MarkRandomOwnerPasswordSet() {
  // Also makes sure the state machine is consistent.
  is_enable_initialized_ = is_enabled_ = is_owned_ = true;
  ownership_status_ = kTpmOwned;
  owner_password_status_ = TpmStatus::kTpmOwned;
  if (!TouchTpmFullyInitializedPath()) {
    LOG(WARNING) << __func__ << ": Failed to touch "
                 << kTpmFullyInitializedPath;
  }
}

bool TpmStatusImpl::SupportU2f() {
  return true;
}

bool TpmStatusImpl::SupportPinweaver() {
  // For TPM1.2, we doesn't support pinweaver.
  return false;
}

GscVersion TpmStatusImpl::GetGscVersion() {
  // TPM1.2 is not a GSC.
  return GscVersion::GSC_VERSION_NOT_GSC;
}

bool TpmStatusImpl::GetRoVerificationStatus(
    tpm_manager::RoVerificationStatus* status) {
  *status = tpm_manager::RO_STATUS_UNSUPPORTED_NOT_TRIGGERED;
  return true;
}

bool TpmStatusImpl::GetAlertsData(AlertsData* alerts) {
  // TPM 1.2 doesn't support to get alerts data.
  return false;
}

bool TpmStatusImpl::GetTi50Stats(uint32_t* fs_init_time,
                                 uint32_t* fs_size,
                                 uint32_t* aprov_time,
                                 uint32_t* aprov_status) {
  return false;
}
}  // namespace tpm_manager
