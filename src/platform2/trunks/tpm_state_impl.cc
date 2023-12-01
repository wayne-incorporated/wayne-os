// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "trunks/tpm_state_impl.h"

#include <base/check.h>
#include <base/functional/bind.h>
#include <base/logging.h>

#include "trunks/error_codes.h"
#include "trunks/tpm_generated.h"
#include "trunks/trunks_factory.h"

namespace {

// From definition of TPMA_PERMANENT.
const trunks::TPMA_PERMANENT kOwnerAuthSetMask = 1U;
const trunks::TPMA_PERMANENT kEndorsementAuthSetMask = 1U << 1;
const trunks::TPMA_PERMANENT kLockoutAuthSetMask = 1U << 2;
const trunks::TPMA_PERMANENT kInLockoutMask = 1U << 9;

// From definition of TPMA_STARTUP_CLEAR.
const trunks::TPMA_STARTUP_CLEAR kPlatformHierarchyMask = 1U;
const trunks::TPMA_STARTUP_CLEAR kStorageHierarchyMask = 1U << 1;
const trunks::TPMA_STARTUP_CLEAR kEndorsementHierarchyMask = 1U << 2;
const trunks::TPMA_STARTUP_CLEAR kOrderlyShutdownMask = 1U << 31;

}  // namespace

namespace trunks {

TpmStateImpl::TpmStateImpl(const TrunksFactory& factory) : factory_(factory) {}

TPM_RC TpmStateImpl::Initialize() {
  TPM_RC result = CacheTpmProperties();
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Failed to query TPM properties: " << GetErrorString(result);
    return result;
  }
  if (tpm_properties_.count(TPM_PT_PERMANENT) == 0 ||
      tpm_properties_.count(TPM_PT_STARTUP_CLEAR) == 0) {
    LOG(ERROR) << "Required properties missing!";
    return TRUNKS_RC_INVALID_TPM_CONFIGURATION;
  }

  result = CacheAlgorithmProperties();
  if (result != TPM_RC_SUCCESS) {
    LOG(ERROR) << "Failed to query TPM algorithms: " << GetErrorString(result);
    return result;
  }
  initialized_ = true;
  return TPM_RC_SUCCESS;
}

bool TpmStateImpl::IsOwnerPasswordSet() {
  CHECK(initialized_);
  return ((tpm_properties_[TPM_PT_PERMANENT] & kOwnerAuthSetMask) ==
          kOwnerAuthSetMask);
}

bool TpmStateImpl::IsEndorsementPasswordSet() {
  CHECK(initialized_);
  return ((tpm_properties_[TPM_PT_PERMANENT] & kEndorsementAuthSetMask) ==
          kEndorsementAuthSetMask);
}

bool TpmStateImpl::IsLockoutPasswordSet() {
  CHECK(initialized_);
  return ((tpm_properties_[TPM_PT_PERMANENT] & kLockoutAuthSetMask) ==
          kLockoutAuthSetMask);
}

bool TpmStateImpl::IsOwned() {
  return (IsOwnerPasswordSet() && IsEndorsementPasswordSet() &&
          IsLockoutPasswordSet());
}

bool TpmStateImpl::IsInLockout() {
  CHECK(initialized_);
  return ((tpm_properties_[TPM_PT_PERMANENT] & kInLockoutMask) ==
          kInLockoutMask);
}

bool TpmStateImpl::IsPlatformHierarchyEnabled() {
  CHECK(initialized_);
  return ((tpm_properties_[TPM_PT_STARTUP_CLEAR] & kPlatformHierarchyMask) ==
          kPlatformHierarchyMask);
}

bool TpmStateImpl::IsStorageHierarchyEnabled() {
  CHECK(initialized_);
  return ((tpm_properties_[TPM_PT_STARTUP_CLEAR] & kStorageHierarchyMask) ==
          kStorageHierarchyMask);
}

bool TpmStateImpl::IsEndorsementHierarchyEnabled() {
  CHECK(initialized_);
  return ((tpm_properties_[TPM_PT_STARTUP_CLEAR] & kEndorsementHierarchyMask) ==
          kEndorsementHierarchyMask);
}

bool TpmStateImpl::IsEnabled() {
  return (!IsPlatformHierarchyEnabled() && IsStorageHierarchyEnabled() &&
          IsEndorsementHierarchyEnabled());
}

bool TpmStateImpl::WasShutdownOrderly() {
  CHECK(initialized_);
  return ((tpm_properties_[TPM_PT_STARTUP_CLEAR] & kOrderlyShutdownMask) ==
          kOrderlyShutdownMask);
}

bool TpmStateImpl::IsRSASupported() {
  CHECK(initialized_);
  return (algorithm_properties_.count(TPM_ALG_RSA) > 0);
}

bool TpmStateImpl::IsECCSupported() {
  CHECK(initialized_);
  return (algorithm_properties_.count(TPM_ALG_ECC) > 0);
}

uint32_t TpmStateImpl::GetLockoutCounter() {
  CHECK(initialized_);
  return tpm_properties_[TPM_PT_LOCKOUT_COUNTER];
}

uint32_t TpmStateImpl::GetLockoutThreshold() {
  CHECK(initialized_);
  return tpm_properties_[TPM_PT_MAX_AUTH_FAIL];
}

uint32_t TpmStateImpl::GetLockoutInterval() {
  CHECK(initialized_);
  return tpm_properties_[TPM_PT_LOCKOUT_INTERVAL];
}

uint32_t TpmStateImpl::GetLockoutRecovery() {
  CHECK(initialized_);
  return tpm_properties_[TPM_PT_LOCKOUT_RECOVERY];
}

uint32_t TpmStateImpl::GetMaxNVSize() {
  CHECK(initialized_);
  uint32_t max_nv_size;
  if (!GetTpmProperty(TPM_PT_NV_INDEX_MAX, &max_nv_size)) {
    max_nv_size = 2048;
  }
  uint32_t max_nv_buffer;
  if (GetTpmProperty(TPM_PT_NV_BUFFER_MAX, &max_nv_buffer) &&
      max_nv_buffer < max_nv_size) {
    max_nv_size = max_nv_buffer;
  }
  return max_nv_size;
}

bool TpmStateImpl::GetTpmProperty(TPM_PT property, uint32_t* value) {
  CHECK(initialized_);
  if (tpm_properties_.count(property) == 0) {
    return false;
  }
  if (value) {
    *value = tpm_properties_[property];
  }
  return true;
}

uint32_t TpmStateImpl::GetTpmFamily() {
  CHECK(initialized_);
  return tpm_properties_[TPM_PT_FAMILY_INDICATOR];
}

uint32_t TpmStateImpl::GetSpecificationLevel() {
  CHECK(initialized_);
  return tpm_properties_[TPM_PT_LEVEL];
}

uint32_t TpmStateImpl::GetSpecificationRevision() {
  CHECK(initialized_);
  return tpm_properties_[TPM_PT_REVISION];
}

uint32_t TpmStateImpl::GetManufacturer() {
  CHECK(initialized_);
  return tpm_properties_[TPM_PT_MANUFACTURER];
}

uint32_t TpmStateImpl::GetTpmModel() {
  CHECK(initialized_);
  return tpm_properties_[TPM_PT_VENDOR_TPM_TYPE];
}

uint64_t TpmStateImpl::GetFirmwareVersion() {
  CHECK(initialized_);
  uint64_t version_high = tpm_properties_[TPM_PT_FIRMWARE_VERSION_1];
  uint64_t version_low = tpm_properties_[TPM_PT_FIRMWARE_VERSION_2];
  return (version_high << 32) | version_low;
}

std::string TpmStateImpl::GetVendorIDString() {
  CHECK(initialized_);
  std::string result;

  for (TPM_PT property : {TPM_PT_VENDOR_STRING_1, TPM_PT_VENDOR_STRING_2,
                          TPM_PT_VENDOR_STRING_3, TPM_PT_VENDOR_STRING_4}) {
    if (tpm_properties_.count(property) == 0) {
      break;
    }

    uint32_t value = tpm_properties_[property];
    for (int i = 3; i >= 0; --i) {
      char byte = static_cast<char>((value >> (i * 8)) & 0xff);
      if (!byte) {
        break;
      }
      result.push_back(byte);
    }
  }

  return result;
}

bool TpmStateImpl::GetAlgorithmProperties(TPM_ALG_ID algorithm,
                                          TPMA_ALGORITHM* properties) {
  CHECK(initialized_);
  if (algorithm_properties_.count(algorithm) == 0) {
    return false;
  }
  if (properties) {
    *properties = algorithm_properties_[algorithm];
  }
  return true;
}

TPM_RC TpmStateImpl::GetCapability(const CapabilityCallback& callback,
                                   TPM_CAP capability,
                                   uint32_t property,
                                   uint32_t max_properties_per_call) {
  TPMI_YES_NO more_data = YES;
  while (more_data) {
    TPMS_CAPABILITY_DATA capability_data;
    TPM_RC result = factory_.GetTpm()->GetCapabilitySync(
        capability, property, max_properties_per_call, &more_data,
        &capability_data, nullptr);
    if (result != TPM_RC_SUCCESS) {
      LOG(ERROR) << __func__ << ": " << GetErrorString(result);
      return result;
    }
    if (capability_data.capability != capability) {
      LOG(ERROR) << __func__ << ": Unexpected capability data.";
      return SAPI_RC_MALFORMED_RESPONSE;
    }
    uint32_t next_property = callback.Run(capability_data.data);
    if (more_data) {
      if (next_property == 0) {
        LOG(ERROR) << __func__ << ": No properties in response.";
        return SAPI_RC_MALFORMED_RESPONSE;
      }
      if (next_property <= property) {
        LOG(ERROR) << __func__ << ": Lower properties in response.";
        return SAPI_RC_MALFORMED_RESPONSE;
      }
      property = next_property;
    }
  }
  return TPM_RC_SUCCESS;
}

uint32_t TpmStateImpl::TpmPropertiesCallback(
    const TPMU_CAPABILITIES& capability_data) {
  uint32_t next_property = 0;
  for (uint32_t i = 0;
       i < capability_data.tpm_properties.count && i < MAX_TPM_PROPERTIES;
       ++i) {
    const TPMS_TAGGED_PROPERTY& property =
        capability_data.tpm_properties.tpm_property[i];
    VLOG(1) << "TPM Property 0x" << std::hex << property.property << " = 0x"
            << property.value;
    tpm_properties_[property.property] = property.value;
    next_property = property.property + 1;
  }
  return next_property;
}

TPM_RC TpmStateImpl::CacheTpmProperties() {
  CapabilityCallback callback = base::BindRepeating(
      &TpmStateImpl::TpmPropertiesCallback, base::Unretained(this));
  if (tpm_properties_.empty()) {
    TPM_RC result = GetCapability(callback, TPM_CAP_TPM_PROPERTIES, PT_FIXED,
                                  MAX_TPM_PROPERTIES);
    if (result != TPM_RC_SUCCESS) {
      return result;
    }
  }
  return GetCapability(callback, TPM_CAP_TPM_PROPERTIES, PT_VAR,
                       MAX_TPM_PROPERTIES);
}

uint32_t TpmStateImpl::AlgorithmCallback(
    const TPMU_CAPABILITIES& capability_data) {
  uint32_t next_property = 0;
  for (uint32_t i = 0; i < capability_data.algorithms.count && i < MAX_CAP_ALGS;
       ++i) {
    const TPMS_ALG_PROPERTY& property =
        capability_data.algorithms.alg_properties[i];
    VLOG(1) << "Algorithm Properties 0x" << std::hex << property.alg << " = 0x"
            << property.alg_properties;
    algorithm_properties_[property.alg] = property.alg_properties;
    next_property = property.alg + 1;
  }
  return next_property;
}

TPM_RC TpmStateImpl::CacheAlgorithmProperties() {
  if (algorithm_properties_.empty()) {
    return GetCapability(base::BindRepeating(&TpmStateImpl::AlgorithmCallback,
                                             base::Unretained(this)),
                         TPM_CAP_ALGS, TPM_ALG_FIRST, MAX_CAP_ALGS);
  }
  return TPM_RC_SUCCESS;
}

}  // namespace trunks
