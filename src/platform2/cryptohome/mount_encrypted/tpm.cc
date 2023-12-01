// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/mount_encrypted/tpm.h"

#include <stddef.h>
#include <stdint.h>

#include <memory>
#include <utility>

#include <openssl/rsa.h>

#include <base/check_op.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <crypto/libcrypto-compat.h>
#include <crypto/scoped_openssl_types.h>
#include <libhwsec-foundation/crypto/rsa.h>
#include <openssl/rand.h>
#include <vboot/tlcl.h>

#include "cryptohome/mount_encrypted/mount_encrypted.h"

namespace mount_encrypted {
namespace {

#if !USE_TPM2

// A delegation family label identifying the delegation family we create as a
// flag that persists until the next TPM clear, at which point it gets cleared
// automatically. This is by the system key handling logic to determine whether
// a fresh system key has been generated after the last TPM clear.
uint8_t kSystemKeyInitializedFakeDelegationFamilyLabel = 0xff;

// Maximum TPM delegation table size.
const uint32_t kDelegationTableSize = 8;

#endif  // !USE_TPM2

// Initial auth policy buffer size that's expected to be large enough across TPM
// 1.2 and TPM 2.0 hardware. The code uses this for retrieving auth policies.
// Note that if the buffer is too small, it retries with the size indicated by
// the failing function.
const size_t kInitialAuthPolicySize = 128;

}  // namespace

NvramSpace::NvramSpace(Tpm* tpm, uint32_t index) : tpm_(tpm), index_(index) {}

void NvramSpace::Reset() {
  attributes_ = 0;
  auth_policy_.clear();
  contents_.clear();
  status_ = Status::kUnknown;
}

result_code NvramSpace::GetAttributes(uint32_t* attributes) {
  result_code rc = GetSpaceInfo();
  if (rc != RESULT_SUCCESS) {
    return rc;
  }

  *attributes = attributes_;
  return RESULT_SUCCESS;
}

result_code NvramSpace::Read(uint32_t size) {
  status_ = Status::kUnknown;
  attributes_ = 0;
  contents_.clear();

  VLOG(1) << "Reading NVRAM area " << index_ << " (size " << size << ")";

  if (!tpm_->available()) {
    status_ = Status::kAbsent;
    return RESULT_FAIL_FATAL;
  }

  brillo::SecureBlob buffer(size);
  uint32_t result = TlclRead(index_, buffer.data(), buffer.size());

  VLOG(1) << "NVRAM read returned: " << (result == TPM_SUCCESS ? "ok" : "FAIL");

  if (result != TPM_SUCCESS) {
    if (result == TPM_E_BADINDEX) {
      LOG(INFO) << "NVRAM space " << index_ << " doesn't exist";
    } else {
      LOG(ERROR) << "Failed to read NVRAM space " << index_ << ": " << result;
    }
    status_ = result == TPM_E_BADINDEX ? Status::kAbsent : Status::kTpmError;
    return RESULT_FAIL_FATAL;
  }

  if (!USE_TPM2) {
    // Ignore defined but unwritten NVRAM area.
    uint8_t bytes_ored = 0x0;
    uint8_t bytes_anded = 0xff;
    for (uint8_t byte : buffer) {
      bytes_ored |= byte;
      bytes_anded &= byte;
    }
    if (bytes_ored == 0x0 || bytes_anded == 0xff) {
      // Still records the contents so the caller can judge if the size is
      // good  before writing.
      contents_.swap(buffer);
      status_ = Status::kWritable;
      LOG(INFO) << "NVRAM area has been defined but not written.";
      return RESULT_FAIL_FATAL;
    }
  }

  contents_.swap(buffer);
  status_ = Status::kValid;
  return RESULT_SUCCESS;
}

result_code NvramSpace::Write(const brillo::SecureBlob& contents) {
  VLOG(1) << "Writing NVRAM area " << index_ << " (size " << contents.size()
          << ")";

  if (!tpm_->available()) {
    return RESULT_FAIL_FATAL;
  }

  brillo::SecureBlob buffer(contents.size());
  uint32_t result = TlclWrite(index_, contents.data(), contents.size());

  VLOG(1) << "NVRAM write returned: "
          << (result == TPM_SUCCESS ? "ok" : "FAIL");

  if (result != TPM_SUCCESS) {
    LOG(ERROR) << "Failed to write NVRAM space " << index_ << ": " << result;
    return RESULT_FAIL_FATAL;
  }

  contents_ = contents;
  status_ = Status::kValid;
  return RESULT_SUCCESS;
}

result_code NvramSpace::ReadLock() {
  if (!tpm_->available()) {
    return RESULT_FAIL_FATAL;
  }

  uint32_t result = TlclReadLock(index_);
  if (result != TPM_SUCCESS) {
    LOG(ERROR) << "Failed to set read lock on NVRAM space " << index_ << ": "
               << result;
    return RESULT_FAIL_FATAL;
  }

  return RESULT_SUCCESS;
}

result_code NvramSpace::WriteLock() {
  if (!tpm_->available()) {
    return RESULT_FAIL_FATAL;
  }

  uint32_t result = TlclWriteLock(index_);
  if (result != TPM_SUCCESS) {
    LOG(ERROR) << "Failed to set write lock on NVRAM space " << index_ << ": "
               << result;
    return RESULT_FAIL_FATAL;
  }

  return RESULT_SUCCESS;
}

result_code NvramSpace::Define(uint32_t attributes,
                               uint32_t size,
                               uint32_t pcr_selection) {
  if (!tpm_->available()) {
    return RESULT_FAIL_FATAL;
  }

  std::vector<uint8_t> policy;
  result_code rc = GetPCRBindingPolicy(pcr_selection, &policy);
  if (rc != RESULT_SUCCESS) {
    LOG(ERROR) << "Failed to initialize PCR binding policy for " << index_;
    return RESULT_FAIL_FATAL;
  }

  uint32_t result = TlclDefineSpaceEx(
      kOwnerSecret, kOwnerSecretSize, index_, attributes, size,
      policy.empty() ? nullptr : policy.data(), policy.size());
  if (result != TPM_SUCCESS) {
    LOG(ERROR) << "Failed to define NVRAM space " << index_ << ": " << result;
    return RESULT_FAIL_FATAL;
  }

  // `kWritable` is not included in the state machine for TPM2.0 by design.
  // Ideally the status should always be consistent with the value of `status_`
  // and it should be TPM-independent. However, for TPM2.0 we don't have to
  // have `kWritable`; once stopping support for TPM1.2, it could be
  // over-complicated for TPM2.0 and hard to clean up. Thus, pursuing the
  // consistency doesn't seem to be a good idea.
  if (USE_TPM2) {
    status_ = Status::kValid;
  } else {
    status_ = Status::kWritable;
  }

  contents_.clear();
  contents_.resize(size);
  attributes_ = attributes;
  auth_policy_ = std::move(policy);

  return RESULT_SUCCESS;
}

result_code NvramSpace::CheckPCRBinding(uint32_t pcr_selection, bool* match) {
  *match = false;

  std::vector<uint8_t> policy;
  result_code rc = GetSpaceInfo();
  if (rc != RESULT_SUCCESS) {
    return rc;
  }

  rc = GetPCRBindingPolicy(pcr_selection, &policy);
  if (rc != RESULT_SUCCESS) {
    return rc;
  }

  *match = auth_policy_ == policy;
  return RESULT_SUCCESS;
}

result_code NvramSpace::GetSpaceInfo() {
  if (attributes_ != 0) {
    return RESULT_SUCCESS;
  }

  if (!tpm_->available()) {
    return RESULT_FAIL_FATAL;
  }

  uint32_t auth_policy_size = kInitialAuthPolicySize;
  auth_policy_.resize(auth_policy_size);
  uint32_t size;
  uint32_t result = TlclGetSpaceInfo(index_, &attributes_, &size,
                                     auth_policy_.data(), &auth_policy_size);
  if (result == TPM_E_BUFFER_SIZE && auth_policy_size > 0) {
    auth_policy_.resize(auth_policy_size);
    result = TlclGetSpaceInfo(index_, &attributes_, &size, auth_policy_.data(),
                              &auth_policy_size);
  }
  if (result != TPM_SUCCESS) {
    attributes_ = 0;
    auth_policy_.clear();
    LOG(ERROR) << "Failed to read NVRAM space info for index " << index_ << ": "
               << result;
    return RESULT_FAIL_FATAL;
  }

  CHECK_LE(auth_policy_size, auth_policy_.size());
  auth_policy_.resize(auth_policy_size);

  return RESULT_SUCCESS;
}

result_code NvramSpace::GetPCRBindingPolicy(uint32_t pcr_selection,
                                            std::vector<uint8_t>* policy) {
  if (!tpm_->available()) {
    return RESULT_FAIL_FATAL;
  }

  if (pcr_selection == 0) {
    policy->clear();
    return RESULT_SUCCESS;
  }

  int value_index = 0;
  uint8_t pcr_values[32][TPM_PCR_DIGEST] = {};
  for (int index = 0; index < 32; ++index) {
    if (((1 << index) & pcr_selection) != 0) {
      std::vector<uint8_t> pcr_value;
      result_code rc = tpm_->ReadPCR(index, &pcr_value);
      if (rc != RESULT_SUCCESS) {
        return rc;
      }
      CHECK_EQ(TPM_PCR_DIGEST, pcr_value.size());
      memcpy(pcr_values[value_index++], pcr_value.data(), TPM_PCR_DIGEST);
    }
  }

  uint32_t auth_policy_size = kInitialAuthPolicySize;
  policy->resize(auth_policy_size);
  uint32_t result = TlclInitNvAuthPolicy(pcr_selection, pcr_values,
                                         policy->data(), &auth_policy_size);
  if (result == TPM_E_BUFFER_SIZE && auth_policy_size > 0) {
    policy->resize(auth_policy_size);
    result = TlclInitNvAuthPolicy(pcr_selection, pcr_values, policy->data(),
                                  &auth_policy_size);
  }

  if (result != TPM_SUCCESS) {
    policy->clear();
    LOG(ERROR) << "Failed to get NV policy " << result;
    return RESULT_FAIL_FATAL;
  }

  CHECK_LE(auth_policy_size, policy->size());
  policy->resize(auth_policy_size);

  return RESULT_SUCCESS;
}

Tpm::Tpm() {
#if USE_TPM2
  is_tpm2_ = true;
#endif

  VLOG(1) << "Opening TPM";

  setenv("TPM_NO_EXIT", "1", 1);
  available_ = (TlclLibInit() == TPM_SUCCESS);

  LOG(INFO) << "TPM " << (available_ ? "ready" : "not available");
}

Tpm::~Tpm() {
  if (available_) {
    TlclLibClose();
  }
}

result_code Tpm::IsOwned(bool* owned) {
  if (ownership_checked_) {
    *owned = owned_;
    return RESULT_SUCCESS;
  }

  VLOG(1) << "Reading TPM Ownership Flag";
  if (!available_) {
    return RESULT_FAIL_FATAL;
  }

  uint8_t tmp_owned = 0;
  uint32_t result = TlclGetOwnership(&tmp_owned);
  VLOG(1) << "TPM Ownership Flag returned: " << (result ? "FAIL" : "ok");
  if (result != TPM_SUCCESS) {
    LOG(INFO) << "Could not determine TPM ownership: error " << result;
    return RESULT_FAIL_FATAL;
  }

  ownership_checked_ = true;
  owned_ = tmp_owned;
  *owned = owned_;
  return RESULT_SUCCESS;
}

result_code Tpm::GetRandomBytes(uint8_t* buffer, int wanted) {
  if (available()) {
    // Read random bytes from TPM, which can return short reads.
    int remaining = wanted;
    while (remaining) {
      uint32_t result, size;
      result = TlclGetRandom(buffer + (wanted - remaining), remaining, &size);
      if (result != TPM_SUCCESS) {
        LOG(ERROR) << "TPM GetRandom failed: error " << result;
        return RESULT_FAIL_FATAL;
      }
      CHECK_LE(size, remaining);
      remaining -= size;
    }

    if (remaining == 0) {
      return RESULT_SUCCESS;
    }
  }

  // Fall back to system random source.
  if (RAND_bytes(buffer, wanted)) {
    return RESULT_SUCCESS;
  }

  LOG(ERROR) << "Failed to obtain randomness.";
  return RESULT_FAIL_FATAL;
}

result_code Tpm::ReadPCR(uint32_t index, std::vector<uint8_t>* value) {
  // See whether the PCR is available in the cache. Note that we currently
  // assume PCR values remain constant during the lifetime of the process, so we
  // only ever read once.
  auto entry = pcr_values_.find(index);
  if (entry != pcr_values_.end()) {
    *value = entry->second;
    return RESULT_SUCCESS;
  }

  if (!available()) {
    return RESULT_FAIL_FATAL;
  }

  std::vector<uint8_t> temp_value(TPM_PCR_DIGEST);
  uint32_t result = TlclPCRRead(index, temp_value.data(), temp_value.size());
  if (result != TPM_SUCCESS) {
    LOG(ERROR) << "TPM PCR " << index << " read failed: " << result;
    return RESULT_FAIL_FATAL;
  }

  pcr_values_[index] = temp_value;
  *value = std::move(temp_value);
  return RESULT_SUCCESS;
}

bool Tpm::GetVersionInfo(uint32_t* vendor,
                         uint64_t* firmware_version,
                         std::vector<uint8_t>* vendor_specific) {
  size_t vendor_specific_size = 32;
  vendor_specific->resize(vendor_specific_size);
  uint32_t result = TlclGetVersion(
      vendor, firmware_version, vendor_specific->data(), &vendor_specific_size);
  if (result != TPM_SUCCESS) {
    LOG(ERROR) << "Failed to obtain TPM version info.";
    return false;
  }

  vendor_specific->resize(vendor_specific_size);
  return true;
}

bool Tpm::GetIFXFieldUpgradeInfo(TPM_IFX_FIELDUPGRADEINFO* field_upgrade_info) {
  uint32_t result = TlclIFXFieldUpgradeInfo(field_upgrade_info);
  if (result != TPM_SUCCESS) {
    LOG(ERROR) << "Failed to obtain IFX field upgrade info.";
    return false;
  }

  return true;
}

NvramSpace* Tpm::GetLockboxSpace() {
  if (lockbox_space_) {
    return lockbox_space_.get();
  }

  lockbox_space_ = std::make_unique<NvramSpace>(this, kLockboxIndex);

  // Reading the NVRAM takes 40ms. Instead of querying the NVRAM area for its
  // size (which takes time), just read the expected size. If it fails, then
  // fall back to the older size. This means cleared devices take 80ms (2 failed
  // reads), legacy devices take 80ms (1 failed read, 1 good read), and
  // populated devices take 40ms, which is the minimum possible time (instead of
  // 40ms + time to query NVRAM size).
  if (lockbox_space_->Read(kLockboxSizeV2) == RESULT_SUCCESS) {
    LOG(INFO) << "Version 2 Lockbox NVRAM area found.";
  } else if (lockbox_space_->Read(kLockboxSizeV1) == RESULT_SUCCESS) {
    LOG(INFO) << "Version 1 Lockbox NVRAM area found.";
  } else {
    LOG(INFO) << "No Lockbox NVRAM area defined.";
  }

  return lockbox_space_.get();
}

NvramSpace* Tpm::GetEncStatefulSpace() {
  if (encstateful_space_) {
    return encstateful_space_.get();
  }

  encstateful_space_ = std::make_unique<NvramSpace>(this, kEncStatefulIndex);

  if (encstateful_space_->Read(kEncStatefulSize) == RESULT_SUCCESS) {
    LOG(INFO) << "Found encstateful NVRAM area.";
  } else {
    LOG(INFO) << "No encstateful NVRAM area defined.";
  }

  return encstateful_space_.get();
}

#if USE_TPM2

result_code Tpm::TakeOwnership() {
  return RESULT_FAIL_FATAL;
}

result_code Tpm::SetSystemKeyInitializedFlag() {
  return RESULT_FAIL_FATAL;
}

result_code Tpm::HasSystemKeyInitializedFlag(bool* flag_value) {
  return RESULT_FAIL_FATAL;
}

#else

result_code Tpm::TakeOwnership() {
  // Read the public half of the EK.
  uint32_t public_exponent = 0;
  uint8_t modulus[TPM_RSA_2048_LEN];
  uint32_t modulus_size = sizeof(modulus);
  uint32_t result = TlclReadPubek(&public_exponent, modulus, &modulus_size);
  if (result != TPM_SUCCESS) {
    LOG(ERROR) << "Failed to read public endorsement key: " << result;
    return RESULT_FAIL_FATAL;
  }

  crypto::ScopedRSA rsa(RSA_new());
  crypto::ScopedBIGNUM e(BN_new()), n(BN_new());
  if (!rsa || !e || !n) {
    LOG(ERROR) << "Failed to allocate RSA or BIGNUM.";
    return RESULT_FAIL_FATAL;
  }
  if (!BN_set_word(e.get(), public_exponent) ||
      !BN_bin2bn(modulus, modulus_size, n.get())) {
    LOG(ERROR) << "Failed to convert BIGNUM for RSA.";
    return RESULT_FAIL_FATAL;
  }
  if (!RSA_set0_key(rsa.get(), n.release(), e.release(), nullptr)) {
    LOG(ERROR) << "Failed to set modulus or exponent for RSA.";
    return RESULT_FAIL_FATAL;
  }

  // Encrypt the well-known owner secret under the EK.
  brillo::SecureBlob owner_auth(kOwnerSecret, kOwnerSecret + kOwnerSecretSize);
  brillo::SecureBlob enc_auth;
  if (!hwsec_foundation::TpmCompatibleOAEPEncrypt(rsa.get(), owner_auth,
                                                  &enc_auth)) {
    LOG(ERROR) << "Failed to encrypt owner secret.";
    return RESULT_FAIL_FATAL;
  }

  // Take ownership.
  result =
      TlclTakeOwnership(enc_auth.data(), enc_auth.data(), owner_auth.data());
  if (result != TPM_SUCCESS) {
    LOG(ERROR) << "Failed to take TPM ownership: " << result;
    return RESULT_FAIL_FATAL;
  }

  ownership_checked_ = true;
  owned_ = true;

  // Ownership implies the initialization flag.
  initialized_flag_checked_ = true;
  initialized_flag_ = true;

  return RESULT_SUCCESS;
}

result_code Tpm::SetSystemKeyInitializedFlag() {
  bool flag_value = false;
  result_code rc = HasSystemKeyInitializedFlag(&flag_value);
  if (rc != TPM_SUCCESS) {
    return RESULT_FAIL_FATAL;
  }

  if (flag_value) {
    return RESULT_SUCCESS;
  }

  uint32_t result = TlclCreateDelegationFamily(
      kSystemKeyInitializedFakeDelegationFamilyLabel);
  if (result != TPM_SUCCESS) {
    LOG(ERROR) << "Failed to create fake delegation family: " << result;
    return RESULT_FAIL_FATAL;
  }

  initialized_flag_ = true;
  initialized_flag_checked_ = true;

  return RESULT_SUCCESS;
}

result_code Tpm::HasSystemKeyInitializedFlag(bool* flag_value) {
  if (!available()) {
    return RESULT_FAIL_FATAL;
  }

  if (initialized_flag_checked_) {
    *flag_value = initialized_flag_;
    return RESULT_SUCCESS;
  }

  // The fake delegation family is only relevant for unowned TPMs.
  // Pretend the flag is present if the TPM is owned.
  bool owned = false;
  result_code rc = IsOwned(&owned);
  if (rc != RESULT_SUCCESS) {
    LOG(ERROR) << "Failed to determine ownership.";
    return rc;
  }
  if (owned) {
    initialized_flag_checked_ = true;
    initialized_flag_ = true;
    *flag_value = initialized_flag_;
    return RESULT_SUCCESS;
  }

  TPM_FAMILY_TABLE_ENTRY table[kDelegationTableSize];
  uint32_t table_size = kDelegationTableSize;
  uint32_t result = TlclReadDelegationFamilyTable(table, &table_size);
  if (result != TPM_SUCCESS) {
    LOG(ERROR) << "Failed to read delegation family table: " << result;
    return RESULT_FAIL_FATAL;
  }

  for (uint32_t i = 0; i < table_size; ++i) {
    if (table[i].familyLabel ==
        kSystemKeyInitializedFakeDelegationFamilyLabel) {
      initialized_flag_ = true;
      break;
    }
  }

  initialized_flag_checked_ = true;
  *flag_value = initialized_flag_;
  return RESULT_SUCCESS;
}

#endif
}  // namespace mount_encrypted
