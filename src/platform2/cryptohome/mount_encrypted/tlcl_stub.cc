// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/mount_encrypted/tlcl_stub.h"

#include <algorithm>

#include <base/check.h>
#include <base/logging.h>

#include <openssl/sha.h>

#include <vboot/tlcl.h>

#include <brillo/secure_blob.h>

#include <libhwsec-foundation/crypto/sha.h>
#include "cryptohome/mount_encrypted/tpm.h"

namespace mount_encrypted {
namespace {

#if !USE_TPM2

const uint8_t kEndorsementKeyModulus[] = {
    0xde, 0x3b, 0x6a, 0x3c, 0x55, 0xe0, 0x9f, 0x81, 0x67, 0xeb, 0xa6, 0x31,
    0x93, 0x88, 0xa7, 0xcd, 0xf6, 0xea, 0x7d, 0x25, 0x7c, 0x61, 0x9c, 0x52,
    0xfc, 0xa4, 0x96, 0x91, 0xd2, 0x87, 0x9a, 0x17, 0xc4, 0x88, 0x06, 0x9e,
    0x14, 0x01, 0xc8, 0x11, 0x0b, 0x5b, 0x86, 0xae, 0x60, 0x39, 0x5d, 0xb2,
    0x16, 0x4e, 0x8a, 0x92, 0x26, 0x8e, 0xbe, 0x9f, 0xdb, 0x02, 0xe9, 0x64,
    0xe6, 0xbd, 0x49, 0x2b, 0x8f, 0xda, 0x7d, 0xea, 0xbd, 0x80, 0x1d, 0xbc,
    0xc0, 0x7b, 0x68, 0x2b, 0xf4, 0xb6, 0xa4, 0x45, 0xf6, 0x94, 0xca, 0x16,
    0x4d, 0x1f, 0xbb, 0x86, 0xe2, 0x31, 0xc4, 0xf4, 0xa4, 0xa1, 0x06, 0xf3,
    0x12, 0x17, 0xa9, 0xbd, 0x61, 0xd2, 0x47, 0x70, 0x87, 0x05, 0x21, 0x0b,
    0x14, 0x96, 0x89, 0xb4, 0x8c, 0x57, 0x80, 0x7d, 0xed, 0xc9, 0x13, 0x2c,
    0xc2, 0xb3, 0xb4, 0x8f, 0x49, 0xd5, 0xfd, 0x9c, 0x32, 0x3e, 0x07, 0x7a,
    0xd5, 0xdc, 0xdc, 0x59, 0xa7, 0x6a, 0xc4, 0xaf, 0xbb, 0xe0, 0x46, 0x65,
    0x40, 0x16, 0x1c, 0x95, 0xb1, 0xea, 0xdd, 0x7e, 0x78, 0x1c, 0x61, 0x6f,
    0x3a, 0x57, 0xc5, 0x81, 0xea, 0x03, 0x5e, 0x7b, 0xe6, 0x3e, 0xbc, 0x9e,
    0x79, 0x38, 0xfd, 0x46, 0xd9, 0x2c, 0xa0, 0x59, 0xf0, 0xd5, 0x55, 0xe3,
    0x65, 0xa2, 0xda, 0xd1, 0xc4, 0x98, 0x15, 0xbd, 0x1d, 0x3a, 0x8a, 0xc9,
    0x93, 0xea, 0x33, 0x99, 0x45, 0xd7, 0x7b, 0x4f, 0x1b, 0x3b, 0xb0, 0x97,
    0xbf, 0x07, 0xe1, 0x4b, 0x14, 0xd4, 0x96, 0x98, 0x5a, 0x65, 0x74, 0xbb,
    0xce, 0x62, 0xeb, 0xca, 0xdc, 0x29, 0x4d, 0x3f, 0xbb, 0x8b, 0x26, 0xb1,
    0x8d, 0xad, 0x8e, 0x67, 0xc3, 0x11, 0xdd, 0xeb, 0x1a, 0xf2, 0xff, 0x0c,
    0x1a, 0x49, 0xa0, 0x66, 0x9d, 0x83, 0x39, 0xf0, 0x0d, 0x53, 0x86, 0x38,
    0x72, 0x26, 0xd1, 0xb7,
};

const size_t kMaxDelegationFamilyTableSize = 8;

#endif  // !USE_TPM2

const uint8_t kVersionVendorSpecific[] = {
    0x04, 0x20, 0x03, 0x6f, 0x00, 0x74, 0x70,
    0x6d, 0x33, 0x38, 0xff, 0xff, 0xff,
};

}  // namespace

TlclStub* TlclStub::g_instance = nullptr;

TlclStub::TlclStub() {
  g_instance = this;
}

TlclStub::~TlclStub() {
  g_instance = nullptr;
}

TlclStub::NvramSpaceData* TlclStub::GetSpace(uint32_t index) {
  return &nvram_spaces_[index];
}

void TlclStub::SetOwned(const std::vector<uint8_t>& owner_auth) {
  owner_auth_ = owner_auth;
}

bool TlclStub::IsOwned() {
  return !owner_auth_.empty();
}

void TlclStub::Clear() {
  owner_auth_.clear();
  pcr_values_.clear();
#if !USE_TPM2
  delegation_family_id_ = 0;
  delegation_family_table_.clear();
#endif
}

void TlclStub::Reset() {
  for (auto& entry : nvram_spaces_) {
    entry.second.read_locked = false;
    entry.second.write_locked = false;
  }
}

void TlclStub::SetPCRValue(uint32_t index,
                           const uint8_t value[TPM_PCR_DIGEST]) {
  memcpy(pcr_values_[index], value, TPM_PCR_DIGEST);
}

int TlclStub::GetDictionaryAttackCounter() {
  return dictionary_attack_counter_;
}

TlclStub* TlclStub::Get() {
  CHECK(g_instance);
  return g_instance;
}

uint32_t TlclStub::GetOwnership(uint8_t* owned) {
  *owned = is_owned();
  return TPM_SUCCESS;
}

uint32_t TlclStub::GetRandom(uint8_t* data, uint32_t length, uint32_t* size) {
  memset(data, '0x5a', length);
  *size = length;
  return TPM_SUCCESS;
}

uint32_t TlclStub::DefineSpace(uint32_t index, uint32_t perm, uint32_t size) {
  return DefineSpaceEx(nullptr, 0, index, perm, size, nullptr, 0);
}

uint32_t TlclStub::DefineSpaceEx(const uint8_t* owner_auth,
                                 uint32_t owner_auth_size,
                                 uint32_t index,
                                 uint32_t perm,
                                 uint32_t size,
                                 const void* auth_policy,
                                 uint32_t auth_policy_size) {
  bool authenticated = false;

#if USE_TPM2
  // NVRAM space creation in normal mode only works as long as the TPM isn't
  // owned yet. Only non-existing spaces can be defined.
  authenticated = !is_owned() && nvram_spaces_.count(index) == 0;
#else
  std::vector<uint8_t> in_auth(owner_auth, owner_auth + owner_auth_size);
  authenticated = is_owned() && in_auth == owner_auth_;
  if (is_owned() && in_auth != owner_auth_) {
    ++dictionary_attack_counter_;
  }
#endif

  if (!authenticated) {
    return TPM_E_AUTHFAIL;
  }

  nvram_spaces_[index] = NvramSpaceData();
  nvram_spaces_[index].attributes = perm;
  if (auth_policy) {
    nvram_spaces_[index].policy.resize(auth_policy_size);
    memcpy(nvram_spaces_[index].policy.data(), auth_policy, auth_policy_size);
  } else {
    nvram_spaces_[index].policy.clear();
  }
  nvram_spaces_[index].contents.resize(size);

  return TPM_SUCCESS;
}

uint32_t TlclStub::GetPermissions(uint32_t index, uint32_t* permissions) {
  return WithSpace(index, [=](NvramSpaceData* space) {
    *permissions = space->attributes;
    return TPM_SUCCESS;
  });
}

uint32_t TlclStub::GetSpaceInfo(uint32_t index,
                                uint32_t* permissions,
                                uint32_t* size,
                                void* auth_policy,
                                uint32_t* auth_policy_size) {
  return WithSpace(index, [=](NvramSpaceData* space) {
    if (space->policy.size() > *auth_policy_size) {
      *auth_policy_size = space->policy.size();
      return TPM_E_BUFFER_SIZE;
    }

    *permissions = space->attributes;
    *size = space->contents.size();
    memcpy(auth_policy, space->policy.data(), space->policy.size());
    *auth_policy_size = space->policy.size();
    return TPM_SUCCESS;
  });
}

uint32_t TlclStub::Write(uint32_t index, const void* data, uint32_t length) {
  return WithSpace(index, [=](NvramSpaceData* space) {
    if (length > space->contents.size()) {
      return TPM_E_INTERNAL_ERROR;  // should be TPM_NOSPACE
    }
    if (space->write_locked) {
      return TPM_E_INTERNAL_ERROR;  // should be TPM_AREA_LOCKED
    }
    memcpy(space->contents.data(), data, length);
#if USE_TPM2
    space->attributes |= TPMA_NV_WRITTEN;
#endif
    return TPM_SUCCESS;
  });
}

uint32_t TlclStub::Read(uint32_t index, void* data, uint32_t length) {
  return WithSpace(index, [=](NvramSpaceData* space) {
#if USE_TPM2
    if ((space->attributes & TPMA_NV_WRITTEN) != TPMA_NV_WRITTEN) {
      return TPM_E_INTERNAL_ERROR;  // should be TPM_RC_NV_UNINITIALIZED
    }
#endif
    if (length > space->contents.size()) {
      return TPM_E_INTERNAL_ERROR;  // should be TPM_NOSPACE
    }
    if (space->read_locked) {
      return TPM_E_INTERNAL_ERROR;  // should be TPM_AREA_LOCKED
    }
    memcpy(data, space->contents.data(),
           std::min(space->contents.size(), static_cast<size_t>(length)));
    return TPM_SUCCESS;
  });
}

uint32_t TlclStub::WriteLock(uint32_t index) {
  return WithSpace(index, [=](NvramSpaceData* space) {
    if (space->write_locked) {
      return TPM_E_INTERNAL_ERROR;  // should be TPM_AREA_LOCKED
    }
    space->write_locked = true;
    return TPM_SUCCESS;
  });
}

uint32_t TlclStub::ReadLock(uint32_t index) {
  return WithSpace(index, [=](NvramSpaceData* space) {
    if (space->read_locked) {
      return TPM_E_INTERNAL_ERROR;  // should be TPM_AREA_LOCKED
    }
    space->read_locked = true;
    return TPM_SUCCESS;
  });
}

uint32_t TlclStub::PCRRead(uint32_t index, void* data, uint32_t length) {
  if (length < TPM_PCR_DIGEST) {
    return TPM_E_BUFFER_SIZE;
  }

  auto entry = pcr_values_.find(index);
  if (entry != pcr_values_.end()) {
    memcpy(data, entry->second, TPM_PCR_DIGEST);
  } else {
    memset(data, 0, TPM_PCR_DIGEST);
  }

  return TPM_SUCCESS;
}

uint32_t TlclStub::GetVersion(uint32_t* vendor,
                              uint64_t* firmware_version,
                              uint8_t* vendor_specific_buf,
                              size_t* vendor_specific_buf_size) {
  if (*vendor_specific_buf_size < sizeof(kVersionVendorSpecific)) {
    return TPM_E_BUFFER_SIZE;
  }

  *vendor = 0x49465800;
  *firmware_version = 0x420;
  memcpy(vendor_specific_buf, kVersionVendorSpecific,
         sizeof(kVersionVendorSpecific));
  *vendor_specific_buf_size = sizeof(kVersionVendorSpecific);

  return TPM_SUCCESS;
}

uint32_t TlclStub::IFXFieldUpgradeInfo(TPM_IFX_FIELDUPGRADEINFO* info) {
  memset(info, 0, sizeof(*info));
  return TPM_SUCCESS;
}

#if !USE_TPM2

uint32_t TlclStub::ReadPubek(uint32_t* public_exponent,
                             uint8_t* modulus,
                             uint32_t* modulus_size) {
  if (*modulus_size < sizeof(kEndorsementKeyModulus)) {
    return TPM_E_BUFFER_SIZE;
  }
  *public_exponent = 65535;
  memcpy(modulus, kEndorsementKeyModulus, sizeof(kEndorsementKeyModulus));
  *modulus_size = sizeof(kEndorsementKeyModulus);
  return TPM_SUCCESS;
}

uint32_t TlclStub::TakeOwnership(uint8_t enc_owner_auth[TPM_RSA_2048_LEN],
                                 uint8_t enc_srk_auth[TPM_RSA_2048_LEN],
                                 uint8_t owner_auth[TPM_AUTH_DATA_LEN]) {
  if (is_owned()) {
    return TPM_E_OWNER_SET;
  }

  // We'd ideally decrypt the secrets here to validate that they're correctly
  // encrypted and match |owner_auth_|, but this doesn't the additional coverage
  // we'd get is not worth the effort right now.
  owner_auth_.assign(owner_auth, owner_auth + TPM_AUTH_DATA_LEN);

  return TPM_SUCCESS;
}

uint32_t TlclStub::CreateDelegationFamily(uint8_t family_label) {
  if (is_owned()) {
    return TPM_E_OWNER_SET;
  }

  if (delegation_family_table_.size() >= kMaxDelegationFamilyTableSize) {
    return TPM_E_INTERNAL_ERROR;
  }

  delegation_family_table_.push_back(
      {0, family_label, ++delegation_family_id_, 1, 0});

  return TPM_SUCCESS;
}

uint32_t TlclStub::ReadDelegationFamilyTable(TPM_FAMILY_TABLE_ENTRY* table,
                                             uint32_t* table_size) {
  if (*table_size < delegation_family_table_.size()) {
    return TPM_E_BUFFER_SIZE;
  }

  *table_size = delegation_family_table_.size();
  std::copy(delegation_family_table_.begin(), delegation_family_table_.end(),
            table);

  return TPM_SUCCESS;
}

#endif  // !USE_TPM2

template <typename Action>
uint32_t TlclStub::WithSpace(uint32_t index, Action action) {
  auto entry = nvram_spaces_.find(index);
  if (entry == nvram_spaces_.end()) {
    return TPM_E_BADINDEX;
  }

  return action(&entry->second);
}

extern "C" {

uint32_t TlclLibInit(void) {
  // Check that a stub has been set up.
  CHECK(TlclStub::Get());
  return TPM_SUCCESS;
}

uint32_t TlclLibClose(void) {
  return TPM_SUCCESS;
}

uint32_t TlclGetOwnership(uint8_t* owned) {
  return TlclStub::Get()->GetOwnership(owned);
}

uint32_t TlclGetRandom(uint8_t* data, uint32_t length, uint32_t* size) {
  return TlclStub::Get()->GetRandom(data, length, size);
}

uint32_t TlclDefineSpace(uint32_t index, uint32_t perm, uint32_t size) {
  return TlclStub::Get()->DefineSpace(index, perm, size);
}

uint32_t TlclDefineSpaceEx(const uint8_t* owner_auth,
                           uint32_t owner_auth_size,
                           uint32_t index,
                           uint32_t perm,
                           uint32_t size,
                           const void* auth_policy,
                           uint32_t auth_policy_size) {
  return TlclStub::Get()->DefineSpaceEx(owner_auth, owner_auth_size, index,
                                        perm, size, auth_policy,
                                        auth_policy_size);
}

uint32_t TlclGetPermissions(uint32_t index, uint32_t* permissions) {
  return TlclStub::Get()->GetPermissions(index, permissions);
}

uint32_t TlclGetSpaceInfo(uint32_t index,
                          uint32_t* attributes,
                          uint32_t* size,
                          void* auth_policy,
                          uint32_t* auth_policy_size) {
  return TlclStub::Get()->GetSpaceInfo(index, attributes, size, auth_policy,
                                       auth_policy_size);
}

uint32_t TlclWrite(uint32_t index, const void* data, uint32_t length) {
  return TlclStub::Get()->Write(index, data, length);
}

uint32_t TlclRead(uint32_t index, void* data, uint32_t length) {
  return TlclStub::Get()->Read(index, data, length);
}

uint32_t TlclWriteLock(uint32_t index) {
  return TlclStub::Get()->WriteLock(index);
}

uint32_t TlclReadLock(uint32_t index) {
  return TlclStub::Get()->ReadLock(index);
}

uint32_t TlclPCRRead(uint32_t index, void* data, uint32_t length) {
  return TlclStub::Get()->PCRRead(index, data, length);
}

uint32_t TlclInitNvAuthPolicy(uint32_t pcr_selection_bitmap,
                              const uint8_t pcr_values[][TPM_PCR_DIGEST],
                              void* auth_policy,
                              uint32_t* auth_policy_size) {
  int buffer_size = *auth_policy_size;
  *auth_policy_size = SHA256_DIGEST_LENGTH;
  if (buffer_size < SHA256_DIGEST_LENGTH) {
    return TPM_E_BUFFER_SIZE;
  }

  std::vector<uint8_t> input(32);
  for (int index = 0; index < 32; ++index) {
    input[index] = (pcr_selection_bitmap & (1 << index)) != 0;
    if (input[index]) {
      input.insert(input.end(), *pcr_values, *pcr_values + TPM_PCR_DIGEST);
      ++pcr_values;
    }
  }

  brillo::SecureBlob digest = hwsec_foundation::Sha256ToSecureBlob(input);
  memcpy(auth_policy, digest.data(), digest.size());
  return TPM_SUCCESS;
}

uint32_t TlclGetVersion(uint32_t* vendor,
                        uint64_t* firmware_version,
                        uint8_t* vendor_specific_buf,
                        size_t* vendor_specific_buf_size) {
  return TlclStub::Get()->GetVersion(
      vendor, firmware_version, vendor_specific_buf, vendor_specific_buf_size);
}

uint32_t TlclIFXFieldUpgradeInfo(TPM_IFX_FIELDUPGRADEINFO* info) {
  return TlclStub::Get()->IFXFieldUpgradeInfo(info);
}

#if !USE_TPM2

uint32_t TlclReadPubek(uint32_t* public_exponent,
                       uint8_t* modulus,
                       uint32_t* modulus_size) {
  return TlclStub::Get()->ReadPubek(public_exponent, modulus, modulus_size);
}

uint32_t TlclTakeOwnership(uint8_t enc_owner_auth[TPM_RSA_2048_LEN],
                           uint8_t enc_srk_auth[TPM_RSA_2048_LEN],
                           uint8_t owner_auth[TPM_AUTH_DATA_LEN]) {
  return TlclStub::Get()->TakeOwnership(enc_owner_auth, enc_srk_auth,
                                        owner_auth);
}

uint32_t TlclCreateDelegationFamily(uint8_t family_label) {
  return TlclStub::Get()->CreateDelegationFamily(family_label);
}

uint32_t TlclReadDelegationFamilyTable(TPM_FAMILY_TABLE_ENTRY* table,
                                       uint32_t* table_size) {
  return TlclStub::Get()->ReadDelegationFamilyTable(table, table_size);
}

#endif  // !USE_TPM2

}  // extern "C"

}  // namespace mount_encrypted
