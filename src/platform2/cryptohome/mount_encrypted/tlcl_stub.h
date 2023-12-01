// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_MOUNT_ENCRYPTED_TLCL_STUB_H_
#define CRYPTOHOME_MOUNT_ENCRYPTED_TLCL_STUB_H_

#include <stdint.h>

#include <map>
#include <vector>

#include <vboot/tlcl.h>

namespace mount_encrypted {

class TlclStub {
 public:
  struct NvramSpaceData {
    uint32_t attributes = 0;
    std::vector<uint8_t> policy;
    std::vector<uint8_t> contents;
    bool write_locked = false;
    bool read_locked = false;
  };

  TlclStub();
  TlclStub(const TlclStub&) = delete;
  TlclStub& operator=(const TlclStub&) = delete;

  ~TlclStub();

  // Get the space data for |index|.
  NvramSpaceData* GetSpace(uint32_t index);

  // Put the TPM into owned state with the specified owner auth secret.
  void SetOwned(const std::vector<uint8_t>& owner_auth);

  // Returns the ownership flag.
  bool IsOwned();

  // Clear the TPM owner.
  void Clear();

  // Reset the TPM (i.e. what happens at reboot).
  void Reset();

  // Configure a PCR to contain the specified value.
  void SetPCRValue(uint32_t index, const uint8_t value[TPM_PCR_DIGEST]);

  // Returns the emulated dictionary attack counter.
  int GetDictionaryAttackCounter();

  // This is used to obtain the current stub instance for servicing Tlcl calls.
  // Do not call directly in tests, but construct your own TlclStub instance
  // which will then be returned by Get().
  static TlclStub* Get();

  // Service functions to handle Tlcl invocations follow.
  uint32_t GetOwnership(uint8_t* owned);

  uint32_t GetRandom(uint8_t* data, uint32_t length, uint32_t* size);

  uint32_t DefineSpace(uint32_t index, uint32_t perm, uint32_t size);
  uint32_t DefineSpaceEx(const uint8_t* owner_auth,
                         uint32_t owner_auth_size,
                         uint32_t index,
                         uint32_t perm,
                         uint32_t size,
                         const void* auth_policy,
                         uint32_t auth_policy_size);
  uint32_t GetPermissions(uint32_t index, uint32_t* permissions);
  uint32_t GetSpaceInfo(uint32_t index,
                        uint32_t* permissions,
                        uint32_t* size,
                        void* auth_policy,
                        uint32_t* auth_policy_size);
  uint32_t Write(uint32_t index, const void* data, uint32_t length);
  uint32_t Read(uint32_t index, void* data, uint32_t length);
  uint32_t WriteLock(uint32_t index);
  uint32_t ReadLock(uint32_t index);

  uint32_t PCRRead(uint32_t index, void* data, uint32_t length);

  uint32_t GetVersion(uint32_t* vendor,
                      uint64_t* firmware_version,
                      uint8_t* vendor_specific_buf,
                      size_t* vendor_specific_buf_size);

  uint32_t IFXFieldUpgradeInfo(TPM_IFX_FIELDUPGRADEINFO* info);

#if !USE_TPM2
  uint32_t ReadPubek(uint32_t* public_exponent,
                     uint8_t* modulus,
                     uint32_t* modulus_size);
  uint32_t TakeOwnership(uint8_t enc_owner_auth[TPM_RSA_2048_LEN],
                         uint8_t enc_srk_auth[TPM_RSA_2048_LEN],
                         uint8_t owner_auth[TPM_AUTH_DATA_LEN]);

  uint32_t CreateDelegationFamily(uint8_t family_label);
  uint32_t ReadDelegationFamilyTable(TPM_FAMILY_TABLE_ENTRY* table,
                                     uint32_t* table_size);
#endif  // !USE_TPM2

 private:
  bool is_owned() const { return !owner_auth_.empty(); }

  template <typename Action>
  uint32_t WithSpace(uint32_t index, Action action);

  std::vector<uint8_t> owner_auth_;
  std::map<uint32_t, NvramSpaceData> nvram_spaces_;
  std::map<uint32_t, uint8_t[TPM_PCR_DIGEST]> pcr_values_;

#if !USE_TPM2
  uint32_t delegation_family_id_ = 0;
  std::vector<TPM_FAMILY_TABLE_ENTRY> delegation_family_table_;
#endif  // !USE_TPM2

  // The emulated dictionary attack counter.
  int dictionary_attack_counter_ = 0;

  // The static instance pointer return by Get(). Points at the most recently
  // constructed TlclStub instance.
  static TlclStub* g_instance;
};

}  // namespace mount_encrypted

#endif  // CRYPTOHOME_MOUNT_ENCRYPTED_TLCL_STUB_H_
