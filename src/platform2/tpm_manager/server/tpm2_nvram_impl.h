// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TPM_MANAGER_SERVER_TPM2_NVRAM_IMPL_H_
#define TPM_MANAGER_SERVER_TPM2_NVRAM_IMPL_H_

#include "tpm_manager/server/tpm_nvram.h"

#include <memory>
#include <string>
#include <vector>

#include <tpm_manager/proto_bindings/tpm_manager.pb.h>
#include <trunks/trunks_factory.h>

#include "tpm_manager/server/local_data_store.h"
#include "tpm_manager/server/nv_index_authenticator.h"
#include "tpm_manager/server/tpm_status.h"

namespace tpm_manager {

// A TpmNvram implementation backed by a TPM 2.0 device. All index values are
// the 'index' portion of an NV handle and must fit in 24 bits.
class Tpm2NvramImpl : public TpmNvram {
 public:
  // Does not take ownership of arguments.
  Tpm2NvramImpl(const trunks::TrunksFactory& factory,
                LocalDataStore* local_data_store,
                TpmStatus* tpm_status);
  Tpm2NvramImpl(const Tpm2NvramImpl&) = delete;
  Tpm2NvramImpl& operator=(const Tpm2NvramImpl&) = delete;

  ~Tpm2NvramImpl() override = default;

  // TpmNvram methods.
  NvramResult DefineSpace(uint32_t index,
                          size_t size,
                          const std::vector<NvramSpaceAttribute>& attributes,
                          const std::string& authorization_value,
                          NvramSpacePolicy policy) override;
  NvramResult DestroySpace(uint32_t index) override;
  NvramResult WriteSpace(uint32_t index,
                         const std::string& data,
                         const std::string& authorization_value) override;
  NvramResult ReadSpace(uint32_t index,
                        std::string* data,
                        const std::string& authorization_value) override;
  NvramResult LockSpace(uint32_t index,
                        bool lock_read,
                        bool lock_write,
                        const std::string& authorization_value) override;
  NvramResult ListSpaces(std::vector<uint32_t>* index_list) override;
  NvramResult GetSpaceInfo(uint32_t index,
                           uint32_t* size,
                           bool* is_read_locked,
                           bool* is_write_locked,
                           std::vector<NvramSpaceAttribute>* attributes,
                           NvramSpacePolicy* policy) override;

  void PrunePolicies() override;

 private:
  // Must be called before using any data members. This may be called multiple
  // times and will be very fast if already initialized.
  bool Initialize();

  // Gets the TPM owner password. Returns an empty string if not available.
  std::string GetOwnerPassword();

  // TODO(menghuan): use NvIndexAuthenticator.GetOwnerAuthDelegate() instead?
  // Configures |trunks_session_| with owner authorization. Returns true on
  // success.
  bool SetupOwnerSession();

  // Configures a new policy |session| for a given |policy_record|,
  // |authorization_value|, and |command_code|. Returns true on success.
  bool SetupPolicySession(const NvramPolicyRecord& policy_record,
                          const std::string& authorization_value,
                          trunks::TPM_CC command_code,
                          trunks::PolicySession* session);

  // A helper to add policies to a |session| for a particular |command_code| and
  // |policy_record|. Returns true on success.
  bool AddPoliciesForCommand(const NvramPolicyRecord& policy_record,
                             trunks::TPM_CC command_code,
                             trunks::PolicySession* session);

  // A helper to add an OR policy to |session| based on |policy_record|. Returns
  // true on success.
  bool AddPolicyOR(const NvramPolicyRecord& policy_record,
                   trunks::PolicySession* session);

  // Computes the policy |digest| for a given |policy_record| and fills the
  // policy_digests field in the |policy_record|.
  bool ComputePolicyDigest(NvramPolicyRecord* policy_record,
                           std::string* digest);

  // Gets the policy |record| for the given |index|. Returns true on success.
  bool GetPolicyRecord(uint32_t index, NvramPolicyRecord* record);

  // Saves a policy |record| in the local_data_store_.
  bool SavePolicyRecord(const NvramPolicyRecord& record);

  // Best effort delete of the policy |record| for |index|.
  void DeletePolicyRecord(uint32_t index);

  const trunks::TrunksFactory& trunks_factory_;
  LocalDataStore* local_data_store_;
  TpmStatus* tpm_status_;
  bool initialized_;
  std::unique_ptr<trunks::HmacSession> trunks_session_;
  std::unique_ptr<trunks::TpmUtility> trunks_utility_;

  friend class Tpm2NvramTest;
};

}  // namespace tpm_manager

#endif  // TPM_MANAGER_SERVER_TPM2_NVRAM_IMPL_H_
