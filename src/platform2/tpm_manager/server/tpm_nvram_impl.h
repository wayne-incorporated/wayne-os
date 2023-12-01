// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TPM_MANAGER_SERVER_TPM_NVRAM_IMPL_H_
#define TPM_MANAGER_SERVER_TPM_NVRAM_IMPL_H_

#include "tpm_manager/server/tpm_nvram.h"

#include <stdint.h>

#include <string>
#include <vector>

#include <trousers/scoped_tss_type.h>
#include <trousers/tss.h>

#include "tpm_manager/server/tpm_connection.h"

namespace tpm_manager {

class LocalDataStore;

class TpmNvramImpl : public TpmNvram {
 public:
  explicit TpmNvramImpl(LocalDataStore* local_data_store);
  TpmNvramImpl(const TpmNvramImpl&) = delete;
  TpmNvramImpl& operator=(const TpmNvramImpl&) = delete;

  ~TpmNvramImpl() override = default;

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
  // If |data| is a nullptr, read-locks the NV index; otherwise, reads content
  // from the |index| with |authorization_value| and stores the content into
  // |data|.
  NvramResult ReadSpaceInternal(uint32_t index,
                                const std::string& authorization_value,
                                std::string* data);

  // This method creates and initializes the nvram object associated with
  // |handle| at |index|. Returns true on success, else false.
  bool InitializeNvramHandle(uint32_t index,
                             trousers::ScopedTssNvStore* nv_handle,
                             TpmConnection* connection);

  // Initializes the nvram handle |nv_handle| at |index| with the TPM
  // |connection|. If |need_auth_policy| is set, the method also initializes
  // |policy_handle| with |authorization_value| and associates |policy_handle|
  // with |nv_handle|.
  //
  // Note: the caller should make sure the lifetime of |policy_handle| is >= the
  // lifetime of |nv_handle|.
  //
  // Returns whether the initialization is successful.
  bool InitializeNvramHandleWithPolicy(uint32_t index,
                                       bool need_auth_policy,
                                       const std::string& authorization_value,
                                       trousers::ScopedTssNvStore* nv_handle,
                                       trousers::ScopedTssPolicy* policy_handle,
                                       TpmConnection* connection);

  // This method sets up the composite pcr provided by |pcr_handle| with the
  // value of PCR0 at locality 1. Returns true on success.
  bool SetCompositePcr0(trousers::ScopedTssPcrs* pcr_handle,
                        TpmConnection* connection);

  // This method gets the owner password stored on disk and returns it via the
  // out argument |owner_password|. Returns true if we were able to read a
  // non empty owner_password off disk, else false.
  bool GetOwnerPassword(std::string* owner_password);

  LocalDataStore* local_data_store_;
  // A default non-owner connection.
  TpmConnection tpm_connection_;
};

}  // namespace tpm_manager

#endif  // TPM_MANAGER_SERVER_TPM_NVRAM_IMPL_H_
