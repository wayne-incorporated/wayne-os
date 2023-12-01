// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ATTESTATION_COMMON_TPM_UTILITY_COMMON_H_
#define ATTESTATION_COMMON_TPM_UTILITY_COMMON_H_

#include "attestation/common/tpm_utility.h"

#include <memory>
#include <string>
#include <unordered_set>

#include <tpm_manager/client/tpm_manager_utility.h>

namespace attestation {

// A TpmUtility implementation for version-independent functions.
class TpmUtilityCommon : public TpmUtility {
 public:
  TpmUtilityCommon();
  // Testing constructor.
  explicit TpmUtilityCommon(
      tpm_manager::TpmManagerUtility* tpm_manager_utility);
  TpmUtilityCommon(const TpmUtilityCommon&) = delete;
  TpmUtilityCommon& operator=(const TpmUtilityCommon&) = delete;

  ~TpmUtilityCommon() override;

  // TpmUtility methods.
  bool Initialize() override;
  bool IsTpmReady() override;
  bool RemoveOwnerDependency() override;

 protected:
  // Gets the endorsement password from tpm_managerd. Returns false if the
  // password is not available.
  bool GetEndorsementPassword(std::string* password);

  // Gets the owner password from tpm_managerd. Returns false if the password is
  // not available.
  bool GetOwnerPassword(std::string* password);

 private:
  void UpdateTpmLocalData(const tpm_manager::LocalData& local_data);
  void OnOwnershipTakenSignal();
  void BuildValidPCR0Values();

 protected:
  bool has_cache_tpm_state_{false};
  bool is_ready_{false};
  std::string endorsement_password_;
  std::string owner_password_;
  std::string delegate_blob_;
  std::string delegate_secret_;

  std::unordered_set<std::string> valid_pcr0_values_;

  tpm_manager::TpmManagerUtility* tpm_manager_utility_;

  // For testing purpose.
  friend class TpmUtilityCommonTest;
};

}  // namespace attestation

#endif  // ATTESTATION_COMMON_TPM_UTILITY_COMMON_H_
