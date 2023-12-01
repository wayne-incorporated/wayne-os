// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TPM_SOFTCLEAR_UTILS_TPM_IMPL_H_
#define TPM_SOFTCLEAR_UTILS_TPM_IMPL_H_

#include "tpm_softclear_utils/tpm.h"

#include <optional>
#include <string>

namespace tpm_softclear_utils {

// Utility class for soft-clearing TPM 1.2.
class TpmImpl : public Tpm {
 public:
  TpmImpl() = default;
  TpmImpl(const TpmImpl&) = delete;
  TpmImpl& operator=(const TpmImpl&) = delete;

  ~TpmImpl() override = default;

  // Not used by TPM 1.2.
  bool Initialize() override { return true; }

  // Gets the owner password from an on-disk file and returns it. In case of an
  // error, returns an empty Optional object.
  std::optional<std::string> GetAuthForOwnerReset() override;

  // This function does a bunch of things:
  //   1. changing the owner password from |auth_for_owner_reset| to the default
  //      well-known value,
  //   2. removing all owner-defined NV space, except for those write-locked,
  //   3. unloading all keys, and
  //   4. resetting the dictionary attack counter.
  //
  // Returns if the TPM is soft-cleared successfully.
  //
  // Note that this function neither fully clears the owner hierarchy nor
  // brings the TPM back to the unowned state. It just resets as much as it can
  // in the owner hierarchy.
  bool SoftClearOwner(const std::string& auth_for_owner_reset) override;

 private:
  // Changes TPM's owner password from |owner_auth| to the default one. Returns
  // if the operation succeeds.
  bool ResetOwnerPassword(const std::string& owner_auth);

  // Removes all owner-defined NV spaces, except for those write-locked. This
  // function uses the default owner password for authentication and should only
  // be called after ResetOwnerPassword().
  //
  // Note: this function doesn't rollback changes it already made if it failed
  // to remove some NV space.
  //
  // Returns if all removable spaces are removed.
  bool RemoveNvSpace();

  // Lists all loaded keys in the owner hierarchy and unloads them. This
  // function uses the default owner password for authentication and should only
  // be called after ResetOwnerPassword().
  //
  // Note: this function doesn't rollback changes it already made if it failed
  // to unload some key.
  //
  // Returns if all keys are unloaded.
  bool UnloadKeys();

  // Resets the DA counter. This function uses the default owner password for
  // authentication and should only be called after ResetOwnerPassword().
  //
  // Returns if the DA counter is reset successfully.
  bool ResetDictionaryAttackCounter();
};

}  // namespace tpm_softclear_utils

#endif  // TPM_SOFTCLEAR_UTILS_TPM_IMPL_H_
