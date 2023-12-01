// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TPM_SOFTCLEAR_UTILS_TPM_H_
#define TPM_SOFTCLEAR_UTILS_TPM_H_

#include <optional>
#include <string>

namespace tpm_softclear_utils {

// Interface for soft-clearing TPM utilities.
class Tpm {
 public:
  Tpm() = default;
  Tpm(const Tpm&) = delete;
  Tpm& operator=(const Tpm&) = delete;

  virtual ~Tpm() = default;

  // Performs TPM-version-dependent initialization and returns if the
  // initialization is successful.
  virtual bool Initialize() = 0;

  // Gets the authentication value for soft-clearing TPM owner from an on-disk
  // file. The auth value in TPM 1.2 and 2.0 are different. Check the child
  // classes for details.
  //
  // If the file doesn't exist, returns the default password. Note that the file
  // not existing doesn't necessarily mean an error. It might just mean the TPM
  // is already soft-cleared.
  //
  // Returns an empty Optional object if failing to read the file.
  //
  // This function doesn't check if the password, either default or from a file,
  // works. Callers need to figure it out by themselves.
  virtual std::optional<std::string> GetAuthForOwnerReset() = 0;

  // Resets TPM's owner hierarchy (and endorsement hierarchy for 2.0) using the
  // given auth value |auth_for_owner_reset| and returns if the TPM is
  // soft-cleared successfully. Implementation details for TPM 1.2 and 2.0 may
  // vary. Check the function descriptions in the child classes for details.
  virtual bool SoftClearOwner(const std::string& auth_for_owner_reset) = 0;

  // Creates a new TpmImpl or Tpm2Impl object, according to which
  // version the TPM is, and returns the pointer to the new object.
  static Tpm* Create();
};

}  // namespace tpm_softclear_utils

#endif  // TPM_SOFTCLEAR_UTILS_TPM_H_
