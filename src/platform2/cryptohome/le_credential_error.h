// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_LE_CREDENTIAL_ERROR_H_
#define CRYPTOHOME_LE_CREDENTIAL_ERROR_H_

namespace cryptohome {

// List of all the errors returned by the LECredentialManager interface.
enum LECredError {
  // Operation succeeded.
  LE_CRED_SUCCESS = 0,
  // Check failed due to incorrect Low Entropy(LE) secret.
  LE_CRED_ERROR_INVALID_LE_SECRET,
  // Check failed due to incorrect Reset secret.
  LE_CRED_ERROR_INVALID_RESET_SECRET,
  // Check failed due to too many attempts as per delay schedule.
  LE_CRED_ERROR_TOO_MANY_ATTEMPTS,
  // Error in hash tree synchronization.
  LE_CRED_ERROR_HASH_TREE,
  // Label provided isn't present in hash tree.
  LE_CRED_ERROR_INVALID_LABEL,
  // No free labels available.
  LE_CRED_ERROR_NO_FREE_LABEL,
  // Invalid metadata in label.
  LE_CRED_ERROR_INVALID_METADATA,
  // Unclassified error.
  LE_CRED_ERROR_UNCLASSIFIED,
  // Credential Manager Locked.
  LE_CRED_ERROR_LE_LOCKED,
  // Unexpected PCR state.
  LE_CRED_ERROR_PCR_NOT_MATCH,
  // Check failed due to credential expired.
  LE_CRED_ERROR_EXPIRED,
  // Sentinel value.
  LE_CRED_ERROR_MAX,
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_LE_CREDENTIAL_ERROR_H_
