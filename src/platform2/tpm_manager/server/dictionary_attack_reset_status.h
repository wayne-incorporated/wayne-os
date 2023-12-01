// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TPM_MANAGER_SERVER_DICTIONARY_ATTACK_RESET_STATUS_H_
#define TPM_MANAGER_SERVER_DICTIONARY_ATTACK_RESET_STATUS_H_

namespace tpm_manager {

// These values are persisted to logs. Entries should not be renumbered and
// numeric values should never be reused since the status is reported as UMA.
enum DictionaryAttackResetStatus {
  kResetNotNecessary,
  kResetAttemptSucceeded,
  kResetAttemptFailed,
  kDelegateNotAllowed,
  kDelegateNotAvailable,
  kCounterQueryFailed,
  kInvalidPcr0State,
  kDictionaryAttackResetStatusNumBuckets
};

}  // namespace tpm_manager

#endif  // TPM_MANAGER_SERVER_DICTIONARY_ATTACK_RESET_STATUS_H_
