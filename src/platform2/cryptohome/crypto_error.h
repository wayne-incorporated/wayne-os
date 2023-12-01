// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_CRYPTO_ERROR_H_
#define CRYPTOHOME_CRYPTO_ERROR_H_

#include <iostream>

#include "cryptohome/le_credential_error.h"

namespace cryptohome {

// These values are persisted to logs. Entries should not be renumbered and
// numeric values should never be reused.
// Keep in sync with respective enum in tools/metrics/histograms/enums.xml
enum class CryptoError {
  CE_NONE = 0,
  CE_TPM_FATAL = 1,
  CE_TPM_COMM_ERROR = 2,
  CE_TPM_DEFEND_LOCK = 3,
  CE_TPM_CRYPTO = 4,
  CE_TPM_REBOOT = 5,
  CE_SCRYPT_CRYPTO = 6,
  CE_OTHER_FATAL = 7,
  CE_OTHER_CRYPTO = 8,
  CE_NO_PUBLIC_KEY_HASH = 9,
  // Low Entropy(LE) credential protection is not supported on this device.
  CE_LE_NOT_SUPPORTED = 10,
  // The LE secret provided during decryption is invalid.
  CE_LE_INVALID_SECRET = 11,
  CE_LE_FLAGS_AND_POLICY_MISMATCH = 12,
  // The LE credential had been locked, and this error will take priority over
  // the |CE_LE_INVALID_SECRET|.
  CE_CREDENTIAL_LOCKED = 13,
  // Cryptohome recovery failed with a transient error (retrying the flow may
  // fix the issue).
  CE_RECOVERY_TRANSIENT = 14,
  // Cryptohome recovery failed with a fatal error.
  CE_RECOVERY_FATAL = 15,
  // The LE credential has expired.
  CE_LE_EXPIRED = 16,
  // Add any new values above this one.
  CE_MAX_VALUE,
};

// Enum classes are not implicitly converted for log statements.
std::ostream& operator<<(std::ostream& os, const CryptoError& obj);

// Helper function to avoid the double nested if statements involved with
// checking the error pointer. If |error| is |nullptr|, this does nothing.
template <typename ErrorType>
void PopulateError(ErrorType* error, ErrorType error_code) {
  if (error)
    *error = error_code;
}

CryptoError LECredErrorToCryptoError(LECredError le_error);

}  // namespace cryptohome

#endif  // CRYPTOHOME_CRYPTO_ERROR_H_
