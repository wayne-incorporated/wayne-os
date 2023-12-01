// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/crypto_error.h"

#include <iostream>
#include <type_traits>

#include <base/logging.h>

namespace cryptohome {

std::ostream& operator<<(std::ostream& os, const CryptoError& obj) {
  os << static_cast<std::underlying_type<CryptoError>::type>(obj);
  return os;
}

CryptoError LECredErrorToCryptoError(LECredError le_error) {
  switch (le_error) {
    case LE_CRED_ERROR_INVALID_LE_SECRET:
      return CryptoError::CE_LE_INVALID_SECRET;
    case LE_CRED_ERROR_TOO_MANY_ATTEMPTS:
      return CryptoError::CE_TPM_DEFEND_LOCK;
    case LE_CRED_ERROR_INVALID_LABEL:
      return CryptoError::CE_OTHER_CRYPTO;
    case LE_CRED_ERROR_HASH_TREE:
      // TODO(b/195473713): This should be CE_OTHER_FATAL, but return
      // CE_OTHER_CRYPTO here to prevent unintended user homedir removal.
      return CryptoError::CE_OTHER_CRYPTO;
    case LE_CRED_ERROR_PCR_NOT_MATCH:
      // We might want to return an error here that will make the device
      // reboot.
      LOG(ERROR) << "PCR in unexpected state.";
      return CryptoError::CE_LE_INVALID_SECRET;
    case LE_CRED_ERROR_EXPIRED:
      return CryptoError::CE_LE_EXPIRED;
    default:
      return CryptoError::CE_OTHER_CRYPTO;
  }
}

}  // namespace cryptohome
