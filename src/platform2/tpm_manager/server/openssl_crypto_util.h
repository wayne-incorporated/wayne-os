// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TPM_MANAGER_SERVER_OPENSSL_CRYPTO_UTIL_H_
#define TPM_MANAGER_SERVER_OPENSSL_CRYPTO_UTIL_H_

#include <string>

namespace tpm_manager {

// This class is used to provide a mockable interface for openssl calls.
class OpensslCryptoUtil {
 public:
  OpensslCryptoUtil() = default;
  OpensslCryptoUtil(const OpensslCryptoUtil&) = delete;
  OpensslCryptoUtil& operator=(const OpensslCryptoUtil&) = delete;

  virtual ~OpensslCryptoUtil() = default;

  // This method sets the out argument |random_data| to a string with at
  // least |num_bytes| of random data and returns true on success.
  [[nodiscard]] virtual bool GetRandomBytes(size_t num_bytes,
                                            std::string* random_data) = 0;
};

}  // namespace tpm_manager

#endif  // TPM_MANAGER_SERVER_OPENSSL_CRYPTO_UTIL_H_
