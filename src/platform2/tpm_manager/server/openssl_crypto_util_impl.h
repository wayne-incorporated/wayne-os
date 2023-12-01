// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TPM_MANAGER_SERVER_OPENSSL_CRYPTO_UTIL_IMPL_H_
#define TPM_MANAGER_SERVER_OPENSSL_CRYPTO_UTIL_IMPL_H_

#include <string>

#include "tpm_manager/server/openssl_crypto_util.h"

namespace tpm_manager {

// OpensslCryptoUtilImpl is the default implementation of the
// OpensslCryptoUtil interface.
// Example usage:
// OpensslCryptoUtilImpl util;
// std::string random_bytes;
// bool result = util.GetRandomBytes(5, &random_bytes);
class OpensslCryptoUtilImpl : public OpensslCryptoUtil {
 public:
  OpensslCryptoUtilImpl() = default;
  OpensslCryptoUtilImpl(const OpensslCryptoUtilImpl&) = delete;
  OpensslCryptoUtilImpl& operator=(const OpensslCryptoUtilImpl&) = delete;

  ~OpensslCryptoUtilImpl() override = default;

  // OpensslCryptoUtil methods.
  [[nodiscard]] bool GetRandomBytes(size_t num_bytes,
                                    std::string* random_data) override;
};

}  // namespace tpm_manager

#endif  // TPM_MANAGER_SERVER_OPENSSL_CRYPTO_UTIL_IMPL_H_
