// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TPM_MANAGER_SERVER_MOCK_OPENSSL_CRYPTO_UTIL_H_
#define TPM_MANAGER_SERVER_MOCK_OPENSSL_CRYPTO_UTIL_H_

#include <string>

#include <gmock/gmock.h>

#include "tpm_manager/server/openssl_crypto_util.h"

namespace tpm_manager {

class MockOpensslCryptoUtil : public OpensslCryptoUtil {
 public:
  MockOpensslCryptoUtil();
  ~MockOpensslCryptoUtil() override;

  MOCK_METHOD(bool, GetRandomBytes, (size_t, std::string*), (override));

 private:
  bool FakeGetRandomBytes(size_t num_bytes, std::string* random_data);
};

}  // namespace tpm_manager

#endif  // TPM_MANAGER_SERVER_MOCK_OPENSSL_CRYPTO_UTIL_H_
