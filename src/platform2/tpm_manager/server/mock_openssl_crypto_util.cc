// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tpm_manager/server/mock_openssl_crypto_util.h"

using testing::_;
using testing::Invoke;

namespace tpm_manager {

MockOpensslCryptoUtil::MockOpensslCryptoUtil() {
  ON_CALL(*this, GetRandomBytes(_, _))
      .WillByDefault(Invoke(this, &MockOpensslCryptoUtil::FakeGetRandomBytes));
}

MockOpensslCryptoUtil::~MockOpensslCryptoUtil() {}

bool MockOpensslCryptoUtil::FakeGetRandomBytes(size_t num_bytes,
                                               std::string* random_data) {
  random_data->assign(num_bytes, 'a');
  return true;
}

}  // namespace tpm_manager
