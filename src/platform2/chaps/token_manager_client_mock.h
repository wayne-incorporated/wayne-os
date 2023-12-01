// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHAPS_TOKEN_MANAGER_CLIENT_MOCK_H_
#define CHAPS_TOKEN_MANAGER_CLIENT_MOCK_H_

#include "chaps/token_manager_client.h"

#include <string>
#include <vector>

#include <brillo/secure_blob.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace chaps {

class TokenManagerClientMock : public TokenManagerClient {
 public:
  MOCK_METHOD2(OpenIsolate, bool(brillo::SecureBlob*, bool*));
  MOCK_METHOD1(CloseIsolate, void(const brillo::SecureBlob&));
  MOCK_METHOD5(LoadToken,
               bool(const brillo::SecureBlob&,
                    const base::FilePath&,
                    const brillo::SecureBlob&,
                    const std::string&,
                    int*));
  MOCK_METHOD2(UnloadToken,
               bool(const brillo::SecureBlob&, const base::FilePath&));
  MOCK_METHOD3(GetTokenPath,
               bool(const brillo::SecureBlob&, int, base::FilePath*));
  MOCK_METHOD2(GetTokenList,
               bool(const brillo::SecureBlob&, std::vector<std::string>*));
};

}  // namespace chaps

#endif  // CHAPS_TOKEN_MANAGER_CLIENT_MOCK_H_
