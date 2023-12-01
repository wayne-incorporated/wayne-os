// Copyright 2011 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LOGIN_MANAGER_MOCK_POLICY_KEY_H_
#define LOGIN_MANAGER_MOCK_POLICY_KEY_H_

#include "login_manager/policy_key.h"

#include <stdint.h>
#include <unistd.h>

#include <string>
#include <vector>

#include <crypto/signature_verifier.h>
#include <gmock/gmock.h>

namespace base {
class RSAPrivateKey;
}

namespace login_manager {
class MockPolicyKey : public PolicyKey {
 public:
  MockPolicyKey();
  ~MockPolicyKey() override;
  MOCK_METHOD(bool, Equals, (const std::string&), (const, override));
  MOCK_METHOD(bool, VEquals, (const std::vector<uint8_t>&), (const, override));
  MOCK_METHOD(bool, HaveCheckedDisk, (), (const, override));
  MOCK_METHOD(bool, IsPopulated, (), (const, override));
  MOCK_METHOD(bool, PopulateFromDiskIfPossible, (), (override));
  MOCK_METHOD(bool,
              PopulateFromBuffer,
              (const std::vector<uint8_t>&),
              (override));
  MOCK_METHOD(bool, PopulateFromKeypair, (crypto::RSAPrivateKey*), (override));
  MOCK_METHOD(bool, Persist, (), (override));
  MOCK_METHOD(bool,
              Rotate,
              (const std::vector<uint8_t>&,
               const std::vector<uint8_t>&,
               const crypto::SignatureVerifier::SignatureAlgorithm algorithm),
              (override));
  MOCK_METHOD(bool,
              ClobberCompromisedKey,
              (const std::vector<uint8_t>&),
              (override));
  MOCK_METHOD(bool,
              Verify,
              (const std::vector<uint8_t>&,
               const std::vector<uint8_t>&,
               const crypto::SignatureVerifier::SignatureAlgorithm algorithm),
              (override));
  MOCK_METHOD(const std::vector<uint8_t>&,
              public_key_der,
              (),
              (const, override));
};
}  // namespace login_manager

#endif  // LOGIN_MANAGER_MOCK_POLICY_KEY_H_
