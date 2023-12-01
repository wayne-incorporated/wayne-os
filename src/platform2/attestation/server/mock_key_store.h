// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ATTESTATION_SERVER_MOCK_KEY_STORE_H_
#define ATTESTATION_SERVER_MOCK_KEY_STORE_H_

#include "attestation/server/key_store.h"

#include <string>

#include <gmock/gmock.h>

namespace attestation {

class MockKeyStore : public KeyStore {
 public:
  MockKeyStore();
  MockKeyStore(const MockKeyStore&) = delete;
  MockKeyStore& operator=(const MockKeyStore&) = delete;

  ~MockKeyStore() override;

  MOCK_METHOD(bool,
              Read,
              (const std::string&, const std::string&, std::string*),
              (override));
  MOCK_METHOD(bool,
              Write,
              (const std::string&, const std::string&, const std::string&),
              (override));
  MOCK_METHOD(bool,
              Delete,
              (const std::string&, const std::string&),
              (override));
  MOCK_METHOD(bool,
              DeleteByPrefix,
              (const std::string&, const std::string&),
              (override));
  MOCK_METHOD(bool,
              Register,
              (const std::string&,
               const std::string&,
               KeyType,
               KeyUsage,
               const std::string&,
               const std::string&,
               const std::string&),
              (override));
  MOCK_METHOD(bool,
              RegisterCertificate,
              (const std::string&, const std::string&),
              (override));
};

}  // namespace attestation

#endif  // ATTESTATION_SERVER_MOCK_KEY_STORE_H_
