// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_MOCK_EAP_CREDENTIALS_H_
#define SHILL_MOCK_EAP_CREDENTIALS_H_

#include <string>

#include "shill/eap_credentials.h"

#include <gmock/gmock.h>

namespace shill {

class MockEapCredentials : public EapCredentials {
 public:
  MockEapCredentials();
  MockEapCredentials(const MockEapCredentials&) = delete;
  MockEapCredentials& operator=(const MockEapCredentials&) = delete;

  ~MockEapCredentials() override;

  MOCK_METHOD(bool, IsConnectable, (), (const, override));
  MOCK_METHOD(bool, IsConnectableUsingPassphrase, (), (const, override));
  MOCK_METHOD(void,
              Load,
              (const StoreInterface*, const std::string&),
              (override));
  MOCK_METHOD(void,
              OutputConnectionMetrics,
              (Metrics*, Technology),
              (const, override));
  MOCK_METHOD(void,
              PopulateSupplicantProperties,
              (CertificateFile*, KeyValueStore*),
              (const, override));
  MOCK_METHOD(void,
              Save,
              (StoreInterface*, const std::string&, bool),
              (const, override));
  MOCK_METHOD(void, Reset, (), (override));
  MOCK_METHOD(bool, SetKeyManagement, (const std::string&, Error*), (override));
  MOCK_METHOD(const std::string&, identity, (), (const, override));
  MOCK_METHOD(const std::string&, key_management, (), (const, override));
  MOCK_METHOD(void, set_password, (const std::string&), (override));
  MOCK_METHOD(const std::string&, pin, (), (const, override));

 private:
  std::string kDefaultKeyManagement;
};

}  // namespace shill

#endif  // SHILL_MOCK_EAP_CREDENTIALS_H_
