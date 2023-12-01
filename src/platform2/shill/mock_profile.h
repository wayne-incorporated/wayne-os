// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_MOCK_PROFILE_H_
#define SHILL_MOCK_PROFILE_H_

#include <string>

#include <gmock/gmock.h>

#include "shill/profile.h"

namespace shill {

class MockProfile : public Profile {
 public:
  explicit MockProfile(Manager* manager);
  MockProfile(Manager* manager, const std::string& identifier);
  MockProfile(const MockProfile&) = delete;
  MockProfile& operator=(const MockProfile&) = delete;

  ~MockProfile() override;

  MOCK_METHOD(bool, AdoptService, (const ServiceRefPtr&), (override));
  MOCK_METHOD(bool, AbandonService, (const ServiceRefPtr&), (override));
  MOCK_METHOD(bool, LoadService, (const ServiceRefPtr&), (override));
  MOCK_METHOD(bool, ConfigureService, (const ServiceRefPtr&), (override));
  MOCK_METHOD(bool, ConfigureDevice, (const DeviceRefPtr&), (override));
  MOCK_METHOD(void, DeleteEntry, (const std::string&, Error*), (override));
  MOCK_METHOD(const RpcIdentifier&, GetRpcIdentifier, (), (const, override));
  MOCK_METHOD(bool, UpdateService, (const ServiceRefPtr&), (override));
  MOCK_METHOD(bool, UpdateDevice, (const DeviceRefPtr&), (override));
  MOCK_METHOD(bool,
              AdoptCredentials,
              (const PasspointCredentialsRefPtr&),
              (override));
  MOCK_METHOD(bool, Save, (), (override));
  MOCK_METHOD(StoreInterface*, GetStorage, (), (override));
  MOCK_METHOD(const StoreInterface*, GetConstStorage, (), (const, override));
  MOCK_METHOD(bool, IsDefault, (), (const, override));

 private:
  RpcIdentifier rpcid_;
};

}  // namespace shill

#endif  // SHILL_MOCK_PROFILE_H_
