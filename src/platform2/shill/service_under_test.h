// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_SERVICE_UNDER_TEST_H_
#define SHILL_SERVICE_UNDER_TEST_H_

#include <string>
#include <vector>

#include "shill/ipconfig.h"
#include "shill/service.h"
#include "shill/store/key_value_store.h"

namespace shill {

class Error;
class Manager;

// This is a simple Service subclass with all the pure-virtual methods stubbed.
class ServiceUnderTest : public Service {
 public:
  static const char kKeyValueStoreProperty[];
  static const RpcIdentifier kRpcId;
  static const char kStringsProperty[];
  static const char kStorageId[];

  explicit ServiceUnderTest(Manager* manager);
  ServiceUnderTest(const ServiceUnderTest&) = delete;
  ServiceUnderTest& operator=(const ServiceUnderTest&) = delete;

  ~ServiceUnderTest() override;

  const RpcIdentifier& GetRpcIdentifier() const override;
  RpcIdentifier GetDeviceRpcId(Error* error) const override;
  std::string GetStorageIdentifier() const override;

  // Getter and setter for a string array property for use in testing.
  void set_strings(const std::vector<std::string>& strings) {
    strings_ = strings;
  }
  const std::vector<std::string>& strings() const { return strings_; }

  // Getter and setter for a KeyValueStore property for use in testing.
  bool SetKeyValueStore(const KeyValueStore& value, Error* error);
  KeyValueStore GetKeyValueStore(Error* error);

  void SetDisconnectable(bool disconnectable) {
    disconnectable_ = disconnectable;
  }

  int connect_calls() const { return connect_calls_; }

 protected:
  // Inherited from Service.
  void OnConnect(Error* error) override;
  void OnDisconnect(Error* /*error*/, const char* /*reason*/) override {}
  bool IsDisconnectable(Error* error) const override;

 private:
  // The Service superclass has no string array or KeyValueStore properties
  // but we need them in order to test Service::Configure.
  std::vector<std::string> strings_;
  KeyValueStore key_value_store_;

  bool disconnectable_ = true;
  int connect_calls_ = 0;
};

}  // namespace shill

#endif  // SHILL_SERVICE_UNDER_TEST_H_
