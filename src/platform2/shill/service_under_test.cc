// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/service_under_test.h"

#include <string>

#include "shill/mock_adaptors.h"
#include "shill/store/property_accessor.h"

namespace shill {

// static
const char ServiceUnderTest::kKeyValueStoreProperty[] = "key_value_store";
const RpcIdentifier ServiceUnderTest::kRpcId =
    RpcIdentifier("/mock_device_rpc");
const char ServiceUnderTest::kStringsProperty[] = "strings";
const char ServiceUnderTest::kStorageId[] = "service";

ServiceUnderTest::ServiceUnderTest(Manager* manager)
    : Service(manager, Technology::kUnknown) {
  mutable_store()->RegisterStrings(kStringsProperty, &strings_);
  mutable_store()->RegisterDerivedKeyValueStore(
      kKeyValueStoreProperty,
      KeyValueStoreAccessor(new CustomAccessor<ServiceUnderTest, KeyValueStore>(
          this, &ServiceUnderTest::GetKeyValueStore,
          &ServiceUnderTest::SetKeyValueStore)));

  SetConnectable(true);
}

ServiceUnderTest::~ServiceUnderTest() = default;

const RpcIdentifier& ServiceUnderTest::GetRpcIdentifier() const {
  return ServiceMockAdaptor::kRpcId;
}

RpcIdentifier ServiceUnderTest::GetDeviceRpcId(Error* /*error*/) const {
  return kRpcId;
}

std::string ServiceUnderTest::GetStorageIdentifier() const {
  return kStorageId;
}

bool ServiceUnderTest::SetKeyValueStore(const KeyValueStore& value,
                                        Error* error) {
  key_value_store_.Clear();
  key_value_store_.CopyFrom(value);
  return true;
}

KeyValueStore ServiceUnderTest::GetKeyValueStore(Error* error) {
  return key_value_store_;
}

bool ServiceUnderTest::IsDisconnectable(Error* error) const {
  if (!Service::IsDisconnectable(error))
    return false;
  return disconnectable_;
}

void ServiceUnderTest::OnConnect(Error* error) {
  connect_calls_++;
}

}  // namespace shill
