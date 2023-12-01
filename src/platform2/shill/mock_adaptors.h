// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_MOCK_ADAPTORS_H_
#define SHILL_MOCK_ADAPTORS_H_

#include <string>
#include <vector>

#include <gmock/gmock.h>

#include "shill/adaptor_interfaces.h"
#include "shill/error.h"
#include "shill/store/key_value_store.h"

namespace shill {

// These are the functions that a Device adaptor must support
class DeviceMockAdaptor : public DeviceAdaptorInterface {
 public:
  static const RpcIdentifier kRpcId;
  static const RpcIdentifier kRpcConnId;

  DeviceMockAdaptor();
  ~DeviceMockAdaptor() override;
  const RpcIdentifier& GetRpcIdentifier() const override;

  MOCK_METHOD(void, EmitBoolChanged, (const std::string&, bool), (override));
  MOCK_METHOD(void,
              EmitUintChanged,
              (const std::string&, uint32_t),
              (override));
  MOCK_METHOD(void,
              EmitUint16Changed,
              (const std::string&, uint16_t),
              (override));
  MOCK_METHOD(void, EmitIntChanged, (const std::string&, int), (override));
  MOCK_METHOD(void,
              EmitStringChanged,
              (const std::string&, const std::string&),
              (override));
  MOCK_METHOD(void,
              EmitStringmapChanged,
              (const std::string&, const Stringmap&),
              (override));
  MOCK_METHOD(void,
              EmitStringmapsChanged,
              (const std::string&, const Stringmaps&),
              (override));
  MOCK_METHOD(void,
              EmitStringsChanged,
              (const std::string&, const Strings&),
              (override));
  MOCK_METHOD(void,
              EmitKeyValueStoreChanged,
              (const std::string&, const KeyValueStore&),
              (override));
  MOCK_METHOD(void,
              EmitKeyValueStoresChanged,
              (const std::string&, const KeyValueStores&),
              (override));
  MOCK_METHOD(void,
              EmitRpcIdentifierChanged,
              (const std::string&, const RpcIdentifier&),
              (override));
  MOCK_METHOD(void,
              EmitRpcIdentifierArrayChanged,
              (const std::string&, const std::vector<RpcIdentifier>&),
              (override));

 private:
  const RpcIdentifier rpc_id_;
  const RpcIdentifier rpc_conn_id_;
};

// These are the functions that a IPConfig adaptor must support
class IPConfigMockAdaptor : public IPConfigAdaptorInterface {
 public:
  static const RpcIdentifier kRpcId;

  IPConfigMockAdaptor();
  ~IPConfigMockAdaptor() override;
  const RpcIdentifier& GetRpcIdentifier() const override;

  MOCK_METHOD(void, EmitBoolChanged, (const std::string&, bool), (override));
  MOCK_METHOD(void,
              EmitUintChanged,
              (const std::string&, uint32_t),
              (override));
  MOCK_METHOD(void, EmitIntChanged, (const std::string&, int), (override));
  MOCK_METHOD(void,
              EmitStringChanged,
              (const std::string&, const std::string&),
              (override));
  MOCK_METHOD(void,
              EmitStringsChanged,
              (const std::string&, const std::vector<std::string>&),
              (override));

 private:
  const RpcIdentifier rpc_id_;
};

// These are the functions that a Manager adaptor must support
class ManagerMockAdaptor : public ManagerAdaptorInterface {
 public:
  static const RpcIdentifier kRpcId;

  ManagerMockAdaptor();
  ~ManagerMockAdaptor() override;
  const RpcIdentifier& GetRpcIdentifier() const override;

  MOCK_METHOD(void,
              RegisterAsync,
              (base::OnceCallback<void(bool)>),
              (override));
  MOCK_METHOD(void, EmitBoolChanged, (const std::string&, bool), (override));
  MOCK_METHOD(void,
              EmitUintChanged,
              (const std::string&, uint32_t),
              (override));
  MOCK_METHOD(void, EmitIntChanged, (const std::string&, int), (override));
  MOCK_METHOD(void,
              EmitStringChanged,
              (const std::string&, const std::string&),
              (override));
  MOCK_METHOD(void,
              EmitStringsChanged,
              (const std::string&, const std::vector<std::string>&),
              (override));
  MOCK_METHOD(void,
              EmitKeyValueStoreChanged,
              (const std::string&, const KeyValueStore&),
              (override));
  MOCK_METHOD(void,
              EmitRpcIdentifierChanged,
              (const std::string&, const RpcIdentifier&),
              (override));
  MOCK_METHOD(void,
              EmitRpcIdentifierArrayChanged,
              (const std::string&, const std::vector<RpcIdentifier>&),
              (override));

 private:
  const RpcIdentifier rpc_id_;
};

// These are the functions that a Profile adaptor must support
class ProfileMockAdaptor : public ProfileAdaptorInterface {
 public:
  static const RpcIdentifier kRpcId;

  ProfileMockAdaptor();
  ~ProfileMockAdaptor() override;
  const RpcIdentifier& GetRpcIdentifier() const override;

  MOCK_METHOD(void, EmitBoolChanged, (const std::string&, bool), (override));
  MOCK_METHOD(void,
              EmitUintChanged,
              (const std::string&, uint32_t),
              (override));
  MOCK_METHOD(void, EmitIntChanged, (const std::string&, int), (override));
  MOCK_METHOD(void,
              EmitStringChanged,
              (const std::string&, const std::string&),
              (override));

 private:
  const RpcIdentifier rpc_id_;
};

// These are the functions that a Task adaptor must support
class RpcTaskMockAdaptor : public RpcTaskAdaptorInterface {
 public:
  static const RpcIdentifier kRpcId;
  static const RpcIdentifier kRpcConnId;

  RpcTaskMockAdaptor();
  ~RpcTaskMockAdaptor() override;

  const RpcIdentifier& GetRpcIdentifier() const override;
  const RpcIdentifier& GetRpcConnectionIdentifier() const override;

 private:
  const RpcIdentifier rpc_id_;
  const RpcIdentifier rpc_conn_id_;
};

// These are the functions that a Service adaptor must support
class ServiceMockAdaptor : public ServiceAdaptorInterface {
 public:
  static const RpcIdentifier kRpcId;

  ServiceMockAdaptor();
  ~ServiceMockAdaptor() override;
  const RpcIdentifier& GetRpcIdentifier() const override;

  MOCK_METHOD(void, EmitBoolChanged, (const std::string&, bool), (override));
  MOCK_METHOD(void,
              EmitUint8Changed,
              (const std::string&, uint8_t),
              (override));
  MOCK_METHOD(void,
              EmitUint16Changed,
              (const std::string&, uint16_t),
              (override));
  MOCK_METHOD(void,
              EmitUint16sChanged,
              (const std::string&, const Uint16s&),
              (override));
  MOCK_METHOD(void,
              EmitUintChanged,
              (const std::string&, uint32_t),
              (override));
  MOCK_METHOD(void,
              EmitUint64Changed,
              (const std::string&, uint64_t),
              (override));

  MOCK_METHOD(void, EmitIntChanged, (const std::string&, int), (override));
  MOCK_METHOD(void,
              EmitRpcIdentifierChanged,
              (const std::string&, const RpcIdentifier&),
              (override));
  MOCK_METHOD(void,
              EmitStringChanged,
              (const std::string&, const std::string&),
              (override));
  MOCK_METHOD(void,
              EmitStringmapChanged,
              (const std::string&, const Stringmap&),
              (override));
  MOCK_METHOD(void,
              EmitStringmapsChanged,
              (const std::string&, const Stringmaps&),
              (override));

 private:
  const RpcIdentifier rpc_id_;
};

#ifndef DISABLE_VPN
class ThirdPartyVpnMockAdaptor : public ThirdPartyVpnAdaptorInterface {
 public:
  ThirdPartyVpnMockAdaptor();
  ~ThirdPartyVpnMockAdaptor() override;

  MOCK_METHOD(void,
              EmitPacketReceived,
              (const std::vector<uint8_t>&),
              (override));
  MOCK_METHOD(void, EmitPlatformMessage, (uint32_t), (override));
};
#endif

}  // namespace shill

#endif  // SHILL_MOCK_ADAPTORS_H_
