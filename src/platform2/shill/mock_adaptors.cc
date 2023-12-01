// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/mock_adaptors.h"

namespace shill {

// static
const RpcIdentifier DeviceMockAdaptor::kRpcId("/device_rpc");
// static
const RpcIdentifier DeviceMockAdaptor::kRpcConnId =
    RpcIdentifier("/device_rpc_conn");

DeviceMockAdaptor::DeviceMockAdaptor()
    : rpc_id_(kRpcId), rpc_conn_id_(kRpcConnId) {}

DeviceMockAdaptor::~DeviceMockAdaptor() = default;

const RpcIdentifier& DeviceMockAdaptor::GetRpcIdentifier() const {
  return rpc_id_;
}

// static
const RpcIdentifier IPConfigMockAdaptor::kRpcId("/ipconfig_rpc");

IPConfigMockAdaptor::IPConfigMockAdaptor() : rpc_id_(kRpcId) {}

IPConfigMockAdaptor::~IPConfigMockAdaptor() = default;

const RpcIdentifier& IPConfigMockAdaptor::GetRpcIdentifier() const {
  return rpc_id_;
}

// static
const RpcIdentifier ManagerMockAdaptor::kRpcId("/manager_rpc");

ManagerMockAdaptor::ManagerMockAdaptor() : rpc_id_(kRpcId) {}

ManagerMockAdaptor::~ManagerMockAdaptor() = default;

const RpcIdentifier& ManagerMockAdaptor::GetRpcIdentifier() const {
  return rpc_id_;
}

// static
const RpcIdentifier ProfileMockAdaptor::kRpcId("/profile_rpc");

ProfileMockAdaptor::ProfileMockAdaptor() : rpc_id_(kRpcId) {}

ProfileMockAdaptor::~ProfileMockAdaptor() = default;

const RpcIdentifier& ProfileMockAdaptor::GetRpcIdentifier() const {
  return rpc_id_;
}

// static
const RpcIdentifier RpcTaskMockAdaptor::kRpcId("/rpc_task_rpc");
const RpcIdentifier RpcTaskMockAdaptor::kRpcConnId("/rpc_task_rpc_conn");

RpcTaskMockAdaptor::RpcTaskMockAdaptor()
    : rpc_id_(kRpcId), rpc_conn_id_(kRpcConnId) {}

RpcTaskMockAdaptor::~RpcTaskMockAdaptor() = default;

const RpcIdentifier& RpcTaskMockAdaptor::GetRpcIdentifier() const {
  return rpc_id_;
}
const RpcIdentifier& RpcTaskMockAdaptor::GetRpcConnectionIdentifier() const {
  return rpc_conn_id_;
}

// static
const RpcIdentifier ServiceMockAdaptor::kRpcId("/service_rpc");

ServiceMockAdaptor::ServiceMockAdaptor() : rpc_id_(kRpcId) {}

ServiceMockAdaptor::~ServiceMockAdaptor() = default;

const RpcIdentifier& ServiceMockAdaptor::GetRpcIdentifier() const {
  return rpc_id_;
}

#ifndef DISABLE_VPN
ThirdPartyVpnMockAdaptor::ThirdPartyVpnMockAdaptor() = default;

ThirdPartyVpnMockAdaptor::~ThirdPartyVpnMockAdaptor() = default;
#endif

}  // namespace shill
