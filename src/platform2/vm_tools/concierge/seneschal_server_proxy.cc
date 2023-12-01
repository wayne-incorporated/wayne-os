// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/concierge/seneschal_server_proxy.h"

#include <base/logging.h>
#include <brillo/dbus/dbus_proxy_util.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/message.h>
#include <dbus/object_path.h>
#include <seneschal/proto_bindings/seneschal_service.pb.h>

namespace vm_tools {
namespace concierge {

// static
std::unique_ptr<SeneschalServerProxy>
SeneschalServerProxy::SeneschalCreateProxy(scoped_refptr<dbus::Bus> bus,
                                           dbus::ObjectProxy* seneschal_proxy,
                                           dbus::MethodCall* method_call) {
  std::unique_ptr<dbus::Response> dbus_response =
      brillo::dbus_utils::CallDBusMethod(
          bus, seneschal_proxy, method_call,
          dbus::ObjectProxy::TIMEOUT_USE_DEFAULT);
  if (!dbus_response) {
    LOG(ERROR) << "Failed to send StartServer message to seneschal service";
    return nullptr;
  }

  dbus::MessageReader reader(dbus_response.get());
  vm_tools::seneschal::StartServerResponse response;
  if (!reader.PopArrayOfBytesAsProto(&response)) {
    LOG(ERROR) << "Failed to parse StartServerResponse protobuf";
    return nullptr;
  }

  if (!response.success()) {
    LOG(ERROR) << "Failed to start server: " << response.failure_reason();
    return nullptr;
  }

  return std::unique_ptr<SeneschalServerProxy>(
      new SeneschalServerProxy(bus, seneschal_proxy, response.handle()));
}

// static
std::unique_ptr<SeneschalServerProxy> SeneschalServerProxy::CreateVsockProxy(
    scoped_refptr<dbus::Bus> bus,
    dbus::ObjectProxy* seneschal_proxy,
    uint32_t port,
    uint32_t accept_cid,
    std::vector<std::pair<uint32_t, uint32_t>> uid_map,
    std::vector<std::pair<uint32_t, uint32_t>> gid_map) {
  dbus::MethodCall method_call(vm_tools::seneschal::kSeneschalInterface,
                               vm_tools::seneschal::kStartServerMethod);
  dbus::MessageWriter writer(&method_call);

  vm_tools::seneschal::StartServerRequest request;
  request.mutable_vsock()->set_port(port);
  request.mutable_vsock()->set_accept_cid(accept_cid);

  for (const auto& mapping : uid_map) {
    seneschal::IdMap* id_map = request.add_uid_maps();
    id_map->set_server(mapping.first);
    id_map->set_client(mapping.second);
  }

  for (const auto& mapping : gid_map) {
    seneschal::IdMap* id_map = request.add_gid_maps();
    id_map->set_server(mapping.first);
    id_map->set_client(mapping.second);
  }

  if (!writer.AppendProtoAsArrayOfBytes(request)) {
    LOG(ERROR) << "Failed to encode StartServerRequest protobuf";
    return nullptr;
  }

  return SeneschalCreateProxy(bus, seneschal_proxy, &method_call);
}

// static
std::unique_ptr<SeneschalServerProxy> SeneschalServerProxy::CreateFdProxy(
    scoped_refptr<dbus::Bus> bus,
    dbus::ObjectProxy* seneschal_proxy,
    const base::ScopedFD& socket_fd) {
  dbus::MethodCall method_call(vm_tools::seneschal::kSeneschalInterface,
                               vm_tools::seneschal::kStartServerMethod);
  dbus::MessageWriter writer(&method_call);

  vm_tools::seneschal::StartServerRequest request;
  request.mutable_fd();
  if (!writer.AppendProtoAsArrayOfBytes(request)) {
    LOG(ERROR) << "Failed to encode StartServerRequest protobuf";
    return nullptr;
  }

  writer.AppendFileDescriptor(socket_fd.get());

  return SeneschalCreateProxy(bus, seneschal_proxy, &method_call);
}

SeneschalServerProxy::SeneschalServerProxy(scoped_refptr<dbus::Bus> bus,
                                           dbus::ObjectProxy* seneschal_proxy,
                                           uint32_t handle)
    : bus_(std::move(bus)),
      seneschal_proxy_(seneschal_proxy),
      handle_(handle) {}

SeneschalServerProxy::~SeneschalServerProxy() {
  dbus::MethodCall method_call(vm_tools::seneschal::kSeneschalInterface,
                               vm_tools::seneschal::kStopServerMethod);
  dbus::MessageWriter writer(&method_call);

  vm_tools::seneschal::StopServerRequest request;
  request.set_handle(handle_);

  if (!writer.AppendProtoAsArrayOfBytes(request)) {
    LOG(ERROR) << "Failed to encode StopServerRequest protobuf";
    return;
  }

  std::unique_ptr<dbus::Response> dbus_response =
      brillo::dbus_utils::CallDBusMethod(
          bus_, seneschal_proxy_, &method_call,
          dbus::ObjectProxy::TIMEOUT_USE_DEFAULT);
  if (!dbus_response) {
    LOG(ERROR) << "Failed to send StopServer message to seneschal service";
    return;
  }

  dbus::MessageReader reader(dbus_response.get());
  vm_tools::seneschal::StopServerResponse response;
  if (!reader.PopArrayOfBytesAsProto(&response)) {
    LOG(ERROR) << "Failed to parse StopServerResponse protobuf";
    return;
  }

  if (!response.success()) {
    LOG(ERROR) << "Failed to stop server " << handle_ << ": "
               << response.failure_reason();
    return;
  }
}

}  // namespace concierge
}  // namespace vm_tools
