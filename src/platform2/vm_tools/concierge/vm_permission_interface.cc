// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <utility>

#include <base/check.h>
#include <base/logging.h>
#include <brillo/dbus/dbus_proxy_util.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/bus.h>
#include <dbus/exported_object.h>
#include <dbus/message.h>
#include <dbus/object_proxy.h>
#include <dbus/scoped_dbus_error.h>

#include <vm_permission_service/vm_permission_service.pb.h>

#include "vm_tools/concierge/vm_permission_interface.h"

namespace vm_tools {
namespace concierge {
namespace vm_permission {

namespace {

bool QueryVmPermission(scoped_refptr<dbus::Bus> bus,
                       dbus::ObjectProxy* proxy,
                       const std::string& vm_token,
                       vm_permission_service::Permission::Kind permission) {
  // TODO(dtor): remove when we remove Camera/Mic Chrome flags and
  // always have non-empty token.
  if (vm_token.empty())
    return false;

  dbus::MethodCall method_call(
      chromeos::kVmPermissionServiceInterface,
      chromeos::kVmPermissionServiceGetPermissionsMethod);
  dbus::MessageWriter writer(&method_call);

  vm_permission_service::GetPermissionsRequest request;
  request.set_token(vm_token);

  if (!writer.AppendProtoAsArrayOfBytes(request)) {
    LOG(ERROR) << "Failed to encode GetPermissionsRequest protobuf";
    return false;
  }

  dbus::ScopedDBusError dbus_error;
  std::unique_ptr<dbus::Response> dbus_response =
      brillo::dbus_utils::CallDBusMethodWithErrorResponse(
          bus, proxy, &method_call, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT,
          &dbus_error);
  if (!dbus_response) {
    if (dbus_error.is_set()) {
      LOG(ERROR) << "Getpermissions call failed: " << dbus_error.name() << " ("
                 << dbus_error.message() << ")";
    } else {
      LOG(ERROR)
          << "Failed to send GetPermissions message to permission service";
    }
    return false;
  }

  dbus::MessageReader reader(dbus_response.get());
  vm_permission_service::GetPermissionsResponse response;
  if (!reader.PopArrayOfBytesAsProto(&response)) {
    LOG(ERROR) << "Failed to parse GetPermissionsResponse protobuf";
    return false;
  }

  for (const auto& p : response.permissions()) {
    if (p.kind() == permission)
      return p.allowed();
  }

  return false;
}

};  // namespace

dbus::ObjectProxy* GetServiceProxy(scoped_refptr<dbus::Bus> bus) {
  return bus->GetObjectProxy(
      chromeos::kVmPermissionServiceName,
      dbus::ObjectPath(chromeos::kVmPermissionServicePath));
}

bool RegisterVm(scoped_refptr<dbus::Bus> bus,
                dbus::ObjectProxy* proxy,
                const VmId& vm_id,
                VmType type,
                std::string* token) {
  CHECK(token);

  LOG(INFO) << "Registering VM " << vm_id << " with permission service";

  dbus::MethodCall method_call(chromeos::kVmPermissionServiceInterface,
                               chromeos::kVmPermissionServiceRegisterVmMethod);
  dbus::MessageWriter writer(&method_call);

  vm_permission_service::RegisterVmRequest request;
  request.set_owner_id(vm_id.owner_id());
  request.set_name(vm_id.name());
  switch (type) {
    case VmType::CROSTINI_VM:
      request.set_type(vm_permission_service::RegisterVmRequest::CROSTINI_VM);
      break;
    case VmType::PLUGIN_VM:
      request.set_type(vm_permission_service::RegisterVmRequest::PLUGIN_VM);
      break;
    case VmType::BOREALIS:
      request.set_type(vm_permission_service::RegisterVmRequest::BOREALIS);
      break;
  }

  if (!writer.AppendProtoAsArrayOfBytes(request)) {
    LOG(ERROR) << "Failed to encode RegisterVmRequest protobuf";
    return false;
  }

  dbus::ScopedDBusError dbus_error;
  std::unique_ptr<dbus::Response> dbus_response =
      brillo::dbus_utils::CallDBusMethodWithErrorResponse(
          bus, proxy, &method_call, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT,
          &dbus_error);
  if (!dbus_response) {
    if (!dbus_error.is_set()) {
      LOG(ERROR) << "Failed to send RegisterVm message to permission service";
    } else if (strcmp(dbus_error.name(), DBUS_ERROR_NOT_SUPPORTED) == 0) {
      // TODO(dtor): remove when we remove Camera/Mic Chrome flags stop
      // returning DBUS_ERROR_NOT_SUPPORTED.
      *token = std::string();
      return true;
    } else {
      LOG(ERROR) << "RegisterVm call failed: " << dbus_error.name() << " ("
                 << dbus_error.message() << ")";
    }
    return false;
  }

  dbus::MessageReader reader(dbus_response.get());
  vm_permission_service::RegisterVmResponse response;
  if (!reader.PopArrayOfBytesAsProto(&response)) {
    LOG(ERROR) << "Failed to parse RegisterVmResponse protobuf";
    return false;
  }

  if (response.token().empty()) {
    LOG(ERROR) << "Permission service returned invalid token";
    return false;
  }

  *token = response.token();
  return true;
}

bool UnregisterVm(scoped_refptr<dbus::Bus> bus,
                  dbus::ObjectProxy* proxy,
                  const VmId& vm_id) {
  LOG(INFO) << "Unregistering VM " << vm_id << " from permission service";

  dbus::MethodCall method_call(
      chromeos::kVmPermissionServiceInterface,
      chromeos::kVmPermissionServiceUnregisterVmMethod);
  dbus::MessageWriter writer(&method_call);

  vm_permission_service::UnregisterVmRequest request;
  request.set_owner_id(vm_id.owner_id());
  request.set_name(vm_id.name());

  if (!writer.AppendProtoAsArrayOfBytes(request)) {
    LOG(ERROR) << "Failed to encode UnregisterVmRequest protobuf";
    return false;
  }

  dbus::ScopedDBusError dbus_error;
  std::unique_ptr<dbus::Response> dbus_response =
      brillo::dbus_utils::CallDBusMethodWithErrorResponse(
          bus, proxy, &method_call, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT,
          &dbus_error);
  if (!dbus_response) {
    if (dbus_error.is_set()) {
      LOG(ERROR) << "UnregisterVm call failed: " << dbus_error.name() << " ("
                 << dbus_error.message() << ")";
    } else {
      LOG(ERROR) << "Failed to send UnregisterVm message to permission service";
    }
    return false;
  }

  // There is no body in successful response to unregister request.
  return true;
}

bool IsMicrophoneEnabled(scoped_refptr<dbus::Bus> bus,
                         dbus::ObjectProxy* proxy,
                         const std::string& vm_token) {
  return QueryVmPermission(std::move(bus), proxy, vm_token,
                           vm_permission_service::Permission::MICROPHONE);
}

bool IsCameraEnabled(scoped_refptr<dbus::Bus> bus,
                     dbus::ObjectProxy* proxy,
                     const std::string& vm_token) {
  return QueryVmPermission(std::move(bus), proxy, vm_token,
                           vm_permission_service::Permission::CAMERA);
}
}  // namespace vm_permission
}  // namespace concierge
}  // namespace vm_tools
