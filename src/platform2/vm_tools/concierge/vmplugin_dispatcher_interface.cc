// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <optional>
#include <utility>

#include <base/check_op.h>
#include <base/logging.h>
#include <base/time/time.h>
#include <base/uuid.h>
#include <brillo/dbus/dbus_proxy_util.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/bus.h>
#include <dbus/exported_object.h>
#include <dbus/message.h>
#include <dbus/object_proxy.h>
#include <dbus/scoped_dbus_error.h>

#include <vm_plugin_dispatcher/vm_plugin_dispatcher.pb.h>

#include "vm_tools/concierge/plugin_vm_config.h"
#include "vm_tools/concierge/vmplugin_dispatcher_interface.h"

namespace vm_tools {
namespace concierge {
namespace pvm {
namespace dispatcher {
namespace {

constexpr base::TimeDelta kVmShutdownTimeout = base::Minutes(2);
constexpr base::TimeDelta kVmSuspendTimeout = base::Seconds(20);

// Native Parallels error codes.
constexpr int PRL_ERR_SUCCESS = 0;
constexpr int PRL_ERR_DISP_SHUTDOWN_IN_PROCESS = 0x80000404;
constexpr int PRL_ERR_LICENSE_NOT_VALID = 0x80011000;
constexpr int PRL_ERR_LICENSE_EXPIRED = 0x80011001;
constexpr int PRL_ERR_LICENSE_WRONG_VERSION = 0x80011002;
constexpr int PRL_ERR_LICENSE_WRONG_PLATFORM = 0x80011004;
constexpr int PRL_ERR_LICENSE_BETA_KEY_RELEASE_PRODUCT = 0x80011011;
constexpr int PRL_ERR_LICENSE_RELEASE_KEY_BETA_PRODUCT = 0x80011013;
constexpr int PRL_ERR_LICENSE_SUBSCR_EXPIRED = 0x80011074;
constexpr int PRL_ERR_JLIC_WRONG_HWID = 0x80057005;
constexpr int PRL_ERR_JLIC_LICENSE_DISABLED = 0x80057010;
constexpr int PRL_ERR_JLIC_WEB_PORTAL_ACCESS_REQUIRED = 0x80057012;

VmOpResult ConvertNativeResult(int result) {
  switch (result) {
    case PRL_ERR_SUCCESS:
      return VmOpResult::SUCCESS;
    case PRL_ERR_DISP_SHUTDOWN_IN_PROCESS:
      return VmOpResult::DISPATCHER_SHUTTING_DOWN;
    case PRL_ERR_LICENSE_NOT_VALID:
    case PRL_ERR_LICENSE_EXPIRED:
    case PRL_ERR_LICENSE_WRONG_VERSION:
    case PRL_ERR_LICENSE_WRONG_PLATFORM:
    case PRL_ERR_LICENSE_BETA_KEY_RELEASE_PRODUCT:
    case PRL_ERR_LICENSE_RELEASE_KEY_BETA_PRODUCT:
    case PRL_ERR_LICENSE_SUBSCR_EXPIRED:
    case PRL_ERR_JLIC_WRONG_HWID:
    case PRL_ERR_JLIC_LICENSE_DISABLED:
    case PRL_ERR_JLIC_WEB_PORTAL_ACCESS_REQUIRED:
      return VmOpResult::DISPATCHER_LICENSE_ERROR;
    default:
      return VmOpResult::DISPATCHER_GENERIC_ERROR;
  }
}

VmOpResult ConvertDispatcherResult(plugin_dispatcher::VmErrorCode result,
                                   int native_result) {
  switch (result) {
    case plugin_dispatcher::VM_SUCCESS:
      return VmOpResult::SUCCESS;
    case plugin_dispatcher::VM_ERR_NATIVE_RESULT_CODE:
      return ConvertNativeResult(native_result);
    default:
      return VmOpResult::INTERNAL_ERROR;
  }
}

bool GetVmInfo(scoped_refptr<dbus::Bus> bus,
               dbus::ObjectProxy* proxy,
               const VmId& vm_id,
               std::optional<vm_tools::plugin_dispatcher::VmInfo>* info) {
  dbus::MethodCall method_call(
      vm_tools::plugin_dispatcher::kVmPluginDispatcherInterface,
      vm_tools::plugin_dispatcher::kListVmsMethod);
  dbus::MessageWriter writer(&method_call);

  vm_tools::plugin_dispatcher::ListVmRequest request;

  request.set_owner_id(vm_id.owner_id());
  request.set_vm_name_uuid(vm_id.name());

  if (!writer.AppendProtoAsArrayOfBytes(request)) {
    LOG(ERROR) << "Failed to encode ListVmRequest protobuf";
    return false;
  }

  std::unique_ptr<dbus::Response> dbus_response =
      brillo::dbus_utils::CallDBusMethod(
          bus, proxy, &method_call, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT);
  if (!dbus_response) {
    LOG(ERROR) << "Failed to send ListVm message to dispatcher service";
    return false;
  }

  dbus::MessageReader reader(dbus_response.get());
  vm_tools::plugin_dispatcher::ListVmResponse response;
  if (!reader.PopArrayOfBytesAsProto(&response)) {
    LOG(ERROR) << "Failed to parse ListVmResponse protobuf";
    return false;
  }

  if (response.error() != vm_tools::plugin_dispatcher::VM_SUCCESS) {
    LOG(ERROR) << "Failed to get VM info: " << std::hex << std::showbase
               << response.error() << " (" << response.result_code() << ")";
    return false;
  }

  *info = std::nullopt;
  for (const auto& vm_info : response.vm_info()) {
    if (vm_info.name() == vm_id.name()) {
      *info = vm_info;
      break;
    }
  }

  return info;
}

}  // namespace

dbus::ObjectProxy* GetServiceProxy(scoped_refptr<dbus::Bus> bus) {
  return bus->GetObjectProxy(
      vm_tools::plugin_dispatcher::kVmPluginDispatcherServiceName,
      dbus::ObjectPath(
          vm_tools::plugin_dispatcher::kVmPluginDispatcherServicePath));
}

bool RegisterVm(scoped_refptr<dbus::Bus> bus,
                dbus::ObjectProxy* proxy,
                const VmId& vm_id,
                const base::FilePath& image_path) {
  dbus::MethodCall method_call(
      vm_tools::plugin_dispatcher::kVmPluginDispatcherInterface,
      vm_tools::plugin_dispatcher::kRegisterVmMethod);
  dbus::MessageWriter writer(&method_call);

  vm_tools::plugin_dispatcher::RegisterVmRequest request;

  request.set_owner_id(vm_id.owner_id());
  request.set_new_name(vm_id.name());
  base::FilePath dispatcher_image_path(base::FilePath(kImageDir)
                                           .Append(vm_id.owner_id())
                                           .Append(image_path.BaseName()));
  LOG(INFO) << "Registering VM at " << dispatcher_image_path.value();
  request.set_path(dispatcher_image_path.value());
  // We do not track VMs by uuid but rather by their name, so always generate
  // new one.
  request.set_new_uuid(base::Uuid::GenerateRandomV4().AsLowercaseString());
  request.set_preserve_uuid(false);
  request.set_regenerate_src_uuid(true);

  if (!writer.AppendProtoAsArrayOfBytes(request)) {
    LOG(ERROR) << "Failed to encode RegisterVmRequest protobuf";
    return false;
  }

  std::unique_ptr<dbus::Response> dbus_response =
      brillo::dbus_utils::CallDBusMethod(
          bus, proxy, &method_call, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT);
  if (!dbus_response) {
    LOG(ERROR) << "Failed to send RegisterVm message to dispatcher service";
    return false;
  }

  dbus::MessageReader reader(dbus_response.get());
  vm_tools::plugin_dispatcher::RegisterVmResponse response;
  if (!reader.PopArrayOfBytesAsProto(&response)) {
    LOG(ERROR) << "Failed to parse RegisterVmResponse protobuf";
    return false;
  }

  if (response.error() != vm_tools::plugin_dispatcher::VM_SUCCESS) {
    LOG(ERROR) << "Failed to register VM: " << std::hex << std::showbase
               << response.error() << " (" << response.result_code() << ")";
    return false;
  }

  return true;
}

bool UnregisterVm(scoped_refptr<dbus::Bus> bus,
                  dbus::ObjectProxy* proxy,
                  const VmId& vm_id) {
  LOG(INFO) << "Unregistering VM " << vm_id;

  dbus::MethodCall method_call(
      vm_tools::plugin_dispatcher::kVmPluginDispatcherInterface,
      vm_tools::plugin_dispatcher::kUnregisterVmMethod);
  dbus::MessageWriter writer(&method_call);

  vm_tools::plugin_dispatcher::UnregisterVmRequest request;

  request.set_owner_id(vm_id.owner_id());
  request.set_vm_name_uuid(vm_id.name());

  if (!writer.AppendProtoAsArrayOfBytes(request)) {
    LOG(ERROR) << "Failed to encode UnregisterVmRequest protobuf";
    return false;
  }

  std::unique_ptr<dbus::Response> dbus_response =
      brillo::dbus_utils::CallDBusMethod(
          bus, proxy, &method_call, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT);
  if (!dbus_response) {
    LOG(ERROR) << "Failed to send UnregisterVm message to dispatcher service";
    return false;
  }

  dbus::MessageReader reader(dbus_response.get());
  vm_tools::plugin_dispatcher::UnregisterVmResponse response;
  if (!reader.PopArrayOfBytesAsProto(&response)) {
    LOG(ERROR) << "Failed to parse UnregisterVmResponse protobuf";
    return false;
  }

  if (response.error() != vm_tools::plugin_dispatcher::VM_SUCCESS) {
    LOG(ERROR) << "Failed to unregister VM: " << std::hex << std::showbase
               << response.error() << " (" << response.result_code() << ")";
    return false;
  }

  return true;
}

bool IsVmRegistered(scoped_refptr<dbus::Bus> bus,
                    dbus::ObjectProxy* proxy,
                    const VmId& vm_id,
                    bool* result) {
  LOG(INFO) << "Checking whether VM " << vm_id << " is registered";

  std::optional<vm_tools::plugin_dispatcher::VmInfo> info;
  if (!GetVmInfo(bus, proxy, vm_id, &info))
    return false;

  *result = info.has_value();
  return true;
}

bool IsVmShutDown(scoped_refptr<dbus::Bus> bus,
                  dbus::ObjectProxy* proxy,
                  const VmId& vm_id,
                  bool* result) {
  LOG(INFO) << "Checking whether VM " << vm_id << " is shut down";

  std::optional<vm_tools::plugin_dispatcher::VmInfo> info;
  if (!GetVmInfo(bus, proxy, vm_id, &info))
    return false;

  *result =
      info.has_value() &&
      info.value().state() == vm_tools::plugin_dispatcher::VM_STATE_STOPPED;
  return true;
}

VmOpResult ShutdownVm(scoped_refptr<dbus::Bus> bus,
                      dbus::ObjectProxy* proxy,
                      const VmId& vm_id) {
  LOG(INFO) << "Shutting down VM " << vm_id;

  dbus::MethodCall method_call(
      vm_tools::plugin_dispatcher::kVmPluginDispatcherInterface,
      vm_tools::plugin_dispatcher::kStopVmMethod);
  dbus::MessageWriter writer(&method_call);

  vm_tools::plugin_dispatcher::StopVmRequest request;

  request.set_owner_id(vm_id.owner_id());
  request.set_vm_name_uuid(vm_id.name());
  // Allow request to fail if VM is busy.
  request.set_noforce(true);

  if (!writer.AppendProtoAsArrayOfBytes(request)) {
    LOG(ERROR) << "Failed to encode StopVmRequest protobuf";
    return VmOpResult::INTERNAL_ERROR;
  }

  dbus::ScopedDBusError dbus_error;
  std::unique_ptr<dbus::Response> dbus_response =
      brillo::dbus_utils::CallDBusMethodWithErrorResponse(
          bus, proxy, &method_call, kVmShutdownTimeout.InMilliseconds(),
          &dbus_error);
  if (!dbus_response) {
    if (dbus_error.is_set() &&
        strcmp(dbus_error.name(), DBUS_ERROR_SERVICE_UNKNOWN) == 0) {
      LOG(ERROR) << "Failed to send ShutdownVm request to dispatcher: service "
                    "unavailable";
      return VmOpResult::DISPATCHER_NOT_AVAILABLE;
    } else if (dbus_error.is_set() &&
               strcmp(dbus_error.name(), DBUS_ERROR_NO_REPLY) == 0) {
      LOG(ERROR) << "ShutdownVm request to dispatcher timed out";
      return VmOpResult::DISPATCHER_TIMEOUT;
    } else {
      LOG(ERROR) << "Failed to send ShutdownVm message to dispatcher service";
      return VmOpResult::INTERNAL_ERROR;
    }
  }

  dbus::MessageReader reader(dbus_response.get());
  vm_tools::plugin_dispatcher::StopVmResponse response;
  if (!reader.PopArrayOfBytesAsProto(&response)) {
    LOG(ERROR) << "Failed to parse StopVmResponse protobuf";
    return VmOpResult::INTERNAL_ERROR;
  }

  return ConvertDispatcherResult(response.error(), response.result_code());
}

VmOpResult SuspendVm(scoped_refptr<dbus::Bus> bus,
                     dbus::ObjectProxy* proxy,
                     const VmId& vm_id) {
  LOG(INFO) << "Suspending VM " << vm_id;

  dbus::MethodCall method_call(
      vm_tools::plugin_dispatcher::kVmPluginDispatcherInterface,
      vm_tools::plugin_dispatcher::kSuspendVmMethod);
  dbus::MessageWriter writer(&method_call);

  vm_tools::plugin_dispatcher::SuspendVmRequest request;

  request.set_owner_id(vm_id.owner_id());
  request.set_vm_name_uuid(vm_id.name());

  if (!writer.AppendProtoAsArrayOfBytes(request)) {
    LOG(ERROR) << "Failed to encode SuspendVmRequest protobuf";
    return VmOpResult::INTERNAL_ERROR;
  }

  dbus::ScopedDBusError dbus_error;
  std::unique_ptr<dbus::Response> dbus_response =
      brillo::dbus_utils::CallDBusMethodWithErrorResponse(
          bus, proxy, &method_call, kVmSuspendTimeout.InMilliseconds(),
          &dbus_error);
  if (!dbus_response) {
    if (dbus_error.is_set() &&
        strcmp(dbus_error.name(), DBUS_ERROR_SERVICE_UNKNOWN) == 0) {
      return VmOpResult::DISPATCHER_NOT_AVAILABLE;
    } else if (dbus_error.is_set() &&
               strcmp(dbus_error.name(), DBUS_ERROR_NO_REPLY) == 0) {
      return VmOpResult::DISPATCHER_TIMEOUT;
    } else {
      LOG(ERROR) << "Failed to send SuspendVm message to dispatcher service";
      return VmOpResult::INTERNAL_ERROR;
    }
  }

  dbus::MessageReader reader(dbus_response.get());
  vm_tools::plugin_dispatcher::SuspendVmResponse response;
  if (!reader.PopArrayOfBytesAsProto(&response)) {
    LOG(ERROR) << "Failed to parse SuspendVmResponse protobuf";
    return VmOpResult::INTERNAL_ERROR;
  }

  return ConvertDispatcherResult(response.error(), response.result_code());
}

void RegisterVmToolsChangedCallbacks(
    dbus::ObjectProxy* proxy,
    dbus::ObjectProxy::SignalCallback cb,
    dbus::ObjectProxy::OnConnectedCallback on_connected_cb) {
  proxy->ConnectToSignal(
      vm_tools::plugin_dispatcher::kVmPluginDispatcherServiceName,
      vm_tools::plugin_dispatcher::kVmToolsStateChangedSignal, cb,
      std::move(on_connected_cb));
}

bool ParseVmToolsChangedSignal(dbus::Signal* signal,
                               std::string* owner_id,
                               std::string* vm_name,
                               bool* running) {
  DCHECK_EQ(signal->GetInterface(),
            vm_tools::plugin_dispatcher::kVmPluginDispatcherInterface);
  DCHECK_EQ(signal->GetMember(),
            vm_tools::plugin_dispatcher::kVmToolsStateChangedSignal);

  vm_tools::plugin_dispatcher::VmToolsStateChangedSignal message;
  dbus::MessageReader reader(signal);
  if (!reader.PopArrayOfBytesAsProto(&message)) {
    LOG(ERROR) << "Failed to parse VmToolsStateChangedSignal from DBus Signal";
    return false;
  }

  auto state = message.vm_tools_state();
  LOG(INFO) << "Tools raw state: " << state;

  *owner_id = message.owner_id();
  *vm_name = message.vm_name();
  *running = state == vm_tools::plugin_dispatcher::VM_TOOLS_STATE_INSTALLED;
  return true;
}

}  // namespace dispatcher
}  // namespace pvm
}  // namespace concierge
}  // namespace vm_tools
