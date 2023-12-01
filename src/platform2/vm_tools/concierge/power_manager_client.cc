// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/concierge/power_manager_client.h"

#include <utility>

#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/time/time.h>
#include <brillo/dbus/dbus_proxy_util.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/object_path.h>
#include <power_manager/proto_bindings/suspend.pb.h>

namespace vm_tools {
namespace concierge {
namespace {
// How long powerd should wait for us to report suspend readiness.
constexpr base::TimeDelta kSuspendDelayTimeout = base::Seconds(5);

// Used to mark that the device is not currently suspended or about to suspend.
constexpr int32_t kNoSuspendId = -1;

}  // namespace

PowerManagerClient::PowerManagerClient(scoped_refptr<dbus::Bus> bus)
    : bus_(bus),
      power_manager_proxy_(nullptr),
      delay_id_(-1),
      current_suspend_id_(kNoSuspendId) {
  power_manager_proxy_ = bus_->GetObjectProxy(
      power_manager::kPowerManagerServiceName,
      dbus::ObjectPath(power_manager::kPowerManagerServicePath));
}

PowerManagerClient::~PowerManagerClient() {
  if (delay_id_ == -1) {
    return;
  }

  dbus::MethodCall method_call(power_manager::kPowerManagerInterface,
                               power_manager::kUnregisterSuspendDelayMethod);

  power_manager::UnregisterSuspendDelayRequest request;
  request.set_delay_id(delay_id_);

  if (!dbus::MessageWriter(&method_call).AppendProtoAsArrayOfBytes(request)) {
    LOG(ERROR) << "Failed to encode UnregisterSuspendDelayRequest";
    return;
  }

  auto dbus_response = brillo::dbus_utils::CallDBusMethod(
      bus_, power_manager_proxy_, &method_call,
      dbus::ObjectProxy::TIMEOUT_USE_DEFAULT);
  if (!dbus_response) {
    LOG(WARNING) << "Failed to un-register suspend delay with powerd";
  }
}

void PowerManagerClient::RegisterSuspendDelay(
    const base::RepeatingClosure& suspend_imminent_cb,
    const base::RepeatingClosure& suspend_done_cb) {
  // We don't need to check whether powerd is running because it should start
  // automatically at boot while concierge is not started until the user
  // explicitly tries to start a VM.

  dbus::MethodCall method_call(power_manager::kPowerManagerInterface,
                               power_manager::kRegisterSuspendDelayMethod);

  power_manager::RegisterSuspendDelayRequest request;
  request.set_timeout(kSuspendDelayTimeout.ToInternalValue());
  request.set_description("Pause VMs while suspended");

  if (!dbus::MessageWriter(&method_call).AppendProtoAsArrayOfBytes(request)) {
    LOG(ERROR) << "Failed to encode RegisterSuspendDelayRequest";
    return;
  }

  auto dbus_response = brillo::dbus_utils::CallDBusMethod(
      bus_, power_manager_proxy_, &method_call,
      dbus::ObjectProxy::TIMEOUT_USE_DEFAULT);
  if (!dbus_response) {
    LOG(WARNING) << "Failed to register suspend delay with powerd";
    return;
  }

  power_manager::RegisterSuspendDelayReply response;
  if (!dbus::MessageReader(dbus_response.get())
           .PopArrayOfBytesAsProto(&response)) {
    LOG(ERROR) << "Failed to read RegisterSuspendDelayReply message";
    return;
  }

  delay_id_ = response.delay_id();

  // Now that we've registered with powerd, store the callbacks and start
  // watching the signals.
  suspend_imminent_cb_ = std::move(suspend_imminent_cb);
  suspend_done_cb_ = std::move(suspend_done_cb);

  power_manager_proxy_->ConnectToSignal(
      power_manager::kPowerManagerInterface,
      power_manager::kSuspendImminentSignal,
      base::BindRepeating(&PowerManagerClient::HandleSuspendImminent,
                          weak_factory_.GetWeakPtr()),
      base::BindOnce(&PowerManagerClient::HandleSignalConnected,
                     weak_factory_.GetWeakPtr()));

  power_manager_proxy_->ConnectToSignal(
      power_manager::kPowerManagerInterface, power_manager::kSuspendDoneSignal,
      base::BindRepeating(&PowerManagerClient::HandleSuspendDone,
                          weak_factory_.GetWeakPtr()),
      base::BindOnce(&PowerManagerClient::HandleSignalConnected,
                     weak_factory_.GetWeakPtr()));

  power_manager_proxy_->SetNameOwnerChangedCallback(base::BindRepeating(
      &PowerManagerClient::HandleNameOwnerChanged, weak_factory_.GetWeakPtr()));
}

void PowerManagerClient::HandleSuspendImminent(dbus::Signal* signal) {
  power_manager::SuspendImminent message;
  if (!dbus::MessageReader(signal).PopArrayOfBytesAsProto(&message)) {
    LOG(ERROR) << "Failed to decode SuspendImminent message";
    return;
  }

  if (current_suspend_id_ != kNoSuspendId) {
    LOG(WARNING) << "Received new SuspendImminent signal before receiving "
                 << "SuspendDone signal for suspend id " << current_suspend_id_;
  }

  current_suspend_id_ = message.suspend_id();

  suspend_imminent_cb_.Run();

  dbus::MethodCall method_call(power_manager::kPowerManagerInterface,
                               power_manager::kHandleSuspendReadinessMethod);

  power_manager::SuspendReadinessInfo ready;
  ready.set_delay_id(delay_id_);
  ready.set_suspend_id(current_suspend_id_);

  if (!dbus::MessageWriter(&method_call).AppendProtoAsArrayOfBytes(ready)) {
    LOG(ERROR) << "Failed to encode SuspendReadinessInfo";
    return;
  }

  auto dbus_response = brillo::dbus_utils::CallDBusMethod(
      bus_, power_manager_proxy_, &method_call,
      dbus::ObjectProxy::TIMEOUT_USE_DEFAULT);
  if (!dbus_response) {
    LOG(WARNING) << "Failed to notify powerd of suspend readiness for suspend "
                 << "id " << current_suspend_id_;
  }
}

void PowerManagerClient::HandleSuspendDone(dbus::Signal* signal) {
  power_manager::SuspendDone message;
  if (!dbus::MessageReader(signal).PopArrayOfBytesAsProto(&message)) {
    LOG(ERROR) << "Failed to decode SuspendImminent message";
  }

  if (current_suspend_id_ != message.suspend_id()) {
    LOG(WARNING) << "Ignoring SuspendDone signal for suspend id "
                 << message.suspend_id() << " because it does not match the "
                 << "current suspend id (" << current_suspend_id_ << ")";
    return;
  }

  suspend_done_cb_.Run();

  current_suspend_id_ = kNoSuspendId;
}

void PowerManagerClient::HandleNameOwnerChanged(const std::string& old_owner,
                                                const std::string& new_owner) {
  if (!new_owner.empty() && delay_id_ != -1) {
    // We had previously registered a suspend delay so re-register it.
    RegisterSuspendDelay(std::move(suspend_imminent_cb_),
                         std::move(suspend_done_cb_));
  }
}

void PowerManagerClient::HandleSignalConnected(
    const std::string& interface_name,
    const std::string& signal_name,
    bool success) {
  if (!success) {
    LOG(WARNING) << "Failed to connect to " << signal_name << " signal from "
                 << interface_name;
  }
}
}  // namespace concierge
}  // namespace vm_tools
