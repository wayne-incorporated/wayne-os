// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/dbus_wrapper_stub.h"

#include <memory>
#include <tuple>
#include <utility>

#include <base/check.h>
#include <base/check_op.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/memory/ptr_util.h>
#include <base/task/single_thread_task_runner.h>
#include <dbus/dbus.h>

namespace power_manager::system {

namespace {

// Returns a copy of |signal|.
std::unique_ptr<dbus::Signal> DuplicateSignal(dbus::Signal* signal) {
  return dbus::Signal::FromRawMessage(dbus_message_copy(signal->raw_message()));
}

// Transfers |src_response| to |dest_response|. Passed as a response callback to
// exported methods.
void MoveResponse(std::unique_ptr<dbus::Response>* dest_response,
                  std::unique_ptr<dbus::Response> src_response) {
  *dest_response = std::move(src_response);
}

// Callback for CallMethodAsync() to pass |response| to |callback|.
void RunResponseCallback(dbus::ObjectProxy::ResponseCallback callback,
                         std::unique_ptr<dbus::Response> response) {
  std::move(callback).Run(response.get());
}

}  // namespace

bool DBusWrapperStub::RegisteredSignalInfo::operator<(
    const RegisteredSignalInfo& o) const {
  return std::tie(proxy, interface_name, signal_name) <
         std::tie(o.proxy, o.interface_name, o.signal_name);
}

DBusWrapperStub::DBusWrapperStub() = default;

DBusWrapperStub::~DBusWrapperStub() = default;

std::string DBusWrapperStub::GetSentSignalName(size_t index) {
  CHECK_LT(index, sent_signals_.size());
  return sent_signals_[index].signal_name;
}

bool DBusWrapperStub::GetSentSignal(size_t index,
                                    const std::string& expected_signal_name,
                                    google::protobuf::MessageLite* protobuf_out,
                                    std::unique_ptr<dbus::Signal>* signal_out) {
  if (index >= sent_signals_.size()) {
    LOG(ERROR) << "Got request to return " << expected_signal_name << " signal "
               << "at position " << index << ", but only "
               << sent_signals_.size() << " were sent";
    return false;
  }

  SignalInfo& info = sent_signals_[index];
  if (info.signal_name != expected_signal_name) {
    LOG(ERROR) << "Expected " << expected_signal_name << " signal at position "
               << index << " but had " << info.signal_name << " instead";
    return false;
  }

  if (protobuf_out) {
    if (info.protobuf_type != protobuf_out->GetTypeName()) {
      LOG(ERROR) << info.signal_name << " signal at position " << index
                 << " has " << info.protobuf_type << " protobuf instead of "
                 << "expected " << protobuf_out->GetTypeName();
      return false;
    }
    if (!protobuf_out->ParseFromString(info.serialized_data)) {
      LOG(ERROR) << "Unable to parse " << info.protobuf_type
                 << " protobuf from " << info.signal_name
                 << " signal at position " << index;
      return false;
    }
  }

  if (signal_out) {
    if (!info.signal.get()) {
      LOG(ERROR) << info.signal_name << " signal at position " << index
                 << " wasn't sent using EmitSignal()";
      return false;
    }
    *signal_out = DuplicateSignal(info.signal.get());
  }

  return true;
}

void DBusWrapperStub::ClearSentSignals() {
  sent_signals_.clear();
}

bool DBusWrapperStub::IsMethodExported(const std::string& method_name) const {
  return exported_methods_.count(method_name);
}

void DBusWrapperStub::CallExportedMethod(
    dbus::MethodCall* method_call,
    dbus::ExportedObject::ResponseSender response_cb) {
  CHECK(method_call);

  // libdbus asserts that the serial number is set. Prevent tests from needing
  // to bother setting it.
  method_call->SetSerial(1);

  const std::string name = method_call->GetMember();
  CHECK(exported_methods_.count(name)) << "Method " << name << " not exported";
  exported_methods_[name].Run(method_call, std::move(response_cb));
}

std::unique_ptr<dbus::Response> DBusWrapperStub::CallExportedMethodSync(
    dbus::MethodCall* method_call) {
  std::unique_ptr<dbus::Response> response;
  CallExportedMethod(method_call, base::BindOnce(&MoveResponse, &response));
  return response;
}

void DBusWrapperStub::EmitRegisteredSignal(dbus::ObjectProxy* proxy,
                                           dbus::Signal* signal) {
  CHECK(proxy);
  CHECK(signal);
  RegisteredSignalInfo info{proxy, signal->GetInterface(), signal->GetMember()};
  CHECK(signal_handlers_.count(info))
      << "No signal handler registered on " << proxy << " for "
      << info.interface_name << "." << info.signal_name;
  signal_handlers_[info].Run(signal);
}

void DBusWrapperStub::SetMethodCallback(const MethodCallback& callback) {
  method_callback_ = callback;
}

void DBusWrapperStub::NotifyServiceAvailable(dbus::ObjectProxy* proxy,
                                             bool available) {
  auto it = service_availability_callbacks_.find(proxy);
  if (it == service_availability_callbacks_.end())
    return;

  auto callbacks = std::move(it->second);
  service_availability_callbacks_.erase(it);
  for (auto& cb : callbacks)
    std::move(cb).Run(available);
}

void DBusWrapperStub::NotifyNameOwnerChanged(const std::string& service_name,
                                             const std::string& old_owner,
                                             const std::string& new_owner) {
  for (DBusWrapperInterface::Observer& observer : observers_)
    observer.OnDBusNameOwnerChanged(service_name, old_owner, new_owner);
}

void DBusWrapperStub::AddObserver(Observer* observer) {
  CHECK(observer);
  observers_.AddObserver(observer);
}

void DBusWrapperStub::RemoveObserver(Observer* observer) {
  CHECK(observer);
  observers_.RemoveObserver(observer);
}

scoped_refptr<dbus::Bus> DBusWrapperStub::GetBus() {
  return nullptr;
}

dbus::ObjectProxy* DBusWrapperStub::GetObjectProxy(
    const std::string& service_name, const std::string& object_path) {
  // If a proxy was already created, return it.
  for (const auto& info : object_proxy_infos_) {
    if (info.service_name == service_name && info.object_path == object_path) {
      return info.object_proxy.get();
    }
  }

  // Ownership of this is passed to ObjectProxyInfo in the next statement.
  dbus::ObjectProxy* object_proxy = new dbus::ObjectProxy(
      nullptr, service_name, dbus::ObjectPath(object_path), 0);
  object_proxy_infos_.emplace_back(
      ObjectProxyInfo{service_name, object_path, object_proxy});
  return object_proxy;
}

void DBusWrapperStub::RegisterForServiceAvailability(
    dbus::ObjectProxy* proxy,
    dbus::ObjectProxy::WaitForServiceToBeAvailableCallback callback) {
  DCHECK(proxy);
  service_availability_callbacks_[proxy].push_back(std::move(callback));
}

void DBusWrapperStub::RegisterForSignal(
    dbus::ObjectProxy* proxy,
    const std::string& interface_name,
    const std::string& signal_name,
    dbus::ObjectProxy::SignalCallback callback) {
  DCHECK(proxy);
  RegisteredSignalInfo info{proxy, interface_name, signal_name};
  CHECK(!signal_handlers_.count(info))
      << "Signal handler already registered on " << proxy << " for "
      << interface_name << "." << signal_name;
  signal_handlers_[info] = callback;
}

void DBusWrapperStub::ExportMethod(
    const std::string& method_name,
    dbus::ExportedObject::MethodCallCallback callback) {
  CHECK(!service_published_) << "Method " << method_name
                             << " exported after service already published";
  CHECK(!exported_methods_.count(method_name))
      << "Method " << method_name << " exported twice";
  exported_methods_[method_name] = callback;
}

bool DBusWrapperStub::PublishService() {
  CHECK(!service_published_) << "Service already published";
  service_published_ = true;

  // Notify our observers.
  for (DBusWrapper::Observer& observer : observers_) {
    observer.OnServicePublished();
  }

  return true;
}

void DBusWrapperStub::EmitSignal(dbus::Signal* signal) {
  DCHECK(signal);
  sent_signals_.emplace_back(
      SignalInfo{signal->GetMember(), DuplicateSignal(signal)});
}

void DBusWrapperStub::EmitBareSignal(const std::string& signal_name) {
  sent_signals_.emplace_back(SignalInfo{signal_name});
}

void DBusWrapperStub::EmitSignalWithProtocolBuffer(
    const std::string& signal_name,
    const google::protobuf::MessageLite& protobuf) {
  std::string serialized_data;
  protobuf.SerializeToString(&serialized_data);
  sent_signals_.emplace_back(
      SignalInfo{signal_name, std::unique_ptr<dbus::Signal>(),
                 protobuf.GetTypeName(), serialized_data});
}

std::unique_ptr<dbus::Response> DBusWrapperStub::CallMethodSync(
    dbus::ObjectProxy* proxy,
    dbus::MethodCall* method_call,
    base::TimeDelta timeout) {
  DCHECK(proxy);
  DCHECK(method_call);
  DCHECK(!method_callback_.is_null());

  // libdbus asserts that the serial number is set. Prevent tests from needing
  // to bother setting it.
  method_call->SetSerial(1);
  return method_callback_.Run(proxy, method_call);
}

void DBusWrapperStub::CallMethodAsync(
    dbus::ObjectProxy* proxy,
    dbus::MethodCall* method_call,
    base::TimeDelta timeout,
    dbus::ObjectProxy::ResponseCallback callback) {
  // Call the method handler now and post |callback| to run later.
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
      FROM_HERE, base::BindOnce(&RunResponseCallback, std::move(callback),
                                CallMethodSync(proxy, method_call, timeout)));
}

}  // namespace power_manager::system
