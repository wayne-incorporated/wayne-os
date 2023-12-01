// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/notificationd/dbus_service.h"

#include <map>
#include <string>
#include <utility>
#include <vector>

#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/memory/ptr_util.h>

namespace {

const char kNotificationsServiceName[] = "org.freedesktop.Notifications";
const char kNotificationsServicePath[] = "/org/freedesktop/Notifications";

void HandleSynchronousDBusMethodCall(
    base::RepeatingCallback<std::unique_ptr<dbus::Response>(dbus::MethodCall*)>
        handler,
    dbus::MethodCall* method_call,
    dbus::ExportedObject::ResponseSender response_sender) {
  auto response = handler.Run(method_call);
  if (!response)
    response = dbus::Response::FromMethodCall(method_call);

  std::move(response_sender).Run(std::move(response));
}

std::unique_ptr<dbus::ErrorResponse> GetErrorResponseWithLog(
    dbus::MethodCall* method_call,
    const std::string& type,
    const std::string& message) {
  LOG(ERROR) << message;
  return dbus::ErrorResponse::FromMethodCall(method_call, type, message);
}

bool PopStringArray(dbus::MessageReader* reader,
                    std::vector<std::string>* value) {
  dbus::MessageReader array_reader(nullptr);
  if (!reader->PopArray(&array_reader))
    return false;

  while (array_reader.HasMoreData()) {
    std::string data;
    if (!array_reader.PopString(&data))
      return false;
    value->push_back(std::move(data));
  }
  return true;
}

bool PopStringVariantDict(dbus::MessageReader* reader,
                          std::map<std::string, std::string>* value) {
  dbus::MessageReader array_reader(nullptr);
  if (!reader->PopArray(&array_reader))
    return false;

  while (array_reader.HasMoreData()) {
    dbus::MessageReader dict_entry_reader(nullptr);
    if (!array_reader.PopDictEntry(&dict_entry_reader))
      return false;
    // We just skip to parse entries because thier values (not key) may contain
    // complex variant parameters.
    // TODO(toshikikikuchi): Add reader for variant parameters.
  }
  return true;
}

}  // namespace

namespace vm_tools {
namespace notificationd {

DBusService::DBusService(DBusInterface* interface) : interface_(interface) {}

// static
std::unique_ptr<DBusService> DBusService::Create(DBusInterface* interface) {
  auto service = base::WrapUnique(new DBusService(interface));

  if (!service->Init())
    return nullptr;

  return service;
}

void DBusService::SendNotificationClosedSignal(uint32_t id,
                                               ClosedReason reason) {
  dbus::Signal signal(kNotificationsServiceName, "NotificationClosed");
  dbus::MessageWriter writer(&signal);
  writer.AppendUint32(id);
  writer.AppendUint32(static_cast<uint32_t>(reason));
  exported_object_->SendSignal(&signal);
}

void DBusService::SendActionInvokedSignal(uint32_t id,
                                          const std::string& action_key) {
  dbus::Signal signal(kNotificationsServiceName, "ActionInvoked");
  dbus::MessageWriter writer(&signal);
  writer.AppendUint32(id);
  writer.AppendString(action_key);
  exported_object_->SendSignal(&signal);
}

bool DBusService::RegisterMethods() {
  using ServiceMethod =
      std::unique_ptr<dbus::Response> (DBusService::*)(dbus::MethodCall*);
  const std::map<const char*, ServiceMethod> kServiceMethods = {
      {"GetCapabilities", &DBusService::CallGetCapabilities},
      {"Notify", &DBusService::CallNotify},
      {"GetServerInformation", &DBusService::CallGetServerInformation},
      {"CloseNotification", &DBusService::CallCloseNotification},
  };

  for (const auto& iter : kServiceMethods) {
    const bool ret = exported_object_->ExportMethodAndBlock(
        kNotificationsServiceName, iter.first,
        base::BindRepeating(
            &HandleSynchronousDBusMethodCall,
            base::BindRepeating(iter.second, base::Unretained(this))));
    if (!ret) {
      LOG(ERROR) << "Failed to export method " << iter.first;
      return false;
    }
  }

  return true;
}

std::unique_ptr<dbus::Response> DBusService::CallGetCapabilities(
    dbus::MethodCall* method_call) {
  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  std::vector<std::string> out_capabilities;
  if (!interface_->GetCapabilities(&out_capabilities)) {
    return GetErrorResponseWithLog(method_call, DBUS_ERROR_FAILED,
                                   "Failed to call GetCapabilities");
  }

  dbus::MessageWriter writer(dbus_response.get());
  dbus::MessageWriter array_writer(nullptr);
  writer.OpenArray(DBUS_TYPE_STRING_AS_STRING, &array_writer);
  for (const auto& cap : out_capabilities) {
    array_writer.AppendString(cap);
  }
  writer.CloseContainer(&array_writer);

  return dbus_response;
}

std::unique_ptr<dbus::Response> DBusService::CallNotify(
    dbus::MethodCall* method_call) {
  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);
  DBusInterface::NotifyArgument input;

  const auto valid_args = reader.PopString(&input.app_name) &&
                          reader.PopUint32(&input.replaces_id) &&
                          reader.PopString(&input.app_icon) &&
                          reader.PopString(&input.summary) &&
                          reader.PopString(&input.body) &&
                          PopStringArray(&reader, &input.actions) &&
                          PopStringVariantDict(&reader, &input.hints) &&
                          reader.PopInt32(&input.expire_timeout);

  if (!valid_args) {
    return GetErrorResponseWithLog(method_call, DBUS_ERROR_INVALID_ARGS,
                                   "Invalid args for Notify");
  }

  uint32_t out_id;
  if (!interface_->Notify(input, &out_id)) {
    return GetErrorResponseWithLog(method_call, DBUS_ERROR_FAILED,
                                   "Failed to call Notify");
  }

  dbus::MessageWriter writer(dbus_response.get());
  writer.AppendUint32(out_id);

  return dbus_response;
}

std::unique_ptr<dbus::Response> DBusService::CallGetServerInformation(
    dbus::MethodCall* method_call) {
  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  DBusInterface::ServerInformation output;

  if (!interface_->GetServerInformation(&output)) {
    return GetErrorResponseWithLog(method_call, DBUS_ERROR_FAILED,
                                   "Failed to call GetServerInformation");
  }

  dbus::MessageWriter writer(dbus_response.get());
  writer.AppendString(std::move(output.name));
  writer.AppendString(std::move(output.vendor));
  writer.AppendString(std::move(output.version));
  writer.AppendString(std::move(output.spec_version));

  return dbus_response;
}

std::unique_ptr<dbus::Response> DBusService::CallCloseNotification(
    dbus::MethodCall* method_call) {
  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));

  dbus::MessageReader reader(method_call);

  uint32_t id = 0;
  if (!reader.PopUint32(&id)) {
    return GetErrorResponseWithLog(method_call, DBUS_ERROR_INVALID_ARGS,
                                   "Invalid args for CloseNotification");
  }

  if (!interface_->CloseNotification(id)) {
    return GetErrorResponseWithLog(method_call, DBUS_ERROR_FAILED,
                                   "Failed to call CloseNotification");
  }

  return dbus_response;
}

bool DBusService::Init() {
  bus_ = new dbus::Bus(dbus::Bus::Options());
  if (!bus_->Connect()) {
    LOG(ERROR) << "Failed to connect to session bus";
    return false;
  }

  exported_object_ =
      bus_->GetExportedObject(dbus::ObjectPath(kNotificationsServicePath));
  if (!exported_object_) {
    LOG(ERROR) << "Failed to export " << kNotificationsServicePath << " object";
    return false;
  }

  if (!RegisterMethods()) {
    LOG(ERROR) << "Failed to export methods";
    return false;
  }

  if (!bus_->RequestOwnershipAndBlock(kNotificationsServiceName,
                                      dbus::Bus::REQUIRE_PRIMARY)) {
    LOG(ERROR) << "Unable to take ownership of " << kNotificationsServiceName;
    return false;
  }

  return true;
}

}  // namespace notificationd
}  // namespace vm_tools
