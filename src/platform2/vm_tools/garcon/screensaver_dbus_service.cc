// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/garcon/screensaver_dbus_service.h"

#include <map>
#include <string>
#include <utility>
#include <vector>

#include "base/process/launch.h"
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/memory/ptr_util.h>
#include "vm_tools/garcon/host_notifier.h"

namespace {

const char kScreenSaverServiceName[] = "org.freedesktop.ScreenSaver";
const char kScreenSaverServicePath[] = "/org/freedesktop/ScreenSaver";

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

}  // namespace

namespace vm_tools {
namespace garcon {

ScreenSaverDBusService::ScreenSaverDBusService(
    vm_tools::garcon::HostNotifier* host_notifier)
    : host_notifier_(host_notifier) {}

// static
std::unique_ptr<ScreenSaverDBusService> ScreenSaverDBusService::Create(
    vm_tools::garcon::HostNotifier* host_notifier) {
  auto service = base::WrapUnique(new ScreenSaverDBusService(host_notifier));

  if (!service->Init())
    return nullptr;

  return service;
}

bool ScreenSaverDBusService::RegisterMethods() {
  using ServiceMethod = std::unique_ptr<dbus::Response> (
      ScreenSaverDBusService::*)(dbus::MethodCall*);
  const std::map<const char*, ServiceMethod> kServiceMethods = {
      {"Inhibit", &ScreenSaverDBusService::Inhibit},
      {"UnInhibit", &ScreenSaverDBusService::Uninhibit},
  };

  for (const auto& iter : kServiceMethods) {
    const bool ret = exported_object_->ExportMethodAndBlock(
        kScreenSaverServiceName, iter.first,
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

std::unique_ptr<dbus::Response> ScreenSaverDBusService::Inhibit(
    dbus::MethodCall* method_call) {
  uint32_t cookie = cookie_counter_++;
  dbus::MessageReader reader(method_call);
  std::string client;
  reader.PopString(&client);
  std::string reason;
  reader.PopString(&reason);

  vm_tools::container::InhibitScreensaverInfo info;
  info.set_client(client);
  info.set_reason(reason);
  info.set_cookie(cookie);
  if (!host_notifier_->InhibitScreensaver(std::move(info))) {
    LOG(ERROR) << "Failed to inhibit screensaver";
  }

  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));
  dbus::MessageWriter writer(dbus_response.get());
  writer.AppendUint32(cookie);
  return dbus_response;
}
std::unique_ptr<dbus::Response> ScreenSaverDBusService::Uninhibit(
    dbus::MethodCall* method_call) {
  dbus::MessageReader reader(method_call);
  uint32_t cookie;
  reader.PopUint32(&cookie);

  vm_tools::container::UninhibitScreensaverInfo info;
  info.set_cookie(cookie);
  if (!host_notifier_->UninhibitScreensaver(std::move(info))) {
    LOG(ERROR) << "Failed to uninhibit screensaver";
  }

  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));
  return dbus_response;
}

bool ScreenSaverDBusService::Init() {
  dbus::Bus::Options options;
  bus_ = new dbus::Bus(options);

  if (!bus_->Connect()) {
    LOG(ERROR) << "Failed to connect to session bus";
    return false;
  }

  exported_object_ =
      bus_->GetExportedObject(dbus::ObjectPath(kScreenSaverServicePath));
  if (!exported_object_) {
    LOG(ERROR) << "Failed to export " << kScreenSaverServicePath << " object";
    return false;
  }

  if (!RegisterMethods()) {
    LOG(ERROR) << "Failed to export methods";
    return false;
  }

  if (!bus_->RequestOwnershipAndBlock(kScreenSaverServiceName,
                                      dbus::Bus::REQUIRE_PRIMARY)) {
    LOG(ERROR) << "Unable to take ownership of " << kScreenSaverServiceName;
    return false;
  }

  return true;
}

}  // namespace garcon
}  // namespace vm_tools
