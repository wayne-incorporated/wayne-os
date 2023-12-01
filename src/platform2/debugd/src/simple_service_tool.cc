// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "debugd/src/simple_service_tool.h"

#include <utility>

#include <base/check.h>
#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <base/location.h>
#include <base/logging.h>
#include <brillo/process/process.h>
#include <dbus/object_path.h>

using std::string;

namespace debugd {
namespace {

// Posted to the MessageLoop by dbus::ObjectProxy once the concierge
// service is available on dbus.
void ServiceReady(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<bool>> response,
    bool is_available) {
  response->Return(is_available);
}

}  // namespace

SimpleServiceTool::SimpleServiceTool(const std::string& name,
                                     scoped_refptr<dbus::Bus> bus,
                                     const std::string& dbus_service_name,
                                     const std::string& dbus_service_path)
    : name_(name), bus_(bus), running_(false) {
  CHECK(bus_);

  proxy_ = bus_->GetObjectProxy(dbus_service_name,
                                dbus::ObjectPath(dbus_service_path));
  proxy_->SetNameOwnerChangedCallback(base::BindRepeating(
      &SimpleServiceTool::HandleNameOwnerChanged, weak_factory_.GetWeakPtr()));
}

void SimpleServiceTool::StartService(
    std::map<std::string, std::string> args,
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<bool>> response) {
  if (running_) {
    response->Return(true);
    return;
  }

  LOG(INFO) << "Starting " << name_;
  brillo::ProcessImpl service;
  service.AddArg("/sbin/start");
  service.AddArg(name_);
  for (const auto& arg : args) {
    service.AddArg(
        base::StringPrintf("%s=%s", arg.first.c_str(), arg.second.c_str()));
  }
  service.Run();

  // dbus::ObjectProxy keeps a list of WaitForServiceToBeAvailable
  // callbacks so we can safely call this multiple times if there are multiple
  // pending dbus requests.
  proxy_->WaitForServiceToBeAvailable(
      base::BindOnce(&ServiceReady, std::move(response)));
}

void SimpleServiceTool::StopService() {
  if (!running_) {
    // Nothing to do.
    return;
  }

  LOG(INFO) << "Stopping " << name_;

  brillo::ProcessImpl service;
  service.AddArg("/sbin/stop");
  service.AddArg(name_);

  service.Run();
}

void SimpleServiceTool::HandleNameOwnerChanged(const string& old_owner,
                                               const string& new_owner) {
  running_ = !new_owner.empty();
}

}  // namespace debugd
