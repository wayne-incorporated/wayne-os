// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/dbus/rpc_task_dbus_adaptor.h"

#include "shill/error.h"
#include "shill/logging.h"
#include "shill/rpc_task.h"

#include <base/logging.h>

namespace shill {

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kDBus;
static std::string ObjectID(const RpcTaskDBusAdaptor* r) {
  return r->GetRpcIdentifier().value();
}
}  // namespace Logging

// static
const char RpcTaskDBusAdaptor::kPath[] = "/task/";

RpcTaskDBusAdaptor::RpcTaskDBusAdaptor(const scoped_refptr<dbus::Bus>& bus,
                                       RpcTask* task)
    : org::chromium::flimflam::TaskAdaptor(this),
      DBusAdaptor(bus, kPath + task->UniqueName()),
      task_(task),
      connection_name_(RpcIdentifier(bus->GetConnectionName())) {
  // Register DBus object.
  RegisterWithDBusObject(dbus_object());
  dbus_object()->RegisterAndBlock();
}

RpcTaskDBusAdaptor::~RpcTaskDBusAdaptor() {
  dbus_object()->UnregisterAndBlock();
  task_ = nullptr;
}

const RpcIdentifier& RpcTaskDBusAdaptor::GetRpcIdentifier() const {
  return dbus_path();
}

const RpcIdentifier& RpcTaskDBusAdaptor::GetRpcConnectionIdentifier() const {
  return connection_name_;
}

bool RpcTaskDBusAdaptor::getsec(brillo::ErrorPtr* /*error*/,
                                std::string* user,
                                std::string* password) {
  SLOG(this, 2) << __func__ << ": " << user;
  task_->GetLogin(user, password);
  return true;
}

bool RpcTaskDBusAdaptor::notify(
    brillo::ErrorPtr* /*error*/,
    const std::string& reason,
    const std::map<std::string, std::string>& dict) {
  SLOG(this, 2) << __func__ << ": " << reason;
  task_->Notify(reason, dict);
  return true;
}

}  // namespace shill
