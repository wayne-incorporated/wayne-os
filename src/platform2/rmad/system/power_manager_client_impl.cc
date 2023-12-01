// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rmad/system/power_manager_client_impl.h"

#include <memory>

#include <base/logging.h>
#include <base/memory/scoped_refptr.h>
#include <dbus/bus.h>
#include <dbus/message.h>
#include <dbus/object_proxy.h>
#include <dbus/power_manager/dbus-constants.h>

namespace rmad {

PowerManagerClientImpl::PowerManagerClientImpl(
    const scoped_refptr<dbus::Bus>& bus) {
  proxy_ = bus->GetObjectProxy(
      power_manager::kPowerManagerServiceName,
      dbus::ObjectPath(power_manager::kPowerManagerServicePath));
}

bool PowerManagerClientImpl::Restart() {
  dbus::MethodCall method_call(power_manager::kPowerManagerInterface,
                               power_manager::kRequestRestartMethod);
  dbus::MessageWriter writer(&method_call);
  writer.AppendInt32(power_manager::REQUEST_RESTART_OTHER);
  writer.AppendString("rmad request restart");

  std::unique_ptr<dbus::Response> response = proxy_->CallMethodAndBlock(
      &method_call, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT);

  if (!response.get()) {
    LOG(ERROR) << "Failed to call powerd service";
    return false;
  }
  return true;
}

bool PowerManagerClientImpl::Shutdown() {
  dbus::MethodCall method_call(power_manager::kPowerManagerInterface,
                               power_manager::kRequestShutdownMethod);
  dbus::MessageWriter writer(&method_call);
  writer.AppendInt32(power_manager::REQUEST_SHUTDOWN_OTHER);
  writer.AppendString("rmad request shutdown");

  std::unique_ptr<dbus::Response> response = proxy_->CallMethodAndBlock(
      &method_call, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT);

  if (!response.get()) {
    LOG(ERROR) << "Failed to call powerd service";
    return false;
  }
  return true;
}

}  // namespace rmad
