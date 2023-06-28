// Copyright 2016 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "login_manager/systemd_unit_starter.h"

#include <memory>
#include <string>
#include <vector>

#include <base/callback.h>
#include <base/callback_helpers.h>
#include <base/check.h>
#include <base/logging.h>
#include <dbus/message.h>
#include <dbus/object_proxy.h>

namespace {

constexpr char kInterface[] = "org.freedesktop.systemd1.Manager";
constexpr char kStartUnitMode[] = "replace";
constexpr char kStartUnitMethodName[] = "StartUnit";
constexpr char kSetEnvironmentMethodName[] = "SetEnvironment";
constexpr char kUnsetEnvironmentMethodName[] = "UnsetEnvironment";

std::unique_ptr<dbus::Response> CallEnvironmentMethod(
    dbus::ObjectProxy* proxy,
    const std::string& method_name,
    const std::vector<std::string>& args_keyvals) {
  DCHECK(proxy);
  dbus::MethodCall method_call(kInterface, method_name);
  dbus::MessageWriter writer(&method_call);
  writer.AppendArrayOfStrings(args_keyvals);

  return proxy->CallMethodAndBlock(&method_call,
                                   dbus::ObjectProxy::TIMEOUT_USE_DEFAULT);
}

std::unique_ptr<dbus::Response> SetEnvironment(
    dbus::ObjectProxy* proxy, const std::vector<std::string>& args_keyvals) {
  return CallEnvironmentMethod(proxy, kSetEnvironmentMethodName, args_keyvals);
}

std::unique_ptr<dbus::Response> UnsetEnvironment(
    dbus::ObjectProxy* proxy, const std::vector<std::string>& args_keyvals) {
  std::vector<std::string> env_vars;
  env_vars.reserve(args_keyvals.size());

  // Keep only the keys from environment array
  for (const auto& keyval : args_keyvals) {
    size_t i = keyval.find('=');
    env_vars.emplace_back(i == std::string::npos ? keyval
                                                 : keyval.substr(0, i));
  }

  return CallEnvironmentMethod(proxy, kUnsetEnvironmentMethodName, env_vars);
}

}  // namespace

namespace login_manager {

constexpr char SystemdUnitStarter::kServiceName[] = "org.freedesktop.systemd1";
constexpr char SystemdUnitStarter::kPath[] = "/org/freedesktop/systemd1";

SystemdUnitStarter::SystemdUnitStarter(dbus::ObjectProxy* proxy)
    : systemd_dbus_proxy_(proxy) {}

SystemdUnitStarter::~SystemdUnitStarter() = default;

std::unique_ptr<dbus::Response> SystemdUnitStarter::TriggerImpulse(
    const std::string& unit_name,
    const std::vector<std::string>& args_keyvals,
    TriggerMode mode) {
  DLOG(INFO) << "Starting " << unit_name << " unit";

  // If we are not able to properly set the environment for the
  // target unit, there is no point in going forward
  if (!SetEnvironment(systemd_dbus_proxy_, args_keyvals)) {
    DLOG(WARNING) << "Could not set environment for " << unit_name;
    return nullptr;
  }
  dbus::MethodCall method_call(kInterface, kStartUnitMethodName);
  dbus::MessageWriter writer(&method_call);
  writer.AppendString(unit_name + ".target");
  writer.AppendString(kStartUnitMode);

  std::unique_ptr<dbus::Response> response;
  switch (mode) {
    case TriggerMode::SYNC:
      response = systemd_dbus_proxy_->CallMethodAndBlock(
          &method_call, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT);
      break;
    case TriggerMode::ASYNC:
      systemd_dbus_proxy_->CallMethod(&method_call,
                                      dbus::ObjectProxy::TIMEOUT_USE_DEFAULT,
                                      base::DoNothing());
      break;
  }

  if (!UnsetEnvironment(systemd_dbus_proxy_, args_keyvals))
    DLOG(WARNING) << "Unable to unset environment after starting" << unit_name;

  return response;
}

}  // namespace login_manager
