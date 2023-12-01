// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/dbus/dhcpcd_proxy.h"

#include <base/functional/callback_helpers.h>
#include <base/logging.h>

#include "shill/logging.h"

namespace shill {

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kDHCP;
}  // namespace Logging

DHCPCDProxy::DHCPCDProxy(const scoped_refptr<dbus::Bus>& bus,
                         const std::string& service_name)
    : dhcpcd_proxy_(new org::chromium::dhcpcdProxy(bus, service_name)) {
  SLOG(2) << "DHCPCDProxy(service=" << service_name << ").";
  // Do not register signal handlers, signals are processed by
  // DHCPCDListener.
}

DHCPCDProxy::~DHCPCDProxy() {
  dhcpcd_proxy_->ReleaseObjectProxy(base::DoNothing());
}

void DHCPCDProxy::Rebind(const std::string& interface) {
  SLOG(2) << __func__;
  brillo::ErrorPtr error;
  if (!dhcpcd_proxy_->Rebind(interface, &error)) {
    LogDBusError(error, __func__, interface);
  }
}

void DHCPCDProxy::Release(const std::string& interface) {
  SLOG(2) << __func__;
  brillo::ErrorPtr error;
  if (!dhcpcd_proxy_->Release(interface, &error)) {
    LogDBusError(error, __func__, interface);
  }
}

void DHCPCDProxy::LogDBusError(const brillo::ErrorPtr& error,
                               const std::string& method,
                               const std::string& interface) {
  if (error->GetCode() == DBUS_ERROR_SERVICE_UNKNOWN ||
      error->GetCode() == DBUS_ERROR_NO_REPLY) {
    LOG(INFO) << method << ": dhcpcd daemon appears to have exited.";
  } else {
    LOG(FATAL) << "DBus error: " << method << " " << interface << ": "
               << error->GetCode() << ": " << error->GetMessage();
  }
}

}  // namespace shill
