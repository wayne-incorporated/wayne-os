// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "dns-proxy/session_monitor.h"
#include <base/functional/bind.h>
#include <base/logging.h>

namespace dns_proxy {

namespace {

void OnSignalConnected(const std::string& interface,
                       const std::string& signal,
                       bool success) {
  if (!success) {
    LOG(ERROR) << "Could not connect to session signal " << signal
               << "on interface " << interface;
  }
}

}  // namespace

SessionMonitor::SessionMonitor(scoped_refptr<dbus::Bus> bus)
    : proxy_(bus), weak_ptr_factory_(this) {
  proxy_.RegisterSessionStateChangedSignalHandler(
      base::BindRepeating(&SessionMonitor::OnSessionStateChanged,
                          weak_ptr_factory_.GetWeakPtr()),
      base::BindOnce(&OnSignalConnected));
}

void SessionMonitor::RegisterSessionStateHandler(
    base::RepeatingCallback<void(bool)> handler) {
  handler_ = handler;
}

void SessionMonitor::OnSessionStateChanged(const std::string& state) {
  if (handler_.is_null())
    return;

  // Values are described in:
  // login_manager/dbus_bindings/org.chromium.SessionManagerInterface.xml
  if (state == "started") {
    handler_.Run(true);
  } else if (state == "stopping") {
    handler_.Run(false);
  }
}

}  // namespace dns_proxy
