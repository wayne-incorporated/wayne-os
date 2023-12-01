// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "pciguard/session_monitor.h"
#include <base/functional/bind.h>
#include <base/logging.h>

namespace pciguard {

namespace {

void OnSignalConnected(const std::string& interface,
                       const std::string& signal,
                       bool success) {
  if (!success) {
    LOG(ERROR) << "Could not connect to session signal " << signal
               << "on interface " << interface;
    exit(EXIT_FAILURE);
  }
}

}  // namespace

SessionMonitor::SessionMonitor(scoped_refptr<dbus::Bus> bus,
                               EventHandler* ev_handler)
    : proxy_(bus), event_handler_(ev_handler), weak_ptr_factory_(this) {
  proxy_.RegisterScreenIsLockedSignalHandler(
      base::BindRepeating(&SessionMonitor::OnScreenIsLocked,
                          weak_ptr_factory_.GetWeakPtr()),
      base::BindOnce(&OnSignalConnected));
  proxy_.RegisterScreenIsUnlockedSignalHandler(
      base::BindRepeating(&SessionMonitor::OnScreenIsUnlocked,
                          weak_ptr_factory_.GetWeakPtr()),
      base::BindOnce(&OnSignalConnected));
  proxy_.RegisterSessionStateChangedSignalHandler(
      base::BindRepeating(&SessionMonitor::OnSessionStateChanged,
                          weak_ptr_factory_.GetWeakPtr()),
      base::BindOnce(&OnSignalConnected));
}

void SessionMonitor::OnScreenIsLocked() {
  event_handler_->OnScreenLocked();
}

void SessionMonitor::OnScreenIsUnlocked() {
  event_handler_->OnScreenUnlocked();
}

void SessionMonitor::OnSessionStateChanged(const std::string& state) {
  LOG(INFO) << __func__ << "Session state changed, new state = " << state;

  if (state == "started") {
    // Ignore Guest sessions.
    bool is_guest;
    brillo::ErrorPtr error;
    proxy_.IsGuestSessionActive(&is_guest, &error);
    if (error || is_guest) {
      LOG(INFO) << "Ignoring Guest session (error=" << error
                << ", is_guest=" << is_guest << ")";
      return;
    }

    event_handler_->OnUserLogin();

  } else if (state == "stopping") {
    event_handler_->OnUserLogout();
  }
}

}  // namespace pciguard
