// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DNS_PROXY_SESSION_MONITOR_H_
#define DNS_PROXY_SESSION_MONITOR_H_

#include <memory>
#include <string>

#include <base/functional/callback_helpers.h>
#include <session_manager/dbus-proxies.h>

namespace dns_proxy {

// Monitors session manager for session state (login/logout) changes.
class SessionMonitor {
 public:
  explicit SessionMonitor(scoped_refptr<dbus::Bus> bus);
  SessionMonitor(const SessionMonitor&) = delete;
  SessionMonitor& operator=(const SessionMonitor&) = delete;
  virtual ~SessionMonitor() = default;

  // Attaches a handler to be called whenever the session state changes.
  // A parameter value of |true| indicates a user is logging in, and |false|
  // indicates a user is logging out.
  void RegisterSessionStateHandler(base::RepeatingCallback<void(bool)> handler);

 protected:
  // Handles the SessionStateChanged DBus signal.
  void OnSessionStateChanged(const std::string& state);

 private:
  org::chromium::SessionManagerInterfaceProxy proxy_;
  base::RepeatingCallback<void(bool)> handler_;
  base::WeakPtrFactory<SessionMonitor> weak_ptr_factory_;
};

}  // namespace dns_proxy

#endif  // DNS_PROXY_SESSION_MONITOR_H_
