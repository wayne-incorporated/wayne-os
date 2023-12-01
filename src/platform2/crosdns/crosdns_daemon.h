// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CROSDNS_CROSDNS_DAEMON_H_
#define CROSDNS_CROSDNS_DAEMON_H_

#include <memory>
#include <string>

#include <brillo/daemons/dbus_daemon.h>
#include <brillo/errors/error.h>

#include "crosdns/dbus_adaptors/org.chromium.CrosDns.h"
#include "crosdns/hosts_modifier.h"

namespace crosdns {

// D-Bus service daemon implementation, this is used to receive requests to add
// and remove entries from the /etc/hosts files.
class CrosDnsDaemon : public brillo::DBusServiceDaemon,
                      public org::chromium::CrosDnsInterface {
 public:
  CrosDnsDaemon();
  CrosDnsDaemon(const CrosDnsDaemon&) = delete;
  CrosDnsDaemon& operator=(const CrosDnsDaemon&) = delete;

  ~CrosDnsDaemon() override;

  // Implementations of the public methods interface.
  // org::chromium::CrosDnsInterface:
  bool SetHostnameIpMapping(brillo::ErrorPtr* err,
                            const std::string& hostname,
                            const std::string& ipv4,
                            const std::string& ipv6) override;
  bool RemoveHostnameIpMapping(brillo::ErrorPtr* err,
                               const std::string& hostname) override;

 protected:
  // brillo::DBusServiceDaemon:
  void RegisterDBusObjectsAsync(
      brillo::dbus_utils::AsyncEventSequencer* sequencer) override;
  int OnInit() override;

 private:
  std::unique_ptr<brillo::dbus_utils::DBusObject> dbus_object_;

  org::chromium::CrosDnsAdaptor dbus_adaptor_;

  HostsModifier hosts_modifier_;
};

}  // namespace crosdns

#endif  // CROSDNS_CROSDNS_DAEMON_H_
