// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#ifndef SYSTEM_PROXY_SYSTEM_PROXY_DAEMON_H_
#define SYSTEM_PROXY_SYSTEM_PROXY_DAEMON_H_

#include <memory>

#include <brillo/daemons/dbus_daemon.h>

namespace brillo {
namespace dbus_utils {
class AsyncEventSequencer;
}
}  // namespace brillo

namespace system_proxy {

class SystemProxyAdaptor;

class SystemProxyDaemon : public brillo::DBusServiceDaemon {
 public:
  SystemProxyDaemon();
  SystemProxyDaemon(const SystemProxyDaemon&) = delete;
  SystemProxyDaemon& operator=(const SystemProxyDaemon&) = delete;
  ~SystemProxyDaemon();

 protected:
  void RegisterDBusObjectsAsync(
      brillo::dbus_utils::AsyncEventSequencer* sequencer) override;

 private:
  std::unique_ptr<SystemProxyAdaptor> adaptor_;
};
}  // namespace system_proxy
#endif  // SYSTEM_PROXY_SYSTEM_PROXY_DAEMON_H_
