// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef KERBEROS_KERBEROS_DAEMON_H_
#define KERBEROS_KERBEROS_DAEMON_H_

#include <memory>

#include <brillo/daemons/dbus_daemon.h>

namespace brillo {
namespace dbus_utils {
class AsyncEventSequencer;
}
}  // namespace brillo

namespace kerberos {

class KerberosAdaptor;

class KerberosDaemon : public brillo::DBusServiceDaemon {
 public:
  KerberosDaemon();
  KerberosDaemon(const KerberosDaemon&) = delete;
  KerberosDaemon& operator=(const KerberosDaemon&) = delete;

  ~KerberosDaemon();

 protected:
  void RegisterDBusObjectsAsync(
      brillo::dbus_utils::AsyncEventSequencer* sequencer) override;

 private:
  std::unique_ptr<KerberosAdaptor> adaptor_;
};

}  // namespace kerberos

#endif  // KERBEROS_KERBEROS_DAEMON_H_
