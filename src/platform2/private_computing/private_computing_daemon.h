// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#ifndef PRIVATE_COMPUTING_PRIVATE_COMPUTING_DAEMON_H_
#define PRIVATE_COMPUTING_PRIVATE_COMPUTING_DAEMON_H_

#include <memory>

#include <brillo/daemons/dbus_daemon.h>
#include "./private_computing_adaptor.h"

namespace brillo::dbus_utils {
class AsyncEventSequencer;
}  // namespace brillo::dbus_utils

namespace private_computing {

class PrivateComputingDaemon : public brillo::DBusServiceDaemon {
 public:
  PrivateComputingDaemon();
  PrivateComputingDaemon(const PrivateComputingDaemon&) = delete;
  PrivateComputingDaemon& operator=(const PrivateComputingDaemon&) = delete;
  ~PrivateComputingDaemon() override = default;

 protected:
  void RegisterDBusObjectsAsync(
      brillo::dbus_utils::AsyncEventSequencer* sequencer) override;

 private:
  // The adaptor class for private_computing dbus daemon service.
  // This class provides the save and get last ping dates method interfaces
  // to Ash Chrome.
  std::unique_ptr<PrivateComputingAdaptor> adaptor_;
};

}  // namespace private_computing
#endif  // PRIVATE_COMPUTING_PRIVATE_COMPUTING_DAEMON_H_
