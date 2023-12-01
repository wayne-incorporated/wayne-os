// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MISSIVE_DAEMON_MISSIVE_DAEMON_H_
#define MISSIVE_DAEMON_MISSIVE_DAEMON_H_

#include <memory>
#include <string>
#include "base/functional/bind.h"

#include <brillo/daemons/dbus_daemon.h>
#include <missive/dbus/dbus_adaptor.h>
#include <missive/missive/missive_impl.h>
#include <missive/missive/missive_service.h>

namespace reporting {

class MissiveDaemon : public brillo::DBusServiceDaemon {
 public:
  explicit MissiveDaemon(std::unique_ptr<MissiveService> missive =
                             std::make_unique<MissiveImpl>());
  MissiveDaemon(const MissiveDaemon&) = delete;
  MissiveDaemon& operator=(const MissiveDaemon&) = delete;
  virtual ~MissiveDaemon();

 private:
  friend class MissiveDaemonTest;

  void RegisterDBusObjectsAsync(
      brillo::dbus_utils::AsyncEventSequencer* sequencer) override;

  void OnShutdown(int* exit_code) override;

  std::unique_ptr<DBusAdaptor> adaptor_;
  std::unique_ptr<MissiveService> missive_;
};
}  // namespace reporting

#endif  // MISSIVE_DAEMON_MISSIVE_DAEMON_H_
