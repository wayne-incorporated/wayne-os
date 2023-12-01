// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PRINTSCANMGR_DAEMON_DAEMON_H_
#define PRINTSCANMGR_DAEMON_DAEMON_H_

#include <memory>

#include <brillo/daemons/dbus_daemon.h>
#include <mojo/core/embedder/scoped_ipc_support.h>
#include <mojo/public/cpp/platform/platform_channel_endpoint.h>

#include "printscanmgr/daemon/dbus_adaptor.h"

namespace printscanmgr {

class Daemon final : public brillo::DBusServiceDaemon {
 public:
  explicit Daemon(mojo::PlatformChannelEndpoint endpoint);
  Daemon(const Daemon&) = delete;
  Daemon& operator=(const Daemon&) = delete;
  ~Daemon() override;

 protected:
  void RegisterDBusObjectsAsync(
      brillo::dbus_utils::AsyncEventSequencer* sequencer) override;

 private:
  // For mojo thread initialization.
  mojo::core::ScopedIPCSupport ipc_support_;
  std::unique_ptr<DbusAdaptor> dbus_adaptor_;
};

}  // namespace printscanmgr

#endif  // PRINTSCANMGR_DAEMON_DAEMON_H_
