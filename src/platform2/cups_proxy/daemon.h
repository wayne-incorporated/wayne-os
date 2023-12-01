// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CUPS_PROXY_DAEMON_H_
#define CUPS_PROXY_DAEMON_H_

#include <memory>

#include <base/memory/weak_ptr.h>
#include <brillo/daemons/dbus_daemon.h>
#include <dbus/exported_object.h>
#include <mojo/core/embedder/scoped_ipc_support.h>

#include "cups_proxy/mhd_util.h"
#include "cups_proxy/mojo_handler.h"
#include "cups_proxy/mojom/proxy.mojom.h"

namespace dbus {
class MethodCall;
}  // namespace dbus

namespace cups_proxy {

class Daemon : public brillo::DBusDaemon {
 public:
  Daemon();
  ~Daemon() override;

 protected:
  // brillo::DBusDaemon:
  int OnInit() override;

 private:
  // This function initializes the D-Bus service. The primary function of the
  // D-Bus interface is to receive a FD from the Chrome process so that we can
  // bootstrap a Mojo IPC channel.
  void InitDBus();

  // Handles org.chromium.BootstrapMojoConnection D-Bus method calls.
  void BootstrapMojoConnection(
      dbus::MethodCall* method_call,
      dbus::ExportedObject::ResponseSender response_sender);

  // Responds to Mojo connection errors by quitting the daemon.
  void OnConnectionError();

  MojoHandler mojo_handler_;

  ScopedMHDDaemon mhd_daemon_;

  std::unique_ptr<mojo::core::ScopedIPCSupport> ipc_support_;

  // Must be last class member.
  base::WeakPtrFactory<Daemon> weak_ptr_factory_;
};

}  // namespace cups_proxy

#endif  // CUPS_PROXY_DAEMON_H_
