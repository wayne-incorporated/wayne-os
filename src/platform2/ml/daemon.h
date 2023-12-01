// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ML_DAEMON_H_
#define ML_DAEMON_H_

#include <memory>

#include <base/memory/weak_ptr.h>
#include <brillo/daemons/dbus_daemon.h>
#include <dbus/exported_object.h>
#include <mojo/core/embedder/scoped_ipc_support.h>

#include "ml/metrics.h"
#include "ml/mojom/machine_learning_service.mojom.h"

namespace dbus {
class MethodCall;
}  // namespace dbus

namespace ml {

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
  // bootstrap a Mojo IPC channel. Since we should expect requests for client
  // registration to occur as soon as the D-Bus channel is up, this
  // initialization should be the last thing that happens in Daemon::OnInit().
  void InitDBus();

  // Handles org.chromium.BootstrapMojoConnection D-Bus method calls.
  void BootstrapMojoConnection(
      dbus::MethodCall* method_call,
      dbus::ExportedObject::ResponseSender response_sender);

  // Responds to Mojo disconnection by quitting the daemon.
  void OnMojoDisconnection();

  // IPC Support
  std::unique_ptr<mojo::core::ScopedIPCSupport> ipc_support_;

  // The top-level interface. Empty until it is created & bound to a pipe by
  // BootstrapMojoConnection.
  std::unique_ptr<chromeos::machine_learning::mojom::MachineLearningService>
      machine_learning_service_;

  // For periodic and on-demand UMA metrics logging.
  Metrics metrics_;

  // Must be last class member.
  base::WeakPtrFactory<Daemon> weak_ptr_factory_;
};

}  // namespace ml

#endif  // ML_DAEMON_H_
