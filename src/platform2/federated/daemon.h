// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef FEDERATED_DAEMON_H_
#define FEDERATED_DAEMON_H_

#include <memory>

#include <base/memory/weak_ptr.h>
#include <base/task/single_thread_task_runner.h>
#include <brillo/daemons/dbus_daemon.h>
#include <dbus/exported_object.h>
#include <mojo/core/embedder/scoped_ipc_support.h>

#include "federated/mojom/federated_service.mojom.h"
#include "federated/scheduler.h"

namespace dbus {
class MethodCall;
}  // namespace dbus

namespace federated {

class Daemon : public brillo::DBusDaemon {
 public:
  Daemon();
  ~Daemon() override;

 protected:
  // brillo::DBusDaemon:
  int OnInit() override;

 private:
  void InitDBus();

  // Handles org.chromium.Federated.BootstrapMojoConnection D-Bus method calls.
  void BootstrapMojoConnection(
      dbus::MethodCall* method_call,
      dbus::ExportedObject::ResponseSender response_sender);

  // Responds to Mojo disconnection by quitting the daemon.
  void OnMojoDisconnection();

  // IPC Support
  std::unique_ptr<mojo::core::ScopedIPCSupport> ipc_support_;

  // The top-level interface. Empty until it is created & bound to a pipe by
  // BootstrapMojoConnection.
  std::unique_ptr<chromeos::federated::mojom::FederatedService>
      federated_service_;

  std::unique_ptr<Scheduler> scheduler_;

  // If true, starts the scheduling OnInit, useful when testing.
#if USE_LOCAL_FEDERATED_SERVER
  bool should_schedule_ = true;
#else
  bool should_schedule_ = false;
#endif

  // Must be last class member.
  const base::WeakPtrFactory<Daemon> weak_ptr_factory_;
};

}  // namespace federated

#endif  // FEDERATED_DAEMON_H_
