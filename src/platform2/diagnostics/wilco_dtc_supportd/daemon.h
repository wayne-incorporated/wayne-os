// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_WILCO_DTC_SUPPORTD_DAEMON_H_
#define DIAGNOSTICS_WILCO_DTC_SUPPORTD_DAEMON_H_

#include <memory>

#include <base/timer/timer.h>
#include <brillo/daemons/dbus_daemon.h>
#include <mojo/core/embedder/scoped_ipc_support.h>

#include "diagnostics/wilco_dtc_supportd/core.h"
#include "diagnostics/wilco_dtc_supportd/core_delegate_impl.h"
#include "diagnostics/wilco_dtc_supportd/dbus_service.h"
#include "diagnostics/wilco_dtc_supportd/grpc_client_manager.h"
#include "diagnostics/wilco_dtc_supportd/mojo_grpc_adapter.h"
#include "diagnostics/wilco_dtc_supportd/mojo_service_factory.h"

namespace diagnostics {
namespace wilco {

// Daemon class for the wilco_dtc_supportd daemon.
class Daemon final : public brillo::DBusServiceDaemon {
 public:
  Daemon();
  Daemon(const Daemon&) = delete;
  Daemon& operator=(const Daemon&) = delete;

  ~Daemon() override;

 private:
  // brillo::DBusServiceDaemon overrides:
  int OnInit() override;
  void RegisterDBusObjectsAsync(
      brillo::dbus_utils::AsyncEventSequencer* sequencer) override;
  void OnShutdown(int* error_code) override;

  // Forces shutting down the whole process if the graceful shutdown wasn't
  // done within timeout.
  void ForceShutdown();

  std::unique_ptr<mojo::core::ScopedIPCSupport> ipc_support_;
  GrpcClientManager grpc_client_manager_;
  MojoGrpcAdapter mojo_grpc_adapter_{&grpc_client_manager_};
  MojoServiceFactory mojo_service_factory_;
  DBusService dbus_service_{&mojo_service_factory_};
  CoreDelegateImpl wilco_dtc_supportd_core_delegate_impl_;
  Core wilco_dtc_supportd_core_;

  base::OneShotTimer force_shutdown_timer_;
};

}  // namespace wilco
}  // namespace diagnostics

#endif  // DIAGNOSTICS_WILCO_DTC_SUPPORTD_DAEMON_H_
