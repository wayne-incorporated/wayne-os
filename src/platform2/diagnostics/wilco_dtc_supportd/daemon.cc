// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/wilco_dtc_supportd/daemon.h"

#include <cstdlib>

#include <base/barrier_closure.h>
#include <base/check.h>
#include <base/functional/callback.h>
#include <base/location.h>
#include <base/logging.h>
#include <base/run_loop.h>
#include <base/task/single_thread_task_runner.h>
#include <base/time/time.h>
#include <dbus/wilco_dtc_supportd/dbus-constants.h>
#include <mojo/core/embedder/embedder.h>

#include "diagnostics/constants/grpc_constants.h"
#include "diagnostics/wilco_dtc_supportd/service_util.h"

namespace diagnostics {
namespace wilco {

// The time (in TimeDelta) after which ForceShutdown will be called if graceful
// shutdown wasn't done within that time.
constexpr base::TimeDelta kForceShutdownDelayTimeDelta = base::Seconds(2);

Daemon::Daemon()
    : DBusServiceDaemon(kWilcoDtcSupportdServiceName /* service_name */),
      mojo_service_factory_(
          &mojo_grpc_adapter_,
          base::BindRepeating(&brillo::Daemon::Quit, base::Unretained(this))),
      wilco_dtc_supportd_core_(&wilco_dtc_supportd_core_delegate_impl_,
                               &grpc_client_manager_,
                               {GetWilcoDtcSupportdGrpcHostVsockUri(),
                                kWilcoDtcSupportdGrpcDomainSocketUri},
                               &mojo_service_factory_) {}

Daemon::~Daemon() = default;

int Daemon::OnInit() {
  VLOG(0) << "Starting";
  const int exit_code = DBusServiceDaemon::OnInit();
  if (exit_code != EXIT_SUCCESS)
    return exit_code;

  grpc_client_manager_.Start(GetUiMessageReceiverWilcoDtcGrpcHostVsockUri(),
                             {GetWilcoDtcGrpcHostVsockUri()});

  if (!wilco_dtc_supportd_core_.Start()) {
    LOG(ERROR) << "Shutting down due to fatal initialization failure";
    ShutDownServicesInRunLoop(&wilco_dtc_supportd_core_, &grpc_client_manager_);
    return EXIT_FAILURE;
  }
  // Init the Mojo Embedder API.
  mojo::core::Init();
  ipc_support_ = std::make_unique<mojo::core::ScopedIPCSupport>(
      base::SingleThreadTaskRunner::
          GetCurrentDefault() /* io_thread_task_runner */,
      mojo::core::ScopedIPCSupport::ShutdownPolicy::
          CLEAN /* blocking shutdown */);

  return EXIT_SUCCESS;
}

void Daemon::RegisterDBusObjectsAsync(
    brillo::dbus_utils::AsyncEventSequencer* sequencer) {
  DCHECK(bus_);
  dbus_service_.RegisterDBusObjectsAsync(bus_, sequencer);
  wilco_dtc_supportd_core_.CreateDbusAdapters(bus_);
}

void Daemon::OnShutdown(int* error_code) {
  // Gracefully tear down pieces that require asynchronous shutdown.
  VLOG(1) << "Shutting down";

  // Allow time for Core to gracefully shut down all threads.
  force_shutdown_timer_.Start(FROM_HERE, kForceShutdownDelayTimeDelta, this,
                              &Daemon::ForceShutdown);

  dbus_service_.ShutDown();

  ShutDownServicesInRunLoop(&wilco_dtc_supportd_core_, &grpc_client_manager_);

  VLOG(0) << "Shutting down with code " << *error_code;
}

void Daemon::ForceShutdown() {
  LOG(ERROR) << "ForceShutdown's the whole process due to a failure while "
                "gracefully shutting down";
  std::exit(EXIT_FAILURE);
}

}  // namespace wilco
}  // namespace diagnostics
