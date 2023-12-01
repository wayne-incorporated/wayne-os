// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_CROS_HEALTHD_DAEMON_H_
#define DIAGNOSTICS_CROS_HEALTHD_CROS_HEALTHD_DAEMON_H_

#include <memory>

#include <brillo/daemons/daemon.h>
#include <mojo/core/embedder/scoped_ipc_support.h>
#include <mojo/public/cpp/platform/platform_channel_endpoint.h>

#include "diagnostics/cros_healthd/cros_healthd_diagnostics_service.h"
#include "diagnostics/cros_healthd/cros_healthd_mojo_service.h"
#include "diagnostics/cros_healthd/cros_healthd_routine_factory_impl.h"
#include "diagnostics/cros_healthd/event_aggregator.h"
#include "diagnostics/cros_healthd/fetch_aggregator.h"
#include "diagnostics/cros_healthd/system/context.h"

namespace diagnostics {

// Daemon class for cros_healthd.
class CrosHealthdDaemon final : public brillo::Daemon {
 public:
  explicit CrosHealthdDaemon(
      mojo::PlatformChannelEndpoint endpoint,
      std::unique_ptr<brillo::UdevMonitor>&& udev_monitor);
  CrosHealthdDaemon(const CrosHealthdDaemon&) = delete;
  CrosHealthdDaemon& operator=(const CrosHealthdDaemon&) = delete;
  ~CrosHealthdDaemon() override;

 private:
  // For mojo thread initialization.
  mojo::core::ScopedIPCSupport ipc_support_;
  // Provides access to helper objects. Used by various telemetry fetchers,
  // event implementations and diagnostic routines.
  Context context_;
  // |fetch_aggregator_| is responsible for fulfulling all ProbeTelemetryInfo
  // requests.
  FetchAggregator fetch_aggregator_{&context_};
  // |event_aggregator_| is responsible for fulfulling all event requests from
  // CrosHealthdEventService.
  EventAggregator event_aggregator_{&context_};
  // |diagnostics_service_| delegates routine creation to |routine_factory_|.
  CrosHealthdRoutineFactoryImpl routine_factory_{&context_};
  // Maintains the Mojo connection with cros_healthd clients.
  CrosHealthdMojoService mojo_service_{&context_, &fetch_aggregator_,
                                       &event_aggregator_};
  // Creates new diagnostic routines and controls existing diagnostic routines.
  CrosHealthdDiagnosticsService diagnostics_service_{
      &context_, &routine_factory_, &mojo_service_};
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_CROS_HEALTHD_DAEMON_H_
