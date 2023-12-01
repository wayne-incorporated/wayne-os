// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/cros_healthd_daemon.h"

#include <memory>
#include <utility>

#include <base/task/single_thread_task_runner.h>
#include <brillo/udev/udev_monitor.h>
#include <mojo/public/cpp/platform/platform_channel_endpoint.h>

namespace diagnostics {

CrosHealthdDaemon::CrosHealthdDaemon(
    mojo::PlatformChannelEndpoint endpoint,
    std::unique_ptr<brillo::UdevMonitor>&& udev_monitor)
    : ipc_support_(base::SingleThreadTaskRunner::GetCurrentDefault(),
                   mojo::core::ScopedIPCSupport::ShutdownPolicy::
                       CLEAN /* blocking shutdown */),
      context_(
          std::move(endpoint),
          std::move(udev_monitor),
          base::BindOnce(&CrosHealthdDaemon::Quit, base::Unretained(this))) {}

CrosHealthdDaemon::~CrosHealthdDaemon() = default;

}  // namespace diagnostics
