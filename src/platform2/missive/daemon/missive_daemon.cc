// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "missive/daemon/missive_daemon.h"

#include <cstdlib>
#include <memory>
#include <string>
#include <utility>

#include <base/logging.h>
#include <chromeos/dbus/service_constants.h>

#include "missive/missive/missive_service.h"
#include "missive/proto/interface.pb.h"
#include "missive/proto/record.pb.h"
#include "missive/util/status.h"

namespace reporting {

MissiveDaemon::MissiveDaemon(std::unique_ptr<MissiveService> missive)
    : brillo::DBusServiceDaemon(::missive::kMissiveServiceName),
      missive_(std::move(missive)) {}

MissiveDaemon::~MissiveDaemon() = default;

void MissiveDaemon::RegisterDBusObjectsAsync(
    brillo::dbus_utils::AsyncEventSequencer* sequencer) {
  adaptor_ = std::make_unique<DBusAdaptor>(bus_, std::move(missive_));
  adaptor_->RegisterAsync(
      sequencer->GetHandler(/*descriptive_message=*/"RegisterAsync() failed",
                            /*failure_is_fatal=*/true));
}

void MissiveDaemon::OnShutdown(int* exit_code) {
  adaptor_->Shutdown();
  brillo::DBusServiceDaemon::OnShutdown(exit_code);
}
}  // namespace reporting
