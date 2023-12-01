// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "image-burner/daemon.h"

#include <utility>

#include "image-burner/image_burn_service.h"

namespace imageburn {

Daemon::Daemon() : brillo::DBusServiceDaemon(kImageBurnServiceName) {}

Daemon::~Daemon() = default;

void Daemon::RegisterDBusObjectsAsync(
    brillo::dbus_utils::AsyncEventSequencer* sequencer) {
  service_ = std::make_unique<ImageBurnService>(bus_, &burner_);
  burner_.InitSignalSender(service_.get());

  service_->RegisterAsync(sequencer->GetHandler(
      "Failed to export image-burner service.", true /* failure_is_fatal */));
}

}  // namespace imageburn
