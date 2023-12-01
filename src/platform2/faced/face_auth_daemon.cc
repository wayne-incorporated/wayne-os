// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "faced/face_auth_daemon.h"

#include <sysexits.h>

#include <cstdlib>
#include <memory>
#include <utility>

#include <base/check.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/task/single_thread_task_runner.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/bus.h>
#include <dbus/message.h>
#include <mojo/core/embedder/embedder.h>

namespace faced {

FaceAuthDaemon::FaceAuthDaemon() : DBusServiceDaemon(kFaceAuthDaemonName) {}

int FaceAuthDaemon::OnInit() {
  mojo::core::Init();

  absl::StatusOr<std::unique_ptr<FaceAuthService>> face_auth_service =
      FaceAuthService::Create();
  if (!face_auth_service.ok()) {
    return EXIT_FAILURE;
  }

  face_auth_service_ = std::move(face_auth_service.value());

  int return_code = DBusServiceDaemon::OnInit();
  if (return_code != EXIT_SUCCESS) {
    return return_code;
  }

  return EXIT_SUCCESS;
}

void FaceAuthDaemon::RegisterDBusObjectsAsync(
    brillo::dbus_utils::AsyncEventSequencer* sequencer) {
  // face_auth_service must outlive this class instance
  adaptor_ = std::make_unique<DBusAdaptor>(bus_, *face_auth_service_.get());
  adaptor_->RegisterAsync(
      sequencer->GetHandler("RegisterAsync() failed", true));
}

}  // namespace faced
