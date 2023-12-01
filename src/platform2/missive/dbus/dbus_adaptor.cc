// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "missive/dbus/dbus_adaptor.h"

#include <cstdlib>
#include <string>
#include <utility>
#include <vector>

#include <base/logging.h>
#include <base/task/bind_post_task.h>
#include <base/task/sequenced_task_runner.h>
#include <base/time/time.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/bus.h>
#include <featured/feature_library.h>

#include "missive/missive/missive_service.h"
#include "missive/proto/interface.pb.h"
#include "missive/proto/record.pb.h"
#include "missive/util/status.h"

namespace reporting {

namespace {
template <typename ResponseType>
ResponseType RespondDaemonNotReady() {
  ResponseType response_body;
  auto* status = response_body.mutable_status();
  status->set_code(error::UNAVAILABLE);
  status->set_error_message("The daemon is still starting.");
  return response_body;
}
}  // namespace

DBusAdaptor::DBusAdaptor(scoped_refptr<dbus::Bus> bus,
                         std::unique_ptr<MissiveService> missive,
                         base::OnceCallback<void(Status)> failure_cb)
    : org::chromium::MissivedAdaptor(this),
      dbus_object_(/*object_manager=*/nullptr,
                   bus,
                   org::chromium::MissivedAdaptor::GetObjectPath()),
      missive_(std::move(missive)),
      failure_cb_(std::move(failure_cb)) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  CHECK(feature::PlatformFeatures::Initialize(bus));

  missive_->StartUp(
      bus, feature::PlatformFeatures::Get(),
      base::BindPostTaskToCurrentDefault(base::BindOnce(
          &DBusAdaptor::StartupFinished, weak_ptr_factory_.GetWeakPtr())));
}

void DBusAdaptor::StartupFinished(Status status) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (!status.ok()) {
    if (failure_cb_) {
      std::move(failure_cb_).Run(status);
    }
    return;
  }
  daemon_is_ready_ = true;
  missive_->OnReady();
}

// static
void DBusAdaptor::OnFailure(Status status) {
  LOG(FATAL) << "Unable to start Missive daemon, status: " << status;
}

void DBusAdaptor::RegisterAsync(
    brillo::dbus_utils::AsyncEventSequencer::CompletionAction cb) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  RegisterWithDBusObject(&dbus_object_);
  dbus_object_.RegisterAsync(std::move(cb));
}

void DBusAdaptor::Shutdown() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  auto status = missive_->ShutDown();
  if (!status.ok()) {
    LOG(FATAL) << "Failed to shutdown Missive daemon, status: " << status;
  }
  daemon_is_ready_ = false;
  missive_.reset();
}

void DBusAdaptor::EnqueueRecord(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        EnqueueRecordResponse>> out_response,
    const EnqueueRecordRequest& in_request) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (!daemon_is_ready_) {
    out_response->Return(RespondDaemonNotReady<EnqueueRecordResponse>());
    return;
  }
  missive_->EnqueueRecord(in_request, std::move(out_response));
}

void DBusAdaptor::FlushPriority(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        FlushPriorityResponse>> out_response,
    const FlushPriorityRequest& in_request) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (!daemon_is_ready_) {
    out_response->Return(RespondDaemonNotReady<FlushPriorityResponse>());
    return;
  }
  missive_->FlushPriority(in_request, std::move(out_response));
}

void DBusAdaptor::ConfirmRecordUpload(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        ConfirmRecordUploadResponse>> out_response,
    const ConfirmRecordUploadRequest& in_request) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  ConfirmRecordUploadResponse response_body;
  if (!daemon_is_ready_) {
    out_response->Return(RespondDaemonNotReady<ConfirmRecordUploadResponse>());
    return;
  }
  missive_->ConfirmRecordUpload(in_request, std::move(out_response));
}

void DBusAdaptor::UpdateEncryptionKey(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
        UpdateEncryptionKeyResponse>> out_response,
    const UpdateEncryptionKeyRequest& in_request) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  UpdateEncryptionKeyResponse response_body;
  if (!daemon_is_ready_) {
    out_response->Return(RespondDaemonNotReady<UpdateEncryptionKeyResponse>());
    return;
  }
  missive_->UpdateEncryptionKey(in_request, std::move(out_response));
}
}  // namespace reporting
