// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "faced/enrollment_session.h"

#include <cstdint>
#include <memory>
#include <utility>
#include <vector>

#include <absl/status/status.h>
#include <base/functional/bind.h>
#include <base/location.h>
#include <base/task/sequenced_task_runner.h>

#include "faced/common/face_status.h"
#include "faced/util/task.h"

namespace faced {

using ::chromeos::faceauth::mojom::EnrollmentCompleteMessage;
using ::chromeos::faceauth::mojom::EnrollmentCompleteMessagePtr;
using ::chromeos::faceauth::mojom::EnrollmentSessionConfigPtr;
using ::chromeos::faceauth::mojom::EnrollmentUpdateMessage;
using ::chromeos::faceauth::mojom::EnrollmentUpdateMessagePtr;
using ::chromeos::faceauth::mojom::FaceEnrollmentSessionDelegate;
using ::chromeos::faceauth::mojom::FaceOperationStatus;
using ::chromeos::faceauth::mojom::SessionError;

using ::faceauth::eora::AbortEnrollmentRequest;
using ::faceauth::eora::AbortEnrollmentResponse;
using ::faceauth::eora::CompleteEnrollmentRequest;
using ::faceauth::eora::CompleteEnrollmentResponse;
using ::faceauth::eora::ProcessFrameForEnrollmentRequest;
using ::faceauth::eora::ProcessFrameForEnrollmentResponse;
using ::faceauth::eora::StartEnrollmentRequest;
using ::faceauth::eora::StartEnrollmentResponse;

namespace {

faceauth::eora::FrameType FormatToFrameType(Frame::Format format) {
  switch (format) {
    case Frame::Format::kMjpeg:
      return faceauth::eora::FrameType::MJPG;
    case Frame::Format::kYuvNv12:
      return faceauth::eora::FrameType::YUV_NV12;
    default:
      return faceauth::eora::FrameType::UNKNOWN;
  }
}

faceauth::eora::CameraFrame FrameToCameraFrame(std::unique_ptr<Frame> frame) {
  faceauth::eora::CameraFrame result;
  result.set_width(frame->width);
  result.set_height(frame->height);
  result.set_type(FormatToFrameType(frame->format));
  *result.mutable_payload() = std::move(frame->data);
  return result;
}

}  // namespace

absl::StatusOr<std::unique_ptr<EnrollmentSession>> EnrollmentSession::Create(
    absl::BitGen& bitgen,
    mojo::PendingReceiver<FaceEnrollmentSession> receiver,
    mojo::PendingRemote<FaceEnrollmentSessionDelegate> delegate,
    EnrollmentSessionConfigPtr config,
    Lease<brillo::AsyncGrpcClient<faceauth::eora::FaceService>> client,
    std::unique_ptr<StreamReader<InputFrame>> stream_reader) {
  uint64_t session_id = GenerateSessionId(bitgen);

  // Using `new` to access private constructor of `EnrollmentSession`.
  std::unique_ptr<EnrollmentSession> session(new EnrollmentSession(
      session_id, std::move(receiver), std::move(delegate), std::move(client),
      std::move(stream_reader)));

  session->delegate_.set_disconnect_handler(base::BindOnce(
      &EnrollmentSession::TryCancel, base::Unretained(session.get())));

  session->receiver_.set_disconnect_handler(base::BindOnce(
      &EnrollmentSession::TryCancel, base::Unretained(session.get())));

  return session;
}

EnrollmentSession::EnrollmentSession(
    uint64_t session_id,
    mojo::PendingReceiver<FaceEnrollmentSession> receiver,
    mojo::PendingRemote<FaceEnrollmentSessionDelegate> delegate,
    Lease<brillo::AsyncGrpcClient<faceauth::eora::FaceService>> client,
    std::unique_ptr<StreamReader<InputFrame>> stream_reader)
    : session_id_(session_id),
      receiver_(this, std::move(receiver)),
      delegate_(std::move(delegate)),
      rpc_client_(std::move(client)),
      stream_reader_(std::move(stream_reader)) {}

void EnrollmentSession::NotifyUpdate(FaceOperationStatus status) {
  EnrollmentUpdateMessagePtr message(
      EnrollmentUpdateMessage::New(status, /*poses=*/std::vector<bool>()));
  delegate_->OnEnrollmentUpdate(std::move(message));
}

void EnrollmentSession::NotifyComplete() {
  delegate_->OnEnrollmentComplete(EnrollmentCompleteMessage::New());

  FinishSession(absl::OkStatus());
}

void EnrollmentSession::NotifyCancelled() {
  delegate_->OnEnrollmentCancelled();

  FinishSession(absl::CancelledError());
}

void EnrollmentSession::NotifyError(absl::Status error) {
  // TODO(bkersten): map absl::Status to SessionError
  SessionError session_error = SessionError::UNKNOWN;
  delegate_->OnEnrollmentError(session_error);

  FinishSession(error);
}

void EnrollmentSession::Start(StartCallback start_callback,
                              CompletionCallback completion_callback) {
  completion_callback_ = std::move(completion_callback);

  (*rpc_client_)
      ->CallRpc(
          &faceauth::eora::FaceService::Stub::AsyncStartEnrollment,
          StartEnrollmentRequest(),
          base::BindOnce(&EnrollmentSession::CompleteStartEnrollment,
                         base::Unretained(this), std::move(start_callback)));
}

void EnrollmentSession::CompleteStartEnrollment(
    StartCallback callback,
    grpc::Status status,
    std::unique_ptr<StartEnrollmentResponse> response) {
  // Ensure the StartEnrollment RPC succeeded.
  if (!status.ok()) {
    FinishSession(absl::UnavailableError(status.error_message()));
    return;
  }

  absl::Status rpc_status = ToAbslStatus(response->status());
  if (!rpc_status.ok()) {
    FinishSession(rpc_status);
    return;
  }

  PostToCurrentSequence(std::move(callback));

  // Begin processing frames.
  stream_reader_->Read(base::BindOnce(
      &EnrollmentSession::ProcessAvailableFrame, base::Unretained(this),
      base::BindOnce(&EnrollmentSession::CompleteProcessFrame,
                     base::Unretained(this))));
}

void EnrollmentSession::ProcessAvailableFrame(ProcessFrameCallback callback,
                                              StreamValue<InputFrame> frame) {
  if (abort_requested_) {
    AbortEnrollment(base::BindOnce(&EnrollmentSession::CompleteCancelEnrollment,
                                   base::Unretained(this)));
    return;
  }

  CHECK(frame.value != std::nullopt) << "Camera stream unexpectedly closed";

  if (!frame.value->ok()) {
    AbortEnrollment(base::BindOnce(&EnrollmentSession::CompleteAbortEnrollment,
                                   base::Unretained(this),
                                   frame.value->status()));
    return;
  }

  // Convert input frame to CameraFrame for request.
  ProcessFrameForEnrollmentRequest request;
  std::unique_ptr<Frame> frame_ptr = std::move(*frame.value.value());
  *request.mutable_frame() = FrameToCameraFrame(std::move(frame_ptr));

  (*rpc_client_)
      ->CallRpc(
          &faceauth::eora::FaceService::Stub::AsyncProcessFrameForEnrollment,
          request, std::move(callback));
}

void EnrollmentSession::CompleteProcessFrame(
    grpc::Status status,
    std::unique_ptr<ProcessFrameForEnrollmentResponse> response) {
  if (!status.ok()) {
    NotifyError(absl::UnavailableError(status.error_message()));
    return;
  }

  absl::Status rpc_status = ToAbslStatus(response->status());
  if (!rpc_status.ok()) {
    AbortEnrollment(base::BindOnce(&EnrollmentSession::CompleteAbortEnrollment,
                                   base::Unretained(this), rpc_status));
    return;
  }

  if (abort_requested_) {
    AbortEnrollment(base::BindOnce(&EnrollmentSession::CompleteCancelEnrollment,
                                   base::Unretained(this)));
    return;
  }

  if (response->enrollment_completed()) {
    CompleteEnrollment(
        base::BindOnce(&EnrollmentSession::CompleteCompleteEnrollment,
                       base::Unretained(this)));
    return;
  }

  // Proceed to process the next frame.
  stream_reader_->Read(base::BindOnce(
      &EnrollmentSession::ProcessAvailableFrame, base::Unretained(this),
      base::BindOnce(&EnrollmentSession::CompleteProcessFrame,
                     base::Unretained(this))));
}

void EnrollmentSession::CompleteEnrollment(CompleteCallback callback) {
  (*rpc_client_)
      ->CallRpc(&faceauth::eora::FaceService::Stub::AsyncCompleteEnrollment,
                CompleteEnrollmentRequest(), std::move(callback));
}

void EnrollmentSession::CompleteCompleteEnrollment(
    grpc::Status status, std::unique_ptr<CompleteEnrollmentResponse> response) {
  if (!status.ok()) {
    NotifyError(absl::UnavailableError(status.error_message()));
    return;
  }

  absl::Status rpc_status = ToAbslStatus(response->status());
  if (!rpc_status.ok()) {
    NotifyError(rpc_status);
    return;
  }

  NotifyComplete();
}

void EnrollmentSession::TryCancel() {
  abort_requested_ = true;
  stream_reader_->Close();
}

void EnrollmentSession::AbortEnrollment(AbortCallback callback) {
  (*rpc_client_)
      ->CallRpc(&faceauth::eora::FaceService::Stub::AsyncAbortEnrollment,
                AbortEnrollmentRequest(), std::move(callback));
}

void EnrollmentSession::CompleteAbortEnrollment(
    absl::Status error,
    grpc::Status status,
    std::unique_ptr<AbortEnrollmentResponse> response) {
  // gRPC and abort operation errors are not propagated back to the client.
  // Instead the client will be notified of the original error.
  if (!status.ok()) {
    LOG(WARNING) << status.error_message();
  }

  absl::Status rpc_status = ToAbslStatus(response->status());
  if (!rpc_status.ok()) {
    LOG(WARNING) << rpc_status.message();
  }

  NotifyError(error);
}

void EnrollmentSession::CompleteCancelEnrollment(
    grpc::Status status, std::unique_ptr<AbortEnrollmentResponse> response) {
  // gRPC and abort operation errors are not propagated back to the client.
  // Instead the client will be notified of cancellation.
  if (!status.ok()) {
    LOG(WARNING) << status.error_message();
  }

  absl::Status rpc_status = ToAbslStatus(response->status());
  if (!rpc_status.ok()) {
    LOG(WARNING) << rpc_status.message();
  }

  NotifyCancelled();
}

void EnrollmentSession::FinishSession(absl::Status status) {
  // Close the connections to the enrollment session interfaces.
  delegate_.reset();
  receiver_.reset();

  PostToCurrentSequence(
      base::BindOnce(std::move(completion_callback_), status));
}

}  // namespace faced
