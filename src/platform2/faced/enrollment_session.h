// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef FACED_ENROLLMENT_SESSION_H_
#define FACED_ENROLLMENT_SESSION_H_

#include <cstdint>
#include <memory>

#include <absl/random/random.h>
#include <absl/status/status.h>
#include <absl/status/statusor.h>
#include <base/functional/callback_forward.h>
#include <brillo/grpc/async_grpc_client.h>
#include <mojo/public/cpp/bindings/receiver.h>
#include <mojo/public/cpp/bindings/remote.h>

#include "faced/camera/frame.h"
#include "faced/mojom/faceauth.mojom.h"
#include "faced/proto/face_service.grpc.pb.h"
#include "faced/session.h"
#include "faced/util/lease.h"
#include "faced/util/stream.h"

namespace faced {

// Enrollment session encapsulates the dependencies needed and operations
// performed during enrollment.
class EnrollmentSession
    : public SessionInterface,
      public chromeos::faceauth::mojom::FaceEnrollmentSession {
 public:
  using InputFrame = absl::StatusOr<std::unique_ptr<Frame>>;

  static absl::StatusOr<std::unique_ptr<EnrollmentSession>> Create(
      absl::BitGen& bitgen,
      mojo::PendingReceiver<chromeos::faceauth::mojom::FaceEnrollmentSession>
          receiver,
      mojo::PendingRemote<
          chromeos::faceauth::mojom::FaceEnrollmentSessionDelegate> delegate,
      chromeos::faceauth::mojom::EnrollmentSessionConfigPtr config,
      Lease<brillo::AsyncGrpcClient<faceauth::eora::FaceService>> client,
      std::unique_ptr<StreamReader<InputFrame>> stream_reader);

  ~EnrollmentSession() override = default;

  // Disallow copy and move.
  EnrollmentSession(const EnrollmentSession&) = delete;
  EnrollmentSession& operator=(const EnrollmentSession&) = delete;

  // `SessionInterface` implementation.
  uint64_t session_id() override { return session_id_; }
  void Start(StartCallback start_callback,
             CompletionCallback completion_callback) override;

  // Notify FaceEnrollmentSessionDelegate of enrollment state changes.
  //
  // Notify of enrollment progress.
  void NotifyUpdate(chromeos::faceauth::mojom::FaceOperationStatus status);
  // Notify of completed enrollment and close the connection.
  void NotifyComplete();
  // Notify of cancelled enrollment and close the connection.
  void NotifyCancelled();
  // Notify of unrecoverable error and close the connection.
  void NotifyError(absl::Status error);

 private:
  EnrollmentSession(
      uint64_t session_id,
      mojo::PendingReceiver<chromeos::faceauth::mojom::FaceEnrollmentSession>
          receiver,
      mojo::PendingRemote<
          chromeos::faceauth::mojom::FaceEnrollmentSessionDelegate> delegate,
      Lease<brillo::AsyncGrpcClient<faceauth::eora::FaceService>> client,
      std::unique_ptr<StreamReader<InputFrame>> stream_reader);

  // Attempt to abort cancel the current operation.
  //
  // Any long running operations will be signalled to finish up and abort.
  // There is no guarantee that the operation will actually be cancelled,
  // and this class instance still must not be deleted until the current
  // operation's complete callback is called.
  void TryCancel();

  void StartEnrollment(StartCallback callback);
  // Callback to process the response from StartEnrollment.
  void CompleteStartEnrollment(
      StartCallback callback,
      grpc::Status status,
      std::unique_ptr<faceauth::eora::StartEnrollmentResponse> response);

  using ProcessFrameCallback = base::OnceCallback<void(
      grpc::Status status,
      std::unique_ptr<faceauth::eora::ProcessFrameForEnrollmentResponse>)>;
  // Callback to process frame provided by StreamReader.
  void ProcessAvailableFrame(ProcessFrameCallback callback,
                             StreamValue<InputFrame> frame);
  void CompleteProcessFrame(
      grpc::Status status,
      std::unique_ptr<faceauth::eora::ProcessFrameForEnrollmentResponse>
          response);

  using CompleteCallback = base::OnceCallback<void(
      grpc::Status status,
      std::unique_ptr<faceauth::eora::CompleteEnrollmentResponse> response)>;
  void CompleteEnrollment(CompleteCallback callback);
  void CompleteCompleteEnrollment(
      grpc::Status status,
      std::unique_ptr<faceauth::eora::CompleteEnrollmentResponse> response);

  using AbortCallback = base::OnceCallback<void(
      grpc::Status status,
      std::unique_ptr<faceauth::eora::AbortEnrollmentResponse> response)>;
  void AbortEnrollment(AbortCallback callback);

  void CompleteCancelEnrollment(
      grpc::Status status,
      std::unique_ptr<faceauth::eora::AbortEnrollmentResponse> response);
  void CompleteAbortEnrollment(
      absl::Status error,
      grpc::Status status,
      std::unique_ptr<faceauth::eora::AbortEnrollmentResponse> response);

  void FinishSession(absl::Status status);

  int64_t session_id_;
  mojo::Receiver<chromeos::faceauth::mojom::FaceEnrollmentSession> receiver_;
  mojo::Remote<chromeos::faceauth::mojom::FaceEnrollmentSessionDelegate>
      delegate_;

  CompletionCallback completion_callback_;
  bool abort_requested_ = false;

  // Async gRPC client that uses an internal completion queue.
  Lease<brillo::AsyncGrpcClient<faceauth::eora::FaceService>> rpc_client_;

  std::unique_ptr<StreamReader<InputFrame>> stream_reader_;
};

}  // namespace faced

#endif  // FACED_ENROLLMENT_SESSION_H_
