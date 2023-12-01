// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef FACED_FACE_AUTH_SERVICE_IMPL_H_
#define FACED_FACE_AUTH_SERVICE_IMPL_H_

#include <memory>
#include <string>

#include <absl/random/random.h>
#include <absl/status/status.h>
#include <base/files/file_path.h>
#include <mojo/public/cpp/bindings/pending_receiver.h>
#include <mojo/public/cpp/bindings/receiver.h>
#include <mojo/public/cpp/bindings/receiver_set.h>

#include "faced/camera/frame.h"
#include "faced/enrollment_storage.h"
#include "faced/face_service.h"
#include "faced/mojom/faceauth.mojom.h"
#include "faced/session.h"
#include "faced/util/queueing_stream.h"

namespace faced {

// Face Authentication Service implementation.
//
// Creates and manages enrollment and authentication sessions.
class FaceAuthServiceImpl
    : public chromeos::faceauth::mojom::FaceAuthenticationService {
 public:
  using DisconnectionCallback = base::OnceCallback<void()>;

  // FaceAuthServiceImpl constructor.
  //
  // `receiver` is the pending receiver of `FaceAuthenticationService`.
  // `disconnect_handler` is the callback invoked when the receiver is
  // disconnected.
  // `manager` is an implementation of `FaceServiceManagerInterface` which
  // leases a client to the Face Service gRPC process.
  FaceAuthServiceImpl(
      mojo::PendingReceiver<FaceAuthenticationService> receiver,
      DisconnectionCallback disconnect_handler,
      FaceServiceManagerInterface& manager,
      std::optional<base::FilePath> daemon_store_path = std::nullopt);

  bool has_active_session() { return session_.get() != nullptr; }

  // `FaceAuthenticationService` implementation.
  void CreateEnrollmentSession(
      chromeos::faceauth::mojom::EnrollmentSessionConfigPtr config,
      mojo::PendingReceiver<chromeos::faceauth::mojom::FaceEnrollmentSession>
          receiver,
      mojo::PendingRemote<
          chromeos::faceauth::mojom::FaceEnrollmentSessionDelegate> delegate,
      CreateEnrollmentSessionCallback callback) override;

  void CreateAuthenticationSession(
      chromeos::faceauth::mojom::AuthenticationSessionConfigPtr config,
      mojo::PendingReceiver<
          chromeos::faceauth::mojom::FaceAuthenticationSession> receiver,
      mojo::PendingRemote<
          chromeos::faceauth::mojom::FaceAuthenticationSessionDelegate>
          delegate,
      CreateAuthenticationSessionCallback callback) override;

  void Clone(mojo::PendingReceiver<
             chromeos::faceauth::mojom::FaceAuthenticationService> receiver);

  void ListEnrollments(ListEnrollmentsCallback callback) override;

  void RemoveEnrollment(const std::string& hashed_username,
                        RemoveEnrollmentCallback callback) override;

  void ClearEnrollments(ClearEnrollmentsCallback callback) override;

  void IsUserEnrolled(const std::string& hashed_username,
                      IsUserEnrolledCallback callback) override;

 private:
  // Handle the disconnection of the receiver.
  void HandleDisconnect(base::OnceClosure callback);

  // Called when the session has started.
  void CompleteSessionStart();
  CreateEnrollmentSessionCallback create_session_callback_;

  // Called with the result of completed session.
  void CompleteSessionDone(absl::Status status);

  // Primordial receiver bootstrapped over D-Bus. Once opened, is never closed.
  mojo::Receiver<chromeos::faceauth::mojom::FaceAuthenticationService>
      receiver_;

  // Additional receivers.
  mojo::ReceiverSet<chromeos::faceauth::mojom::FaceAuthenticationService>
      receiver_set_;

  absl::BitGen bitgen_;

  std::unique_ptr<SessionInterface> session_;

  std::unique_ptr<QueueingStream<absl::StatusOr<std::unique_ptr<Frame>>>>
      stream_;

  EnrollmentStorage enrollment_storage_;
  FaceServiceManagerInterface& face_service_manager_;
};

}  // namespace faced

#endif  // FACED_FACE_AUTH_SERVICE_IMPL_H_
