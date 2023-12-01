// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef FACED_FACED_CLI_FACED_CLIENT_H_
#define FACED_FACED_CLI_FACED_CLIENT_H_

#include <absl/status/status.h>
#include <absl/status/statusor.h>
#include <base/strings/string_piece.h>
#include <brillo/dbus/dbus_connection.h>
#include <mojo/public/cpp/bindings/receiver.h>
#include <mojo/public/cpp/bindings/remote.h>
#include <mojo/public/cpp/system/message_pipe.h>

#include "faced/faced_cli/face_enrollment_session_delegate_impl.h"
#include "faced/mojom/faceauth.mojom.h"

namespace faced {

// Components of a connection to the Faced daemon
struct FacedConnection {
  // DBus connection to Faced
  scoped_refptr<dbus::Bus> bus;

  // Pipe for Mojo communication
  mojo::ScopedMessagePipeHandle pipe;

  // Remote for interacting with Faced Mojo APIs
  mojo::Remote<chromeos::faceauth::mojom::FaceAuthenticationService> service;
};

// Establish Mojo connection to Faced bootstrapped over DBus
absl::StatusOr<FacedConnection> ConnectToFaced();

// Establish a Mojo connection to Faced bootstrapped over DBus then disconnect
absl::Status ConnectAndDisconnectFromFaced();

// Run an enrollment via Faced for a given user
absl::Status Enroll(base::StringPiece user);

// Checks whether a user is enrolled.
absl::Status IsEnrolled(base::StringPiece user);

// Removes a user's enrollment.
absl::Status RemoveEnrollment(base::StringPiece user);

// Lists saved enrollments.
absl::Status ListEnrollments();

// Clears all saved enrollments.
absl::Status ClearEnrollments();

// Internal implementation details (exposed for testing) below.

// Enroller manages the lifetimes of mojo Remotes and Receivers that are
// required to enroll a user.
class Enroller {
 public:
  using EnrollmentCompleteCallback = base::OnceCallback<void(absl::Status)>;

  explicit Enroller(
      mojo::Remote<chromeos::faceauth::mojom::FaceAuthenticationService>&
          service,
      EnrollmentCompleteCallback enrollment_complete);

  ~Enroller() = default;

  // Disallow copy and move.
  Enroller(const Enroller&) = delete;
  Enroller& operator=(const Enroller&) = delete;

  // Performs an enrollment for the specified user and disconnects upon
  // completion or on error.
  void Run(base::StringPiece user);

 private:
  mojo::Remote<chromeos::faceauth::mojom::FaceAuthenticationService>&
      service_;  // Not owned

  // Enroller manages the lifetime of the the below.
  mojo::Remote<chromeos::faceauth::mojom::FaceEnrollmentSession>
      session_remote_;
  scoped_refptr<FaceEnrollmentSessionDelegateImpl> delegate_;
  mojo::Receiver<chromeos::faceauth::mojom::FaceEnrollmentSessionDelegate>
      receiver_;
};

}  // namespace faced

#endif  // FACED_FACED_CLI_FACED_CLIENT_H_
