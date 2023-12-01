// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "faced/faced_cli/face_enrollment_session_delegate_impl.h"

#include <base/strings/strcat.h>

#include "faced/mojom/faceauth.mojom.h"
#include "faced/status_to_string.h"
#include "faced/util/task.h"

namespace faced {

using ::chromeos::faceauth::mojom::CreateSessionResultPtr;
using ::chromeos::faceauth::mojom::EnrollmentCompleteMessagePtr;
using ::chromeos::faceauth::mojom::EnrollmentUpdateMessagePtr;
using ::chromeos::faceauth::mojom::SessionError;

void FaceEnrollmentSessionDelegateImpl::CreateEnrollmentSessionComplete(
    CreateSessionResultPtr result) {
  // Check if session creation failed.
  if (!result->is_session_info()) {
    PostToCurrentSequence(base::BindOnce(
        std::move(enrollment_complete_),
        absl::InternalError(
            base::StrCat({"Failed to create an enrollment session: ",
                          SessionCreationErrorString(result->get_error())}))));
    return;
  }

  std::cout << "Successfully created enrollment.\n";
}

void FaceEnrollmentSessionDelegateImpl::
    OnFaceAuthenticationServiceDisconnect() {
  if (enrollment_complete_) {
    PostToCurrentSequence(base::BindOnce(
        std::move(enrollment_complete_),
        absl::UnknownError(
            "FaceAuthenticationService unexpectedly disconnected.")));
  }
}

void FaceEnrollmentSessionDelegateImpl::OnEnrollmentUpdate(
    EnrollmentUpdateMessagePtr message) {
  std::cout << "Enrollment update: "
            << FaceOperationStatusString(message->status) << "\n";
}

void FaceEnrollmentSessionDelegateImpl::OnEnrollmentComplete(
    EnrollmentCompleteMessagePtr message) {
  std::cout << "Enrollment completed";

  PostToCurrentSequence(
      base::BindOnce(std::move(enrollment_complete_), absl::OkStatus()));
}

void FaceEnrollmentSessionDelegateImpl::OnEnrollmentCancelled() {
  PostToCurrentSequence(
      base::BindOnce(std::move(enrollment_complete_),
                     absl::CancelledError("Enrollment Cancelled.")));
}

void FaceEnrollmentSessionDelegateImpl::OnEnrollmentError(SessionError error) {
  PostToCurrentSequence(base::BindOnce(
      std::move(enrollment_complete_),
      absl::InternalError(
          base::StrCat({"Enrollment Error: ", SessionErrorString(error)}))));
}

}  // namespace faced
