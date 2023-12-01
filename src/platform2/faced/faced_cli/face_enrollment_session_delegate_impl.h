// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef FACED_FACED_CLI_FACE_ENROLLMENT_SESSION_DELEGATE_IMPL_H_
#define FACED_FACED_CLI_FACE_ENROLLMENT_SESSION_DELEGATE_IMPL_H_

#include <utility>

#include <absl/status/status.h>
#include <base/memory/ref_counted.h>

#include "faced/mojom/faceauth.mojom.h"

namespace faced {

// FaceEnrollmentSessionDelegateImpl is the main interface faced has to
// communicate with the client. FaceEnrollmentSessionDelegateImpl handles
// processing of messages sent by faced.
class FaceEnrollmentSessionDelegateImpl
    : public chromeos::faceauth::mojom::FaceEnrollmentSessionDelegate,
      public base::RefCountedThreadSafe<FaceEnrollmentSessionDelegateImpl> {
 public:
  using EnrollmentCompleteCallback = base::OnceCallback<void(absl::Status)>;

  explicit FaceEnrollmentSessionDelegateImpl(
      EnrollmentCompleteCallback enrollment_complete)
      : enrollment_complete_(std::move(enrollment_complete)) {}

  // Callback for handling the response to
  // FaceAuthenticationService::CreateEnrollmentSession.
  void CreateEnrollmentSessionComplete(
      chromeos::faceauth::mojom::CreateSessionResultPtr result);

  // Callback for handling disconnection of FaceAuthenticationService remote.
  void OnFaceAuthenticationServiceDisconnect();

  // `FaceEnrollmentSessionDelegate` implementations
  void OnEnrollmentUpdate(
      chromeos::faceauth::mojom::EnrollmentUpdateMessagePtr message) override;
  void OnEnrollmentComplete(
      chromeos::faceauth::mojom::EnrollmentCompleteMessagePtr message) override;
  void OnEnrollmentCancelled() override;
  void OnEnrollmentError(
      chromeos::faceauth::mojom::SessionError error) override;

 private:
  EnrollmentCompleteCallback enrollment_complete_;
};

}  // namespace faced

#endif  // FACED_FACED_CLI_FACE_ENROLLMENT_SESSION_DELEGATE_IMPL_H_
