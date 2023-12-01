// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef FACED_FACED_CLI_MOCK_FACE_AUTHENTICATION_SERVICE_H_
#define FACED_FACED_CLI_MOCK_FACE_AUTHENTICATION_SERVICE_H_

#include <string>
#include <utility>

#include <gmock/gmock.h>

#include "faced/mojom/faceauth.mojom.h"

namespace faced {

class MockFaceAuthService
    : public chromeos::faceauth::mojom::FaceAuthenticationService {
 public:
  explicit MockFaceAuthService(
      mojo::PendingReceiver<
          chromeos::faceauth::mojom::FaceAuthenticationService> receiver)
      : receiver_(this, std::move(receiver)) {}

  MOCK_METHOD(
      void,
      CreateEnrollmentSession,
      (chromeos::faceauth::mojom::EnrollmentSessionConfigPtr,
       mojo::PendingReceiver<chromeos::faceauth::mojom::FaceEnrollmentSession>,
       mojo::PendingRemote<
           chromeos::faceauth::mojom::FaceEnrollmentSessionDelegate>,
       CreateEnrollmentSessionCallback),
      (override));

  MOCK_METHOD(
      void,
      CreateAuthenticationSession,
      (chromeos::faceauth::mojom::AuthenticationSessionConfigPtr,
       mojo::PendingReceiver<
           chromeos::faceauth::mojom::FaceAuthenticationSession>,
       mojo::PendingRemote<
           chromeos::faceauth::mojom::FaceAuthenticationSessionDelegate>,
       CreateEnrollmentSessionCallback),
      (override));

  MOCK_METHOD(void, ListEnrollments, (ListEnrollmentsCallback), (override));
  MOCK_METHOD(void,
              RemoveEnrollment,
              (const std::string&, RemoveEnrollmentCallback),
              (override));
  MOCK_METHOD(void, ClearEnrollments, (ClearEnrollmentsCallback), (override));
  MOCK_METHOD(void,
              IsUserEnrolled,
              (const std::string&, IsUserEnrolledCallback),
              (override));

 private:
  mojo::Receiver<chromeos::faceauth::mojom::FaceAuthenticationService>
      receiver_;
};

}  // namespace faced

#endif  // FACED_FACED_CLI_MOCK_FACE_AUTHENTICATION_SERVICE_H_
