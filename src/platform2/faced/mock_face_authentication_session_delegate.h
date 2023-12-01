// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef FACED_MOCK_FACE_AUTHENTICATION_SESSION_DELEGATE_H_
#define FACED_MOCK_FACE_AUTHENTICATION_SESSION_DELEGATE_H_

#include <gmock/gmock.h>

#include "faced/mojom/faceauth.mojom.h"

namespace faced {

class MockFaceAuthenticationSessionDelegate
    : public chromeos::faceauth::mojom::FaceAuthenticationSessionDelegate {
 public:
  MOCK_METHOD(
      void,
      OnAuthenticationUpdate,
      (chromeos::faceauth::mojom::AuthenticationUpdateMessagePtr message),
      (override));

  MOCK_METHOD(
      void,
      OnAuthenticationComplete,
      (chromeos::faceauth::mojom::AuthenticationCompleteMessagePtr message),
      (override));

  MOCK_METHOD(void, OnAuthenticationCancelled, (), (override));
  MOCK_METHOD(void,
              OnAuthenticationError,
              (chromeos::faceauth::mojom::SessionError error),
              (override));
};

}  // namespace faced

#endif  // FACED_MOCK_FACE_AUTHENTICATION_SESSION_DELEGATE_H_
