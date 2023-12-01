// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "faced/authentication_session.h"

#include <cstdint>
#include <string>
#include <utility>

#include <absl/random/random.h>
#include <absl/status/status.h>
#include <base/functional/bind.h>
#include <base/run_loop.h>
#include <base/test/bind.h>
#include <base/test/task_environment.h>
#include <brillo/cryptohome.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <mojo/public/cpp/bindings/receiver.h>
#include <mojo/public/cpp/bindings/remote.h>

#include "faced/mock_face_authentication_session_delegate.h"
#include "faced/mojom/faceauth.mojom.h"
#include "faced/testing/face_service.h"
#include "faced/testing/status.h"

namespace faced {

namespace {

constexpr char kUserName[] = "someone@example.com";

using ::testing::_;
using ::testing::Invoke;
using ::testing::StrictMock;

using ::chromeos::faceauth::mojom::AuthenticationCompleteMessagePtr;
using ::chromeos::faceauth::mojom::AuthenticationSessionConfig;
using ::chromeos::faceauth::mojom::FaceAuthenticationSession;
using ::chromeos::faceauth::mojom::FaceAuthenticationSessionDelegate;
using ::chromeos::faceauth::mojom::FaceOperationStatus;
using ::chromeos::faceauth::mojom::SessionError;

using ::brillo::cryptohome::home::SanitizeUserName;

std::string SampleUserHash() {
  return *SanitizeUserName(::brillo::cryptohome::home::Username(kUserName));
}

absl::BitGen bitgen;

}  // namespace

TEST(TestAuthenticationSession, TestStartSessionError) {
  // Create a mock session delegate, that expects no events to be triggered.
  StrictMock<MockFaceAuthenticationSessionDelegate> mock_delegate;

  FACE_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<FaceServiceManagerInterface> service_mgr,
      FakeFaceServiceManager::Create());

  FACE_ASSERT_OK_AND_ASSIGN(
      Lease<brillo::AsyncGrpcClient<faceauth::eora::FaceService>> client,
      service_mgr->LeaseClient());

  // Create an authentication session.
  mojo::Remote<FaceAuthenticationSession> session_remote;
  mojo::Receiver<FaceAuthenticationSessionDelegate> delegate(&mock_delegate);
  FACE_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<AuthenticationSession> session,
      AuthenticationSession::Create(
          bitgen, session_remote.BindNewPipeAndPassReceiver(),
          delegate.BindNewPipeAndPassRemote(),
          AuthenticationSessionConfig::New(SampleUserHash()),
          std::move(client)));

  // Set up a loop to run until the client disconnects.
  base::RunLoop run_loop;

  // Start the session and run the loop until the service is disconnected.
  session->Start(
      base::BindLambdaForTesting([&]() {
        EXPECT_FALSE(true);  // The start callback should not be invoked.
      }),
      base::BindLambdaForTesting([&](absl::Status status) {
        EXPECT_FALSE(status.ok());
        run_loop.Quit();
      }));

  run_loop.Run();

  // On destruction, `mock_delegate` will ensure OnAuthenticationError
  // was called.
}

}  // namespace faced
