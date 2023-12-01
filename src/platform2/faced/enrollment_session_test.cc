// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "faced/enrollment_session.h"

#include <cstdint>
#include <memory>
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

#include "faced/mock_face_enrollment_session_delegate.h"
#include "faced/mojom/faceauth.mojom.h"
#include "faced/testing/face_service.h"
#include "faced/testing/status.h"
#include "faced/util/queueing_stream.h"

namespace faced {

namespace {

constexpr char kUserName[] = "someone@example.com";

using ::testing::_;
using ::testing::Invoke;
using ::testing::StrictMock;

using ::chromeos::faceauth::mojom::EnrollmentCompleteMessagePtr;
using ::chromeos::faceauth::mojom::EnrollmentSessionConfig;
using ::chromeos::faceauth::mojom::FaceEnrollmentSession;
using ::chromeos::faceauth::mojom::FaceEnrollmentSessionDelegate;
using ::chromeos::faceauth::mojom::FaceOperationStatus;
using ::chromeos::faceauth::mojom::SessionError;

using ::brillo::cryptohome::home::SanitizeUserName;

std::string SampleUserHash() {
  return *SanitizeUserName(::brillo::cryptohome::home::Username(kUserName));
}

absl::BitGen bitgen;

}  // namespace

TEST(TestEnrollmentSession, TestSessionComplete) {
  // Create a mock session delegate, that expects a completion event to be
  // triggered.
  StrictMock<MockFaceEnrollmentSessionDelegate> mock_delegate;
  EXPECT_CALL(mock_delegate, OnEnrollmentComplete(_)).Times(1);

  FACE_ASSERT_OK_AND_ASSIGN(std::unique_ptr<FakeFaceServiceManager> service_mgr,
                            FakeFaceServiceManager::Create());
  EXPECT_CALL(*(service_mgr->mock_service()), StartEnrollment)
      .WillOnce(GrpcReplyOk(StartEnrollmentSuccessResponse()));
  EXPECT_CALL(*(service_mgr->mock_service()), ProcessFrameForEnrollment)
      .WillOnce(GrpcReplyOk(EnrollmentCompleteResponse()));
  EXPECT_CALL(*(service_mgr->mock_service()), CompleteEnrollment)
      .WillOnce(GrpcReplyOk(CompleteEnrollmentSuccessResponse(TestUserData())));

  FACE_ASSERT_OK_AND_ASSIGN(
      Lease<brillo::AsyncGrpcClient<faceauth::eora::FaceService>> client,
      service_mgr->LeaseClient());

  // Create an enrollment session.
  mojo::Receiver<FaceEnrollmentSessionDelegate> delegate(&mock_delegate);
  mojo::Remote<FaceEnrollmentSession> session_remote;
  QueueingStream<EnrollmentSession::InputFrame> stream(/*max_queue_size=*/3);
  FACE_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<EnrollmentSession> session,
      EnrollmentSession::Create(
          bitgen, session_remote.BindNewPipeAndPassReceiver(),
          delegate.BindNewPipeAndPassRemote(),
          EnrollmentSessionConfig::New(SampleUserHash(),
                                       /*accessibility=*/false),
          std::move(client), stream.GetReader()));

  // Set up a loop to run until the client disconnects.
  base::RunLoop run_loop;

  // Add a frame to the input stream.
  stream.Write(std::make_unique<Frame>());

  // Start the session and run the loop until the service is disconnected.
  session->Start(base::BindLambdaForTesting([]() {}),
                 base::BindLambdaForTesting([&](absl::Status status) {
                   EXPECT_TRUE(status.ok());
                   run_loop.Quit();
                 }));
  run_loop.Run();

  // On destruction, `mock_delegate` will ensure OnEnrollmentComplete
  // was called.
}

TEST(TestEnrollmentSession, TestStartSessionError) {
  // Create a mock session delegate, that expects no events to be triggered.
  StrictMock<MockFaceEnrollmentSessionDelegate> mock_delegate;

  FACE_ASSERT_OK_AND_ASSIGN(std::unique_ptr<FakeFaceServiceManager> service_mgr,
                            FakeFaceServiceManager::Create());
  EXPECT_CALL(*(service_mgr->mock_service()), StartEnrollment)
      .WillOnce(GrpcReplyOk(StartEnrollmentFailureResponse()));

  FACE_ASSERT_OK_AND_ASSIGN(
      Lease<brillo::AsyncGrpcClient<faceauth::eora::FaceService>> client,
      service_mgr->LeaseClient());

  // Create an enrollment session.
  mojo::Receiver<FaceEnrollmentSessionDelegate> delegate(&mock_delegate);
  mojo::Remote<FaceEnrollmentSession> session_remote;
  QueueingStream<EnrollmentSession::InputFrame> stream(/*max_queue_size=*/3);
  FACE_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<EnrollmentSession> session,
      EnrollmentSession::Create(bitgen,
                                session_remote.BindNewPipeAndPassReceiver(),
                                delegate.BindNewPipeAndPassRemote(),
                                EnrollmentSessionConfig::New(
                                    SampleUserHash(), /*accessibility=*/false),
                                std::move(client), stream.GetReader()));

  // Set up a loop to run until the client disconnects.
  base::RunLoop run_loop;

  // Start the session and run the loop until the service is disconnected.
  session->Start(
      base::BindLambdaForTesting([]() {
        EXPECT_FALSE(true);  // The start callback should not be invoked.
      }),
      base::BindLambdaForTesting([&](absl::Status status) {
        EXPECT_FALSE(status.ok());
        run_loop.Quit();
      }));
  run_loop.Run();

  // On destruction, `mock_delegate` will ensure OnEnrollmentError
  // was called.
}

TEST(TestEnrollmentSession, TestSessionStreamError) {
  // Create a mock session delegate, that expects an error event to be
  // triggered.
  StrictMock<MockFaceEnrollmentSessionDelegate> mock_delegate;
  EXPECT_CALL(mock_delegate, OnEnrollmentError(_))
      .WillOnce(Invoke([&](SessionError error) {
        EXPECT_EQ(error, SessionError::UNKNOWN);
      }));

  FACE_ASSERT_OK_AND_ASSIGN(std::unique_ptr<FakeFaceServiceManager> service_mgr,
                            FakeFaceServiceManager::Create());
  EXPECT_CALL(*(service_mgr->mock_service()), StartEnrollment)
      .WillOnce(GrpcReplyOk(StartEnrollmentSuccessResponse()));
  EXPECT_CALL(*(service_mgr->mock_service()), AbortEnrollment)
      .WillOnce(GrpcReplyOk(AbortEnrollmentSuccessResponse()));

  FACE_ASSERT_OK_AND_ASSIGN(
      Lease<brillo::AsyncGrpcClient<faceauth::eora::FaceService>> client,
      service_mgr->LeaseClient());

  // Create an enrollment session.
  mojo::Receiver<FaceEnrollmentSessionDelegate> delegate(&mock_delegate);
  mojo::Remote<FaceEnrollmentSession> session_remote;
  QueueingStream<EnrollmentSession::InputFrame> stream(/*max_queue_size=*/3);
  FACE_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<EnrollmentSession> session,
      EnrollmentSession::Create(bitgen,
                                session_remote.BindNewPipeAndPassReceiver(),
                                delegate.BindNewPipeAndPassRemote(),
                                EnrollmentSessionConfig::New(
                                    SampleUserHash(), /*accessibility=*/false),
                                std::move(client), stream.GetReader()));

  // Set up a loop to run until the client disconnects.
  base::RunLoop run_loop;

  // Add an error to the input stream.
  stream.Write(absl::InternalError("test frame capture failure"));

  // Start the session, and run the loop until the service is disconnected.
  session->Start(base::BindLambdaForTesting([]() {}),
                 base::BindLambdaForTesting([&](absl::Status status) {
                   EXPECT_FALSE(status.ok());
                   run_loop.Quit();
                 }));
  run_loop.Run();

  // On destruction, `mock_delegate` will ensure OnEnrollmentError
  // was called.
}

TEST(TestEnrollmentSession, TestSessionProcessingError) {
  // Create a mock session delegate, that expects an error event to be
  // triggered.
  StrictMock<MockFaceEnrollmentSessionDelegate> mock_delegate;
  EXPECT_CALL(mock_delegate, OnEnrollmentError(_))
      .WillOnce(Invoke([&](SessionError error) {
        EXPECT_EQ(error, SessionError::UNKNOWN);
      }));

  FACE_ASSERT_OK_AND_ASSIGN(std::unique_ptr<FakeFaceServiceManager> service_mgr,
                            FakeFaceServiceManager::Create());
  EXPECT_CALL(*(service_mgr->mock_service()), StartEnrollment)
      .WillOnce(GrpcReplyOk(StartEnrollmentSuccessResponse()));
  EXPECT_CALL(*(service_mgr->mock_service()), ProcessFrameForEnrollment)
      .WillOnce(GrpcReplyOk(EnrollmentProcessingErrorResponse()));
  EXPECT_CALL(*(service_mgr->mock_service()), AbortEnrollment)
      .WillOnce(GrpcReplyOk(AbortEnrollmentSuccessResponse()));

  FACE_ASSERT_OK_AND_ASSIGN(
      Lease<brillo::AsyncGrpcClient<faceauth::eora::FaceService>> client,
      service_mgr->LeaseClient());

  // Create an enrollment session.
  mojo::Receiver<FaceEnrollmentSessionDelegate> delegate(&mock_delegate);
  mojo::Remote<FaceEnrollmentSession> session_remote;
  QueueingStream<EnrollmentSession::InputFrame> stream(/*max_queue_size=*/3);
  FACE_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<EnrollmentSession> session,
      EnrollmentSession::Create(bitgen,
                                session_remote.BindNewPipeAndPassReceiver(),
                                delegate.BindNewPipeAndPassRemote(),
                                EnrollmentSessionConfig::New(
                                    SampleUserHash(), /*accessibility=*/false),
                                std::move(client), stream.GetReader()));

  // Set up a loop to run until the client disconnects.
  base::RunLoop run_loop;

  // Add an empty frame to the input stream.
  stream.Write(std::make_unique<Frame>());

  // Start the session, and run the loop until the service is disconnected.
  session->Start(base::BindLambdaForTesting([]() {}),
                 base::BindLambdaForTesting([&](absl::Status status) {
                   EXPECT_FALSE(status.ok());
                   run_loop.Quit();
                 }));
  run_loop.Run();

  // On destruction, `mock_delegate` will ensure OnEnrollmentError
  // was called.
}

TEST(TestEnrollmentSession, TestSessionCancelled) {
  // Create a mock session delegate, that expects an cancelled event to be
  // triggered.
  StrictMock<MockFaceEnrollmentSessionDelegate> mock_delegate;
  EXPECT_CALL(mock_delegate, OnEnrollmentCancelled()).Times(1);

  FACE_ASSERT_OK_AND_ASSIGN(std::unique_ptr<FakeFaceServiceManager> service_mgr,
                            FakeFaceServiceManager::Create());
  EXPECT_CALL(*(service_mgr->mock_service()), StartEnrollment)
      .WillOnce(GrpcReplyOk(StartEnrollmentSuccessResponse()));
  EXPECT_CALL(*(service_mgr->mock_service()), AbortEnrollment)
      .WillOnce(GrpcReplyOk(AbortEnrollmentSuccessResponse()));

  FACE_ASSERT_OK_AND_ASSIGN(
      Lease<brillo::AsyncGrpcClient<faceauth::eora::FaceService>> client,
      service_mgr->LeaseClient());

  // Create an enrollment session.
  mojo::Receiver<FaceEnrollmentSessionDelegate> delegate(&mock_delegate);
  mojo::Remote<FaceEnrollmentSession> session_remote;
  QueueingStream<EnrollmentSession::InputFrame> stream(/*max_queue_size=*/3);
  FACE_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<EnrollmentSession> session,
      EnrollmentSession::Create(bitgen,
                                session_remote.BindNewPipeAndPassReceiver(),
                                delegate.BindNewPipeAndPassRemote(),
                                EnrollmentSessionConfig::New(
                                    SampleUserHash(), /*accessibility=*/false),
                                std::move(client), stream.GetReader()));

  // Set up a loop to run until the client disconnects.
  base::RunLoop run_loop;

  // Start the session and run the loop until the service
  // is disconnected.
  session->Start(base::BindLambdaForTesting([&]() {
                   // Disconnect session remote to cancel.
                   session_remote.reset();
                 }),
                 base::BindLambdaForTesting([&](absl::Status status) {
                   EXPECT_FALSE(status.ok());
                   run_loop.Quit();
                 }));
  run_loop.Run();

  // On destruction, `mock_delegate` will ensure OnEnrollmentError
  // was called.
}

}  // namespace faced
