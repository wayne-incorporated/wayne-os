// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "faced/faced_cli/faced_client.h"

#include <string>
#include <utility>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "faced/faced_cli/mock_face_authentication_service.h"
#include "faced/mojom/faceauth.mojom.h"
#include "faced/testing/status.h"
#include "faced/util/blocking_future.h"
#include "faced/util/task.h"

namespace faced {
namespace {

using ::chromeos::faceauth::mojom::CreateSessionResult;
using ::chromeos::faceauth::mojom::EnrollmentCompleteMessage;
using ::chromeos::faceauth::mojom::EnrollmentSessionConfigPtr;
using ::chromeos::faceauth::mojom::EnrollmentUpdateMessage;
using ::chromeos::faceauth::mojom::FaceAuthenticationService;
using ::chromeos::faceauth::mojom::FaceEnrollmentSession;
using ::chromeos::faceauth::mojom::FaceEnrollmentSessionDelegate;
using ::chromeos::faceauth::mojom::FaceOperationStatus;
using ::chromeos::faceauth::mojom::SessionCreationError;
using ::chromeos::faceauth::mojom::SessionError;
using ::chromeos::faceauth::mojom::SessionInfo;
using ::testing::_;
using ::testing::Invoke;
using ::testing::StrictMock;

constexpr int kSessionId = 0;
constexpr char kUserName[] = "someone@example.com";

TEST(EnrollWithRemoteService, HandleCreateEnrollmentSessionFailure) {
  mojo::Remote<FaceAuthenticationService> service;

  // Return failure for CreateEnrollmentSession.
  StrictMock<MockFaceAuthService> mock_service(
      service.BindNewPipeAndPassReceiver());
  EXPECT_CALL(mock_service, CreateEnrollmentSession(_, _, _, _))
      .WillOnce(
          Invoke([&](EnrollmentSessionConfigPtr,
                     mojo::PendingReceiver<FaceEnrollmentSession>,
                     mojo::PendingRemote<FaceEnrollmentSessionDelegate>,
                     FaceAuthenticationService::CreateEnrollmentSessionCallback
                         callback) {
            PostToCurrentSequence(base::BindOnce(
                std::move(callback),
                CreateSessionResult::NewError(SessionCreationError::UNKNOWN)));
          }));

  BlockingFuture<absl::Status> enrollment_result;
  Enroller enroller(service, enrollment_result.PromiseCallback());
  enroller.Run(kUserName);
  EXPECT_FALSE(enrollment_result.Wait().ok());
}

TEST(EnrollWithRemoteService, HandleCompleteEnrollmentSuccess) {
  mojo::Remote<FaceAuthenticationService> service;
  mojo::Remote<FaceEnrollmentSessionDelegate> session_delegate;

  // Return success for CreateEnrollmentSession and subsequently send an
  // EnrollmentComplete.
  StrictMock<MockFaceAuthService> mock_service(
      service.BindNewPipeAndPassReceiver());
  EXPECT_CALL(mock_service, CreateEnrollmentSession(_, _, _, _))
      .WillOnce(Invoke(
          [&](EnrollmentSessionConfigPtr,
              mojo::PendingReceiver<FaceEnrollmentSession>,
              mojo::PendingRemote<FaceEnrollmentSessionDelegate> delegate,
              FaceAuthenticationService::CreateEnrollmentSessionCallback
                  callback) {
            session_delegate = mojo::Remote<FaceEnrollmentSessionDelegate>(
                std::move(delegate));
            PostToCurrentSequence(base::BindOnce(
                std::move(callback), CreateSessionResult::NewSessionInfo(
                                         SessionInfo::New(kSessionId))));

            session_delegate->OnEnrollmentComplete(
                EnrollmentCompleteMessage::New());
          }));

  BlockingFuture<absl::Status> enrollment_result;
  Enroller enroller(service, enrollment_result.PromiseCallback());
  enroller.Run(kUserName);

  FACE_EXPECT_OK(enrollment_result.Wait());
}

TEST(EnrollWithRemoteService, HandleCompleteEnrollmentSuccessComplex) {
  mojo::Remote<FaceAuthenticationService> service;
  mojo::Remote<FaceEnrollmentSessionDelegate> session_delegate;

  // Return success for CreateEnrollmentSession and a series of
  // EnrollmentUpdates followed by an EnrollmentComplete.
  StrictMock<MockFaceAuthService> mock_service(
      service.BindNewPipeAndPassReceiver());
  EXPECT_CALL(mock_service, CreateEnrollmentSession(_, _, _, _))
      .WillOnce(Invoke(
          [&](EnrollmentSessionConfigPtr,
              mojo::PendingReceiver<FaceEnrollmentSession>,
              mojo::PendingRemote<FaceEnrollmentSessionDelegate> delegate,
              FaceAuthenticationService::CreateEnrollmentSessionCallback
                  callback) {
            session_delegate = mojo::Remote<FaceEnrollmentSessionDelegate>(
                std::move(delegate));
            PostToCurrentSequence(base::BindOnce(
                std::move(callback), CreateSessionResult::NewSessionInfo(
                                         SessionInfo::New(kSessionId))));

            session_delegate->OnEnrollmentUpdate(
                EnrollmentUpdateMessage::New(FaceOperationStatus::OK,
                                             /*poses=*/std::vector<bool>()));
            session_delegate->OnEnrollmentUpdate(
                EnrollmentUpdateMessage::New(FaceOperationStatus::NO_FACE,
                                             /*poses=*/std::vector<bool>()));
            session_delegate->OnEnrollmentComplete(
                EnrollmentCompleteMessage::New());
          }));

  BlockingFuture<absl::Status> enrollment_result;
  Enroller enroller(service, enrollment_result.PromiseCallback());
  enroller.Run(kUserName);

  FACE_EXPECT_OK(enrollment_result.Wait());
}

TEST(EnrollWithRemoteService, HandleEnrollmentCancelled) {
  mojo::Remote<FaceAuthenticationService> service;
  mojo::Remote<FaceEnrollmentSessionDelegate> session_delegate;

  // Return success for CreateEnrollmentSession and a series of
  // EnrollmentUpdates followed by an EnrollmentCancelled.
  StrictMock<MockFaceAuthService> mock_service(
      service.BindNewPipeAndPassReceiver());
  EXPECT_CALL(mock_service, CreateEnrollmentSession(_, _, _, _))
      .WillOnce(Invoke(
          [&](EnrollmentSessionConfigPtr,
              mojo::PendingReceiver<FaceEnrollmentSession>,
              mojo::PendingRemote<FaceEnrollmentSessionDelegate> delegate,
              FaceAuthenticationService::CreateEnrollmentSessionCallback
                  callback) {
            session_delegate = mojo::Remote<FaceEnrollmentSessionDelegate>(
                std::move(delegate));
            PostToCurrentSequence(base::BindOnce(
                std::move(callback), CreateSessionResult::NewSessionInfo(
                                         SessionInfo::New(kSessionId))));

            session_delegate->OnEnrollmentUpdate(
                EnrollmentUpdateMessage::New(FaceOperationStatus::OK,
                                             /*poses=*/std::vector<bool>()));
            session_delegate->OnEnrollmentUpdate(
                EnrollmentUpdateMessage::New(FaceOperationStatus::NO_FACE,
                                             /*poses=*/std::vector<bool>()));
            session_delegate->OnEnrollmentCancelled();
          }));

  BlockingFuture<absl::Status> enrollment_result;
  Enroller enroller(service, enrollment_result.PromiseCallback());
  enroller.Run(kUserName);

  EXPECT_FALSE(enrollment_result.Wait().ok());
}

TEST(EnrollWithRemoteService, HandleEnrollmentError) {
  mojo::Remote<FaceAuthenticationService> service;
  mojo::Remote<FaceEnrollmentSessionDelegate> session_delegate;

  // Return success for CreateEnrollmentSession and a series of
  // EnrollmentUpdates followed by an EnrollmentError.
  StrictMock<MockFaceAuthService> mock_service(
      service.BindNewPipeAndPassReceiver());
  EXPECT_CALL(mock_service, CreateEnrollmentSession(_, _, _, _))
      .WillOnce(Invoke(
          [&](EnrollmentSessionConfigPtr,
              mojo::PendingReceiver<FaceEnrollmentSession>,
              mojo::PendingRemote<FaceEnrollmentSessionDelegate> delegate,
              FaceAuthenticationService::CreateEnrollmentSessionCallback
                  callback) {
            session_delegate = mojo::Remote<FaceEnrollmentSessionDelegate>(
                std::move(delegate));
            PostToCurrentSequence(base::BindOnce(
                std::move(callback), CreateSessionResult::NewSessionInfo(
                                         SessionInfo::New(kSessionId))));

            session_delegate->OnEnrollmentUpdate(
                EnrollmentUpdateMessage::New(FaceOperationStatus::OK,
                                             /*poses=*/std::vector<bool>()));
            session_delegate->OnEnrollmentUpdate(
                EnrollmentUpdateMessage::New(FaceOperationStatus::NO_FACE,
                                             /*poses=*/std::vector<bool>()));
            session_delegate->OnEnrollmentError(SessionError::UNKNOWN);
          }));

  BlockingFuture<absl::Status> enrollment_result;
  Enroller enroller(service, enrollment_result.PromiseCallback());
  enroller.Run(kUserName);

  EXPECT_FALSE(enrollment_result.Wait().ok());
}

}  // namespace
}  // namespace faced
