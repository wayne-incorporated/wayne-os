// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "faced/testing/face_service.h"

#include <memory>
#include <vector>

#include <absl/status/status.h>
#include <absl/status/statusor.h>
#include <base/strings/strcat.h>
#include <base/strings/string_piece.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "faced/common/face_status.h"
#include "faced/proto/face_service.pb.h"

namespace faced {

constexpr base::StringPiece kServerSocket = "face_service.socket";

using ::testing::StrictMock;

faceauth::eora::FaceStatusCode FaceStatusOk() {
  faceauth::eora::FaceStatusCode status;
  status.set_status(static_cast<int>(StatusCode::kOk));
  return status;
}

faceauth::eora::FaceStatusCode FaceStatusInvalid() {
  faceauth::eora::FaceStatusCode status;
  status.set_status(static_cast<int>(StatusCode::kGenericError));
  return status;
}

// Authentication

faceauth::eora::StartAuthenticationResponse
StartAuthenticationSuccessResponse() {
  faceauth::eora::StartAuthenticationResponse response;
  *response.mutable_status() = FaceStatusOk();
  return response;
}

faceauth::eora::AbortAuthenticationResponse
AbortAuthenticationSuccessResponse() {
  faceauth::eora::AbortAuthenticationResponse response;
  *response.mutable_status() = FaceStatusOk();
  return response;
}

faceauth::eora::CompleteAuthenticationResponse
CompleteAuthenticationSuccessResponse(
    const faceauth::eora::UserData& user_data) {
  faceauth::eora::CompleteAuthenticationResponse response;
  *response.mutable_status() = FaceStatusOk();
  *response.mutable_user_data() = user_data;
  return response;
}

faceauth::eora::CompleteAuthenticationResponse
CompleteAuthenticationFailureResponse() {
  faceauth::eora::CompleteAuthenticationResponse response;
  *response.mutable_status() = FaceStatusInvalid();
  return response;
}

faceauth::eora::ProcessFrameForAuthenticationResponse
AuthenticationIncompleteResponse() {
  faceauth::eora::ProcessFrameForAuthenticationResponse response;
  *response.mutable_status() = FaceStatusOk();
  response.set_need_more_data(true);
  return response;
}

faceauth::eora::ProcessFrameForAuthenticationResponse
AuthenticationCompleteResponse() {
  faceauth::eora::ProcessFrameForAuthenticationResponse response;
  *response.mutable_status() = FaceStatusOk();
  response.set_need_more_data(false);
  return response;
}

// Enrollment
faceauth::eora::StartEnrollmentResponse StartEnrollmentSuccessResponse() {
  faceauth::eora::StartEnrollmentResponse response;
  *response.mutable_status() = FaceStatusOk();
  return response;
}

faceauth::eora::StartEnrollmentResponse StartEnrollmentFailureResponse() {
  faceauth::eora::StartEnrollmentResponse response;
  *response.mutable_status() = FaceStatusInvalid();
  return response;
}

faceauth::eora::AbortEnrollmentResponse AbortEnrollmentSuccessResponse() {
  faceauth::eora::AbortEnrollmentResponse response;
  *response.mutable_status() = FaceStatusOk();
  return response;
}

faceauth::eora::AbortEnrollmentResponse AbortEnrollmentFailureResponse() {
  faceauth::eora::AbortEnrollmentResponse response;
  *response.mutable_status() = FaceStatusInvalid();
  return response;
}

faceauth::eora::CompleteEnrollmentResponse CompleteEnrollmentSuccessResponse(
    const faceauth::eora::UserData& user_data) {
  faceauth::eora::CompleteEnrollmentResponse response;
  *response.mutable_status() = FaceStatusOk();
  *response.mutable_user_data() = user_data;
  return response;
}

faceauth::eora::ProcessFrameForEnrollmentResponse
EnrollmentProcessingErrorResponse() {
  faceauth::eora::ProcessFrameForEnrollmentResponse response;
  *response.mutable_status() = FaceStatusInvalid();
  return response;
}

faceauth::eora::ProcessFrameForEnrollmentResponse
EnrollmentIncompleteResponse() {
  faceauth::eora::ProcessFrameForEnrollmentResponse response;
  *response.mutable_status() = FaceStatusOk();
  response.set_enrollment_completed(false);
  return response;
}

faceauth::eora::ProcessFrameForEnrollmentResponse EnrollmentCompleteResponse() {
  faceauth::eora::ProcessFrameForEnrollmentResponse response;
  *response.mutable_status() = FaceStatusOk();
  response.set_enrollment_completed(true);
  return response;
}

faceauth::eora::UserData TestUserData() {
  faceauth::eora::UserData user_data;
  *user_data.mutable_payload() = std::string(kTestUserDataPayload);
  return user_data;
}

faceauth::eora::UserData TestUserData2() {
  faceauth::eora::UserData user_data;
  *user_data.mutable_payload() = std::string(kTestUserDataPayload2);
  return user_data;
}

absl::StatusOr<std::unique_ptr<FakeFaceServiceManager>>
FakeFaceServiceManager::Create() {
  // Create a service manager
  std::unique_ptr<FakeFaceServiceManager> manager(new FakeFaceServiceManager());

  // Create a temp directory for storing the socket address
  if (!manager->temp_dir_.CreateUniqueTempDir()) {
    return absl::InternalError("Unable to create temp directory");
  }

  manager->uds_address_ = base::StrCat(
      {"unix:", manager->temp_dir_.GetPath().value(), kServerSocket});

  // Create a server
  std::vector<std::string> server_uris = {manager->uds_address_};
  std::unique_ptr<
      brillo::AsyncGrpcServer<faceauth::eora::FaceService::AsyncService>>
      server = std::make_unique<
          brillo::AsyncGrpcServer<faceauth::eora::FaceService::AsyncService>>(
          base::SequencedTaskRunner::GetCurrentDefault(), server_uris);

  // Create the mock rpc handler to be used by the server
  std::shared_ptr<MockFaceServiceRpcHandler> mock_handler =
      std::make_shared<StrictMock<MockFaceServiceRpcHandler>>();

  // Register the mock as the server request handler
  server->RegisterHandler(
      &faceauth::eora::FaceService::AsyncService::RequestStartAuthentication,
      base::BindRepeating(&MockFaceServiceRpcHandler::StartAuthentication,
                          base::Unretained(mock_handler.get())));
  server->RegisterHandler(
      &faceauth::eora::FaceService::AsyncService::RequestAbortAuthentication,
      base::BindRepeating(&MockFaceServiceRpcHandler::AbortAuthentication,
                          base::Unretained(mock_handler.get())));
  server->RegisterHandler(
      &faceauth::eora::FaceService::AsyncService::
          RequestProcessFrameForAuthentication,
      base::BindRepeating(
          &MockFaceServiceRpcHandler::ProcessFrameForAuthentication,
          mock_handler));
  server->RegisterHandler(
      &faceauth::eora::FaceService::AsyncService::RequestCompleteAuthentication,
      base::BindRepeating(&MockFaceServiceRpcHandler::CompleteAuthentication,
                          base::Unretained(mock_handler.get())));

  server->RegisterHandler(
      &faceauth::eora::FaceService::AsyncService::RequestStartEnrollment,
      base::BindRepeating(&MockFaceServiceRpcHandler::StartEnrollment,
                          base::Unretained(mock_handler.get())));
  server->RegisterHandler(
      &faceauth::eora::FaceService::AsyncService::RequestAbortEnrollment,
      base::BindRepeating(&MockFaceServiceRpcHandler::AbortEnrollment,
                          base::Unretained(mock_handler.get())));
  server->RegisterHandler(
      &faceauth::eora::FaceService::AsyncService::
          RequestProcessFrameForEnrollment,
      base::BindRepeating(&MockFaceServiceRpcHandler::ProcessFrameForEnrollment,
                          mock_handler));
  server->RegisterHandler(
      &faceauth::eora::FaceService::AsyncService::RequestCompleteEnrollment,
      base::BindRepeating(&MockFaceServiceRpcHandler::CompleteEnrollment,
                          base::Unretained(mock_handler.get())));
  server->Start();

  manager->mock_handler_ = mock_handler;
  manager->server_ = std::move(server);

  manager->client_ =
      std::make_unique<brillo::AsyncGrpcClient<faceauth::eora::FaceService>>(
          base::SequencedTaskRunner::GetCurrentDefault(),
          manager->uds_address_);

  manager->client_->SetDefaultRpcDeadlineForTesting(base::Seconds(5));

  return manager;
}

FakeFaceServiceManager::~FakeFaceServiceManager() {
  {
    base::RunLoop run_loop;
    client_->ShutDown(run_loop.QuitClosure());
    run_loop.Run();
  }

  {
    base::RunLoop run_loop;
    server_->ShutDown(run_loop.QuitClosure());
    run_loop.Run();
  }
}

std::shared_ptr<MockFaceServiceRpcHandler>
FakeFaceServiceManager::mock_service() {
  return mock_handler_;
}

absl::StatusOr<Lease<brillo::AsyncGrpcClient<faceauth::eora::FaceService>>>
FakeFaceServiceManager::LeaseClient() {
  return Lease<brillo::AsyncGrpcClient<faceauth::eora::FaceService>>(
      client_.get());
}

}  // namespace faced
