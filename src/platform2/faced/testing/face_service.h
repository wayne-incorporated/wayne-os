// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef FACED_TESTING_FACE_SERVICE_H_
#define FACED_TESTING_FACE_SERVICE_H_

#include <memory>
#include <string>
#include <utility>

#include <base/files/scoped_temp_dir.h>
#include <base/task/sequenced_task_runner.h>
#include <base/test/task_environment.h>
#include <brillo/grpc/async_grpc_server.h>
#include <gmock/gmock.h>

#include "base/functional/callback_forward.h"
#include "faced/face_service.h"
#include "faced/proto/face_service.grpc.pb.h"
#include "faced/proto/face_service.pb.h"

namespace faced {

constexpr base::StringPiece kTestUserDataPayload =
    "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod "
    "tempor incididunt ut labore et dolore magna aliqua";
constexpr base::StringPiece kTestUserDataPayload2 = "test user data";

// Return a FaceStatusCode with an "OK" code.
faceauth::eora::FaceStatusCode FaceStatusOk();

// Return a FaceStatusCode with an "INVALID" code.
faceauth::eora::FaceStatusCode FaceStatusInvalid();

// Return a StartAuthentication response indicating that an authentication was
// successfully started.
faceauth::eora::StartAuthenticationResponse
StartAuthenticationSuccessResponse();

// Return an AbortAuthentication response indicating that the authentication was
// aborted.
faceauth::eora::AbortAuthenticationResponse
AbortAuthenticationSuccessResponse();

// Return a CompleteAuthentication response indicating that an authentication
// was successfully completed / failed to complete.
//
// The success response specifies the UserData to respond with
faceauth::eora::CompleteAuthenticationResponse
CompleteAuthenticationSuccessResponse(
    const faceauth::eora::UserData& user_data);
faceauth::eora::CompleteAuthenticationResponse
CompleteAuthenticationFailureResponse();

// Return a ProcessFrameForAuthenticationResponse proto indicating
// that more data / no more data is needed, respectively.
faceauth::eora::ProcessFrameForAuthenticationResponse
AuthenticationIncompleteResponse();
faceauth::eora::ProcessFrameForAuthenticationResponse
AuthenticationCompleteResponse();

// Return a StartEnrollment response indicating that an enrollment was
// successfully started / failed to start.
faceauth::eora::StartEnrollmentResponse StartEnrollmentSuccessResponse();
faceauth::eora::StartEnrollmentResponse StartEnrollmentFailureResponse();

// Return an AbortEnrollment response indicating that the enrollment was
// aborted or failed.
faceauth::eora::AbortEnrollmentResponse AbortEnrollmentSuccessResponse();
faceauth::eora::AbortEnrollmentResponse AbortEnrollmentFailureResponse();

// Return a CompleteEnrollment response indicating that an enrollment
// was successfully completed.
//
// user_data specifies the UserData to respond with
faceauth::eora::CompleteEnrollmentResponse CompleteEnrollmentSuccessResponse(
    const faceauth::eora::UserData& user_data);

// Return a ProcessFrameForEnrollmentResponse proto indicating
// that more data / no more data is needed, respectively.
faceauth::eora::ProcessFrameForEnrollmentResponse
EnrollmentProcessingErrorResponse();
faceauth::eora::ProcessFrameForEnrollmentResponse
EnrollmentIncompleteResponse();
faceauth::eora::ProcessFrameForEnrollmentResponse EnrollmentCompleteResponse();

// Return a test UserData
faceauth::eora::UserData TestUserData();
faceauth::eora::UserData TestUserData2();

// gMock Action to respond to a gRPC with the given response.
//
// For example, to indicate that a gRPC handle should return the given
// protobuff with an OK response, write:
//
//   EXPECT_CALL(*server_mock, MyServerMethod)
//       .WillOnce(GrpcReplyOk(protobuf_response));
//
template <typename Response>
inline auto GrpcReplyOk(Response response) {
  return [response = std::move(response)](auto request, auto&& callback) {
    std::move(callback).Run(grpc::Status::OK,
                            std::make_unique<Response>(response));
  };
}

// Mock Handler that's passed to the gRPC server that allows us to mock
// responses to gRPC calls for testing
class MockFaceServiceRpcHandler {
 public:
  using StartAuthenticationCallback = base::OnceCallback<void(
      grpc::Status,
      std::unique_ptr<faceauth::eora::StartAuthenticationResponse>)>;
  using AbortAuthenticationCallback = base::OnceCallback<void(
      grpc::Status,
      std::unique_ptr<faceauth::eora::AbortAuthenticationResponse>)>;
  using CompleteAuthenticationCallback = base::OnceCallback<void(
      grpc::Status,
      std::unique_ptr<faceauth::eora::CompleteAuthenticationResponse>)>;
  using ProcessFrameForAuthenticationCallback = base::OnceCallback<void(
      grpc::Status,
      std::unique_ptr<faceauth::eora::ProcessFrameForAuthenticationResponse>)>;

  using StartEnrollmentCallback = base::OnceCallback<void(
      grpc::Status, std::unique_ptr<faceauth::eora::StartEnrollmentResponse>)>;
  using AbortEnrollmentCallback = base::OnceCallback<void(
      grpc::Status, std::unique_ptr<faceauth::eora::AbortEnrollmentResponse>)>;
  using CompleteEnrollmentCallback = base::OnceCallback<void(
      grpc::Status,
      std::unique_ptr<faceauth::eora::CompleteEnrollmentResponse>)>;
  using ProcessFrameForEnrollmentCallback = base::OnceCallback<void(
      grpc::Status,
      std::unique_ptr<faceauth::eora::ProcessFrameForEnrollmentResponse>)>;

  // Handler functions mocked for the async gRPC client so that tests are able
  // to define outputs of the fake service.

  MOCK_METHOD(void,
              StartAuthentication,
              (std::unique_ptr<faceauth::eora::StartAuthenticationRequest>,
               StartAuthenticationCallback));

  MOCK_METHOD(void,
              AbortAuthentication,
              (std::unique_ptr<faceauth::eora::AbortAuthenticationRequest>,
               AbortAuthenticationCallback));

  MOCK_METHOD(void,
              CompleteAuthentication,
              (std::unique_ptr<faceauth::eora::CompleteAuthenticationRequest>,
               CompleteAuthenticationCallback));

  MOCK_METHOD(
      void,
      ProcessFrameForAuthentication,
      (std::unique_ptr<faceauth::eora::ProcessFrameForAuthenticationRequest>,
       ProcessFrameForAuthenticationCallback));

  MOCK_METHOD(void,
              StartEnrollment,
              (std::unique_ptr<faceauth::eora::StartEnrollmentRequest>,
               StartEnrollmentCallback));

  MOCK_METHOD(void,
              AbortEnrollment,
              (std::unique_ptr<faceauth::eora::AbortEnrollmentRequest>,
               AbortEnrollmentCallback));

  MOCK_METHOD(void,
              CompleteEnrollment,
              (std::unique_ptr<faceauth::eora::CompleteEnrollmentRequest>,
               CompleteEnrollmentCallback));

  MOCK_METHOD(
      void,
      ProcessFrameForEnrollment,
      (std::unique_ptr<faceauth::eora::ProcessFrameForEnrollmentRequest>,
       ProcessFrameForEnrollmentCallback));
};

// Fake that sets up the socket for communicating with the FakeServer
class FakeFaceServiceManager : public FaceServiceManagerInterface {
 public:
  static absl::StatusOr<std::unique_ptr<FakeFaceServiceManager>> Create();

  ~FakeFaceServiceManager() override;

  // Disallow copy and move.
  FakeFaceServiceManager(const FakeFaceServiceManager&) = delete;
  FakeFaceServiceManager& operator=(const FakeFaceServiceManager&) = delete;

  absl::StatusOr<Lease<brillo::AsyncGrpcClient<faceauth::eora::FaceService>>>
  LeaseClient() override;

  std::shared_ptr<MockFaceServiceRpcHandler> mock_service();

 protected:
  FakeFaceServiceManager() = default;

  base::ScopedTempDir temp_dir_;

  std::shared_ptr<MockFaceServiceRpcHandler>
      mock_handler_;  // Allows the test to specify outputs
  std::unique_ptr<
      brillo::AsyncGrpcServer<faceauth::eora::FaceService::AsyncService>>
      server_;  // Async gRPC fake server

  std::string uds_address_;  // Socket address

  std::unique_ptr<brillo::AsyncGrpcClient<faceauth::eora::FaceService>> client_;
};

}  // namespace faced
#endif  // FACED_TESTING_FACE_SERVICE_H_
