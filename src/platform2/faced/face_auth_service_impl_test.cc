// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "faced/face_auth_service_impl.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/files/scoped_temp_dir.h>
#include <base/functional/bind.h>
#include <base/run_loop.h>
#include <base/strings/stringprintf.h>
#include <base/test/bind.h>
#include <base/test/task_environment.h>
#include <base/time/time.h>
#include <brillo/cryptohome.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <mojo/public/cpp/bindings/receiver.h>
#include <mojo/public/cpp/bindings/remote.h>

#include "faced/mock_face_authentication_session_delegate.h"
#include "faced/mock_face_enrollment_session_delegate.h"
#include "faced/mojom/faceauth.mojom.h"
#include "faced/testing/face_service.h"
#include "faced/testing/status.h"
#include "faced/util/blocking_future.h"

namespace faced {

namespace {

constexpr char kUserName[] = "someone@example.com";

constexpr char kUserId1[] = "0000000000000000000000000000000000000001";
constexpr char kData1[] = "Hello, world1!";
constexpr char kUserId2[] = "0000000000000000000000000000000000000002";
constexpr char kData2[] = "Hello, world2!";

using ::testing::_;
using ::testing::ElementsAre;
using ::testing::Invoke;
using ::testing::StrictMock;

using ::chromeos::faceauth::mojom::AuthenticationSessionConfig;
using ::chromeos::faceauth::mojom::CreateSessionResultPtr;
using ::chromeos::faceauth::mojom::EnrollmentMetadataPtr;
using ::chromeos::faceauth::mojom::EnrollmentSessionConfig;
using ::chromeos::faceauth::mojom::FaceAuthenticationService;
using ::chromeos::faceauth::mojom::FaceAuthenticationSession;
using ::chromeos::faceauth::mojom::FaceAuthenticationSessionDelegate;
using ::chromeos::faceauth::mojom::FaceEnrollmentSession;
using ::chromeos::faceauth::mojom::FaceEnrollmentSessionDelegate;
using ::chromeos::faceauth::mojom::Result;
using ::chromeos::faceauth::mojom::SessionCreationError;
using ::chromeos::faceauth::mojom::SessionError;
using ::chromeos::faceauth::mojom::SessionInfo;

using ::brillo::cryptohome::home::SanitizeUserName;

std::string SampleUserHash() {
  return *SanitizeUserName(::brillo::cryptohome::home::Username(kUserName));
}

// Create an EnrollmentStorage object backed by a temporary directory.
struct TestStorage {
  base::ScopedTempDir temp_dir;
  std::unique_ptr<EnrollmentStorage> enrollments;
};
TestStorage CreateTestStorage() {
  TestStorage result;
  CHECK(result.temp_dir.CreateUniqueTempDir());
  result.enrollments =
      std::make_unique<EnrollmentStorage>(result.temp_dir.GetPath());
  return result;
}

void RunUntil(std::function<bool()> check,
              base::TimeDelta timeout = base::Minutes(1)) {
  base::TimeTicks start_time(base::TimeTicks::Now());

  // Run the loop.
  base::RunLoop().RunUntilIdle();

  // While the condition hasn't become true, sleep for a
  // short duration, and then check again.
  while (!check() && (base::TimeTicks::Now() - start_time) < timeout) {
    base::PlatformThread::Sleep(base::Milliseconds(10));
    base::RunLoop().RunUntilIdle();
  }
}

}  // namespace

TEST(FaceAuthServiceImpl, TestCreateEnrollmentSessionAndDisconnect) {
  // Create a fake manager and set the expected gRPC service calls.
  FACE_ASSERT_OK_AND_ASSIGN(std::unique_ptr<FakeFaceServiceManager> service_mgr,
                            FakeFaceServiceManager::Create());
  EXPECT_CALL(*(service_mgr->mock_service()), StartEnrollment)
      .WillOnce(GrpcReplyOk(StartEnrollmentSuccessResponse()));
  EXPECT_CALL(*(service_mgr->mock_service()), AbortEnrollment)
      .WillOnce(GrpcReplyOk(AbortEnrollmentSuccessResponse()));

  // Create the service remote and impl.
  mojo::Remote<FaceAuthenticationService> service;
  FaceAuthServiceImpl service_impl(service.BindNewPipeAndPassReceiver(),
                                   base::OnceClosure(), *(service_mgr));

  // Create a mock session delegate.
  StrictMock<MockFaceEnrollmentSessionDelegate> delegate;

  // Request the service to begin an enrollment session.
  base::RunLoop run_loop;
  mojo::Remote<FaceEnrollmentSession> session_remote;
  mojo::Receiver<FaceEnrollmentSessionDelegate> receiver(&delegate);
  service->CreateEnrollmentSession(
      EnrollmentSessionConfig::New(SampleUserHash(), /*accessibility=*/false),
      session_remote.BindNewPipeAndPassReceiver(),
      receiver.BindNewPipeAndPassRemote(),
      base::BindLambdaForTesting([&](CreateSessionResultPtr result) {
        EXPECT_TRUE(result->is_session_info());
        run_loop.Quit();
      }));
  run_loop.Run();

  // Ensure the service indicates a session is active.
  EXPECT_TRUE(service_impl.has_active_session());

  // Reset delegate connection
  receiver.reset();

  // Wait for `service_impl` to report that there is no longer an active
  // session.
  RunUntil([&service_impl]() { return !service_impl.has_active_session(); });
  EXPECT_FALSE(service_impl.has_active_session());
}

TEST(FaceAuthServiceImpl, TestSuccessfulCancelEnrollmentSession) {
  // Create a fake manager and set the expected gRPC service calls.
  FACE_ASSERT_OK_AND_ASSIGN(std::unique_ptr<FakeFaceServiceManager> service_mgr,
                            FakeFaceServiceManager::Create());
  EXPECT_CALL(*(service_mgr->mock_service()), StartEnrollment)
      .WillOnce(GrpcReplyOk(StartEnrollmentSuccessResponse()));
  EXPECT_CALL(*(service_mgr->mock_service()), AbortEnrollment)
      .WillOnce(GrpcReplyOk(AbortEnrollmentSuccessResponse()));

  // Create the service remote and impl.
  mojo::Remote<FaceAuthenticationService> service;
  FaceAuthServiceImpl service_impl(service.BindNewPipeAndPassReceiver(),
                                   base::OnceClosure(), *(service_mgr));

  // Create a mock session delegate, that expects a cancellation event to be
  // triggered.
  StrictMock<MockFaceEnrollmentSessionDelegate> delegate;
  EXPECT_CALL(delegate, OnEnrollmentCancelled()).Times(1);

  // Request the service to begin an enrollment session.
  base::RunLoop run_loop;
  mojo::Remote<FaceEnrollmentSession> session_remote;
  mojo::Receiver<FaceEnrollmentSessionDelegate> receiver(&delegate);
  service->CreateEnrollmentSession(
      EnrollmentSessionConfig::New(SampleUserHash(), /*accessibility=*/false),
      session_remote.BindNewPipeAndPassReceiver(),
      receiver.BindNewPipeAndPassRemote(),
      base::BindLambdaForTesting([&](CreateSessionResultPtr result) {
        EXPECT_TRUE(result->is_session_info());
        run_loop.Quit();
      }));
  run_loop.Run();

  // Ensure the service indicates a session is active.
  EXPECT_TRUE(service_impl.has_active_session());

  // Cancel the session by disconnecting `session_remote`.
  session_remote.reset();

  // Wait for `service_impl` to report that there is no longer an active
  // session.
  RunUntil([&service_impl]() { return !service_impl.has_active_session(); });
  EXPECT_FALSE(service_impl.has_active_session());
}

TEST(FaceAuthServiceImpl, TestCreateAuthenticationSession) {
  // Create a fake manager.
  FACE_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<FaceServiceManagerInterface> service_mgr,
      FakeFaceServiceManager::Create());

  // Create the service remote and impl.
  mojo::Remote<FaceAuthenticationService> service;
  FaceAuthServiceImpl service_impl(service.BindNewPipeAndPassReceiver(),
                                   base::OnceClosure(), *(service_mgr));

  // Create a mock session delegate.
  StrictMock<MockFaceAuthenticationSessionDelegate> delegate;

  // Request the service to begin an authentication session.
  base::RunLoop run_loop;
  mojo::Remote<FaceAuthenticationSession> session_remote;
  mojo::Receiver<FaceAuthenticationSessionDelegate> receiver(&delegate);
  service->CreateAuthenticationSession(
      AuthenticationSessionConfig::New(SampleUserHash()),
      session_remote.BindNewPipeAndPassReceiver(),
      receiver.BindNewPipeAndPassRemote(),
      base::BindLambdaForTesting([&](CreateSessionResultPtr result) {
        EXPECT_TRUE(result->is_session_info());
        run_loop.Quit();
      }));
  run_loop.Run();

  // Ensure the service indicates a session is active.
  EXPECT_TRUE(service_impl.has_active_session());
}

TEST(FaceAuthServiceImpl, TestNoConcurrentSession) {
  // Create a fake manager.
  FACE_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<FaceServiceManagerInterface> service_mgr,
      FakeFaceServiceManager::Create());

  // Create the service remote and impl.
  mojo::Remote<FaceAuthenticationService> service;
  FaceAuthServiceImpl service_impl(service.BindNewPipeAndPassReceiver(),
                                   base::OnceClosure(), *(service_mgr));

  // Create a mock session delegate.
  StrictMock<MockFaceAuthenticationSessionDelegate> delegate;

  // Request the service to begin an authentication session.
  base::RunLoop first_run_loop;
  mojo::Remote<FaceAuthenticationSession> session_remote;
  mojo::Receiver<FaceAuthenticationSessionDelegate> receiver(&delegate);
  service->CreateAuthenticationSession(
      AuthenticationSessionConfig::New(SampleUserHash()),
      session_remote.BindNewPipeAndPassReceiver(),
      receiver.BindNewPipeAndPassRemote(),
      base::BindLambdaForTesting([&](CreateSessionResultPtr result) {
        EXPECT_TRUE(result->is_session_info());
        first_run_loop.Quit();
      }));
  first_run_loop.Run();

  // Ensure the service indicates a session is active.
  EXPECT_TRUE(service_impl.has_active_session());

  // Create a second mock session delegate.
  StrictMock<MockFaceAuthenticationSessionDelegate> second_delegate;

  // Request the service to begin a second authentication session.
  base::RunLoop second_run_loop;
  mojo::Remote<FaceAuthenticationSession> second_session_remote;
  mojo::Receiver<FaceAuthenticationSessionDelegate> second_receiver(
      &second_delegate);
  service->CreateAuthenticationSession(
      AuthenticationSessionConfig::New(SampleUserHash()),
      second_session_remote.BindNewPipeAndPassReceiver(),
      second_receiver.BindNewPipeAndPassRemote(),
      base::BindLambdaForTesting([&](CreateSessionResultPtr result) {
        EXPECT_TRUE(result->is_error());
        EXPECT_EQ(SessionCreationError::ALREADY_EXISTS, result->get_error());
        second_run_loop.Quit();
      }));
  second_run_loop.Run();
}

TEST(FaceAuthServiceImpl, TestSessionMaintainedOnDisconnection) {
  // Create a fake manager.
  FACE_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<FaceServiceManagerInterface> service_mgr,
      FakeFaceServiceManager::Create());

  base::RunLoop second_run_loop;

  // Create the service remote and impl.
  mojo::Remote<FaceAuthenticationService> service;
  FaceAuthServiceImpl service_impl(
      service.BindNewPipeAndPassReceiver(),
      base::BindLambdaForTesting([&]() { second_run_loop.Quit(); }),
      *(service_mgr));

  // Create a mock session delegate.
  StrictMock<MockFaceAuthenticationSessionDelegate> delegate;

  // Request the service to begin an authentication session.
  base::RunLoop run_loop;
  mojo::Remote<FaceAuthenticationSession> session_remote;
  mojo::Receiver<FaceAuthenticationSessionDelegate> receiver(&delegate);
  service->CreateAuthenticationSession(
      AuthenticationSessionConfig::New(SampleUserHash()),
      session_remote.BindNewPipeAndPassReceiver(),
      receiver.BindNewPipeAndPassRemote(),
      base::BindLambdaForTesting([&](CreateSessionResultPtr result) {
        EXPECT_TRUE(result->is_session_info());
        run_loop.Quit();
      }));
  run_loop.Run();

  // Ensure the service indicates a session is active.
  EXPECT_TRUE(service_impl.has_active_session());

  // Disconnect from the FaceAuthService interface.
  service.reset();

  second_run_loop.Run();

  // Ensure the service indicates a session remains active.
  EXPECT_TRUE(service_impl.has_active_session());
}

TEST(FaceAuthServiceImpl, TestIsUserEnrolledForEnrolledAndNotEnrolledUsers) {
  // Create a fake manager.
  FACE_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<FaceServiceManagerInterface> service_mgr,
      FakeFaceServiceManager::Create());

  TestStorage storage = CreateTestStorage();

  // Enroll one user
  FACE_ASSERT_OK(storage.enrollments->WriteEnrollment(kUserId1, kData1));

  mojo::Remote<FaceAuthenticationService> service;
  FaceAuthServiceImpl service_impl(service.BindNewPipeAndPassReceiver(),
                                   base::OnceClosure(), *(service_mgr),
                                   storage.temp_dir.GetPath());

  // Check that kUserId1 is enrolled
  BlockingFuture<bool> is_user_enrolled_1;
  service->IsUserEnrolled(kUserId1, is_user_enrolled_1.PromiseCallback());
  is_user_enrolled_1.Wait();

  EXPECT_TRUE(is_user_enrolled_1.value());

  // Check that kUserId2 is not enrolled
  BlockingFuture<bool> is_user_enrolled_2;
  service->IsUserEnrolled(kUserId2, is_user_enrolled_2.PromiseCallback());
  is_user_enrolled_2.Wait();

  EXPECT_FALSE(is_user_enrolled_2.value());
}

TEST(FaceAuthServiceImpl, TestListEnrollments) {
  // Create a fake manager.
  FACE_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<FaceServiceManagerInterface> service_mgr,
      FakeFaceServiceManager::Create());

  TestStorage storage = CreateTestStorage();

  // Enroll two users
  FACE_ASSERT_OK(storage.enrollments->WriteEnrollment(kUserId1, kData1));
  FACE_ASSERT_OK(storage.enrollments->WriteEnrollment(kUserId2, kData2));

  mojo::Remote<FaceAuthenticationService> service;
  FaceAuthServiceImpl service_impl(service.BindNewPipeAndPassReceiver(),
                                   base::OnceClosure(), *(service_mgr),
                                   storage.temp_dir.GetPath());

  BlockingFuture<std::vector<EnrollmentMetadataPtr>> enrollments;
  service->ListEnrollments(enrollments.PromiseCallback());
  enrollments.Wait();

  std::vector<std::string> users;
  for (const EnrollmentMetadataPtr& enrollment : enrollments.value()) {
    users.push_back(enrollment->hashed_username);
  }

  // Check that both kUserId1 and kUserId2 are enrolled.
  EXPECT_THAT(users, ElementsAre(kUserId1, kUserId2));
}

TEST(FaceAuthServiceImpl, TestRemoveEnrollmentDeletesEnrollment) {
  // Create a fake manager.
  FACE_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<FaceServiceManagerInterface> service_mgr,
      FakeFaceServiceManager::Create());

  TestStorage storage = CreateTestStorage();

  // Enroll one user
  FACE_ASSERT_OK(storage.enrollments->WriteEnrollment(kUserId1, kData1));

  mojo::Remote<FaceAuthenticationService> service;
  FaceAuthServiceImpl service_impl(service.BindNewPipeAndPassReceiver(),
                                   base::OnceClosure(), *(service_mgr),
                                   storage.temp_dir.GetPath());

  // Remove enrollment for kUserId1 via the FaceAuthenticationService API
  BlockingFuture<Result> remove_enrollment_result;
  service->RemoveEnrollment(kUserId1,
                            remove_enrollment_result.PromiseCallback());
  remove_enrollment_result.Wait();

  // Verify that the enrollment for kUserId1 has been removed.
  EXPECT_EQ(remove_enrollment_result.value(), Result::OK);
  EXPECT_EQ(storage.enrollments->ListEnrollments().size(), 0);
}

TEST(FaceAuthServiceImpl, TestRemoveEnrollmentFailureForNotEnrolledUser) {
  // Create a fake manager.
  FACE_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<FaceServiceManagerInterface> service_mgr,
      FakeFaceServiceManager::Create());

  TestStorage storage = CreateTestStorage();

  mojo::Remote<FaceAuthenticationService> service;
  FaceAuthServiceImpl service_impl(service.BindNewPipeAndPassReceiver(),
                                   base::OnceClosure(), *(service_mgr),
                                   storage.temp_dir.GetPath());

  // Verify that RemoveEnrollment for kUserId1 which is not enrolled results in
  // an error result.
  BlockingFuture<Result> remove_enrollment_result;
  service->RemoveEnrollment(kUserId1,
                            remove_enrollment_result.PromiseCallback());
  remove_enrollment_result.Wait();

  EXPECT_EQ(remove_enrollment_result.value(), Result::ERROR);
}

TEST(FaceAuthServiceImpl, TestClearEnrollmentsDeletesEnrollments) {
  // Create a fake manager.
  FACE_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<FaceServiceManagerInterface> service_mgr,
      FakeFaceServiceManager::Create());

  TestStorage storage = CreateTestStorage();

  // Enroll two users
  FACE_ASSERT_OK(storage.enrollments->WriteEnrollment(kUserId1, kData1));
  FACE_ASSERT_OK(storage.enrollments->WriteEnrollment(kUserId2, kData2));

  mojo::Remote<FaceAuthenticationService> service;
  FaceAuthServiceImpl service_impl(service.BindNewPipeAndPassReceiver(),
                                   base::OnceClosure(), *(service_mgr),
                                   storage.temp_dir.GetPath());

  // Verify that ClearEnrollments removes enrollments for both kUserId1 and
  // kUserId2.
  BlockingFuture<Result> clear_enrollments_result;
  service->ClearEnrollments(clear_enrollments_result.PromiseCallback());
  clear_enrollments_result.Wait();

  EXPECT_EQ(clear_enrollments_result.value(), Result::OK);
  EXPECT_EQ(storage.enrollments->ListEnrollments().size(), 0);
}

}  // namespace faced
