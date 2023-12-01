// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/auth_blocks/biometrics_command_processor_impl.h"

#include <memory>
#include <optional>
#include <utility>

#include <base/functional/callback.h>
#include <base/strings/string_number_conversions.h>
#include <base/test/bind.h>
#include <base/test/repeating_test_future.h>
#include <base/task/sequenced_task_runner.h>
#include <base/test/task_environment.h>
#include <base/test/test_future.h>
#include <biod/biod_proxy/mock_auth_stack_manager_proxy_base.h>
#include <brillo/secure_blob.h>
#include <cryptohome/proto_bindings/UserDataAuth.pb.h>
#include <gtest/gtest.h>
#include <libhwsec-foundation/error/testing_helper.h>

#include "cryptohome/error/cryptohome_crypto_error.h"
#include "cryptohome/error/cryptohome_error.h"

namespace cryptohome {
namespace {

using base::test::RepeatingTestFuture;
using base::test::TestFuture;
using hwsec_foundation::error::testing::IsOkAnd;

using ::testing::_;
using ::testing::Field;
using ::testing::SaveArg;
using ::testing::SizeIs;

// As the point needs to be valid, the point is pre-generated.
constexpr char kPubPointXHex[] =
    "78D184E439FD4EC5BADC5431C8A6DD8EC039F945E7AD9DEDC5166BEF390E9AFD";
constexpr char kPubPointYHex[] =
    "4E411B61F1B48601ED3A218E4EE6075A3053130E6F25BBFF7FE08BB6D3EC6BF6";

constexpr char kFakeRecordId[] = "fake_record_id";

biod::EnrollScanDone ConstructEnrollScanDone(biod::ScanResult scan_result,
                                             int percent_complete,
                                             const brillo::Blob& nonce) {
  biod::EnrollScanDone ret;
  ret.set_scan_result(scan_result);
  ret.set_done(percent_complete == 100);
  ret.set_percent_complete(percent_complete);
  ret.set_auth_nonce(brillo::BlobToString(nonce));
  return ret;
}

biod::CreateCredentialReply ConstructCreateCredentialReply(
    biod::CreateCredentialReply::CreateCredentialStatus create_status) {
  const std::string kFakeEncryptedSecret(32, 1), kFakeIv(16, 2);

  biod::CreateCredentialReply reply;
  reply.set_status(create_status);
  if (create_status != biod::CreateCredentialReply::SUCCESS) {
    return reply;
  }
  reply.set_encrypted_secret(kFakeEncryptedSecret);
  reply.set_iv(kFakeIv);
  brillo::Blob x, y;
  base::HexStringToBytes(kPubPointXHex, &x);
  base::HexStringToBytes(kPubPointYHex, &y);
  reply.mutable_pub()->set_x(brillo::BlobToString(x));
  reply.mutable_pub()->set_y(brillo::BlobToString(y));
  reply.set_record_id(kFakeRecordId);
  return reply;
}

biod::AuthenticateCredentialReply ConstructAuthenticateCredentialReply(
    biod::AuthenticateCredentialReply::AuthenticateCredentialStatus auth_status,
    std::optional<biod::ScanResult> scan_result) {
  const std::string kFakeEncryptedSecret(32, 1), kFakeIv(16, 2);

  biod::AuthenticateCredentialReply reply;
  reply.set_status(auth_status);
  if (auth_status != biod::AuthenticateCredentialReply::SUCCESS) {
    return reply;
  }
  reply.set_scan_result(*scan_result);
  if (*scan_result != biod::SCAN_RESULT_SUCCESS) {
    return reply;
  }
  reply.set_encrypted_secret(kFakeEncryptedSecret);
  reply.set_iv(kFakeIv);
  brillo::Blob x, y;
  base::HexStringToBytes(kPubPointXHex, &x);
  base::HexStringToBytes(kPubPointYHex, &y);
  reply.mutable_pub()->set_x(brillo::BlobToString(x));
  reply.mutable_pub()->set_y(brillo::BlobToString(y));
  reply.set_record_id(kFakeRecordId);
  return reply;
}

// Base test fixture which sets up the task environment.
class BaseTestFixture : public ::testing::Test {
 protected:
  base::test::SingleThreadTaskEnvironment task_environment_ = {
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};
  scoped_refptr<base::SequencedTaskRunner> task_runner_ =
      base::SequencedTaskRunner::GetCurrentDefault();
};

class BiometricsCommandProcessorImplTest : public BaseTestFixture {
 public:
  void SetUp() override {
    auto mock_proxy = std::make_unique<biod::MockAuthStackManagerProxyBase>();
    mock_proxy_ = mock_proxy.get();
    EXPECT_CALL(*mock_proxy_, ConnectToEnrollScanDoneSignal(_, _))
        .WillOnce([&](auto&& callback, auto&& on_connected_callback) {
          enroll_callback_ = callback;
          enroll_connected_callback_ = std::move(on_connected_callback);
        });
    EXPECT_CALL(*mock_proxy_, ConnectToAuthScanDoneSignal(_, _))
        .WillOnce([&](auto&& callback, auto&& on_connected_callback) {
          auth_callback_ = callback;
          auth_connected_callback_ = std::move(on_connected_callback);
        });
    EXPECT_CALL(*mock_proxy_, ConnectToSessionFailedSignal(_, _))
        .WillOnce([&](auto&& callback, auto&& on_connected_callback) {
          session_failed_callback_ = callback;
          session_failed_connected_callback_ = std::move(on_connected_callback);
        });
    processor_ =
        std::make_unique<BiometricsCommandProcessorImpl>(std::move(mock_proxy));
  }

 protected:
  const ObfuscatedUsername kFakeUserId{"fake"};

  void EmitEnrollEvent(biod::EnrollScanDone enroll_scan) {
    dbus::Signal enroll_scan_done_signal(
        biod::kBiometricsManagerInterface,
        biod::kBiometricsManagerEnrollScanDoneSignal);
    dbus::MessageWriter writer(&enroll_scan_done_signal);
    writer.AppendProtoAsArrayOfBytes(enroll_scan);
    enroll_callback_.Run(&enroll_scan_done_signal);
  }

  void EmitAuthEvent(biod::AuthScanDone auth_scan) {
    dbus::Signal auth_scan_done_signal(
        biod::kBiometricsManagerInterface,
        biod::kBiometricsManagerAuthScanDoneSignal);
    dbus::MessageWriter writer(&auth_scan_done_signal);
    writer.AppendProtoAsArrayOfBytes(auth_scan);
    auth_callback_.Run(&auth_scan_done_signal);
  }

  void EmitSessionFailedEvent() {
    dbus::Signal session_failed_signal(
        biod::kBiometricsManagerInterface,
        biod::kBiometricsManagerSessionFailedSignal);
    session_failed_callback_.Run(&session_failed_signal);
  }

  base::RepeatingCallback<void(dbus::Signal*)> enroll_callback_;
  base::OnceCallback<void(const std::string&, const std::string&, bool success)>
      enroll_connected_callback_;
  base::RepeatingCallback<void(dbus::Signal*)> auth_callback_;
  base::OnceCallback<void(const std::string&, const std::string&, bool success)>
      auth_connected_callback_;
  base::RepeatingCallback<void(dbus::Signal*)> session_failed_callback_;
  base::OnceCallback<void(const std::string&, const std::string&, bool success)>
      session_failed_connected_callback_;
  biod::MockAuthStackManagerProxyBase* mock_proxy_;
  std::unique_ptr<BiometricsCommandProcessorImpl> processor_;
};

TEST_F(BiometricsCommandProcessorImplTest, IsReady) {
  EXPECT_EQ(processor_->IsReady(), false);
  std::move(enroll_connected_callback_).Run("", "", true);
  EXPECT_EQ(processor_->IsReady(), false);
  std::move(auth_connected_callback_).Run("", "", true);
  EXPECT_EQ(processor_->IsReady(), false);
  std::move(session_failed_connected_callback_).Run("", "", true);
  EXPECT_EQ(processor_->IsReady(), true);
}

TEST_F(BiometricsCommandProcessorImplTest, ConnectToSignalFailed) {
  // If one of the signal connection failed, the processor shouldn't be in the
  // ready state.
  std::move(enroll_connected_callback_).Run("", "", false);
  std::move(auth_connected_callback_).Run("", "", true);
  std::move(session_failed_connected_callback_).Run("", "", true);
  EXPECT_EQ(processor_->IsReady(), false);
}

TEST_F(BiometricsCommandProcessorImplTest, StartEndEnrollSession) {
  EXPECT_CALL(*mock_proxy_, StartEnrollSession(_))
      .WillOnce([](auto&& callback) { std::move(callback).Run(true); });

  TestFuture<bool> result;
  processor_->StartEnrollSession(result.GetCallback());
  ASSERT_TRUE(result.IsReady());
  EXPECT_TRUE(result.Get());

  EXPECT_CALL(*mock_proxy_, EndEnrollSession).Times(1);
  processor_->EndEnrollSession();
}

TEST_F(BiometricsCommandProcessorImplTest, StartEndAuthenticateSession) {
  EXPECT_CALL(*mock_proxy_, StartAuthSession(*kFakeUserId, _))
      .WillOnce([](auto&&, auto&& callback) { std::move(callback).Run(true); });

  TestFuture<bool> result;
  processor_->StartAuthenticateSession(kFakeUserId, result.GetCallback());
  ASSERT_TRUE(result.IsReady());
  EXPECT_TRUE(result.Get());

  EXPECT_CALL(*mock_proxy_, EndAuthSession).Times(1);
  processor_->EndAuthenticateSession();
}

TEST_F(BiometricsCommandProcessorImplTest, ReceiveEnrollSignal) {
  const brillo::Blob kFakeNonce(32, 1);

  RepeatingTestFuture<user_data_auth::AuthEnrollmentProgress,
                      std::optional<brillo::Blob>>
      enroll_signals;
  processor_->SetEnrollScanDoneCallback(enroll_signals.GetCallback());

  EmitEnrollEvent(
      ConstructEnrollScanDone(biod::SCAN_RESULT_PARTIAL, 50, brillo::Blob()));
  ASSERT_FALSE(enroll_signals.IsEmpty());
  auto [progress, nonce] = enroll_signals.Take();
  EXPECT_EQ(progress.scan_result().fingerprint_result(),
            user_data_auth::FINGERPRINT_SCAN_RESULT_PARTIAL);
  EXPECT_FALSE(progress.done());
  EXPECT_EQ(progress.fingerprint_progress().percent_complete(), 50);
  EXPECT_FALSE(nonce.has_value());

  EmitEnrollEvent(
      ConstructEnrollScanDone(biod::SCAN_RESULT_SUCCESS, 100, kFakeNonce));
  ASSERT_FALSE(enroll_signals.IsEmpty());
  std::tie(progress, nonce) = enroll_signals.Take();
  EXPECT_EQ(progress.scan_result().fingerprint_result(),
            user_data_auth::FINGERPRINT_SCAN_RESULT_SUCCESS);
  EXPECT_TRUE(progress.done());
  EXPECT_EQ(progress.fingerprint_progress().percent_complete(), 100);
  ASSERT_TRUE(nonce.has_value());
  EXPECT_EQ(nonce, kFakeNonce);
}

TEST_F(BiometricsCommandProcessorImplTest, ReceiveAuthSignal) {
  const brillo::Blob kFakeNonce1(32, 1), kFakeNonce2(32, 2);

  RepeatingTestFuture<user_data_auth::AuthScanDone, brillo::Blob> auth_signals;
  processor_->SetAuthScanDoneCallback(auth_signals.GetCallback());

  biod::AuthScanDone auth_scan;
  auth_scan.set_auth_nonce(brillo::BlobToString(kFakeNonce1));
  EmitAuthEvent(auth_scan);
  ASSERT_FALSE(auth_signals.IsEmpty());
  auto [scan, nonce] = auth_signals.Take();
  EXPECT_EQ(scan.scan_result().fingerprint_result(),
            user_data_auth::FINGERPRINT_SCAN_RESULT_SUCCESS);
  EXPECT_EQ(nonce, kFakeNonce1);

  auth_scan.set_auth_nonce(brillo::BlobToString(kFakeNonce2));
  EmitAuthEvent(auth_scan);
  ASSERT_FALSE(auth_signals.IsEmpty());
  std::tie(scan, nonce) = auth_signals.Take();
  EXPECT_EQ(scan.scan_result().fingerprint_result(),
            user_data_auth::FINGERPRINT_SCAN_RESULT_SUCCESS);
  EXPECT_EQ(nonce, kFakeNonce2);
}

TEST_F(BiometricsCommandProcessorImplTest, ReceiveSessionFailed) {
  bool called = false;
  processor_->SetSessionFailedCallback(
      base::BindLambdaForTesting([&called]() { called = true; }));

  EXPECT_FALSE(called);
  EmitSessionFailedEvent();
  EXPECT_TRUE(called);
}

TEST_F(BiometricsCommandProcessorImplTest, CreateCredential) {
  const BiometricsCommandProcessor::OperationInput kFakeInput{
      .nonce = brillo::Blob(32, 1),
      .encrypted_label_seed = brillo::Blob(32, 2),
      .iv = brillo::Blob(16, 3),
  };

  EXPECT_CALL(*mock_proxy_, CreateCredential(_, _))
      .WillOnce([](auto&&, auto&& callback) {
        std::move(callback).Run(ConstructCreateCredentialReply(
            biod::CreateCredentialReply::SUCCESS));
      });

  TestFuture<CryptohomeStatusOr<BiometricsCommandProcessor::OperationOutput>>
      result;
  processor_->CreateCredential(kFakeUserId, kFakeInput, result.GetCallback());
  ASSERT_TRUE(result.IsReady());
  ASSERT_THAT(
      result.Get(),
      IsOkAnd(
          AllOf(Field(&BiometricsCommandProcessor::OperationOutput::record_id,
                      kFakeRecordId),
                Field(&BiometricsCommandProcessor::OperationOutput::auth_secret,
                      SizeIs(32)),
                Field(&BiometricsCommandProcessor::OperationOutput::auth_pin,
                      SizeIs(32)))));
}

TEST_F(BiometricsCommandProcessorImplTest, CreateCredentialNoReply) {
  const BiometricsCommandProcessor::OperationInput kFakeInput{
      .nonce = brillo::Blob(32, 1),
      .encrypted_label_seed = brillo::Blob(32, 2),
      .iv = brillo::Blob(16, 3),
  };

  EXPECT_CALL(*mock_proxy_, CreateCredential(_, _))
      .WillOnce([](auto&&, auto&& callback) {
        std::move(callback).Run(std::nullopt);
      });

  TestFuture<CryptohomeStatusOr<BiometricsCommandProcessor::OperationOutput>>
      result;
  processor_->CreateCredential(kFakeUserId, kFakeInput, result.GetCallback());
  ASSERT_TRUE(result.IsReady());
  EXPECT_EQ(result.Get().status()->local_legacy_error(),
            user_data_auth::CRYPTOHOME_ERROR_FINGERPRINT_ERROR_INTERNAL);
}

TEST_F(BiometricsCommandProcessorImplTest, CreateCredentialFailure) {
  const BiometricsCommandProcessor::OperationInput kFakeInput{
      .nonce = brillo::Blob(32, 1),
      .encrypted_label_seed = brillo::Blob(32, 2),
      .iv = brillo::Blob(16, 3),
  };

  EXPECT_CALL(*mock_proxy_, CreateCredential(_, _))
      .WillOnce([](auto&&, auto&& callback) {
        std::move(callback).Run(ConstructCreateCredentialReply(
            biod::CreateCredentialReply::INCORRECT_STATE));
      });

  TestFuture<CryptohomeStatusOr<BiometricsCommandProcessor::OperationOutput>>
      result;
  processor_->CreateCredential(kFakeUserId, kFakeInput, result.GetCallback());
  ASSERT_TRUE(result.IsReady());
  EXPECT_EQ(result.Get().status()->local_legacy_error(),
            user_data_auth::CRYPTOHOME_ERROR_FINGERPRINT_ERROR_INTERNAL);
}

TEST_F(BiometricsCommandProcessorImplTest, MatchCredential) {
  const BiometricsCommandProcessor::OperationInput kFakeInput{
      .nonce = brillo::Blob(32, 1),
      .encrypted_label_seed = brillo::Blob(32, 2),
      .iv = brillo::Blob(16, 3),
  };

  EXPECT_CALL(*mock_proxy_, AuthenticateCredential(_, _))
      .WillOnce([](auto&&, auto&& callback) {
        std::move(callback).Run(ConstructAuthenticateCredentialReply(
            biod::AuthenticateCredentialReply::SUCCESS,
            biod::SCAN_RESULT_SUCCESS));
      });

  TestFuture<CryptohomeStatusOr<BiometricsCommandProcessor::OperationOutput>>
      result;
  processor_->MatchCredential(kFakeInput, result.GetCallback());
  ASSERT_TRUE(result.IsReady());
  ASSERT_THAT(
      result.Get(),
      IsOkAnd(
          AllOf(Field(&BiometricsCommandProcessor::OperationOutput::record_id,
                      kFakeRecordId),
                Field(&BiometricsCommandProcessor::OperationOutput::auth_secret,
                      SizeIs(32)),
                Field(&BiometricsCommandProcessor::OperationOutput::auth_pin,
                      SizeIs(32)))));
}

TEST_F(BiometricsCommandProcessorImplTest, MatchCredentialNoReply) {
  const BiometricsCommandProcessor::OperationInput kFakeInput{
      .nonce = brillo::Blob(32, 1),
      .encrypted_label_seed = brillo::Blob(32, 2),
      .iv = brillo::Blob(16, 3),
  };

  EXPECT_CALL(*mock_proxy_, AuthenticateCredential(_, _))
      .WillOnce([](auto&&, auto&& callback) {
        std::move(callback).Run(std::nullopt);
      });

  TestFuture<CryptohomeStatusOr<BiometricsCommandProcessor::OperationOutput>>
      result;
  processor_->MatchCredential(kFakeInput, result.GetCallback());
  ASSERT_TRUE(result.IsReady());
  EXPECT_EQ(result.Get().status()->local_legacy_error(),
            user_data_auth::CRYPTOHOME_ERROR_FINGERPRINT_ERROR_INTERNAL);
}

TEST_F(BiometricsCommandProcessorImplTest, AuthenticateCredentialFailure) {
  const BiometricsCommandProcessor::OperationInput kFakeInput{
      .nonce = brillo::Blob(32, 1),
      .encrypted_label_seed = brillo::Blob(32, 2),
      .iv = brillo::Blob(16, 3),
  };

  EXPECT_CALL(*mock_proxy_, AuthenticateCredential(_, _))
      .WillOnce([](auto&&, auto&& callback) {
        std::move(callback).Run(ConstructAuthenticateCredentialReply(
            biod::AuthenticateCredentialReply::INCORRECT_STATE, std::nullopt));
      });

  TestFuture<CryptohomeStatusOr<BiometricsCommandProcessor::OperationOutput>>
      result;
  processor_->MatchCredential(kFakeInput, result.GetCallback());
  ASSERT_TRUE(result.IsReady());
  EXPECT_EQ(result.Get().status()->local_legacy_error(),
            user_data_auth::CRYPTOHOME_ERROR_FINGERPRINT_ERROR_INTERNAL);
}

TEST_F(BiometricsCommandProcessorImplTest, AuthenticateCredentialNoMatch) {
  const BiometricsCommandProcessor::OperationInput kFakeInput{
      .nonce = brillo::Blob(32, 1),
      .encrypted_label_seed = brillo::Blob(32, 2),
      .iv = brillo::Blob(16, 3),
  };

  EXPECT_CALL(*mock_proxy_, AuthenticateCredential(_, _))
      .WillOnce([](auto&&, auto&& callback) {
        std::move(callback).Run(ConstructAuthenticateCredentialReply(
            biod::AuthenticateCredentialReply::SUCCESS,
            biod::SCAN_RESULT_INSUFFICIENT));
      });

  TestFuture<CryptohomeStatusOr<BiometricsCommandProcessor::OperationOutput>>
      result;
  processor_->MatchCredential(kFakeInput, result.GetCallback());
  ASSERT_TRUE(result.IsReady());
  EXPECT_EQ(result.Get().status()->local_legacy_error(),
            user_data_auth::CRYPTOHOME_ERROR_FINGERPRINT_RETRY_REQUIRED);
}

}  // namespace
}  // namespace cryptohome
