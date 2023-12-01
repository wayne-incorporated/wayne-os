// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/fingerprint_manager.h"

#include <utility>
#include <vector>

#include <base/test/bind.h>
#include <biod/biod_proxy/mock_biometrics_manager_proxy_base.h>
#include <chromeos/dbus/service_constants.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace cryptohome {

// Peer class for testing FingerprintManager.
class FingerprintManagerPeer {
 public:
  explicit FingerprintManagerPeer(FingerprintManager* fingerprint_manager) {
    fingerprint_manager_ = fingerprint_manager;
  }

  // FingerprintManager won't allow any operation unless
  // |connected_to_auth_scan_done_signal_| is true, so set that for testing.
  void SetConnectedToAuthScanDoneSignal(bool success) {
    fingerprint_manager_->connected_to_auth_scan_done_signal_ = success;
  }

  void SignalAuthScanDone(dbus::Signal* signal) {
    fingerprint_manager_->OnAuthScanDone(signal);
  }

  bool NoAuthSession() {
    return fingerprint_manager_->state_ ==
           FingerprintManager::State::NO_AUTH_SESSION;
  }

  bool AuthSessionIsOpen() {
    return fingerprint_manager_->state_ ==
           FingerprintManager::State::AUTH_SESSION_OPEN;
  }

  bool AuthSessionIsLocked() {
    return fingerprint_manager_->state_ ==
           FingerprintManager::State::AUTH_SESSION_LOCKED;
  }

 private:
  FingerprintManager* fingerprint_manager_;
};

namespace {
using testing::_;
using testing::NiceMock;
using testing::Return;

class FingerprintManagerTest : public testing::Test {
 public:
  const ObfuscatedUsername kUser{"user"};

  FingerprintManagerTest() {
    fingerprint_manager_ = std::make_unique<FingerprintManager>();
    fingerprint_manager_->SetProxy(&mock_biod_proxy_);

    fingerprint_manager_peer_ =
        std::make_unique<FingerprintManagerPeer>(fingerprint_manager_.get());
    // Mark |connected_to_auth_scan_done_signal_| to true to allow operations.
    fingerprint_manager_peer_->SetConnectedToAuthScanDoneSignal(true);
  }

  void AddMatchToScanResult(dbus::MessageWriter* matches_writer,
                            const ObfuscatedUsername& user) {
    dbus::MessageWriter entry_writer(nullptr);
    matches_writer->OpenDictEntry(&entry_writer);
    entry_writer.AppendString(*user);
    // A dumb fingerprint record path is sufficient.
    entry_writer.AppendArrayOfObjectPaths(std::vector<dbus::ObjectPath>());
    matches_writer->CloseContainer(&entry_writer);
  }

  std::unique_ptr<FingerprintManager> fingerprint_manager_;
  std::unique_ptr<FingerprintManagerPeer> fingerprint_manager_peer_;
  NiceMock<biod::MockBiometricsManagerProxyBase> mock_biod_proxy_;
  bool status_;
  FingerprintScanStatus scan_status_;
  FingerprintScanStatus signal_status_;
};

TEST_F(FingerprintManagerTest, StartAuthSessionFail) {
  EXPECT_CALL(mock_biod_proxy_, StartAuthSessionAsync(_))
      .WillOnce([](base::OnceCallback<void(bool success)> callback) {
        std::move(callback).Run(false);
      });
  status_ = true;
  fingerprint_manager_->StartAuthSessionAsyncForUser(
      kUser,
      base::BindLambdaForTesting([this](bool success) { status_ = success; }));
  EXPECT_FALSE(status_);
  EXPECT_TRUE(fingerprint_manager_->GetCurrentUser()->empty());
  EXPECT_TRUE(fingerprint_manager_peer_->NoAuthSession());
}

TEST_F(FingerprintManagerTest, StartAuthSessionSuccess) {
  EXPECT_CALL(mock_biod_proxy_, StartAuthSessionAsync(_))
      .WillOnce([](base::OnceCallback<void(bool success)> callback) {
        std::move(callback).Run(true);
      });
  status_ = false;
  fingerprint_manager_->StartAuthSessionAsyncForUser(
      kUser,
      base::BindLambdaForTesting([this](bool success) { status_ = success; }));
  EXPECT_TRUE(status_);
  EXPECT_EQ(fingerprint_manager_->GetCurrentUser(), kUser);
  EXPECT_TRUE(fingerprint_manager_peer_->AuthSessionIsOpen());

  // Test that we can close the auth session.
  EXPECT_CALL(mock_biod_proxy_, EndAuthSession());
  fingerprint_manager_->EndAuthSession();
  EXPECT_TRUE(fingerprint_manager_peer_->NoAuthSession());
}

TEST_F(FingerprintManagerTest, StartAuthSessionTwice) {
  // First auth session still exists.
  EXPECT_CALL(mock_biod_proxy_, StartAuthSessionAsync(_))
      .WillOnce([](base::OnceCallback<void(bool success)> callback) {
        std::move(callback).Run(true);
      });
  status_ = false;
  fingerprint_manager_->StartAuthSessionAsyncForUser(
      kUser,
      base::BindLambdaForTesting([this](bool success) { status_ = success; }));
  EXPECT_TRUE(status_);
  EXPECT_EQ(fingerprint_manager_->GetCurrentUser(), kUser);

  // Second time should fail.
  status_ = true;
  fingerprint_manager_->StartAuthSessionAsyncForUser(
      kUser,
      base::BindLambdaForTesting([this](bool success) { status_ = success; }));
  EXPECT_FALSE(status_);
  // The existing session is unaffected.
  EXPECT_TRUE(fingerprint_manager_peer_->AuthSessionIsOpen());
}

TEST_F(FingerprintManagerTest, AuthScanDoneNoScanResult) {
  EXPECT_CALL(mock_biod_proxy_, StartAuthSessionAsync(_))
      .WillOnce([](base::OnceCallback<void(bool success)> callback) {
        std::move(callback).Run(true);
      });
  fingerprint_manager_->StartAuthSessionAsyncForUser(
      kUser,
      base::BindLambdaForTesting([this](bool success) { status_ = success; }));
  EXPECT_TRUE(fingerprint_manager_peer_->AuthSessionIsOpen());

  // This signal does not include a ScanResult, so it's invalid.
  dbus::Signal signal(biod::kBiometricsManagerInterface,
                      biod::kBiometricsManagerAuthScanDoneSignal);

  fingerprint_manager_->SetAuthScanDoneCallback(base::BindLambdaForTesting(
      [this](FingerprintScanStatus status) { scan_status_ = status; }));
  scan_status_ = FingerprintScanStatus::SUCCESS;
  fingerprint_manager_->SetSignalCallback(base::BindLambdaForTesting(
      [this](FingerprintScanStatus status) { signal_status_ = status; }));
  signal_status_ = FingerprintScanStatus::SUCCESS;

  fingerprint_manager_peer_->SignalAuthScanDone(&signal);

  EXPECT_EQ(scan_status_, FingerprintScanStatus::FAILED_RETRY_NOT_ALLOWED);
  EXPECT_EQ(signal_status_, FingerprintScanStatus::FAILED_RETRY_NOT_ALLOWED);
  // Unrecoverable error should lock the auth session.
  EXPECT_TRUE(fingerprint_manager_peer_->AuthSessionIsLocked());
}

TEST_F(FingerprintManagerTest, AuthScanDoneNoResultCodeInMessage) {
  EXPECT_CALL(mock_biod_proxy_, StartAuthSessionAsync(_))
      .WillOnce([](base::OnceCallback<void(bool success)> callback) {
        std::move(callback).Run(true);
      });
  fingerprint_manager_->StartAuthSessionAsyncForUser(
      kUser,
      base::BindLambdaForTesting([this](bool success) { status_ = success; }));
  EXPECT_TRUE(fingerprint_manager_peer_->AuthSessionIsOpen());

  // This signal does not include a ScanResult, so it's invalid.
  dbus::Signal signal(biod::kBiometricsManagerInterface,
                      biod::kBiometricsManagerAuthScanDoneSignal);
  dbus::MessageWriter writer(&signal);

  biod::FingerprintMessage auth_result;
  writer.AppendProtoAsArrayOfBytes(auth_result);

  fingerprint_manager_->SetAuthScanDoneCallback(base::BindLambdaForTesting(
      [this](FingerprintScanStatus status) { scan_status_ = status; }));
  scan_status_ = FingerprintScanStatus::SUCCESS;
  fingerprint_manager_->SetSignalCallback(base::BindLambdaForTesting(
      [this](FingerprintScanStatus status) { signal_status_ = status; }));
  signal_status_ = FingerprintScanStatus::SUCCESS;
  fingerprint_manager_peer_->SignalAuthScanDone(&signal);
  EXPECT_EQ(scan_status_, FingerprintScanStatus::FAILED_RETRY_NOT_ALLOWED);
  EXPECT_EQ(signal_status_, FingerprintScanStatus::FAILED_RETRY_NOT_ALLOWED);
  // Unrecoverable error should lock the auth session.
  EXPECT_TRUE(fingerprint_manager_peer_->AuthSessionIsLocked());
}

TEST_F(FingerprintManagerTest, AuthScanDoneScanResultFailed) {
  EXPECT_CALL(mock_biod_proxy_, StartAuthSessionAsync(_))
      .WillOnce([](base::OnceCallback<void(bool success)> callback) {
        std::move(callback).Run(true);
      });
  fingerprint_manager_->StartAuthSessionAsyncForUser(
      kUser,
      base::BindLambdaForTesting([this](bool success) { status_ = success; }));
  EXPECT_TRUE(fingerprint_manager_peer_->AuthSessionIsOpen());

  dbus::Signal signal(biod::kBiometricsManagerInterface,
                      biod::kBiometricsManagerAuthScanDoneSignal);
  dbus::MessageWriter writer(&signal);

  biod::FingerprintMessage auth_result;
  auth_result.set_scan_result(biod::ScanResult::SCAN_RESULT_PARTIAL);
  writer.AppendProtoAsArrayOfBytes(auth_result);

  fingerprint_manager_->SetAuthScanDoneCallback(base::BindLambdaForTesting(
      [this](FingerprintScanStatus status) { scan_status_ = status; }));
  scan_status_ = FingerprintScanStatus::SUCCESS;
  fingerprint_manager_->SetSignalCallback(base::BindLambdaForTesting(
      [this](FingerprintScanStatus status) { signal_status_ = status; }));
  signal_status_ = FingerprintScanStatus::SUCCESS;
  fingerprint_manager_peer_->SignalAuthScanDone(&signal);
  EXPECT_EQ(scan_status_, FingerprintScanStatus::FAILED_RETRY_ALLOWED);
  EXPECT_EQ(signal_status_, FingerprintScanStatus::FAILED_RETRY_ALLOWED);
  // Auth session should still be open since retry is allowed.
  EXPECT_TRUE(fingerprint_manager_peer_->AuthSessionIsOpen());
}

TEST_F(FingerprintManagerTest, AuthScanDoneError) {
  EXPECT_CALL(mock_biod_proxy_, StartAuthSessionAsync(_))
      .WillOnce([](base::OnceCallback<void(bool success)> callback) {
        std::move(callback).Run(true);
      });
  fingerprint_manager_->StartAuthSessionAsyncForUser(
      kUser,
      base::BindLambdaForTesting([this](bool success) { status_ = success; }));
  EXPECT_TRUE(fingerprint_manager_peer_->AuthSessionIsOpen());

  dbus::Signal signal(biod::kBiometricsManagerInterface,
                      biod::kBiometricsManagerAuthScanDoneSignal);
  dbus::MessageWriter writer(&signal);

  biod::FingerprintMessage auth_result;
  auth_result.set_error(biod::FingerprintError::ERROR_NO_TEMPLATES);
  writer.AppendProtoAsArrayOfBytes(auth_result);

  fingerprint_manager_->SetAuthScanDoneCallback(base::BindLambdaForTesting(
      [this](FingerprintScanStatus status) { scan_status_ = status; }));
  scan_status_ = FingerprintScanStatus::SUCCESS;
  fingerprint_manager_->SetSignalCallback(base::BindLambdaForTesting(
      [this](FingerprintScanStatus status) { signal_status_ = status; }));
  signal_status_ = FingerprintScanStatus::SUCCESS;
  fingerprint_manager_peer_->SignalAuthScanDone(&signal);
  EXPECT_EQ(scan_status_, FingerprintScanStatus::FAILED_RETRY_NOT_ALLOWED);
  EXPECT_EQ(signal_status_, FingerprintScanStatus::FAILED_RETRY_NOT_ALLOWED);
  // Unrecoverable error should lock the auth session.
  EXPECT_TRUE(fingerprint_manager_peer_->AuthSessionIsLocked());
}

TEST_F(FingerprintManagerTest, AuthScanDoneNoMatch) {
  EXPECT_CALL(mock_biod_proxy_, StartAuthSessionAsync(_))
      .WillOnce([](base::OnceCallback<void(bool success)> callback) {
        std::move(callback).Run(true);
      });
  fingerprint_manager_->StartAuthSessionAsyncForUser(
      kUser,
      base::BindLambdaForTesting([this](bool success) { status_ = success; }));
  EXPECT_TRUE(fingerprint_manager_peer_->AuthSessionIsOpen());

  dbus::Signal signal(biod::kBiometricsManagerInterface,
                      biod::kBiometricsManagerAuthScanDoneSignal);
  dbus::MessageWriter writer(&signal);

  biod::FingerprintMessage auth_result;
  auth_result.set_scan_result(biod::ScanResult::SCAN_RESULT_NO_MATCH);
  writer.AppendProtoAsArrayOfBytes(auth_result);

  dbus::MessageWriter matches_writer(nullptr);
  writer.OpenArray("{sao}", &matches_writer);
  // No matches.
  writer.CloseContainer(&matches_writer);

  fingerprint_manager_->SetAuthScanDoneCallback(base::BindLambdaForTesting(
      [this](FingerprintScanStatus status) { scan_status_ = status; }));
  scan_status_ = FingerprintScanStatus::SUCCESS;
  fingerprint_manager_->SetSignalCallback(base::BindLambdaForTesting(
      [this](FingerprintScanStatus status) { signal_status_ = status; }));
  signal_status_ = FingerprintScanStatus::SUCCESS;
  fingerprint_manager_peer_->SignalAuthScanDone(&signal);
  EXPECT_EQ(scan_status_, FingerprintScanStatus::FAILED_RETRY_ALLOWED);
  EXPECT_EQ(signal_status_, FingerprintScanStatus::FAILED_RETRY_ALLOWED);
  // Auth session should still be open since retry is allowed.
  EXPECT_TRUE(fingerprint_manager_peer_->AuthSessionIsOpen());
}

TEST_F(FingerprintManagerTest, AuthScanDoneSuccess) {
  EXPECT_CALL(mock_biod_proxy_, StartAuthSessionAsync(_))
      .WillOnce([](base::OnceCallback<void(bool success)> callback) {
        std::move(callback).Run(true);
      });
  fingerprint_manager_->StartAuthSessionAsyncForUser(
      kUser,
      base::BindLambdaForTesting([this](bool success) { status_ = success; }));
  EXPECT_TRUE(fingerprint_manager_peer_->AuthSessionIsOpen());

  dbus::Signal signal(biod::kBiometricsManagerInterface,
                      biod::kBiometricsManagerAuthScanDoneSignal);
  dbus::MessageWriter writer(&signal);

  biod::FingerprintMessage auth_result;
  auth_result.set_scan_result(biod::ScanResult::SCAN_RESULT_SUCCESS);
  writer.AppendProtoAsArrayOfBytes(auth_result);

  dbus::MessageWriter matches_writer(nullptr);
  writer.OpenArray("{sao}", &matches_writer);
  AddMatchToScanResult(&matches_writer, kUser);
  writer.CloseContainer(&matches_writer);

  fingerprint_manager_->SetAuthScanDoneCallback(base::BindLambdaForTesting(
      [this](FingerprintScanStatus status) { scan_status_ = status; }));
  scan_status_ = FingerprintScanStatus::FAILED_RETRY_NOT_ALLOWED;
  fingerprint_manager_->SetSignalCallback(base::BindLambdaForTesting(
      [this](FingerprintScanStatus status) { signal_status_ = status; }));
  signal_status_ = FingerprintScanStatus::FAILED_RETRY_ALLOWED;
  fingerprint_manager_peer_->SignalAuthScanDone(&signal);
  EXPECT_EQ(scan_status_, FingerprintScanStatus::SUCCESS);
  EXPECT_EQ(signal_status_, FingerprintScanStatus::SUCCESS);
  // A successful scan should cause further scans in the same session to be
  // ignored.
  EXPECT_TRUE(fingerprint_manager_peer_->AuthSessionIsLocked());
}

TEST_F(FingerprintManagerTest, AuthScanDoneTooManyRetries) {
  EXPECT_CALL(mock_biod_proxy_, StartAuthSessionAsync(_))
      .WillOnce([](base::OnceCallback<void(bool success)> callback) {
        std::move(callback).Run(true);
      });
  fingerprint_manager_->StartAuthSessionAsyncForUser(
      kUser,
      base::BindLambdaForTesting([this](bool success) { status_ = success; }));
  EXPECT_TRUE(fingerprint_manager_peer_->AuthSessionIsOpen());

  dbus::Signal signal(biod::kBiometricsManagerInterface,
                      biod::kBiometricsManagerAuthScanDoneSignal);
  dbus::MessageWriter writer(&signal);

  biod::FingerprintMessage auth_result;
  auth_result.set_scan_result(biod::ScanResult::SCAN_RESULT_NO_MATCH);
  writer.AppendProtoAsArrayOfBytes(auth_result);

  dbus::MessageWriter matches_writer(nullptr);
  writer.OpenArray("{sao}", &matches_writer);
  // No matches.
  writer.CloseContainer(&matches_writer);

  fingerprint_manager_->SetSignalCallback(base::BindLambdaForTesting(
      [this](FingerprintScanStatus status) { signal_status_ = status; }));
  signal_status_ = FingerprintScanStatus::SUCCESS;
  for (int i = 0; i < kMaxFingerprintRetries - 1; i++) {
    fingerprint_manager_->SetAuthScanDoneCallback(base::BindLambdaForTesting(
        [this](FingerprintScanStatus status) { scan_status_ = status; }));
    scan_status_ = FingerprintScanStatus::SUCCESS;
    fingerprint_manager_peer_->SignalAuthScanDone(&signal);
    EXPECT_EQ(scan_status_, FingerprintScanStatus::FAILED_RETRY_ALLOWED);
    EXPECT_EQ(signal_status_, FingerprintScanStatus::FAILED_RETRY_ALLOWED);
  }
  // The last invalid retry should lock the auth session.
  fingerprint_manager_->SetAuthScanDoneCallback(base::BindLambdaForTesting(
      [this](FingerprintScanStatus status) { scan_status_ = status; }));
  scan_status_ = FingerprintScanStatus::SUCCESS;
  fingerprint_manager_peer_->SignalAuthScanDone(&signal);
  EXPECT_EQ(scan_status_, FingerprintScanStatus::FAILED_RETRY_NOT_ALLOWED);
  EXPECT_EQ(signal_status_, FingerprintScanStatus::FAILED_RETRY_NOT_ALLOWED);
  EXPECT_TRUE(fingerprint_manager_peer_->AuthSessionIsLocked());

  // Any further operation is denied in the auth session, regardless of the
  // scan result.
  scan_status_ = FingerprintScanStatus::SUCCESS;
  fingerprint_manager_->SetAuthScanDoneCallback(base::BindLambdaForTesting(
      [this](FingerprintScanStatus status) { scan_status_ = status; }));
  EXPECT_EQ(scan_status_, FingerprintScanStatus::FAILED_RETRY_NOT_ALLOWED);
}

}  // namespace
}  // namespace cryptohome
