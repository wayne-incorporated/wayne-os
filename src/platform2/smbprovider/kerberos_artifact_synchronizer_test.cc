// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <utility>

#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <gtest/gtest.h>
#include <kerberos/proto_bindings/kerberos_service.pb.h>

#include "smbprovider/fake_kerberos_artifact_client.h"
#include "smbprovider/kerberos_artifact_synchronizer.h"
#include "smbprovider/smbprovider_test_helper.h"

namespace smbprovider {

namespace {

void ExpectSetupSuccess(bool success) {
  EXPECT_TRUE(success);
}

void ExpectSetupFailure(bool success) {
  EXPECT_FALSE(success);
}

void IncrementInt(int* count, bool expected_success, bool success) {
  EXPECT_EQ(expected_success, success);
  (*count)++;
}

}  // namespace

class KerberosArtifactSynchronizerTest : public testing::Test {
 public:
  KerberosArtifactSynchronizerTest() {
    EXPECT_TRUE(temp_dir_.CreateUniqueTempDir());

    krb5_conf_path_ = CreateKrb5ConfPath(temp_dir_.GetPath());
    krb5_ccache_path_ = CreateKrb5CCachePath(temp_dir_.GetPath());

    Initialize(false /* allow_credentials_update */);
  }
  KerberosArtifactSynchronizerTest(const KerberosArtifactSynchronizerTest&) =
      delete;
  KerberosArtifactSynchronizerTest& operator=(
      const KerberosArtifactSynchronizerTest&) = delete;

  ~KerberosArtifactSynchronizerTest() override = default;

  void Initialize(bool allow_credentials_update) {
    auto fake_ptr = std::make_unique<FakeKerberosArtifactClient>();
    fake_artifact_client_ = fake_ptr.get();

    synchronizer_ = std::make_unique<KerberosArtifactSynchronizer>(
        krb5_conf_path_, krb5_ccache_path_, std::move(fake_ptr),
        allow_credentials_update);
  }

 protected:
  base::ScopedTempDir temp_dir_;
  std::string krb5_conf_path_;
  std::string krb5_ccache_path_;
  FakeKerberosArtifactClient* fake_artifact_client_;
  std::unique_ptr<KerberosArtifactSynchronizer> synchronizer_;
};

// SetupKerberos makes a call to GetUserKerberosFiles.
TEST_F(KerberosArtifactSynchronizerTest, SetupKerberosCallsGetFiles) {
  const std::string user = "test user";
  const std::string krb5cc = "test creds";
  const std::string krb5conf = "test conf";

  kerberos::KerberosFiles kerberos_files =
      CreateKerberosFilesProto(krb5cc, krb5conf);
  fake_artifact_client_->AddKerberosFiles(user, kerberos_files);

  synchronizer_->SetupKerberos(user, base::BindOnce(&ExpectSetupSuccess));
  EXPECT_EQ(1, fake_artifact_client_->GetFilesMethodCallCount());
}

// SetupKerberos writes the files to the correct location.
TEST_F(KerberosArtifactSynchronizerTest, KerberosFilesWriteToCorrectLocation) {
  const std::string user = "test user";
  const std::string krb5cc = "test creds";
  const std::string krb5conf = "test conf";

  kerberos::KerberosFiles kerberos_files =
      CreateKerberosFilesProto(krb5cc, krb5conf);
  fake_artifact_client_->AddKerberosFiles(user, kerberos_files);
  synchronizer_->SetupKerberos(user, base::BindOnce(&ExpectSetupSuccess));

  ExpectFileEqual(krb5_conf_path_, krb5conf);
  ExpectFileEqual(krb5_ccache_path_, krb5cc);
}

// SetupKerberos connects to a signal.
TEST_F(KerberosArtifactSynchronizerTest, SetupKerberosConnectsToSignal) {
  const std::string user = "test user";
  const std::string krb5cc = "test creds";
  const std::string krb5conf = "test conf";

  kerberos::KerberosFiles kerberos_files =
      CreateKerberosFilesProto(krb5cc, krb5conf);
  fake_artifact_client_->AddKerberosFiles(user, kerberos_files);

  synchronizer_->SetupKerberos(user, base::BindOnce(&ExpectSetupSuccess));
  EXPECT_TRUE(fake_artifact_client_->IsConnected());
}

// Synchronizer calls GetFiles an additional time when the signal fires.
TEST_F(KerberosArtifactSynchronizerTest, GetFilesRunsOnSignalFire) {
  const std::string user = "test user";
  const std::string krb5cc = "test creds";
  const std::string krb5conf = "test conf";

  kerberos::KerberosFiles kerberos_files =
      CreateKerberosFilesProto(krb5cc, krb5conf);
  fake_artifact_client_->AddKerberosFiles(user, kerberos_files);
  synchronizer_->SetupKerberos(user, base::BindOnce(&ExpectSetupSuccess));
  int setup_callback_count = 0;
  synchronizer_->SetupKerberos(
      user, base::BindOnce(&IncrementInt, &setup_callback_count, true));

  EXPECT_EQ(1, fake_artifact_client_->GetFilesMethodCallCount());

  fake_artifact_client_->FireSignal();

  EXPECT_EQ(2, fake_artifact_client_->GetFilesMethodCallCount());
  EXPECT_EQ(1, setup_callback_count);
}

// Synchronizer calls GetFiles an additional time when the signal fires
// with credentials update allowed.
TEST_F(KerberosArtifactSynchronizerTest,
       GetFilesRunsOnSignalFireUpdateAllowed) {
  Initialize(true /* allow_credentials_update */);

  const std::string user = "test user";
  const std::string krb5cc = "test creds";
  const std::string krb5conf = "test conf";

  kerberos::KerberosFiles kerberos_files =
      CreateKerberosFilesProto(krb5cc, krb5conf);
  fake_artifact_client_->AddKerberosFiles(user, kerberos_files);
  synchronizer_->SetupKerberos(user, base::BindOnce(&ExpectSetupSuccess));
  int setup_callback_count = 0;
  synchronizer_->SetupKerberos(
      user, base::BindOnce(&IncrementInt, &setup_callback_count, true));

  EXPECT_EQ(1, fake_artifact_client_->GetFilesMethodCallCount());

  fake_artifact_client_->FireSignal();

  EXPECT_EQ(2, fake_artifact_client_->GetFilesMethodCallCount());
  EXPECT_EQ(1, setup_callback_count);
}

// Synchronizer calls GetFiles an additional time when the signal fires, but
// GetUserKerberosFiles() fails.
TEST_F(KerberosArtifactSynchronizerTest,
       GetFilesRunsOnSignalFireWithGetFilesFailure) {
  const std::string user = "test user";
  const std::string krb5cc = "test creds";
  const std::string krb5conf = "test conf";

  kerberos::KerberosFiles kerberos_files =
      CreateKerberosFilesProto(krb5cc, krb5conf);
  fake_artifact_client_->AddKerberosFiles(user, kerberos_files);
  synchronizer_->SetupKerberos(user, base::BindOnce(&ExpectSetupSuccess));
  int setup_callback_count = 0;
  synchronizer_->SetupKerberos(
      user, base::BindOnce(&IncrementInt, &setup_callback_count, true));

  EXPECT_EQ(1, fake_artifact_client_->GetFilesMethodCallCount());

  fake_artifact_client_->ResetKerberosFiles();
  fake_artifact_client_->FireSignal();

  EXPECT_EQ(2, fake_artifact_client_->GetFilesMethodCallCount());
  EXPECT_EQ(1, setup_callback_count);
}

// Synchronizer overwrites the Kerberos files when the signal fires.
TEST_F(KerberosArtifactSynchronizerTest, GetFilesOverwritesOldFiles) {
  const std::string user = "test user";
  const std::string krb5cc = "test creds";
  const std::string krb5conf = "test conf";

  kerberos::KerberosFiles kerberos_files =
      CreateKerberosFilesProto(krb5cc, krb5conf);
  fake_artifact_client_->AddKerberosFiles(user, kerberos_files);
  synchronizer_->SetupKerberos(user, base::BindOnce(&ExpectSetupSuccess));

  ExpectFileEqual(krb5_conf_path_, krb5conf);
  ExpectFileEqual(krb5_ccache_path_, krb5cc);

  const std::string new_krb5cc = "new test creds";
  const std::string new_krb5conf = "new test conf";

  kerberos::KerberosFiles new_kerberos_files =
      CreateKerberosFilesProto(new_krb5cc, new_krb5conf);
  fake_artifact_client_->AddKerberosFiles(user, new_kerberos_files);
  fake_artifact_client_->FireSignal();

  ExpectFileNotEqual(krb5_conf_path_, krb5conf);
  ExpectFileNotEqual(krb5_ccache_path_, krb5cc);

  ExpectFileEqual(krb5_conf_path_, new_krb5conf);
  ExpectFileEqual(krb5_ccache_path_, new_krb5cc);
}

// SetupKerberos fails when the getting the user's kerberos files fails.
TEST_F(KerberosArtifactSynchronizerTest, SetupKerberosFailsKerberosFilesEmpty) {
  const std::string user = "test user";

  kerberos::KerberosFiles kerberos_files;
  fake_artifact_client_->AddKerberosFiles(user, kerberos_files);

  synchronizer_->SetupKerberos(user, base::BindOnce(&ExpectSetupFailure));
}

// SetupKerberos is called twice for the same user.
TEST_F(KerberosArtifactSynchronizerTest, SetupKerberosCalledTwice) {
  const std::string user = "test user";
  const std::string krb5cc = "test creds";
  const std::string krb5conf = "test conf";

  kerberos::KerberosFiles kerberos_files =
      CreateKerberosFilesProto(krb5cc, krb5conf);
  fake_artifact_client_->AddKerberosFiles(user, kerberos_files);

  synchronizer_->SetupKerberos(user, base::BindOnce(&ExpectSetupSuccess));
  synchronizer_->SetupKerberos(user, base::BindOnce(&ExpectSetupSuccess));
  EXPECT_EQ(1, fake_artifact_client_->GetFilesMethodCallCount());
}

// SetupKerberos is called twice for different users.
TEST_F(KerberosArtifactSynchronizerTest,
       SetupKerberosCalledTwiceDifferentUsers) {
  const std::string user = "test user";
  const std::string user2 = "test user 2";
  const std::string krb5cc = "test creds";
  const std::string krb5conf = "test conf";

  kerberos::KerberosFiles kerberos_files =
      CreateKerberosFilesProto(krb5cc, krb5conf);
  fake_artifact_client_->AddKerberosFiles(user, kerberos_files);
  fake_artifact_client_->AddKerberosFiles(user2, kerberos_files);

  synchronizer_->SetupKerberos(user, base::BindOnce(&ExpectSetupSuccess));
  synchronizer_->SetupKerberos(user2, base::BindOnce(&ExpectSetupFailure));
  EXPECT_EQ(1, fake_artifact_client_->GetFilesMethodCallCount());
}

// SetupKerberos is called twice for different users with credentials update
// allowed.
TEST_F(KerberosArtifactSynchronizerTest,
       SetupKerberosCalledTwiceDifferentUsersUpdateAllowed) {
  Initialize(true /* allow_credentials_update */);

  const std::string user = "test user";
  const std::string user2 = "test user 2";
  const std::string krb5cc = "test creds";
  const std::string krb5conf = "test conf";

  kerberos::KerberosFiles kerberos_files =
      CreateKerberosFilesProto(krb5cc, krb5conf);
  fake_artifact_client_->AddKerberosFiles(user, kerberos_files);
  fake_artifact_client_->AddKerberosFiles(user2, kerberos_files);

  synchronizer_->SetupKerberos(user, base::BindOnce(&ExpectSetupSuccess));
  synchronizer_->SetupKerberos(user2, base::BindOnce(&ExpectSetupSuccess));
  EXPECT_EQ(2, fake_artifact_client_->GetFilesMethodCallCount());
}

// Remove Kerberos files with credentials update allowed.
TEST_F(KerberosArtifactSynchronizerTest, RemoveFilesUpdateAllowed) {
  Initialize(true /* allow_credentials_update */);

  const std::string user = "test user";
  const std::string krb5cc = "test creds";
  const std::string krb5conf = "test conf";

  kerberos::KerberosFiles kerberos_files =
      CreateKerberosFilesProto(krb5cc, krb5conf);
  fake_artifact_client_->AddKerberosFiles(user, kerberos_files);
  synchronizer_->SetupKerberos(user, base::BindOnce(&ExpectSetupSuccess));

  ExpectFileEqual(krb5_conf_path_, krb5conf);
  ExpectFileEqual(krb5_ccache_path_, krb5cc);

  // Remove by passing empty |account_identifier|.
  synchronizer_->SetupKerberos(std::string() /* account_identifier */,
                               base::BindOnce(&ExpectSetupSuccess));

  // Expect credentials files not exist.
  EXPECT_FALSE(base::PathExists(base::FilePath(krb5_conf_path_)));
  EXPECT_FALSE(base::PathExists(base::FilePath(krb5_ccache_path_)));
}

// Remove Kerberos files with credentials update not allowed.
TEST_F(KerberosArtifactSynchronizerTest, RemoveFilesUpdateNotAllowed) {
  const std::string user = "test user";
  const std::string krb5cc = "test creds";
  const std::string krb5conf = "test conf";

  kerberos::KerberosFiles kerberos_files =
      CreateKerberosFilesProto(krb5cc, krb5conf);
  fake_artifact_client_->AddKerberosFiles(user, kerberos_files);
  synchronizer_->SetupKerberos(user, base::BindOnce(&ExpectSetupSuccess));

  ExpectFileEqual(krb5_conf_path_, krb5conf);
  ExpectFileEqual(krb5_ccache_path_, krb5cc);

  // Try to remove by passing empty |account_identifier|, expect to fail.
  synchronizer_->SetupKerberos(std::string() /* account_identifier */,
                               base::BindOnce(&ExpectSetupFailure));

  // Expect files to be unchanged.
  ExpectFileEqual(krb5_conf_path_, krb5conf);
  ExpectFileEqual(krb5_ccache_path_, krb5cc);
}

// Setup Kerberos without a ticket by passing empty credentials
// when updates are allowed, than add a ticket and call setup again.
TEST_F(KerberosArtifactSynchronizerTest, SetupKerberosNoTicketUpdateAllowed) {
  Initialize(true /* allow_credentials_update */);

  // Setup first time with empty |account_identifier|, expect success.
  synchronizer_->SetupKerberos(std::string() /* account_identifier */,
                               base::BindOnce(&ExpectSetupSuccess));

  // Expect credentials files not exist.
  EXPECT_FALSE(base::PathExists(base::FilePath(krb5_conf_path_)));
  EXPECT_FALSE(base::PathExists(base::FilePath(krb5_ccache_path_)));

  const std::string user = "test user";
  const std::string krb5cc = "test creds";
  const std::string krb5conf = "test conf";

  kerberos::KerberosFiles kerberos_files =
      CreateKerberosFilesProto(krb5cc, krb5conf);
  fake_artifact_client_->AddKerberosFiles(user, kerberos_files);

  // Setup again with valid ticket, expect success.
  synchronizer_->SetupKerberos(user, base::BindOnce(&ExpectSetupSuccess));

  ExpectFileEqual(krb5_conf_path_, krb5conf);
  ExpectFileEqual(krb5_ccache_path_, krb5cc);
}

// SetupKerberos without a ticket by passing empty credentials
// when updates are not allowed.
TEST_F(KerberosArtifactSynchronizerTest,
       SetupKerberosNoTicketUpdateNotAllowed) {
  // If updates are not allowed, it is expected that credentials are valid
  // from the start. Therefore, setting up Kerberos with empty
  // |account_identifier| should fail.
  synchronizer_->SetupKerberos(std::string() /* account_identifier */,
                               base::BindOnce(&ExpectSetupFailure));

  // Expect credentials files not exist.
  EXPECT_FALSE(base::PathExists(base::FilePath(krb5_conf_path_)));
  EXPECT_FALSE(base::PathExists(base::FilePath(krb5_ccache_path_)));
}

}  // namespace smbprovider
