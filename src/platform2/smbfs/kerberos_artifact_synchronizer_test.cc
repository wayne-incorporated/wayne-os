// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <utility>

#include <authpolicy/proto_bindings/active_directory_info.pb.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <gtest/gtest.h>

#include "smbfs/fake_kerberos_artifact_client.h"
#include "smbfs/kerberos_artifact_synchronizer.h"

namespace smbfs {

namespace {

constexpr char kKrb5FileName[] = "krb5.conf";
constexpr char kCCacheFileName[] = "ccache";

constexpr char kTestUserGuid[] = "test user guid";

void ExpectSetupSuccess(bool success) {
  EXPECT_TRUE(success);
}

void ExpectSetupFailure(bool success) {
  EXPECT_FALSE(success);
}

void ExpectFileEqual(const base::FilePath& path,
                     const std::string expected_contents) {
  std::string actual_contents;
  EXPECT_TRUE(ReadFileToString(path, &actual_contents));

  EXPECT_EQ(expected_contents, actual_contents);
}

void ExpectFileNotEqual(const base::FilePath& path,
                        const std::string expected_contents) {
  std::string actual_contents;
  EXPECT_TRUE(ReadFileToString(path, &actual_contents));

  EXPECT_NE(expected_contents, actual_contents);
}

authpolicy::KerberosFiles CreateKerberosFilesProto(
    const std::string& krb5cc, const std::string& krb5conf) {
  authpolicy::KerberosFiles kerberos_files;
  kerberos_files.set_krb5cc(krb5cc);
  kerberos_files.set_krb5conf(krb5conf);
  return kerberos_files;
}

}  // namespace

class KerberosArtifactSynchronizerTest : public testing::Test {
 public:
  KerberosArtifactSynchronizerTest() {
    auto fake_ptr = std::make_unique<FakeKerberosArtifactClient>();
    fake_artifact_client_ = fake_ptr.get();

    EXPECT_TRUE(temp_dir_.CreateUniqueTempDir());

    krb5_conf_path_ = temp_dir_.GetPath().Append(kKrb5FileName);
    krb5_ccache_path_ = temp_dir_.GetPath().Append(kCCacheFileName);

    synchronizer_ = std::make_unique<KerberosArtifactSynchronizer>(
        krb5_conf_path_, krb5_ccache_path_, kTestUserGuid, std::move(fake_ptr));
  }
  KerberosArtifactSynchronizerTest(const KerberosArtifactSynchronizerTest&) =
      delete;
  KerberosArtifactSynchronizerTest& operator=(
      const KerberosArtifactSynchronizerTest&) = delete;

  ~KerberosArtifactSynchronizerTest() override = default;

 protected:
  base::ScopedTempDir temp_dir_;
  base::FilePath krb5_conf_path_;
  base::FilePath krb5_ccache_path_;
  FakeKerberosArtifactClient* fake_artifact_client_;
  std::unique_ptr<KerberosArtifactSynchronizer> synchronizer_;
};

// SetupKerberos makes a call to GetUserKerberosFiles.
TEST_F(KerberosArtifactSynchronizerTest, SetupKerberosCallsGetFiles) {
  const std::string krb5cc = "test creds";
  const std::string krb5conf = "test conf";

  authpolicy::KerberosFiles kerberos_files =
      CreateKerberosFilesProto(krb5cc, krb5conf);
  fake_artifact_client_->AddKerberosFiles(kTestUserGuid, kerberos_files);

  synchronizer_->SetupKerberos(base::BindOnce(&ExpectSetupSuccess));
  EXPECT_EQ(1, fake_artifact_client_->GetFilesMethodCallCount());
}

// SetupKerberos writes the files to the correct location.
TEST_F(KerberosArtifactSynchronizerTest, KerberosFilesWriteToCorrectLocation) {
  const std::string krb5cc = "test creds";
  const std::string krb5conf = "test conf";

  authpolicy::KerberosFiles kerberos_files =
      CreateKerberosFilesProto(krb5cc, krb5conf);
  fake_artifact_client_->AddKerberosFiles(kTestUserGuid, kerberos_files);
  synchronizer_->SetupKerberos(base::BindOnce(&ExpectSetupSuccess));

  ExpectFileEqual(krb5_conf_path_, krb5conf);
  ExpectFileEqual(krb5_ccache_path_, krb5cc);
}

// SetupKerberos connects to a signal.
TEST_F(KerberosArtifactSynchronizerTest, SetupKerberosConnectsToSignal) {
  const std::string krb5cc = "test creds";
  const std::string krb5conf = "test conf";

  authpolicy::KerberosFiles kerberos_files =
      CreateKerberosFilesProto(krb5cc, krb5conf);
  fake_artifact_client_->AddKerberosFiles(kTestUserGuid, kerberos_files);

  synchronizer_->SetupKerberos(base::BindOnce(&ExpectSetupSuccess));
  EXPECT_TRUE(fake_artifact_client_->IsConnected());
}

// Synchronizer calls GetFiles an additional time when the signal fires.
TEST_F(KerberosArtifactSynchronizerTest, GetFilesRunsOnSignalFire) {
  const std::string krb5cc = "test creds";
  const std::string krb5conf = "test conf";

  authpolicy::KerberosFiles kerberos_files =
      CreateKerberosFilesProto(krb5cc, krb5conf);
  fake_artifact_client_->AddKerberosFiles(kTestUserGuid, kerberos_files);
  synchronizer_->SetupKerberos(base::BindOnce(&ExpectSetupSuccess));
  EXPECT_EQ(1, fake_artifact_client_->GetFilesMethodCallCount());

  fake_artifact_client_->FireSignal();
  EXPECT_EQ(2, fake_artifact_client_->GetFilesMethodCallCount());
}

// Synchronizer calls GetFiles an additional time when the signal fires, but
// GetUserKerberosFiles() fails.
TEST_F(KerberosArtifactSynchronizerTest,
       GetFilesRunsOnSignalFireWithGetFilesFailure) {
  const std::string krb5cc = "test creds";
  const std::string krb5conf = "test conf";

  authpolicy::KerberosFiles kerberos_files =
      CreateKerberosFilesProto(krb5cc, krb5conf);
  fake_artifact_client_->AddKerberosFiles(kTestUserGuid, kerberos_files);
  synchronizer_->SetupKerberos(base::BindOnce(&ExpectSetupSuccess));
  EXPECT_EQ(1, fake_artifact_client_->GetFilesMethodCallCount());

  fake_artifact_client_->ResetKerberosFiles();
  fake_artifact_client_->FireSignal();
  EXPECT_EQ(2, fake_artifact_client_->GetFilesMethodCallCount());
}

// Synchronizer overwrites the Kerberos files when the signal fires.
TEST_F(KerberosArtifactSynchronizerTest, GetFilesOverwritesOldFiles) {
  const std::string krb5cc = "test creds";
  const std::string krb5conf = "test conf";

  authpolicy::KerberosFiles kerberos_files =
      CreateKerberosFilesProto(krb5cc, krb5conf);
  fake_artifact_client_->AddKerberosFiles(kTestUserGuid, kerberos_files);
  synchronizer_->SetupKerberos(base::BindOnce(&ExpectSetupSuccess));

  ExpectFileEqual(krb5_conf_path_, krb5conf);
  ExpectFileEqual(krb5_ccache_path_, krb5cc);

  const std::string new_krb5cc = "new test creds";
  const std::string new_krb5conf = "new test conf";

  authpolicy::KerberosFiles new_kerberos_files =
      CreateKerberosFilesProto(new_krb5cc, new_krb5conf);
  fake_artifact_client_->AddKerberosFiles(kTestUserGuid, new_kerberos_files);
  fake_artifact_client_->FireSignal();

  ExpectFileNotEqual(krb5_conf_path_, krb5conf);
  ExpectFileNotEqual(krb5_ccache_path_, krb5cc);

  ExpectFileEqual(krb5_conf_path_, new_krb5conf);
  ExpectFileEqual(krb5_ccache_path_, new_krb5cc);
}

// SetupKerberos fails when the getting the user's kerberos files fails.
TEST_F(KerberosArtifactSynchronizerTest, SetupKerberosFailsKerberosFilesEmpty) {
  authpolicy::KerberosFiles kerberos_files;
  fake_artifact_client_->AddKerberosFiles(kTestUserGuid, kerberos_files);

  synchronizer_->SetupKerberos(base::BindOnce(&ExpectSetupFailure));
}

// Synchronizer calls GetFiles an additional time when the signal fires, but
// files are empty.
TEST_F(KerberosArtifactSynchronizerTest,
       GetFilesRunsOnSignalFireWithFilesEmpty) {
  const std::string krb5cc = "test creds";
  const std::string krb5conf = "test conf";

  authpolicy::KerberosFiles kerberos_files =
      CreateKerberosFilesProto(krb5cc, krb5conf);
  fake_artifact_client_->AddKerberosFiles(kTestUserGuid, kerberos_files);
  synchronizer_->SetupKerberos(base::BindOnce(&ExpectSetupSuccess));
  EXPECT_EQ(1, fake_artifact_client_->GetFilesMethodCallCount());

  fake_artifact_client_->ResetKerberosFiles();
  fake_artifact_client_->AddKerberosFiles(kTestUserGuid, {});
  fake_artifact_client_->FireSignal();
  EXPECT_EQ(2, fake_artifact_client_->GetFilesMethodCallCount());
}

}  // namespace smbfs
