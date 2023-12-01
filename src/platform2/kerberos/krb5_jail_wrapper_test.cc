// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "kerberos/krb5_jail_wrapper.h"

#include <string>

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/files/scoped_temp_dir.h>
#include <gtest/gtest.h>

#include "kerberos/fake_krb5_interface.h"
#include "kerberos/proto_bindings/kerberos_service.pb.h"

namespace kerberos {
namespace {

constexpr char kPrincipal[] = "user@EXAMPLE.COM";
constexpr char kPassword[] = "pzzwutt";
constexpr char kEmptyConfig[] = "";

}  // namespace

class Krb5JailWrapperTest : public ::testing::Test {
 public:
  Krb5JailWrapperTest() {
    auto fake_krb5 = std::make_unique<FakeKrb5Interface>();
    fake_krb5_ = fake_krb5.get();
    krb5_wrapper_ = std::make_unique<Krb5JailWrapper>(std::move(fake_krb5));

    CHECK(storage_dir_.CreateUniqueTempDir());
    krb5cc_path_ = storage_dir_.GetPath().Append("krb5cc");
    krb5conf_path_ = storage_dir_.GetPath().Append("krb5.conf");

    Krb5JailWrapper::DisableChangeUserForTesting(true);
  }
  Krb5JailWrapperTest(const Krb5JailWrapperTest&) = delete;
  Krb5JailWrapperTest& operator=(const Krb5JailWrapperTest&) = delete;

  ~Krb5JailWrapperTest() override = default;

 protected:
  // Fake Kerberos interface for testing, not owned.
  FakeKrb5Interface* fake_krb5_;

  // Wraps the fake Kerberos interface in a minijail.
  std::unique_ptr<Krb5JailWrapper> krb5_wrapper_;

  // Storage for temp files.
  base::ScopedTempDir storage_dir_;
  base::FilePath krb5cc_path_;
  base::FilePath krb5conf_path_;
};

TEST_F(Krb5JailWrapperTest, AcquireTgtSucceeds) {
  EXPECT_EQ(ERROR_NONE,
            krb5_wrapper_->AcquireTgt(kPrincipal, kPassword, krb5cc_path_,
                                      krb5conf_path_));
}

TEST_F(Krb5JailWrapperTest, AcquireTgtReturnsErrorType) {
  fake_krb5_->set_acquire_tgt_error(ERROR_UNKNOWN);
  EXPECT_EQ(ERROR_UNKNOWN,
            krb5_wrapper_->AcquireTgt(kPrincipal, kPassword, krb5cc_path_,
                                      krb5conf_path_));
}

TEST_F(Krb5JailWrapperTest, RenewTgtSucceeds) {
  EXPECT_EQ(ERROR_NONE,
            krb5_wrapper_->RenewTgt(kPrincipal, krb5cc_path_, krb5conf_path_));
}

TEST_F(Krb5JailWrapperTest, RenewTgtReturnsErrorType) {
  fake_krb5_->set_renew_tgt_error(ERROR_UNKNOWN);
  EXPECT_EQ(ERROR_UNKNOWN,
            krb5_wrapper_->RenewTgt(kPrincipal, krb5cc_path_, krb5conf_path_));
}

TEST_F(Krb5JailWrapperTest, GetTgtStatusSucceeds) {
  Krb5Interface::TgtStatus tgt_status;
  EXPECT_EQ(ERROR_NONE, krb5_wrapper_->GetTgtStatus(krb5cc_path_, &tgt_status));
}

TEST_F(Krb5JailWrapperTest, GetTgtStatusReturnsErrorType) {
  fake_krb5_->set_get_tgt_status_error(ERROR_UNKNOWN);
  Krb5Interface::TgtStatus tgt_status;
  EXPECT_EQ(ERROR_UNKNOWN,
            krb5_wrapper_->GetTgtStatus(krb5cc_path_, &tgt_status));
}

TEST_F(Krb5JailWrapperTest, GetTgtStatusReturnsTgtStatus) {
  const Krb5Interface::TgtStatus kExpectedTgtStatus(123, 234);
  fake_krb5_->set_tgt_status(kExpectedTgtStatus);
  Krb5Interface::TgtStatus tgt_status;
  EXPECT_EQ(ERROR_NONE, krb5_wrapper_->GetTgtStatus(krb5cc_path_, &tgt_status));
  EXPECT_EQ(kExpectedTgtStatus, tgt_status);
}

TEST_F(Krb5JailWrapperTest, ValidateConfigSucceeds) {
  ConfigErrorInfo error_info;
  EXPECT_EQ(ERROR_NONE,
            krb5_wrapper_->ValidateConfig(kEmptyConfig, &error_info));
}

TEST_F(Krb5JailWrapperTest, ValidateConfigReturnsErrorType) {
  fake_krb5_->set_validate_config_error(ERROR_UNKNOWN);
  ConfigErrorInfo error_info;
  EXPECT_EQ(ERROR_UNKNOWN,
            krb5_wrapper_->ValidateConfig(kEmptyConfig, &error_info));
}

TEST_F(Krb5JailWrapperTest, ValidateConfigReturnsErrorInfo) {
  ConfigErrorInfo expected_error_info;
  fake_krb5_->set_validate_config_error(ERROR_BAD_CONFIG);
  expected_error_info.set_code(CONFIG_ERROR_EXTRA_CURLY_BRACE);
  expected_error_info.set_line_index(42);
  fake_krb5_->set_config_error_info(expected_error_info);
  ConfigErrorInfo error_info;
  EXPECT_EQ(ERROR_BAD_CONFIG,
            krb5_wrapper_->ValidateConfig(kEmptyConfig, &error_info));
  EXPECT_EQ(expected_error_info.SerializeAsString(),
            error_info.SerializeAsString());
}

// Setting uid should fail in unit tests. This test verifies that things don't
// explode or block forever if jailing fails.
TEST_F(Krb5JailWrapperTest, JailFailure) {
  Krb5JailWrapper::DisableChangeUserForTesting(false);
  EXPECT_EQ(ERROR_JAIL_FAILURE,
            krb5_wrapper_->AcquireTgt(kPrincipal, kPassword, krb5cc_path_,
                                      krb5conf_path_));
}

}  // namespace kerberos
