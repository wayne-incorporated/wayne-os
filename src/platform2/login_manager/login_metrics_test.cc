// Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "login_manager/login_metrics.h"

#include <memory>

#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <gtest/gtest.h>

namespace login_manager {

struct UserTypeTestParams {
  UserTypeTestParams(LoginMetrics::UserType t, bool d, bool g, bool o)
      : expected_type(t), dev_mode(d), guest(g), owner(o) {}
  LoginMetrics::UserType expected_type;
  bool dev_mode;
  bool guest;
  bool owner;
};

class LoginMetricsTest : public testing::Test {
 public:
  LoginMetricsTest() {}
  LoginMetricsTest(const LoginMetricsTest&) = delete;
  LoginMetricsTest& operator=(const LoginMetricsTest&) = delete;

  ~LoginMetricsTest() override {}

  void SetUp() override {
    ASSERT_TRUE(tmpdir_.CreateUniqueTempDir());
    metrics_.reset(new LoginMetrics(tmpdir_.GetPath()));
  }

  int PolicyFilesStatusCode(LoginMetrics::PolicyFilesStatus status) {
    return LoginMetrics::PolicyFilesStatusCode(status);
  }

 protected:
  base::ScopedTempDir tmpdir_;
  std::unique_ptr<LoginMetrics> metrics_;
};

TEST_F(LoginMetricsTest, AllGood) {
  LoginMetrics::PolicyFilesStatus status;
  status.owner_key_file_state = LoginMetrics::GOOD;
  status.policy_file_state = LoginMetrics::GOOD;
  status.defunct_prefs_file_state = LoginMetrics::GOOD;
  EXPECT_EQ(PolicyFilesStatusCode(status), 0 /* 000 in base-4 */);
}

TEST_F(LoginMetricsTest, AllNotThere) {
  LoginMetrics::PolicyFilesStatus status;
  EXPECT_EQ(PolicyFilesStatusCode(status), 42 /* 222 in base-4 */);
}

TEST_F(LoginMetricsTest, Bug24361) {
  LoginMetrics::PolicyFilesStatus status;
  status.owner_key_file_state = LoginMetrics::GOOD;
  status.policy_file_state = LoginMetrics::NOT_PRESENT;
  status.defunct_prefs_file_state = LoginMetrics::GOOD;
  EXPECT_EQ(PolicyFilesStatusCode(status), 8 /* 020 in base-4 */);
}

TEST_F(LoginMetricsTest, NoPrefs) {
  LoginMetrics::PolicyFilesStatus status;
  status.owner_key_file_state = LoginMetrics::GOOD;
  status.policy_file_state = LoginMetrics::GOOD;
  status.defunct_prefs_file_state = LoginMetrics::NOT_PRESENT;
  EXPECT_EQ(PolicyFilesStatusCode(status), 2 /* 002 in base-4 */);
}

TEST_F(LoginMetricsTest, SendStatus) {
  LoginMetrics::PolicyFilesStatus status;
  EXPECT_TRUE(metrics_->SendPolicyFilesStatus(status));
  EXPECT_FALSE(metrics_->SendPolicyFilesStatus(status));
}

class UserTypeTest : public ::testing::TestWithParam<UserTypeTestParams> {
 public:
  UserTypeTest() {}
  virtual ~UserTypeTest() {}

  int LoginUserTypeCode(bool dev_mode, bool guest, bool owner) {
    return LoginMetrics::LoginUserTypeCode(dev_mode, guest, owner);
  }
};

TEST_P(UserTypeTest, CalculateUserType) {
  EXPECT_TRUE(GetParam().expected_type == LoginUserTypeCode(GetParam().dev_mode,
                                                            GetParam().guest,
                                                            GetParam().owner));
}

INSTANTIATE_TEST_SUITE_P(DevGuest,
                         UserTypeTest,
                         ::testing::Values(UserTypeTestParams(
                             LoginMetrics::DEV_GUEST, true, true, false)));

INSTANTIATE_TEST_SUITE_P(DevOwner,
                         UserTypeTest,
                         ::testing::Values(UserTypeTestParams(
                             LoginMetrics::DEV_OWNER, true, false, true)));

INSTANTIATE_TEST_SUITE_P(DevOther,
                         UserTypeTest,
                         ::testing::Values(UserTypeTestParams(
                             LoginMetrics::DEV_OTHER, true, false, false)));

INSTANTIATE_TEST_SUITE_P(Guest,
                         UserTypeTest,
                         ::testing::Values(UserTypeTestParams(
                             LoginMetrics::GUEST, false, true, false)));

INSTANTIATE_TEST_SUITE_P(Owner,
                         UserTypeTest,
                         ::testing::Values(UserTypeTestParams(
                             LoginMetrics::OWNER, false, false, true)));

INSTANTIATE_TEST_SUITE_P(Other,
                         UserTypeTest,
                         ::testing::Values(UserTypeTestParams(
                             LoginMetrics::OTHER, false, false, false)));

}  // namespace login_manager
