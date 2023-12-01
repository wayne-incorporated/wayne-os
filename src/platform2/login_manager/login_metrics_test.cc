// Copyright 2012 The ChromiumOS Authors
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

  int DevicePolicyStatusCode(LoginMetrics::DevicePolicyFilesStatus status) {
    return LoginMetrics::DevicePolicyStatusCode(status);
  }

 protected:
  base::ScopedTempDir tmpdir_;
  std::unique_ptr<LoginMetrics> metrics_;
};

TEST_F(LoginMetricsTest, AllGoodConsumer) {
  LoginMetrics::DevicePolicyFilesStatus status;
  status.owner_key_file_state = LoginMetrics::PolicyFileState::kGood;
  status.policy_file_state = LoginMetrics::PolicyFileState::kGood;
  status.ownership_state = LoginMetrics::OwnershipState::kConsumer;
  // DevicePoliciesState enum:  0 = "Consumer owned good key and policy"
  EXPECT_EQ(DevicePolicyStatusCode(status), 0);
}

TEST_F(LoginMetricsTest, AllGoodEnterprise) {
  LoginMetrics::DevicePolicyFilesStatus status;
  status.owner_key_file_state = LoginMetrics::PolicyFileState::kGood;
  status.policy_file_state = LoginMetrics::PolicyFileState::kGood;
  status.ownership_state = LoginMetrics::OwnershipState::kEnterprise;
  // DevicePoliciesState enum:  9 = "Enrolled device good key and policy"
  EXPECT_EQ(DevicePolicyStatusCode(status), /*0*1 + 0*3 + 1*9=*/9);
}

TEST_F(LoginMetricsTest, KeyMissingEnterprise) {
  LoginMetrics::DevicePolicyFilesStatus status;
  status.owner_key_file_state = LoginMetrics::PolicyFileState::kNotPresent;
  status.policy_file_state =
      LoginMetrics::PolicyFileState::kMalformed;  // No key to validate with
  status.ownership_state = LoginMetrics::OwnershipState::kEnterprise;
  // DevicePoliciesState enum:  14 = "Enrolled device no key, malformed policy"
  EXPECT_EQ(DevicePolicyStatusCode(status), /*2*1 + 1*3 + 1*9=*/14);
}

TEST_F(LoginMetricsTest, PolicyMissingEnterprise) {
  LoginMetrics::DevicePolicyFilesStatus status;
  status.owner_key_file_state = LoginMetrics::PolicyFileState::kGood;
  status.policy_file_state = LoginMetrics::PolicyFileState::kNotPresent;
  status.ownership_state = LoginMetrics::OwnershipState::kEnterprise;
  // DevicePoliciesState enum:  15 = "Enrolled device good key, no policy"
  EXPECT_EQ(DevicePolicyStatusCode(status), /*0*1 + 2*3 + 1*9=*/15);
}

TEST_F(LoginMetricsTest, MaxStatusValue) {
  LoginMetrics::DevicePolicyFilesStatus status;
  status.owner_key_file_state = LoginMetrics::PolicyFileState::kNotPresent;
  status.policy_file_state = LoginMetrics::PolicyFileState::kNotPresent;
  status.ownership_state = LoginMetrics::OwnershipState::kOther;
  // DevicePoliciesState enum:  44 = "Unknown owner no key, no policy"
  EXPECT_EQ(DevicePolicyStatusCode(status), /*2*1 + 2*3 + 4*9=*/44);
}

}  // namespace login_manager
