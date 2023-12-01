// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "login_manager/resilient_policy_store.h"

#include <memory>
#include <string>
#include <utility>

#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/logging.h>
#include <brillo/files/file_util.h>
#include <gtest/gtest.h>

#include "login_manager/mock_metrics.h"
#include "login_manager/system_utils_impl.h"

namespace em = enterprise_management;

namespace login_manager {

class ResilientPolicyStoreTest : public ::testing::Test {
 public:
  ResilientPolicyStoreTest() {}
  ResilientPolicyStoreTest(const ResilientPolicyStoreTest&) = delete;
  ResilientPolicyStoreTest& operator=(const ResilientPolicyStoreTest&) = delete;

  virtual ~ResilientPolicyStoreTest() {}

  virtual void SetUp() {
    ASSERT_TRUE(tmpdir_.CreateUniqueTempDir());

    // Create a temporary filename that's guaranteed to not exist, but is
    // inside our scoped directory so it'll get deleted later.
    ASSERT_TRUE(base::CreateTemporaryFileInDir(tmpdir_.GetPath(), &tmpfile_));
    ASSERT_TRUE(brillo::DeleteFile(tmpfile_));
  }

  virtual void TearDown() {}

  void CheckExpectedPolicy(PolicyStore* store,
                           const em::PolicyFetchResponse& policy) {
    std::string serialized;
    ASSERT_TRUE(policy.SerializeToString(&serialized));
    std::string serialized_from;
    ASSERT_TRUE(store->Get().SerializeToString(&serialized_from));
    EXPECT_EQ(serialized, serialized_from);
  }

  base::ScopedTempDir tmpdir_;
  base::FilePath tmpfile_;
};

TEST_F(ResilientPolicyStoreTest, LoadResilientMissingPolicy) {
  MockMetrics metrics;
  ResilientPolicyStore store(tmpfile_, &metrics);
  ASSERT_TRUE(store.EnsureLoadedOrCreated());
}

TEST_F(ResilientPolicyStoreTest, CheckDeleteAtLoadResilient) {
  MockMetrics metrics;
  ResilientPolicyStore store(tmpfile_, &metrics);
  std::unique_ptr<policy::DevicePolicyImpl> device_policy =
      std::make_unique<policy::DevicePolicyImpl>();
  device_policy->set_policy_path_for_testing(tmpfile_);
  device_policy->set_verify_policy_for_testing(false);
  store.set_device_policy_for_testing(std::move(device_policy));

  enterprise_management::PolicyFetchResponse policy;
  enterprise_management::PolicyData policy_data;
  enterprise_management::ChromeDeviceSettingsProto settings;
  policy_data.set_username("test_user");
  policy_data.set_request_token("secret_token");
  std::string settings_str;
  settings.SerializeToString(&settings_str);
  policy_data.set_policy_value(settings_str);
  policy.set_policy_data(policy_data.SerializeAsString());

  store.Set(policy);

  ASSERT_TRUE(store.Persist());
  CheckExpectedPolicy(&store, policy);

  // Create the file with next index, containing some invalid data.
  base::FilePath policy_path2 = base::FilePath(tmpfile_.value() + ".2");
  SystemUtilsImpl utils;
  utils.AtomicFileWrite(policy_path2, "invalid_data");

  // Check that LoadResilient succeeds and ignores the last file.
  ASSERT_TRUE(store.EnsureLoadedOrCreated());
  CheckExpectedPolicy(&store, policy);

  // Check that the last file was deleted.
  ASSERT_FALSE(base::PathExists(policy_path2));
}

TEST_F(ResilientPolicyStoreTest, CheckCleanupFromPersistResilient) {
  MockMetrics metrics;
  ResilientPolicyStore store(tmpfile_, &metrics);
  enterprise_management::PolicyFetchResponse policy;
  policy.set_error_message("foo");
  store.Set(policy);

  base::FilePath policy_path1(tmpfile_.value() + ".1");
  base::FilePath policy_path2(tmpfile_.value() + ".2");
  base::FilePath policy_path3(tmpfile_.value() + ".3");
  base::FilePath policy_path4(tmpfile_.value() + ".4");

  ASSERT_TRUE(store.Persist());
  CheckExpectedPolicy(&store, policy);
  ASSERT_TRUE(base::PathExists(policy_path1));

  // Change the policy data and store again, expecting to have a new file
  // because cleanup temporary file fails to be created in testing environment.
  policy.set_error_message("foo2");
  store.Set(policy);
  ASSERT_TRUE(store.Persist());
  ASSERT_TRUE(base::PathExists(policy_path2));

  // Create the file with next index, containing some invalid data.
  SystemUtilsImpl utils;
  utils.AtomicFileWrite(policy_path3, "invalid_data");

  // Change the policy data and store again, having a new file.
  policy.set_error_message("foo");
  store.Set(policy);
  ASSERT_TRUE(store.Persist());
  ASSERT_TRUE(base::PathExists(policy_path4));

  // The last Persist resilient should have done the cleanup and removed the
  // oldest file since the limit was reached.
  ASSERT_FALSE(base::PathExists(policy_path1));
  ASSERT_TRUE(base::PathExists(policy_path2));
  ASSERT_TRUE(base::PathExists(policy_path3));
}

}  // namespace login_manager
