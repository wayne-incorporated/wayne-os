// Copyright 2018 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "login_manager/resilient_policy_store.h"

#include <string>

#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/logging.h>
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
    ASSERT_TRUE(base::DeleteFile(tmpfile_));
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
  enterprise_management::PolicyFetchResponse policy;
  policy.set_error_message("foo");
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

  // The last Persist resilient should have done the cleanup, which means the
  // file with index 2 is not present anymore, being invalid.
  ASSERT_FALSE(base::PathExists(policy_path3));

  // Check that file with base policy file name still exists, but will be
  // cleaned up after next persist.
  ASSERT_TRUE(base::PathExists(policy_path1));
  policy.set_error_message("foo2");
  store.Set(policy);
  ASSERT_TRUE(store.Persist());
  ASSERT_TRUE(base::PathExists(policy_path4));
  ASSERT_FALSE(base::PathExists(policy_path1));
}

}  // namespace login_manager
