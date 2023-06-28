// Copyright (c) 2011 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "login_manager/policy_store.h"

#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/logging.h>
#include <gtest/gtest.h>

namespace em = enterprise_management;

namespace login_manager {

class PolicyStoreTest : public ::testing::Test {
 public:
  PolicyStoreTest() {}
  PolicyStoreTest(const PolicyStoreTest&) = delete;
  PolicyStoreTest& operator=(const PolicyStoreTest&) = delete;

  ~PolicyStoreTest() override {}

  void SetUp() override {
    ASSERT_TRUE(tmpdir_.CreateUniqueTempDir());

    // Create a temporary filename that's guaranteed to not exist, but is
    // inside our scoped directory so it'll get deleted later.
    ASSERT_TRUE(base::CreateTemporaryFileInDir(tmpdir_.GetPath(), &tmpfile_));
    ASSERT_TRUE(base::DeleteFile(tmpfile_));
  }

  void TearDown() override {}

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

TEST_F(PolicyStoreTest, InitialEmptyStore) {
  PolicyStore store(tmpfile_);
  CheckExpectedPolicy(&store, em::PolicyFetchResponse());
}

TEST_F(PolicyStoreTest, CreateEmptyStore) {
  PolicyStore store(tmpfile_);
  ASSERT_TRUE(store.EnsureLoadedOrCreated());  // Should create an empty policy.
  CheckExpectedPolicy(&store, em::PolicyFetchResponse());
}

TEST_F(PolicyStoreTest, FailBrokenStore) {
  base::FilePath bad_file;
  ASSERT_TRUE(base::CreateTemporaryFileInDir(tmpdir_.GetPath(), &bad_file));
  PolicyStore store(bad_file);
  ASSERT_FALSE(store.EnsureLoadedOrCreated());
}

TEST_F(PolicyStoreTest, VerifyPolicyStorage) {
  enterprise_management::PolicyFetchResponse policy;
  policy.set_error_message("policy");
  PolicyStore store(tmpfile_);
  store.Set(policy);
  CheckExpectedPolicy(&store, policy);
}

TEST_F(PolicyStoreTest, VerifyPolicyUpdate) {
  PolicyStore store(tmpfile_);
  enterprise_management::PolicyFetchResponse policy;
  policy.set_error_message("policy");
  store.Set(policy);
  CheckExpectedPolicy(&store, policy);

  enterprise_management::PolicyFetchResponse new_policy;
  new_policy.set_error_message("new policy");
  store.Set(new_policy);
  CheckExpectedPolicy(&store, new_policy);
}

TEST_F(PolicyStoreTest, LoadStoreFromDisk) {
  PolicyStore store(tmpfile_);
  enterprise_management::PolicyFetchResponse policy;
  policy.set_error_message("policy");
  store.Set(policy);
  ASSERT_TRUE(store.Persist());
  CheckExpectedPolicy(&store, policy);

  PolicyStore store2(tmpfile_);
  ASSERT_TRUE(store2.EnsureLoadedOrCreated());
  CheckExpectedPolicy(&store2, policy);
}

TEST_F(PolicyStoreTest, DeleteRemovesFileAndData) {
  PolicyStore store(tmpfile_);
  enterprise_management::PolicyFetchResponse policy;
  policy.set_error_message("policy");
  store.Set(policy);
  EXPECT_TRUE(store.Persist());
  CheckExpectedPolicy(&store, policy);

  EXPECT_TRUE(base::PathExists(tmpfile_));
  EXPECT_TRUE(store.Delete());
  EXPECT_FALSE(base::PathExists(tmpfile_));
  CheckExpectedPolicy(&store, em::PolicyFetchResponse());
}

}  // namespace login_manager
