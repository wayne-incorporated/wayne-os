// Copyright 2010 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <unistd.h>

#include <cstring>
#include <utility>

#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <policy/libpolicy.h>
#include <policy/mock_device_policy.h>

#include "metrics/c_metrics_library.h"
#include "metrics/metrics_library.h"
#include "metrics/metrics_library_mock.h"

using base::FilePath;
using ::testing::_;
using ::testing::AnyNumber;
using ::testing::Return;

namespace {
const FilePath kTestUMAEventsFile("test-uma-events");
const FilePath kTestConsentIdFile("test-consent-id");
const char kValidGuidOld[] = "56ff27bf7f774919b08488416d597fd8";
const char kValidGuid[] = "56ff27bf-7f77-4919-b084-88416d597fd8";
}  // namespace

ACTION_P(SetMetricsPolicy, enabled) {
  *arg0 = enabled;
  return true;
}

class MetricsLibraryTest : public testing::Test {
 protected:
  void SetUp() override {
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
    test_dir_ = temp_dir_.GetPath();

    lib_.SetDaemonStoreForTest(test_dir_);
    EXPECT_TRUE(base::CreateDirectory(test_dir_.Append("hash")));

    ASSERT_TRUE(appsync_temp_dir_.CreateUniqueTempDir());
    appsync_test_dir_ = appsync_temp_dir_.GetPath();

    lib_.SetAppSyncDaemonStoreForTest(appsync_test_dir_);
    EXPECT_TRUE(base::CreateDirectory(appsync_test_dir_.Append("hash")));

    test_consent_id_file_ = test_dir_.Append(kTestConsentIdFile);
    lib_.SetConsentFileForTest(test_consent_id_file_);
    SynchronousMetricsWriter& writer =
        *static_cast<SynchronousMetricsWriter*>(lib_.metrics_writer_.get());
    EXPECT_FALSE(writer.uma_events_file_.empty());
    lib_.Init();
    EXPECT_FALSE(writer.uma_events_file_.empty());
    test_uma_events_file_ = test_dir_.Append(kTestUMAEventsFile);
    lib_.SetOutputFile(test_uma_events_file_.value());
    EXPECT_EQ(0, WriteFile(test_uma_events_file_, "", 0));
    device_policy_ = new policy::MockDevicePolicy();
    EXPECT_CALL(*device_policy_, LoadPolicy(/*delete_invalid_files=*/false))
        .Times(AnyNumber())
        .WillRepeatedly(Return(true));
    EXPECT_CALL(*device_policy_, GetMetricsEnabled(_))
        .Times(AnyNumber())
        .WillRepeatedly(SetMetricsPolicy(true));
    lib_.SetPolicyProvider(new policy::PolicyProvider(
        std::unique_ptr<policy::MockDevicePolicy>(device_policy_)));
    // Defeat metrics enabled caching between tests.
    ClearCachedEnabledTime();
    ClearCachedAppSyncEnabledTime();
  }

  void VerifyEnabledCacheHit(bool to_value);
  void VerifyEnabledCacheEviction(bool to_value);

  void ClearCachedEnabledTime() {
    // Defeat metrics enabled caching.
    lib_.cached_enabled_time_ = 0;
  }

  void ClearCachedAppSyncEnabledTime() {
    // Delete cached AppSync opt-in.
    lib_.cached_appsync_enabled_time_ = 0;
  }

  void SetPerUserConsent(bool value) {
    if (value) {
      EXPECT_EQ(1, WriteFile(test_dir_.Append("hash/consent-enabled"), "1", 1));
    } else {
      EXPECT_EQ(1, WriteFile(test_dir_.Append("hash/consent-enabled"), "0", 1));
    }
  }

  void SetPerUserAppSyncOptin(bool value) {
    if (value) {
      EXPECT_EQ(1,
                WriteFile(appsync_test_dir_.Append("hash/opted-in"), "1", 1));
    } else {
      EXPECT_EQ(1,
                WriteFile(appsync_test_dir_.Append("hash/opted-in"), "0", 1));
    }
  }

  MetricsLibrary lib_;
  policy::MockDevicePolicy* device_policy_;  // Not owned.
  base::ScopedTempDir temp_dir_;
  base::ScopedTempDir appsync_temp_dir_;
  base::FilePath test_dir_;
  base::FilePath appsync_test_dir_;
  base::FilePath test_uma_events_file_;
  base::FilePath test_consent_id_file_;
};

// Reject symlinks even if they're to normal files.
TEST_F(MetricsLibraryTest, ConsentIdInvalidSymlinkPath) {
  std::string id;
  base::DeleteFile(test_consent_id_file_);
  ASSERT_EQ(symlink("/bin/sh", test_consent_id_file_.value().c_str()), 0);
  ASSERT_FALSE(lib_.ConsentId(&id));
}

// Reject non-files (like directories).
TEST_F(MetricsLibraryTest, ConsentIdInvalidDirPath) {
  std::string id;
  base::DeleteFile(test_consent_id_file_);
  ASSERT_EQ(mkdir(test_consent_id_file_.value().c_str(), 0755), 0);
  ASSERT_FALSE(lib_.ConsentId(&id));
}

// Reject valid files full of invalid uuids.
TEST_F(MetricsLibraryTest, ConsentIdInvalidContent) {
  std::string id;
  base::DeleteFile(test_consent_id_file_);

  ASSERT_EQ(base::WriteFile(test_consent_id_file_, "", 0), 0);
  ASSERT_FALSE(lib_.ConsentId(&id));

  ASSERT_EQ(base::WriteFile(test_consent_id_file_, "asdf", 4), 4);
  ASSERT_FALSE(lib_.ConsentId(&id));

  char buf[100];
  memset(buf, '0', sizeof(buf));

  // Reject too long UUIDs that lack dashes.
  ASSERT_EQ(base::WriteFile(test_consent_id_file_, buf, 36), 36);
  ASSERT_FALSE(lib_.ConsentId(&id));

  // Reject very long UUIDs.
  ASSERT_EQ(base::WriteFile(test_consent_id_file_, buf, sizeof(buf)),
            sizeof(buf));
  ASSERT_FALSE(lib_.ConsentId(&id));
}

// Accept old consent ids.
TEST_F(MetricsLibraryTest, ConsentIdValidContentOld) {
  std::string id;
  base::DeleteFile(test_consent_id_file_);
  ASSERT_GT(base::WriteFile(test_consent_id_file_, kValidGuidOld,
                            strlen(kValidGuidOld)),
            0);
  ASSERT_TRUE(lib_.ConsentId(&id));
  ASSERT_EQ(id, kValidGuidOld);
}

// Accept current consent ids.
TEST_F(MetricsLibraryTest, ConsentIdValidContent) {
  std::string id;
  base::DeleteFile(test_consent_id_file_);
  ASSERT_GT(
      base::WriteFile(test_consent_id_file_, kValidGuid, strlen(kValidGuid)),
      0);
  ASSERT_TRUE(lib_.ConsentId(&id));
  ASSERT_EQ(id, kValidGuid);
}

// Accept current consent ids (including a newline).
TEST_F(MetricsLibraryTest, ConsentIdValidContentNewline) {
  std::string id;
  std::string outid = std::string(kValidGuid) + "\n";
  base::DeleteFile(test_consent_id_file_);
  ASSERT_GT(base::WriteFile(test_consent_id_file_, outid.c_str(), outid.size()),
            0);
  ASSERT_TRUE(lib_.ConsentId(&id));
  ASSERT_EQ(id, kValidGuid);
}

// MetricsEnabled policy not present, enterprise managed
// -> AreMetricsEnabled returns true.
TEST_F(MetricsLibraryTest, AreMetricsEnabledTrueNoPolicyManaged) {
  EXPECT_CALL(*device_policy_, GetMetricsEnabled(_))
      .WillRepeatedly(Return(false));
  EXPECT_CALL(*device_policy_, IsEnterpriseManaged())
      .WillRepeatedly(Return(true));
  EXPECT_TRUE(lib_.AreMetricsEnabled());

  // Per-user shouldn't affect that -- we haven't set per-user consent at all.
  ClearCachedEnabledTime();
  EXPECT_TRUE(lib_.AreMetricsEnabled());

  // if per-user is enabled, should still be true.
  SetPerUserConsent(true);
  ClearCachedEnabledTime();
  EXPECT_TRUE(lib_.AreMetricsEnabled());
  // But not if it's disabled.
  SetPerUserConsent(false);
  ClearCachedEnabledTime();
  EXPECT_FALSE(lib_.AreMetricsEnabled());
}

// Shouldn't check device policy if per-user consent is off.
TEST_F(MetricsLibraryTest, AreMetricsEnabledFalseNoPolicyNoPerUser) {
  EXPECT_CALL(*device_policy_, GetMetricsEnabled(_)).Times(0);
  EXPECT_CALL(*device_policy_, IsEnterpriseManaged()).Times(0);

  SetPerUserConsent(false);
  EXPECT_FALSE(lib_.AreMetricsEnabled());
}

// MetricsEnabled policy not present, not enterprise managed
// -> AreMetricsEnabled returns false.
TEST_F(MetricsLibraryTest, AreMetricsEnabledFalseNoPolicyUnmanaged) {
  EXPECT_CALL(*device_policy_, GetMetricsEnabled(_))
      .WillRepeatedly(Return(false));
  EXPECT_CALL(*device_policy_, IsEnterpriseManaged())
      .WillRepeatedly(Return(false));
  EXPECT_FALSE(lib_.AreMetricsEnabled());

  // Per-user shouldn't affect that -- we haven't set per-user consent at all.
  ClearCachedEnabledTime();
  EXPECT_FALSE(lib_.AreMetricsEnabled());

  // Even if per-user is enabled, if device policy is not enabled we shouldn't
  // enable consent.
  SetPerUserConsent(true);
  ClearCachedEnabledTime();
  EXPECT_FALSE(lib_.AreMetricsEnabled());

  // Same if it's disabled.
  SetPerUserConsent(false);
  ClearCachedEnabledTime();
  EXPECT_FALSE(lib_.AreMetricsEnabled());
}

// MetricsEnabled policy set to false -> AreMetricsEnabled returns false.
TEST_F(MetricsLibraryTest, AreMetricsEnabledFalse) {
  EXPECT_CALL(*device_policy_, GetMetricsEnabled(_))
      .WillRepeatedly(SetMetricsPolicy(false));
  EXPECT_FALSE(lib_.AreMetricsEnabled());

  // Per-user shouldn't affect that -- we haven't set per-user consent at all.
  ClearCachedEnabledTime();
  EXPECT_FALSE(lib_.AreMetricsEnabled());
  // Even if per-user is enabled, if device policy is not false we shouldn't
  // enable consent.
  SetPerUserConsent(true);
  ClearCachedEnabledTime();
  EXPECT_FALSE(lib_.AreMetricsEnabled());
  // Same if it's disabled.
  SetPerUserConsent(false);
  ClearCachedEnabledTime();
  EXPECT_FALSE(lib_.AreMetricsEnabled());
}

// MetricsEnabled policy set to true -> AreMetricsEnabled returns true.
TEST_F(MetricsLibraryTest, AreMetricsEnabledTrue) {
  EXPECT_TRUE(lib_.AreMetricsEnabled());
  // Per-user shouldn't affect that -- we haven't set per-user consent at all.
  ClearCachedEnabledTime();
  EXPECT_TRUE(lib_.AreMetricsEnabled());
}

// MetricsEnabled policy set to true and user disabled
// -> AreMetricsEnabled returns false.
TEST_F(MetricsLibraryTest, AreMetricsEnabledPerUserFalse) {
  SetPerUserConsent(false);
  EXPECT_FALSE(lib_.AreMetricsEnabled());
}

TEST_F(MetricsLibraryTest, IsAppSyncEnabledDefaultFalse) {
  EXPECT_FALSE(lib_.IsAppSyncEnabled());
}

TEST_F(MetricsLibraryTest, IsAppsSyncEnabledForceFalse) {
  SetPerUserAppSyncOptin(false);
  EXPECT_FALSE(lib_.IsAppSyncEnabled());
}

TEST_F(MetricsLibraryTest, IsAppSyncEnabledTrue) {
  SetPerUserAppSyncOptin(true);
  EXPECT_TRUE(lib_.IsAppSyncEnabled());
}

TEST_F(MetricsLibraryTest, IsAppSyncEnabledTrueThenFalse) {
  SetPerUserAppSyncOptin(true);
  EXPECT_TRUE(lib_.IsAppSyncEnabled());

  SetPerUserAppSyncOptin(false);

  ClearCachedAppSyncEnabledTime();

  EXPECT_FALSE(lib_.IsAppSyncEnabled());
}

// Template SendEnumToUMA(name, T) correctly sets exclusive_max to kMaxValue+1.
TEST_F(MetricsLibraryTest, SendEnumToUMAMax) {
  enum class MyEnum {
    kFirstValue = 0,
    kSecondValue = 1,
    kThirdValue = 2,
    kMaxValue = kThirdValue,
  };
  std::unique_ptr<MetricsLibraryMock> mock =
      std::make_unique<MetricsLibraryMock>();
  EXPECT_CALL(*mock, SendEnumToUMA("My.Enumeration", 1, 3)).Times(1);
  MetricsLibraryInterface* metrics_library =
      static_cast<MetricsLibraryInterface*>(mock.get());
  metrics_library->SendEnumToUMA("My.Enumeration", MyEnum::kSecondValue);
}

TEST_F(MetricsLibraryTest, SendEnumRepeatedToUMA) {
  enum class MyEnum {
    kFirstValue = 0,
    kSecondValue = 1,
    kMaxValue = kSecondValue,
  };
  std::unique_ptr<MetricsLibraryMock> mock =
      std::make_unique<MetricsLibraryMock>();
  EXPECT_CALL(*mock, SendRepeatedEnumToUMA("My.Enumeration", 1, 2, 3)).Times(1);
  MetricsLibraryInterface* metrics_library =
      static_cast<MetricsLibraryInterface*>(mock.get());
  metrics_library->SendRepeatedEnumToUMA("My.Enumeration", MyEnum::kSecondValue,
                                         3);
}

void MetricsLibraryTest::VerifyEnabledCacheHit(bool to_value) {
  // We might step from one second to the next one time, but not 100
  // times in a row.
  for (int i = 0; i < 100; ++i) {
    lib_.cached_enabled_time_ = 0;
    EXPECT_CALL(*device_policy_, GetMetricsEnabled(_))
        .WillOnce(SetMetricsPolicy(!to_value));
    ASSERT_EQ(!to_value, lib_.AreMetricsEnabled());
    testing::Mock::VerifyAndClearExpectations(device_policy_);

    ON_CALL(*device_policy_, GetMetricsEnabled(_))
        .WillByDefault(SetMetricsPolicy(to_value));
    if (lib_.AreMetricsEnabled() == !to_value)
      return;
    testing::Mock::VerifyAndClearExpectations(device_policy_);
  }
  ADD_FAILURE() << "Did not see evidence of caching";
}

void MetricsLibraryTest::VerifyEnabledCacheEviction(bool to_value) {
  lib_.cached_enabled_time_ = 0;
  EXPECT_CALL(*device_policy_, GetMetricsEnabled(_))
      .WillOnce(SetMetricsPolicy(!to_value));
  ASSERT_EQ(!to_value, lib_.AreMetricsEnabled());
  testing::Mock::VerifyAndClearExpectations(device_policy_);

  EXPECT_CALL(*device_policy_, GetMetricsEnabled(_))
      .WillOnce(SetMetricsPolicy(to_value));
  ASSERT_LT(abs(static_cast<int>(time(nullptr) - lib_.cached_enabled_time_)),
            5);
  // Sleep one second (or cheat to be faster).
  --lib_.cached_enabled_time_;
  ASSERT_EQ(to_value, lib_.AreMetricsEnabled());
}

TEST_F(MetricsLibraryTest, AreMetricsEnabledCaching) {
  VerifyEnabledCacheHit(false);
  VerifyEnabledCacheHit(true);
  VerifyEnabledCacheEviction(false);
  VerifyEnabledCacheEviction(true);
}

class CMetricsLibraryTest : public testing::Test {
 protected:
  void SetUp() override {
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
    test_dir_ = temp_dir_.GetPath();

    lib_ = CMetricsLibraryNew();
    MetricsLibrary& ml = *reinterpret_cast<MetricsLibrary*>(lib_);
    SynchronousMetricsWriter& writer =
        *static_cast<SynchronousMetricsWriter*>(ml.metrics_writer_.get());
    EXPECT_FALSE(writer.uma_events_file_.empty());
    CMetricsLibraryInit(lib_);
    EXPECT_FALSE(writer.uma_events_file_.empty());

    test_uma_events_file_ = test_dir_.Append(kTestUMAEventsFile);
    ml.SetOutputFile(test_uma_events_file_.value());
    EXPECT_EQ(0, WriteFile(test_uma_events_file_, "", 0));
    device_policy_ = new policy::MockDevicePolicy();
    EXPECT_CALL(*device_policy_, LoadPolicy(/*delete_invalid_files=*/false))
        .Times(AnyNumber())
        .WillRepeatedly(Return(true));
    EXPECT_CALL(*device_policy_, GetMetricsEnabled(_))
        .Times(AnyNumber())
        .WillRepeatedly(SetMetricsPolicy(true));
    ml.SetPolicyProvider(new policy::PolicyProvider(
        std::unique_ptr<policy::MockDevicePolicy>(device_policy_)));
    ml.cached_enabled_time_ = 0;
  }

  void TearDown() override { CMetricsLibraryDelete(lib_); }

  CMetricsLibrary lib_;
  policy::MockDevicePolicy* device_policy_;  // Not owned.
  base::ScopedTempDir temp_dir_;
  base::FilePath test_dir_;
  base::FilePath test_uma_events_file_;
};

TEST_F(CMetricsLibraryTest, AreMetricsEnabledFalse) {
  EXPECT_CALL(*device_policy_, GetMetricsEnabled(_))
      .WillOnce(SetMetricsPolicy(false));
  EXPECT_FALSE(CMetricsLibraryAreMetricsEnabled(lib_));
}

TEST_F(CMetricsLibraryTest, AreMetricsEnabledTrue) {
  EXPECT_TRUE(CMetricsLibraryAreMetricsEnabled(lib_));
}
