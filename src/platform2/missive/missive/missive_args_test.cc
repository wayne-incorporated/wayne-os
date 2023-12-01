// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "missive/missive/missive_args.h"

#include <utility>

#include <base/functional/bind.h>
#include <base/functional/callback_forward.h>
#include <base/time/time.h>
#include <base/time/time_delta_from_string.h>
#include <base/test/task_environment.h>
#include <featured/fake_platform_features.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "missive/analytics/metrics_test_util.h"
#include "missive/analytics/resource_collector_cpu.h"
#include "missive/analytics/resource_collector_memory.h"
#include "missive/analytics/resource_collector_storage.h"
#include "missive/dbus/dbus_test_environment.h"
#include "missive/util/status.h"
#include "missive/util/statusor.h"
#include "missive/util/test_support_callbacks.h"

using ::testing::_;
using ::testing::Eq;
using ::testing::Return;
using ::testing::StrEq;

namespace reporting {

class MissiveArgsTest : public ::testing::Test {
 protected:
  void SetUp() override {
    // Ignore collector UMA
    ON_CALL(analytics::Metrics::TestEnvironment::GetMockMetricsLibrary(),
            SendToUMA(
                /*name=*/analytics::ResourceCollectorStorage::kUmaName,
                /*sample=*/_,
                /*min=*/analytics::ResourceCollectorStorage::kMin,
                /*max=*/analytics::ResourceCollectorStorage::kMax,
                /*nbuckets=*/
                analytics::ResourceCollectorStorage::kUmaNumberOfBuckets))
        .WillByDefault(Return(true));
    ON_CALL(analytics::Metrics::TestEnvironment::GetMockMetricsLibrary(),
            SendPercentageToUMA(
                /*name=*/analytics::ResourceCollectorCpu::kUmaName,
                /*sample=*/_))
        .WillByDefault(Return(true));
    ON_CALL(analytics::Metrics::TestEnvironment::GetMockMetricsLibrary(),
            SendLinearToUMA(
                /*name=*/analytics::ResourceCollectorMemory::kUmaName,
                /*sample=*/_,
                /*max=*/analytics::ResourceCollectorMemory::kUmaMax))
        .WillByDefault(Return(true));
  }

  base::test::TaskEnvironment task_environment_;
  test::DBusTestEnvironment dbus_test_environment_;
  feature::FakePlatformFeatures* fake_platform_features_;

  // Use the metrics test environment to prevent the real metrics from
  // initializing.
  analytics::Metrics::TestEnvironment metrics_test_environment_;
};

TEST_F(MissiveArgsTest, DefaultCollectionValues) {
  auto fake_platform_features = std::make_unique<feature::FakePlatformFeatures>(
      dbus_test_environment_.mock_bus().get());
  fake_platform_features->SetEnabled(MissiveArgs::kCollectorFeature.name,
                                     false);
  fake_platform_features->SetEnabled(MissiveArgs::kStorageFeature.name, false);
  SequencedMissiveArgs args(
      dbus_test_environment_.mock_bus()->GetDBusTaskRunner(),
      fake_platform_features.get());

  test::TestEvent<StatusOr<MissiveArgs::CollectionParameters>> get_collection;
  args.AsyncCall(&MissiveArgs::GetCollectionParameters)
      .WithArgs(get_collection.cb());
  const auto& collection = get_collection.result();
  ASSERT_OK(collection) << collection.status();
  ASSERT_THAT(
      collection.ValueOrDie().enqueuing_record_tallier,
      Eq(base::TimeDeltaFromString(MissiveArgs::kEnqueuingRecordTallierDefault)
             .value()));
  ASSERT_THAT(
      collection.ValueOrDie().cpu_collector_interval,
      Eq(base::TimeDeltaFromString(MissiveArgs::kCpuCollectorIntervalDefault)
             .value()));
  ASSERT_THAT(collection.ValueOrDie().storage_collector_interval,
              Eq(base::TimeDeltaFromString(
                     MissiveArgs::kStorageCollectorIntervalDefault)
                     .value()));
  ASSERT_THAT(
      collection.ValueOrDie().memory_collector_interval,
      Eq(base::TimeDeltaFromString(MissiveArgs::kMemoryCollectorIntervalDefault)
             .value()));
}

TEST_F(MissiveArgsTest, ExplicitCollectionValues) {
  auto fake_platform_features = std::make_unique<feature::FakePlatformFeatures>(
      dbus_test_environment_.mock_bus().get());
  fake_platform_features->SetEnabled(MissiveArgs::kCollectorFeature.name, true);
  fake_platform_features->SetParam(
      MissiveArgs::kCollectorFeature.name,
      MissiveArgs::kEnqueuingRecordTallierParameter, "10ms");
  fake_platform_features->SetParam(MissiveArgs::kCollectorFeature.name,
                                   MissiveArgs::kCpuCollectorIntervalParameter,
                                   "20s");
  fake_platform_features->SetParam(
      MissiveArgs::kCollectorFeature.name,
      MissiveArgs::kStorageCollectorIntervalParameter, "30m");
  fake_platform_features->SetParam(
      MissiveArgs::kCollectorFeature.name,
      MissiveArgs::kMemoryCollectorIntervalParameter, "40h");
  fake_platform_features->SetEnabled(MissiveArgs::kStorageFeature.name, false);
  SequencedMissiveArgs args(
      dbus_test_environment_.mock_bus()->GetDBusTaskRunner(),
      fake_platform_features.get());

  test::TestEvent<StatusOr<MissiveArgs::CollectionParameters>> get_collection;
  args.AsyncCall(&MissiveArgs::GetCollectionParameters)
      .WithArgs(get_collection.cb());
  const auto& collection = get_collection.result();
  ASSERT_OK(collection) << collection.status();
  ASSERT_THAT(collection.ValueOrDie().enqueuing_record_tallier,
              Eq(base::Milliseconds(10)));
  ASSERT_THAT(collection.ValueOrDie().cpu_collector_interval,
              Eq(base::Seconds(20)));
  ASSERT_THAT(collection.ValueOrDie().storage_collector_interval,
              Eq(base::Minutes(30)));
  ASSERT_THAT(collection.ValueOrDie().memory_collector_interval,
              Eq(base::Hours(40)));
}

TEST_F(MissiveArgsTest, BadCollectionValues) {
  auto fake_platform_features = std::make_unique<feature::FakePlatformFeatures>(
      dbus_test_environment_.mock_bus().get());
  fake_platform_features->SetEnabled(MissiveArgs::kCollectorFeature.name, true);
  fake_platform_features->SetParam(
      MissiveArgs::kCollectorFeature.name,
      MissiveArgs::kEnqueuingRecordTallierParameter, "AAAA");
  fake_platform_features->SetParam(MissiveArgs::kCollectorFeature.name,
                                   MissiveArgs::kCpuCollectorIntervalParameter,
                                   "BAD");
  fake_platform_features->SetParam(
      MissiveArgs::kCollectorFeature.name,
      MissiveArgs::kStorageCollectorIntervalParameter, "WRONG");
  fake_platform_features->SetParam(
      MissiveArgs::kCollectorFeature.name,
      MissiveArgs::kMemoryCollectorIntervalParameter, "123");
  fake_platform_features->SetEnabled(MissiveArgs::kStorageFeature.name, false);
  SequencedMissiveArgs args(
      dbus_test_environment_.mock_bus()->GetDBusTaskRunner(),
      fake_platform_features.get());

  test::TestEvent<StatusOr<MissiveArgs::CollectionParameters>> get_collection;
  args.AsyncCall(&MissiveArgs::GetCollectionParameters)
      .WithArgs(get_collection.cb());
  const auto& collection = get_collection.result();
  ASSERT_OK(collection) << collection.status();
  ASSERT_THAT(
      collection.ValueOrDie().enqueuing_record_tallier,
      Eq(base::TimeDeltaFromString(MissiveArgs::kEnqueuingRecordTallierDefault)
             .value()));
  ASSERT_THAT(
      collection.ValueOrDie().cpu_collector_interval,
      Eq(base::TimeDeltaFromString(MissiveArgs::kCpuCollectorIntervalDefault)
             .value()));
  ASSERT_THAT(collection.ValueOrDie().storage_collector_interval,
              Eq(base::TimeDeltaFromString(
                     MissiveArgs::kStorageCollectorIntervalDefault)
                     .value()));
  ASSERT_THAT(
      collection.ValueOrDie().memory_collector_interval,
      Eq(base::TimeDeltaFromString(MissiveArgs::kMemoryCollectorIntervalDefault)
             .value()));
}

TEST_F(MissiveArgsTest, ListeningForCollectionValuesUpdate) {
  auto fake_platform_features = std::make_unique<feature::FakePlatformFeatures>(
      dbus_test_environment_.mock_bus().get());
  fake_platform_features->SetEnabled(MissiveArgs::kCollectorFeature.name, true);
  fake_platform_features->SetEnabled(MissiveArgs::kStorageFeature.name, false);
  auto* const fake_platform_features_ptr = fake_platform_features.get();
  SequencedMissiveArgs args(
      dbus_test_environment_.mock_bus()->GetDBusTaskRunner(),
      fake_platform_features.get());

  // Get initial results
  test::TestEvent<StatusOr<MissiveArgs::CollectionParameters>> get_collection;
  args.AsyncCall(&MissiveArgs::GetCollectionParameters)
      .WithArgs(get_collection.cb());
  {
    const auto& collection = get_collection.result();
    ASSERT_OK(collection) << collection.status();
    ASSERT_THAT(collection.ValueOrDie().enqueuing_record_tallier,
                Eq(base::TimeDeltaFromString(
                       MissiveArgs::kEnqueuingRecordTallierDefault)
                       .value()));
    ASSERT_THAT(
        collection.ValueOrDie().cpu_collector_interval,
        Eq(base::TimeDeltaFromString(MissiveArgs::kCpuCollectorIntervalDefault)
               .value()));
    ASSERT_THAT(collection.ValueOrDie().storage_collector_interval,
                Eq(base::TimeDeltaFromString(
                       MissiveArgs::kStorageCollectorIntervalDefault)
                       .value()));
    ASSERT_THAT(collection.ValueOrDie().memory_collector_interval,
                Eq(base::TimeDeltaFromString(
                       MissiveArgs::kMemoryCollectorIntervalDefault)
                       .value()));
  }

  // Register update callback.
  test::TestEvent<MissiveArgs::CollectionParameters> update_collection;
  {
    test::TestCallbackAutoWaiter waiter;
    args.AsyncCall(&MissiveArgs::OnCollectionParametersUpdate)
        .WithArgs(update_collection.repeating_cb(),
                  base::BindOnce(&test::TestCallbackAutoWaiter::Signal,
                                 base::Unretained(&waiter)));
  }

  // Change parameters and refresh.
  fake_platform_features_ptr->SetParam(
      MissiveArgs::kCollectorFeature.name,
      MissiveArgs::kEnqueuingRecordTallierParameter, "10ms");
  fake_platform_features_ptr->SetParam(
      MissiveArgs::kCollectorFeature.name,
      MissiveArgs::kCpuCollectorIntervalParameter, "20s");
  fake_platform_features_ptr->SetParam(
      MissiveArgs::kCollectorFeature.name,
      MissiveArgs::kStorageCollectorIntervalParameter, "30m");
  fake_platform_features_ptr->SetParam(
      MissiveArgs::kCollectorFeature.name,
      MissiveArgs::kMemoryCollectorIntervalParameter, "40h");
  fake_platform_features_ptr->TriggerRefetchSignal();

  {
    const auto& collection = update_collection.result();
    ASSERT_THAT(collection.enqueuing_record_tallier,
                Eq(base::Milliseconds(10)));
    ASSERT_THAT(collection.cpu_collector_interval, Eq(base::Seconds(20)));
    ASSERT_THAT(collection.storage_collector_interval, Eq(base::Minutes(30)));
    ASSERT_THAT(collection.memory_collector_interval, Eq(base::Hours(40)));
  }
}

TEST_F(MissiveArgsTest, DefaultStorageValues) {
  auto fake_platform_features = std::make_unique<feature::FakePlatformFeatures>(
      dbus_test_environment_.mock_bus().get());
  fake_platform_features->SetEnabled(MissiveArgs::kCollectorFeature.name,
                                     false);
  fake_platform_features->SetEnabled(MissiveArgs::kStorageFeature.name, false);
  SequencedMissiveArgs args(
      dbus_test_environment_.mock_bus()->GetDBusTaskRunner(),
      fake_platform_features.get());

  test::TestEvent<StatusOr<MissiveArgs::StorageParameters>> get_storage;
  args.AsyncCall(&MissiveArgs::GetStorageParameters).WithArgs(get_storage.cb());
  const auto& storage = get_storage.result();
  ASSERT_OK(storage) << storage.status();
  EXPECT_THAT(storage.ValueOrDie().compression_enabled,
              Eq(MissiveArgs::kCompressionEnabledDefault));
  EXPECT_THAT(storage.ValueOrDie().encryption_enabled,
              Eq(MissiveArgs::kEncryptionEnabledDefault));
  EXPECT_THAT(storage.ValueOrDie().controlled_degradation,
              Eq(MissiveArgs::kControlledDegradationDefault));
  EXPECT_THAT(storage.ValueOrDie().legacy_storage_enabled,
              Eq(MissiveArgs::kLegacyStorageEnabledDefault));
  EXPECT_THAT(storage.ValueOrDie().signature_verification_dev_enabled,
              Eq(MissiveArgs::kSignatureVerificationDevEnabledDefault));
}

TEST_F(MissiveArgsTest, ExplicitStorageValues) {
  auto fake_platform_features = std::make_unique<feature::FakePlatformFeatures>(
      dbus_test_environment_.mock_bus().get());
  fake_platform_features->SetEnabled(MissiveArgs::kCollectorFeature.name,
                                     false);
  fake_platform_features->SetEnabled(MissiveArgs::kStorageFeature.name, true);
  fake_platform_features->SetParam(MissiveArgs::kStorageFeature.name,
                                   MissiveArgs::kCompressionEnabledParameter,
                                   "False");
  fake_platform_features->SetParam(MissiveArgs::kStorageFeature.name,
                                   MissiveArgs::kEncryptionEnabledParameter,
                                   "False");
  fake_platform_features->SetParam(MissiveArgs::kStorageFeature.name,
                                   MissiveArgs::kControlledDegradationParameter,
                                   "True");
  fake_platform_features->SetParam(MissiveArgs::kStorageFeature.name,
                                   MissiveArgs::kLegacyStorageEnabledParameter,
                                   "False");
  fake_platform_features->SetParam(
      MissiveArgs::kStorageFeature.name,
      MissiveArgs::kSignatureVerificationDevEnabledParameter, "True");
  SequencedMissiveArgs args(
      dbus_test_environment_.mock_bus()->GetDBusTaskRunner(),
      fake_platform_features.get());

  test::TestEvent<StatusOr<MissiveArgs::StorageParameters>> get_storage;
  args.AsyncCall(&MissiveArgs::GetStorageParameters).WithArgs(get_storage.cb());
  const auto& storage = get_storage.result();
  ASSERT_OK(storage) << storage.status();
  EXPECT_FALSE(storage.ValueOrDie().compression_enabled);
  EXPECT_FALSE(storage.ValueOrDie().encryption_enabled);
  EXPECT_TRUE(storage.ValueOrDie().controlled_degradation);
  EXPECT_FALSE(storage.ValueOrDie().legacy_storage_enabled);
  EXPECT_TRUE(storage.ValueOrDie().signature_verification_dev_enabled);
}

TEST_F(MissiveArgsTest, BadStorageValues) {
  auto fake_platform_features = std::make_unique<feature::FakePlatformFeatures>(
      dbus_test_environment_.mock_bus().get());
  fake_platform_features->SetEnabled(MissiveArgs::kCollectorFeature.name, true);
  fake_platform_features->SetParam(MissiveArgs::kStorageFeature.name,
                                   MissiveArgs::kCompressionEnabledParameter,
                                   "Unknown");
  fake_platform_features->SetParam(MissiveArgs::kStorageFeature.name,
                                   MissiveArgs::kEncryptionEnabledParameter,
                                   "Nothing");
  fake_platform_features->SetParam(MissiveArgs::kStorageFeature.name,
                                   MissiveArgs::kControlledDegradationParameter,
                                   "BadValue");
  fake_platform_features->SetParam(MissiveArgs::kStorageFeature.name,
                                   MissiveArgs::kLegacyStorageEnabledParameter,
                                   "BadValue");
  fake_platform_features->SetParam(
      MissiveArgs::kStorageFeature.name,
      MissiveArgs::kSignatureVerificationDevEnabledParameter, "BadValue");
  fake_platform_features->SetEnabled(MissiveArgs::kStorageFeature.name, false);
  SequencedMissiveArgs args(
      dbus_test_environment_.mock_bus()->GetDBusTaskRunner(),
      fake_platform_features.get());

  test::TestEvent<StatusOr<MissiveArgs::StorageParameters>> get_storage;
  args.AsyncCall(&MissiveArgs::GetStorageParameters).WithArgs(get_storage.cb());
  const auto& storage = get_storage.result();
  ASSERT_OK(storage) << storage.status();
  EXPECT_THAT(storage.ValueOrDie().compression_enabled,
              Eq(MissiveArgs::kCompressionEnabledDefault));
  EXPECT_THAT(storage.ValueOrDie().encryption_enabled,
              Eq(MissiveArgs::kEncryptionEnabledDefault));
  EXPECT_THAT(storage.ValueOrDie().controlled_degradation,
              Eq(MissiveArgs::kControlledDegradationDefault));
  EXPECT_THAT(storage.ValueOrDie().legacy_storage_enabled,
              Eq(MissiveArgs::kLegacyStorageEnabledDefault));
  EXPECT_THAT(storage.ValueOrDie().signature_verification_dev_enabled,
              Eq(MissiveArgs::kSignatureVerificationDevEnabledDefault));
}

TEST_F(MissiveArgsTest, ListeningForStorageValuesUpdate) {
  auto fake_platform_features = std::make_unique<feature::FakePlatformFeatures>(
      dbus_test_environment_.mock_bus().get());
  fake_platform_features->SetEnabled(MissiveArgs::kCollectorFeature.name,
                                     false);
  fake_platform_features->SetEnabled(MissiveArgs::kStorageFeature.name, true);
  auto* const fake_platform_features_ptr = fake_platform_features.get();
  SequencedMissiveArgs args(
      dbus_test_environment_.mock_bus()->GetDBusTaskRunner(),
      fake_platform_features.get());

  // Get initial results
  test::TestEvent<StatusOr<MissiveArgs::StorageParameters>> get_storage;
  args.AsyncCall(&MissiveArgs::GetStorageParameters).WithArgs(get_storage.cb());
  {
    const auto& storage = get_storage.result();
    ASSERT_OK(storage) << storage.status();
    EXPECT_THAT(storage.ValueOrDie().compression_enabled,
                Eq(MissiveArgs::kCompressionEnabledDefault));
    EXPECT_THAT(storage.ValueOrDie().encryption_enabled,
                Eq(MissiveArgs::kEncryptionEnabledDefault));
    EXPECT_THAT(storage.ValueOrDie().controlled_degradation,
                Eq(MissiveArgs::kControlledDegradationDefault));
    EXPECT_THAT(storage.ValueOrDie().legacy_storage_enabled,
                Eq(MissiveArgs::kLegacyStorageEnabledDefault));
    EXPECT_THAT(storage.ValueOrDie().signature_verification_dev_enabled,
                Eq(MissiveArgs::kSignatureVerificationDevEnabledDefault));
  }

  // Register update callback.
  test::TestEvent<MissiveArgs::StorageParameters> update_storage;
  {
    test::TestCallbackAutoWaiter waiter;
    args.AsyncCall(&MissiveArgs::OnStorageParametersUpdate)
        .WithArgs(update_storage.repeating_cb(),
                  base::BindOnce(&test::TestCallbackAutoWaiter::Signal,
                                 base::Unretained(&waiter)));
  }

  // Change parameters.
  fake_platform_features_ptr->SetParam(
      MissiveArgs::kStorageFeature.name,
      MissiveArgs::kCompressionEnabledParameter, "False");
  fake_platform_features_ptr->SetParam(MissiveArgs::kStorageFeature.name,
                                       MissiveArgs::kEncryptionEnabledParameter,
                                       "False");
  fake_platform_features_ptr->SetParam(
      MissiveArgs::kStorageFeature.name,
      MissiveArgs::kControlledDegradationParameter, "True");
  fake_platform_features_ptr->SetParam(
      MissiveArgs::kStorageFeature.name,
      MissiveArgs::kLegacyStorageEnabledParameter, "False");
  fake_platform_features_ptr->SetParam(
      MissiveArgs::kStorageFeature.name,
      MissiveArgs::kSignatureVerificationDevEnabledParameter, "True");

  // Fetch the updated feature flag values.
  fake_platform_features_ptr->TriggerRefetchSignal();

  {
    const auto& storage = update_storage.result();
    EXPECT_FALSE(storage.compression_enabled);
    EXPECT_FALSE(storage.encryption_enabled);
    EXPECT_TRUE(storage.controlled_degradation);
    EXPECT_FALSE(storage.legacy_storage_enabled);
    EXPECT_TRUE(storage.signature_verification_dev_enabled);
  }
}
}  // namespace reporting
