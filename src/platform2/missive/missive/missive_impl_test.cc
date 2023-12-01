// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "missive/missive/missive_impl.h"

#include <cstddef>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <base/memory/scoped_refptr.h>
#include <base/test/task_environment.h>
#include <brillo/dbus/mock_dbus_method_response.h>
#include <dbus/bus.h>
#include <dbus/mock_bus.h>
#include <featured/fake_platform_features.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "missive/analytics/metrics_test_util.h"
#include "missive/analytics/resource_collector_cpu.h"
#include "missive/analytics/resource_collector_memory.h"
#include "missive/analytics/resource_collector_storage.h"
#include "missive/compression/test_compression_module.h"
#include "missive/dbus/dbus_test_environment.h"
#include "missive/dbus/mock_upload_client.h"
#include "missive/encryption/test_encryption_module.h"
#include "missive/missive/migration.h"
#include "missive/storage/storage_configuration.h"
#include "missive/storage/storage_module.h"
#include "missive/util/status.h"
#include "missive/util/test_support_callbacks.h"
#include "missive/util/test_util.h"

using ::testing::_;
using ::testing::Eq;
using ::testing::NiceMock;
using ::testing::Property;
using ::testing::Return;
using ::testing::StrEq;
using ::testing::WithArg;

namespace reporting {

class MockStorageModule : public StorageModule {
 public:
  // As opposed to the production |StorageModule|, test module does not need to
  // call factory method - it is created directly by constructor. The
  // `legacy_storage_enabled` parameter can be any value since this is a feature
  // flag that only affects internal implementation details.
  MockStorageModule()
      : StorageModule(StorageOptions(),
                      /*legacy_storage_enabled=*/true,
                      /*async_start_upload_cb=*/base::DoNothing(),
                      QueuesContainer::Create(/*is_enabled=*/false),
                      /*encryption_module=*/nullptr,
                      /*compression_module=*/nullptr,
                      /*signature_verification_dev_flag=*/nullptr) {}

  MOCK_METHOD(void,
              AddRecord,
              (Priority priority, Record record, EnqueueCallback callback),
              (override));

  MOCK_METHOD(void,
              Flush,
              (Priority priority, FlushCallback callback),
              (override));

  MOCK_METHOD(void,
              ReportSuccess,
              (SequenceInformation sequence_information, bool force),
              (override));

  MOCK_METHOD(void,
              UpdateEncryptionKey,
              (SignedEncryptionInfo signed_encryption_key),
              (override));
};

class MissiveImplTest : public ::testing::Test {
 public:
  MissiveImplTest() = default;

 protected:
  void SetUp() override {
    // Migration is expected to fail in the test.
    ON_CALL(analytics::Metrics::TestEnvironment::GetMockMetricsLibrary(),
            SendEnumToUMA(kMigrationStatusUmaName, _,
                          static_cast<int>(MigrationStatusForUma::kMaxValue)))
        .WillByDefault(Return(true));

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

    missive_ = std::make_unique<MissiveImpl>(
        base::BindOnce(
            [](MissiveImplTest* self, scoped_refptr<dbus::Bus> bus,
               base::OnceCallback<void(StatusOr<scoped_refptr<UploadClient>>)>
                   callback) {
              self->upload_client_ =
                  base::MakeRefCounted<test::MockUploadClient>();
              std::move(callback).Run(self->upload_client_);
            },
            base::Unretained(this)),
        base::BindOnce(
            [](MissiveImplTest* self,
               const MissiveArgs::StorageParameters& parameters) {
              self->compression_module_ =
                  base::MakeRefCounted<test::TestCompressionModule>();
              return self->compression_module_;
            },
            base::Unretained(this)),
        base::BindOnce(
            [](MissiveImplTest* self,
               const MissiveArgs::StorageParameters& parameters) {
              self->encryption_module_ =
                  base::MakeRefCounted<test::TestEncryptionModule>(
                      parameters.encryption_enabled);
              return self->encryption_module_;
            },
            base::Unretained(this)),
        base::BindOnce(
            [](MissiveImplTest* self, MissiveImpl* missive,
               StorageOptions storage_options,
               MissiveArgs::StorageParameters parameters,
               base::OnceCallback<void(StatusOr<scoped_refptr<StorageModule>>)>
                   callback) {
              self->storage_module_ = base::MakeRefCounted<MockStorageModule>();
              std::move(callback).Run(self->storage_module_);
            },
            base::Unretained(this)));

    fake_platform_features_ = std::make_unique<feature::FakePlatformFeatures>(
        dbus_test_environment_.mock_bus().get());
    fake_platform_features_->SetEnabled(MissiveArgs::kCollectorFeature.name,
                                        false);
    fake_platform_features_->SetEnabled(MissiveArgs::kStorageFeature.name,
                                        true);
    fake_platform_features_ptr_ = fake_platform_features_.get();

    test::TestEvent<Status> started;
    missive_->StartUp(dbus_test_environment_.mock_bus(),
                      fake_platform_features_ptr_, started.cb());
    ASSERT_OK(started.result());
    EXPECT_TRUE(compression_module_->is_enabled());
    EXPECT_TRUE(encryption_module_->is_enabled());
  }

  void TearDown() override {
    if (missive_) {
      EXPECT_OK(missive_->ShutDown());
    }
    // Let everything ongoing to finish.
    task_environment_.RunUntilIdle();
  }

  base::test::TaskEnvironment task_environment_;
  test::DBusTestEnvironment dbus_test_environment_;
  std::unique_ptr<feature::FakePlatformFeatures> fake_platform_features_;
  feature::FakePlatformFeatures* fake_platform_features_ptr_;

  // Use the metrics test environment to prevent the real metrics from
  // initializing.
  analytics::Metrics::TestEnvironment metrics_test_environment_;
  scoped_refptr<UploadClient> upload_client_;
  scoped_refptr<CompressionModule> compression_module_;
  scoped_refptr<EncryptionModuleInterface> encryption_module_;
  scoped_refptr<MockStorageModule> storage_module_;
  std::unique_ptr<MissiveImpl> missive_;
};

TEST_F(MissiveImplTest, AsyncStartUploadTest) {
  test::TestEvent<StatusOr<std::unique_ptr<UploaderInterface>>> uploader_event;
  MissiveImpl::AsyncStartUpload(
      missive_->GetWeakPtr(), UploaderInterface::UploadReason::IMMEDIATE_FLUSH,
      uploader_event.cb());
  auto response_result = uploader_event.result();
  EXPECT_OK(response_result) << response_result.status();
  response_result.ValueOrDie()->Completed(
      Status(error::INTERNAL, "Failing for tests"));
}

TEST_F(MissiveImplTest, AsyncNoStartUploadTest) {
  test::TestEvent<StatusOr<std::unique_ptr<UploaderInterface>>> uploader_event;
  auto weak_ptr = missive_->GetWeakPtr();
  missive_.reset();
  MissiveImpl::AsyncStartUpload(
      weak_ptr, UploaderInterface::UploadReason::IMMEDIATE_FLUSH,
      uploader_event.cb());
  auto response_result = uploader_event.result();
  EXPECT_THAT(response_result,
              Property(&StatusOr<std::unique_ptr<UploaderInterface>>::status,
                       Property(&Status::code, Eq(error::UNAVAILABLE))))
      << response_result.status();
}

TEST_F(MissiveImplTest, EnqueueRecordTest) {
  EnqueueRecordRequest request;
  request.mutable_record()->set_data("DATA");
  request.mutable_record()->set_destination(HEARTBEAT_EVENTS);
  request.set_priority(FAST_BATCH);

  EXPECT_CALL(*storage_module_, AddRecord(Eq(request.priority()),
                                          EqualsProto(request.record()), _))
      .WillOnce(
          WithArg<2>([](StorageModuleInterface::EnqueueCallback callback) {
            std::move(callback).Run(Status::StatusOK());
          }));

  auto response = std::make_unique<
      brillo::dbus_utils::MockDBusMethodResponse<EnqueueRecordResponse>>();
  test::TestEvent<const EnqueueRecordResponse&> response_event;
  response->set_return_callback(response_event.cb());
  missive_->EnqueueRecord(request, std::move(response));
  const auto& response_result = response_event.ref_result();
  EXPECT_THAT(response_result,
              Property(&EnqueueRecordResponse::status,
                       Property(&StatusProto::code, Eq(error::OK))));
}

TEST_F(MissiveImplTest, FlushPriorityTest) {
  FlushPriorityRequest request;
  request.set_priority(MANUAL_BATCH);

  EXPECT_CALL(*storage_module_, Flush(Eq(request.priority()), _))
      .WillOnce(WithArg<1>([](StorageModuleInterface::FlushCallback callback) {
        std::move(callback).Run(Status::StatusOK());
      }));

  auto response = std::make_unique<
      brillo::dbus_utils::MockDBusMethodResponse<FlushPriorityResponse>>();
  test::TestEvent<const FlushPriorityResponse&> response_event;
  response->set_return_callback(response_event.cb());
  missive_->FlushPriority(request, std::move(response));
  const auto& response_result = response_event.ref_result();
  EXPECT_THAT(response_result,
              Property(&FlushPriorityResponse::status,
                       Property(&StatusProto::code, Eq(error::OK))));
}

TEST_F(MissiveImplTest, ConfirmRecordUploadTest) {
  ConfirmRecordUploadRequest request;
  request.mutable_sequence_information()->set_sequencing_id(1234L);
  request.mutable_sequence_information()->set_generation_id(9876L);
  request.mutable_sequence_information()->set_priority(IMMEDIATE);
  request.set_force_confirm(true);

  EXPECT_CALL(*storage_module_,
              ReportSuccess(EqualsProto(request.sequence_information()),
                            Eq(request.force_confirm())))
      .Times(1);

  auto response = std::make_unique<brillo::dbus_utils::MockDBusMethodResponse<
      ConfirmRecordUploadResponse>>();
  test::TestEvent<const ConfirmRecordUploadResponse&> response_event;
  response->set_return_callback(response_event.cb());
  missive_->ConfirmRecordUpload(request, std::move(response));
  const auto& response_result = response_event.ref_result();
  EXPECT_THAT(response_result,
              Property(&ConfirmRecordUploadResponse::status,
                       Property(&StatusProto::code, Eq(error::OK))));
}

TEST_F(MissiveImplTest, UpdateEncryptionKeyTest) {
  UpdateEncryptionKeyRequest request;
  request.mutable_signed_encryption_info()->set_public_asymmetric_key(
      "PUBLIC_KEY");
  request.mutable_signed_encryption_info()->set_public_key_id(555666);
  request.mutable_signed_encryption_info()->set_signature("SIGNATURE");

  EXPECT_CALL(
      *storage_module_,
      UpdateEncryptionKey(EqualsProto(request.signed_encryption_info())))
      .Times(1);

  auto response = std::make_unique<brillo::dbus_utils::MockDBusMethodResponse<
      UpdateEncryptionKeyResponse>>();
  test::TestEvent<const UpdateEncryptionKeyResponse&> response_event;
  response->set_return_callback(response_event.cb());
  missive_->UpdateEncryptionKey(request, std::move(response));
  const auto& response_result = response_event.ref_result();
  EXPECT_THAT(response_result,
              Property(&UpdateEncryptionKeyResponse::status,
                       Property(&StatusProto::code, Eq(error::OK))));
}

TEST_F(MissiveImplTest, ResponseWithErrorTest) {
  const Status error{error::INTERNAL, "Test generated error"};

  FlushPriorityRequest request;
  request.set_priority(SLOW_BATCH);

  EXPECT_CALL(*storage_module_, Flush(Eq(request.priority()), _))
      .WillOnce(
          WithArg<1>([&error](StorageModuleInterface::FlushCallback callback) {
            std::move(callback).Run(error);
          }));

  auto response = std::make_unique<
      brillo::dbus_utils::MockDBusMethodResponse<FlushPriorityResponse>>();
  test::TestEvent<const FlushPriorityResponse&> response_event;
  response->set_return_callback(response_event.cb());
  missive_->FlushPriority(request, std::move(response));
  const auto& response_result = response_event.ref_result();
  EXPECT_THAT(
      response_result,
      Property(&FlushPriorityResponse::status,
               AllOf(Property(&StatusProto::code, Eq(error.error_code())),
                     Property(&StatusProto::error_message,
                              StrEq(error.error_message())))));
}

TEST_F(MissiveImplTest, DisabledReportingTest) {
  // Simulate upload with FAILURE_PRECONDITION response to disable reporting.
  missive_->SetEnabled(/*is_enabled=*/false);

  {
    EnqueueRecordRequest request;
    request.mutable_record()->set_data("DATA");
    request.mutable_record()->set_destination(HEARTBEAT_EVENTS);
    request.set_priority(FAST_BATCH);

    EXPECT_CALL(*storage_module_, AddRecord).Times(0);

    auto response = std::make_unique<
        brillo::dbus_utils::MockDBusMethodResponse<EnqueueRecordResponse>>();
    test::TestEvent<const EnqueueRecordResponse&> response_event;
    response->set_return_callback(response_event.cb());
    missive_->EnqueueRecord(request, std::move(response));
    const auto& response_result = response_event.ref_result();
    EXPECT_THAT(response_result,
                Property(&EnqueueRecordResponse::status,
                         AllOf(Property(&StatusProto::code,
                                        Eq(error::FAILED_PRECONDITION)),
                               Property(&StatusProto::error_message,
                                        StrEq("Reporting is disabled")))));
  }

  {
    FlushPriorityRequest request;
    request.set_priority(MANUAL_BATCH);

    EXPECT_CALL(*storage_module_, Flush).Times(0);

    auto response = std::make_unique<
        brillo::dbus_utils::MockDBusMethodResponse<FlushPriorityResponse>>();
    test::TestEvent<const FlushPriorityResponse&> response_event;
    response->set_return_callback(response_event.cb());
    missive_->FlushPriority(request, std::move(response));
    const auto& response_result = response_event.ref_result();
    EXPECT_THAT(response_result,
                Property(&FlushPriorityResponse::status,
                         AllOf(Property(&StatusProto::code,
                                        Eq(error::FAILED_PRECONDITION)),
                               Property(&StatusProto::error_message,
                                        StrEq("Reporting is disabled")))));
  }

  {
    ConfirmRecordUploadRequest request;
    request.mutable_sequence_information()->set_sequencing_id(1234L);
    request.mutable_sequence_information()->set_generation_id(9876L);
    request.mutable_sequence_information()->set_priority(IMMEDIATE);
    request.set_force_confirm(true);

    EXPECT_CALL(*storage_module_, ReportSuccess).Times(0);

    auto response = std::make_unique<brillo::dbus_utils::MockDBusMethodResponse<
        ConfirmRecordUploadResponse>>();
    test::TestEvent<const ConfirmRecordUploadResponse&> response_event;
    response->set_return_callback(response_event.cb());
    missive_->ConfirmRecordUpload(request, std::move(response));
    const auto& response_result = response_event.ref_result();
    EXPECT_THAT(response_result,
                Property(&ConfirmRecordUploadResponse::status,
                         AllOf(Property(&StatusProto::code,
                                        Eq(error::FAILED_PRECONDITION)),
                               Property(&StatusProto::error_message,
                                        StrEq("Reporting is disabled")))));
  }

  {
    UpdateEncryptionKeyRequest request;
    request.mutable_signed_encryption_info()->set_public_asymmetric_key(
        "PUBLIC_KEY");
    request.mutable_signed_encryption_info()->set_public_key_id(555666);
    request.mutable_signed_encryption_info()->set_signature("SIGNATURE");

    EXPECT_CALL(*storage_module_, UpdateEncryptionKey).Times(0);

    auto response = std::make_unique<brillo::dbus_utils::MockDBusMethodResponse<
        UpdateEncryptionKeyResponse>>();
    test::TestEvent<const UpdateEncryptionKeyResponse&> response_event;
    response->set_return_callback(response_event.cb());
    missive_->UpdateEncryptionKey(request, std::move(response));
    const auto& response_result = response_event.ref_result();
    EXPECT_THAT(response_result,
                Property(&UpdateEncryptionKeyResponse::status,
                         AllOf(Property(&StatusProto::code,
                                        Eq(error::FAILED_PRECONDITION)),
                               Property(&StatusProto::error_message,
                                        StrEq("Reporting is disabled")))));
  }

  {
    test::TestEvent<StatusOr<std::unique_ptr<UploaderInterface>>>
        uploader_event;
    MissiveImpl::AsyncStartUpload(
        missive_->GetWeakPtr(),
        UploaderInterface::UploadReason::IMMEDIATE_FLUSH, uploader_event.cb());
    const auto& response_result = uploader_event.result();
    EXPECT_THAT(response_result,
                Property(&StatusOr<std::unique_ptr<UploaderInterface>>::status,
                         AllOf(Property(&Status::error_code,
                                        Eq(error::FAILED_PRECONDITION)),
                               Property(&Status::error_message,
                                        StrEq("Reporting is disabled")))));
  }
}

TEST_F(MissiveImplTest, DynamicParametersUpdateTest) {
  // Change parameters and refresh.
  fake_platform_features_ptr_->SetParam(
      MissiveArgs::kStorageFeature.name,
      MissiveArgs::kCompressionEnabledParameter, "False");
  fake_platform_features_ptr_->SetParam(
      MissiveArgs::kStorageFeature.name,
      MissiveArgs::kEncryptionEnabledParameter, "False");
  fake_platform_features_ptr_->TriggerRefetchSignal();

  // Let asynchronous update finish.
  task_environment_.RunUntilIdle();

  EXPECT_FALSE(compression_module_->is_enabled());
  EXPECT_FALSE(encryption_module_->is_enabled());
}
}  // namespace reporting
