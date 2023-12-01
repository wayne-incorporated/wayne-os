// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "missive/storage/storage_module.h"

#include <algorithm>
#include <cstddef>
#include <memory>
#include <string>
#include <utility>

#include <base/functional/callback_helpers.h>
#include <base/memory/scoped_refptr.h>
#include <base/test/task_environment.h>
#include <gtest/gtest.h>
#include <unistd.h>

#include "base/files/scoped_temp_dir.h"
#include "base/functional/bind.h"
#include "missive/compression/compression_module.h"
#include "missive/encryption/encryption_module.h"
#include "missive/encryption/verification.h"
#include "missive/proto/record.pb.h"
#include "missive/proto/record_constants.pb.h"
#include "missive/resources/resource_manager.h"
#include "missive/storage/new_storage.h"
#include "missive/storage/storage.h"
#include "missive/storage/storage_base.h"
#include "missive/storage/storage_uploader_interface.h"
#include "missive/util/status.h"
#include "missive/util/statusor.h"
#include "missive/util/test_support_callbacks.h"

namespace reporting {

// UploaderInterface for testing that replies with success every time.
class TestUploaderInterface : public UploaderInterface {
 public:
  TestUploaderInterface() = default;
  // Factory method.
  static void AsyncProvideUploader(
      UploaderInterface::UploadReason reason,
      UploaderInterfaceResultCb start_uploader_cb) {
    std::move(start_uploader_cb).Run(std::make_unique<TestUploaderInterface>());
  }

  void ProcessRecord(EncryptedRecord encrypted_record,
                     ScopedReservation scoped_reservation,
                     base::OnceCallback<void(bool)> processed_cb) override {
    // Reply with success
    std::move(processed_cb).Run(true);
  }

  void ProcessGap(SequenceInformation start,
                  uint64_t count,
                  base::OnceCallback<void(bool)> processed_cb) override {
    // Reply with success
    std::move(processed_cb).Run(true);
  }

  void Completed(Status final_status) override {
    // Do nothing
  }
};

class StorageModuleTest : public ::testing::Test {
 protected:
  StorageModuleTest() = default;

  void SetUp() override { storage_module_.reset(); }

  void CreateStorageModule(bool legacy_storage_enabled) {
    test::TestEvent<StatusOr<scoped_refptr<StorageModule>>> module_event;
    StorageModule::Create(
        StorageOptions(),
        /*legacy_storage_enabled=*/legacy_storage_enabled,
        base::BindRepeating(TestUploaderInterface::AsyncProvideUploader),
        QueuesContainer::Create(/*is_enabled=*/false),
        EncryptionModule::Create(/*is_enabled=*/false),
        CompressionModule::Create(
            /*is_enabled=*/true, /*compression_threshold=*/0,
            /*compression_type=*/CompressionInformation::COMPRESSION_SNAPPY),
        base::MakeRefCounted<SignatureVerificationDevFlag>(
            /*is_enabled=*/false),
        base::BindPostTaskToCurrentDefault(module_event.cb()));
    auto res = module_event.result();
    ASSERT_OK(res);
    EXPECT_TRUE(res.ValueOrDie().get());
    storage_module_ = res.ValueOrDie();
  }

  void RegisterOnStorageSetCallbackForTesting(
      scoped_refptr<StorageModule> storage_module,
      base::OnceCallback<void(StatusOr<scoped_refptr<StorageModule>>)>
          callback) {
    storage_module->RegisterOnStorageSetCallbackForTesting(std::move(callback));
  }

  std::string GetStorageName(scoped_refptr<StorageModule> storage_module) {
    test::TestEvent<const char*> get_storage_impl_name;
    storage_module->GetStorageImplNameForTesting(get_storage_impl_name.cb());
    return get_storage_impl_name.result();
  }

  Status CallAddRecord(scoped_refptr<StorageModule> module) {
    test::TestEvent<Status> event;
    Record record;
    record.set_data("DATA");
    record.set_destination(UPLOAD_EVENTS);
    record.set_dm_token("DM TOKEN");
    module->AddRecord(IMMEDIATE, std::move(record), event.cb());
    return event.result();
  }

  Status CallFlush(scoped_refptr<StorageModule> module) {
    test::TestEvent<Status> event;
    module->Flush(SECURITY, event.cb());
    return event.result();
  }

  void InjectStorageUnavailableError() {
    ASSERT_TRUE(storage_module_);
    storage_module_->InjectStorageUnavailableErrorForTesting();
  }

  base::test::TaskEnvironment task_environment_;
  scoped_refptr<StorageModule> storage_module_;
};

TEST_F(StorageModuleTest, NewStorageTest) {
  // Create storage module with new storage implementation.
  CreateStorageModule(/*legacy_storage_enabled=*/false);
  auto new_storage_module = storage_module_;

  // Expect that the storage module contains a new storage implementation.
  EXPECT_EQ(GetStorageName(new_storage_module), kNewStorageName);
  EXPECT_FALSE(new_storage_module->legacy_storage_enabled());
}

TEST_F(StorageModuleTest, LegacyStorageTest) {
  // Create storage module with legacy storage implementation.
  CreateStorageModule(/*legacy_storage_enabled=*/true);
  auto legacy_storage_module = storage_module_;

  // Expect that the storage module contains a legacy storage implementation.
  EXPECT_EQ(GetStorageName(legacy_storage_module), kLegacyStorageName);
  EXPECT_TRUE(legacy_storage_module->legacy_storage_enabled());
}

TEST_F(StorageModuleTest, SwitchFromLegacyToNewStorage) {
  // Create storage module with legacy storage implementation.
  CreateStorageModule(/*legacy_storage_enabled=*/true);
  auto legacy_storage_module = storage_module_;

  // Expect that the storage module contains a legacy storage implementation.
  EXPECT_EQ(GetStorageName(legacy_storage_module), kLegacyStorageName);
  EXPECT_TRUE(legacy_storage_module->legacy_storage_enabled());

  test::TestEvent<StatusOr<scoped_refptr<StorageModule>>> switch_storage_event;
  RegisterOnStorageSetCallbackForTesting(legacy_storage_module,
                                         switch_storage_event.cb());

  ASSERT_OK(CallAddRecord(legacy_storage_module));

  // Flip the value of legacy_storage_enabled flag to false, triggering
  // `storage_module` to switch from legacy storage to new storage.
  legacy_storage_module->SetValue(false);

  const auto switch_result = switch_storage_event.result();
  ASSERT_OK(switch_result);
  EXPECT_TRUE(switch_result.ValueOrDie().get());
  const auto new_storage_module = switch_result.ValueOrDie();

  // Expect that the storage module contains a new storage implementation.
  EXPECT_EQ(GetStorageName(new_storage_module), kNewStorageName);
  EXPECT_FALSE(new_storage_module->legacy_storage_enabled());

  // Verify we can write to new storage module after switching.
  ASSERT_OK(CallAddRecord(new_storage_module));
}

TEST_F(StorageModuleTest, SwitchFromNewToLegacyStorage) {
  // Create storage module with new storage implementation.
  CreateStorageModule(/*legacy_storage_enabled=*/false);
  auto new_storage_module = storage_module_;

  // Expect that the storage module contains a new storage implementation.
  EXPECT_FALSE(new_storage_module->legacy_storage_enabled());
  EXPECT_EQ(GetStorageName(new_storage_module), kNewStorageName);

  test::TestEvent<StatusOr<scoped_refptr<StorageModule>>> switch_storage_event;
  RegisterOnStorageSetCallbackForTesting(new_storage_module,
                                         switch_storage_event.cb());

  // Verify we can write to new storage module
  ASSERT_OK(CallAddRecord(new_storage_module));

  // Flip the value of `legacy_storage_enabled` flag to true, triggering
  // `storage_module` to switch from new storage to legacy storage.
  new_storage_module->SetValue(true);

  const auto switch_result = switch_storage_event.result();
  ASSERT_OK(switch_result);
  EXPECT_TRUE(switch_result.ValueOrDie().get());
  const auto legacy_storage_module = switch_result.ValueOrDie();

  // Expect that the storage module contains a legacy storage implementation.
  EXPECT_EQ(GetStorageName(legacy_storage_module), kLegacyStorageName);
  EXPECT_TRUE(legacy_storage_module->legacy_storage_enabled());

  // Verify we can write to legacy storage module after switching.
  ASSERT_OK(CallAddRecord(legacy_storage_module));
}

TEST_F(StorageModuleTest, ExpectErrorIfStorageUnavailable) {
  CreateStorageModule(/*legacy_storage_enabled=*/false);
  InjectStorageUnavailableError();

  const Status add_record_status = CallAddRecord(storage_module_);
  EXPECT_FALSE(add_record_status.ok());
  EXPECT_EQ(add_record_status.error_code(), error::UNAVAILABLE);

  const Status flush_status = CallFlush(storage_module_);
  EXPECT_FALSE(flush_status.ok());
  EXPECT_EQ(flush_status.error_code(), error::UNAVAILABLE);
}
}  // namespace reporting
