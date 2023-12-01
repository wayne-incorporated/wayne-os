// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "missive/scheduler/upload_job.h"

#include <utility>
#include <vector>

#include <base/run_loop.h>
#include <base/memory/scoped_refptr.h>
#include <base/task/task_traits.h>
#include <base/task/thread_pool.h>
#include <base/test/task_environment.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "missive/dbus/mock_upload_client.h"
#include "missive/proto/interface.pb.h"
#include "missive/proto/record.pb.h"
#include "missive/resources/resource_manager.h"
#include "missive/util/test_support_callbacks.h"
#include "missive/util/test_util.h"

using ::testing::_;
using ::testing::Eq;
using ::testing::Invoke;
using ::testing::SizeIs;
using ::testing::WithArgs;

namespace reporting {
namespace {

class TestRecordUploader {
 public:
  TestRecordUploader(std::vector<EncryptedRecord> records,
                     scoped_refptr<ResourceManager> memory_resource)
      : records_(std::move(records)),
        memory_resource_(memory_resource),
        sequenced_task_runner_(base::ThreadPool::CreateSequencedTaskRunner(
            {base::TaskPriority::BEST_EFFORT})) {
    DETACH_FROM_SEQUENCE(sequence_checker_);
  }

  void StartUpload(
      StatusOr<std::unique_ptr<UploaderInterface>> uploader_interface) {
    EXPECT_TRUE(uploader_interface.ok());
    uploader_interface_ = std::move(uploader_interface.ValueOrDie());
    PostNextUpload(/*next=*/true);
  }

 private:
  void Upload(bool send_next_record) {
    DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
    if (!send_next_record || records_.empty()) {
      uploader_interface_->Completed(Status::StatusOK());
      uploader_interface_.reset();  // Do not need it anymore.
      return;
    }
    ScopedReservation record_reservation(records_.front().ByteSizeLong(),
                                         memory_resource_);
    uploader_interface_->ProcessRecord(
        std::move(records_.front()), std::move(record_reservation),
        base::BindOnce(&TestRecordUploader::PostNextUpload,
                       base::Unretained(this)));
    records_.erase(records_.begin());
  }

  void PostNextUpload(bool next) {
    sequenced_task_runner_->PostTask(
        FROM_HERE, base::BindOnce(&TestRecordUploader::Upload,
                                  base::Unretained(this), next));
  }

  std::vector<EncryptedRecord> records_;
  const scoped_refptr<ResourceManager> memory_resource_;
  std::unique_ptr<UploaderInterface> uploader_interface_;

  // To protect |records_| running uploads on sequence.
  SEQUENCE_CHECKER(sequence_checker_);
  scoped_refptr<base::SequencedTaskRunner> sequenced_task_runner_;
};

class UploadJobTest : public ::testing::Test {
 protected:
  void SetUp() override {
    upload_client_ = base::MakeRefCounted<test::MockUploadClient>();
    memory_resource_ =
        base::MakeRefCounted<ResourceManager>(4u * 1024LLu * 1024LLu);  // 4 MiB
  }

  void TearDown() override {
    // Let everything ongoing to finish.
    task_environment_.RunUntilIdle();
    EXPECT_THAT(memory_resource_->GetUsed(), Eq(0uL));
  }

  base::test::TaskEnvironment task_environment_;

  scoped_refptr<ResourceManager> memory_resource_;
  scoped_refptr<test::MockUploadClient> upload_client_;
};

TEST_F(UploadJobTest, UploadsRecords) {
  static constexpr char kTestData[] = "TEST_DATA";
  static constexpr int64_t kSequenceId = 42;
  static constexpr int64_t kGenerationId = 1701;
  static constexpr Priority kPriority = Priority::SLOW_BATCH;

  std::vector<EncryptedRecord> records;
  for (size_t seq_id = 0; seq_id < 10; seq_id++) {
    records.emplace_back();
    EncryptedRecord& encrypted_record = records.back();
    encrypted_record.set_encrypted_wrapped_record(kTestData);

    SequenceInformation* sequence_information =
        encrypted_record.mutable_sequence_information();
    sequence_information->set_sequencing_id(kSequenceId);
    sequence_information->set_generation_id(kGenerationId);
    sequence_information->set_priority(kPriority);
  }

  // Create a copy of the records to ensure they are passed correctly.
  const std::vector<EncryptedRecord> expected_records(records);
  EXPECT_CALL(*upload_client_, SendEncryptedRecords(_, _, _, _, _))
      .WillOnce(WithArgs<0, 4>(Invoke(
          [&expected_records](
              std::vector<EncryptedRecord> records,
              UploadClient::HandleUploadResponseCallback response_callback) {
            ASSERT_THAT(records, SizeIs(expected_records.size()));
            for (size_t i = 0; i < records.size(); i++) {
              EXPECT_THAT(records[i], EqualsProto(expected_records[i]));
            }
            UploadEncryptedRecordResponse upload_response;
            upload_response.mutable_status()->set_code(error::OK);
            std::move(response_callback).Run(std::move(upload_response));
          })));

  TestRecordUploader record_uploader(std::move(records), memory_resource_);

  test::TestEvent<StatusOr<UploadEncryptedRecordResponse>> upload_responded;
  auto job_result =
      UploadJob::Create(upload_client_,
                        /*need_encryption_keys=*/false,
                        /*remaining_storage_capacity=*/3000U,
                        /*new_events_rate=*/300U,
                        base::BindOnce(&TestRecordUploader::StartUpload,
                                       base::Unretained(&record_uploader)),
                        upload_responded.cb());
  ASSERT_TRUE(job_result.ok()) << job_result.status();
  Scheduler::Job::SmartPtr<Scheduler::Job> job =
      std::move(job_result.ValueOrDie());

  test::TestEvent<Status> upload_started;
  job->Start(upload_started.cb());
  const Status status = upload_started.result();
  EXPECT_OK(status) << status;
  // Let everything finish before record_uploader destructs.
  const auto upload_result = upload_responded.result();
  EXPECT_OK(upload_result) << upload_result.status();
}
}  // namespace
}  // namespace reporting
