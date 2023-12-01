// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "missive/scheduler/upload_job.h"

#include <cstddef>
#include <memory>
#include <optional>
#include <utility>

#include <base/functional/bind.h>
#include <base/functional/callback.h>
#include <base/functional/callback_helpers.h>
#include <base/memory/ptr_util.h>
#include <base/memory/scoped_refptr.h>
#include <base/memory/weak_ptr.h>
#include <base/task/bind_post_task.h>
#include <base/task/sequenced_task_runner.h>
#include <base/task/task_traits.h>
#include <base/task/thread_pool.h>

#include "missive/dbus/upload_client.h"
#include "missive/proto/record.pb.h"
#include "missive/resources/resource_manager.h"
#include "missive/scheduler/scheduler.h"
#include "missive/storage/storage_uploader_interface.h"
#include "missive/util/status.h"
#include "missive/util/statusor.h"

namespace reporting {
namespace {

// This is a fuzzy max, some functions may go over it but most requests should
// be limited to kMaxUploadSize.
constexpr size_t kMaxUploadSize = 10UL * 1024UL * 1024UL;  // 10MiB

}  // namespace

UploadJob::UploadDelegate::UploadDelegate(
    scoped_refptr<UploadClient> upload_client,
    bool need_encryption_key,
    uint64_t remaining_storage_capacity,
    std::optional<uint64_t> new_events_rate,
    UploadClient::HandleUploadResponseCallback response_cb)
    : upload_client_(upload_client),
      need_encryption_key_(need_encryption_key),
      remaining_storage_capacity_(remaining_storage_capacity),
      new_events_rate_(new_events_rate),
      response_cb_(std::move(response_cb)) {}

UploadJob::UploadDelegate::~UploadDelegate() = default;
UploadJob::SetRecordsCb UploadJob::UploadDelegate::GetSetRecordsCb() {
  return base::BindOnce(&UploadDelegate::SetRecords, base::Unretained(this));
}

Status UploadJob::UploadDelegate::Complete() {
  upload_client_->SendEncryptedRecords(
      std::move(encrypted_records_), need_encryption_key_,
      remaining_storage_capacity_, new_events_rate_, std::move(response_cb_));
  return Status::StatusOK();
}

Status UploadJob::UploadDelegate::Cancel(Status status) {
  // UploadJob has nothing to do in the event of cancellation.
  return Status::StatusOK();
}

void UploadJob::UploadDelegate::SetRecords(EncryptedRecords records) {
  encrypted_records_ = std::move(records);
}

UploadJob::RecordProcessor::RecordProcessor(DoneCb done_cb)
    : done_cb_(std::move(done_cb)) {
  DETACH_FROM_SEQUENCE(sequence_checker_);
  DCHECK(done_cb_);
}

UploadJob::RecordProcessor::~RecordProcessor() = default;

void UploadJob::RecordProcessor::ProcessRecord(
    EncryptedRecord record,
    ScopedReservation scoped_reservation,
    base::OnceCallback<void(bool)> processed_cb) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);  // Guaranteed by storage
  size_t record_size = record.ByteSizeLong();
  // We have to allow a single record through even if it is too large.
  // Otherwise the whole system will backup.
  if (current_size_ != 0 && record_size + current_size_ > kMaxUploadSize) {
    std::move(processed_cb).Run(false);
    return;
  }
  encrypted_records_.push_back(std::move(record));
  encrypted_records_reservation_.HandOver(scoped_reservation);
  current_size_ += record_size;
  std::move(processed_cb).Run(current_size_ < kMaxUploadSize);
}

void UploadJob::RecordProcessor::ProcessGap(
    SequenceInformation start,
    uint64_t count,
    base::OnceCallback<void(bool)> processed_cb) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);  // Guaranteed by storage
  // We'll process the whole gap request, even if it goes over our max.
  for (uint64_t i = 0; i < count; ++i) {
    encrypted_records_.emplace_back();
    *encrypted_records_.rbegin()->mutable_sequence_information() = start;
    start.set_sequencing_id(start.sequencing_id() + 1);
    current_size_ += encrypted_records_.rbegin()->ByteSizeLong();
  }
  std::move(processed_cb).Run(current_size_ < kMaxUploadSize);
}

void UploadJob::RecordProcessor::Completed(Status final_status) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);  // Guaranteed by storage
  DCHECK(done_cb_);
  if (!final_status.ok()) {
    // Destroy the records to regain system memory now.
    encrypted_records_.clear();
    std::move(done_cb_).Run(final_status,
                            std::move(encrypted_records_reservation_));
    return;
  }
  std::move(done_cb_).Run(std::move(encrypted_records_),
                          std::move(encrypted_records_reservation_));
}

// static
StatusOr<Scheduler::Job::SmartPtr<UploadJob>> UploadJob::Create(
    scoped_refptr<UploadClient> upload_client,
    bool need_encryption_key,
    uint64_t remaining_storage_capacity,
    std::optional<uint64_t> new_events_rate,
    UploaderInterface::UploaderInterfaceResultCb start_cb,
    UploadClient::HandleUploadResponseCallback response_cb) {
  if (upload_client == nullptr) {
    Status status(error::INVALID_ARGUMENT,
                  "Unable to create UploadJob, invalid upload_client");
    std::move(start_cb).Run(status);
    return status;
  }

  auto upload_delegate = std::make_unique<UploadDelegate>(
      upload_client, need_encryption_key, remaining_storage_capacity,
      new_events_rate, std::move(response_cb));
  SetRecordsCb set_records_callback = upload_delegate->GetSetRecordsCb();

  scoped_refptr<base::SequencedTaskRunner> sequenced_task_runner =
      base::ThreadPool::CreateSequencedTaskRunner(
          {base::TaskPriority::BEST_EFFORT, base::MayBlock()});
  return std::unique_ptr<UploadJob, base::OnTaskRunnerDeleter>(
      new UploadJob(std::move(upload_delegate), sequenced_task_runner,
                    std::move(set_records_callback), std::move(start_cb)),
      base::OnTaskRunnerDeleter(sequenced_task_runner));
}

void UploadJob::StartImpl() {
  std::move(start_cb_).Run(std::make_unique<RecordProcessor>(base::BindPostTask(
      sequenced_task_runner(),
      base::BindOnce(&UploadJob::Done, weak_ptr_factory_.GetWeakPtr()))));
}

void UploadJob::Done(StatusOr<EncryptedRecords> records_result,
                     ScopedReservation records_reservation) {
  CheckValidSequence();
  if (!records_result.ok()) {
    Finish(records_result.status());
    return;
  }
  std::move(set_records_cb_).Run(std::move(records_result.ValueOrDie()));
  Finish(Status::StatusOK());
}

UploadJob::UploadJob(
    std::unique_ptr<UploadDelegate> upload_delegate,
    scoped_refptr<base::SequencedTaskRunner> sequenced_task_runner,
    SetRecordsCb set_records_cb,
    UploaderInterface::UploaderInterfaceResultCb start_cb)
    : Job(std::move(upload_delegate), sequenced_task_runner),
      set_records_cb_(std::move(set_records_cb)),
      start_cb_(std::move(start_cb)) {}

}  // namespace reporting
