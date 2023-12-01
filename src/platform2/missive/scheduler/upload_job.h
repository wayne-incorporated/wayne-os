// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MISSIVE_SCHEDULER_UPLOAD_JOB_H_
#define MISSIVE_SCHEDULER_UPLOAD_JOB_H_

#include <memory>
#include <optional>
#include <vector>

#include <base/functional/callback.h>
#include <base/memory/scoped_refptr.h>
#include <base/memory/weak_ptr.h>
#include <base/task/sequenced_task_runner.h>

#include "missive/dbus/upload_client.h"
#include "missive/proto/record.pb.h"
#include "missive/proto/record_constants.pb.h"
#include "missive/resources/resource_manager.h"
#include "missive/scheduler/scheduler.h"
#include "missive/storage/storage_uploader_interface.h"
#include "missive/util/status.h"
#include "missive/util/statusor.h"

namespace reporting {

class UploadJob : public Scheduler::Job {
 public:
  using EncryptedRecords = std::vector<EncryptedRecord>;
  using SetRecordsCb = base::OnceCallback<void(EncryptedRecords)>;
  using DoneCb =
      base::OnceCallback<void(StatusOr<EncryptedRecords>, ScopedReservation)>;

  class UploadDelegate : public Job::JobDelegate {
   public:
    UploadDelegate(scoped_refptr<UploadClient> upload_client,
                   bool need_encryption_key,
                   uint64_t remaining_storage_capacity,
                   std::optional<uint64_t> new_events_rate,
                   UploadClient::HandleUploadResponseCallback response_cb);
    UploadDelegate(const UploadDelegate& other) = delete;
    UploadDelegate& operator=(const UploadDelegate& other) = delete;
    ~UploadDelegate() override;

    SetRecordsCb GetSetRecordsCb();

   private:
    Status Complete() override;
    Status Cancel(Status status) override;

    void SetRecords(EncryptedRecords records);

    const scoped_refptr<UploadClient> upload_client_;
    const bool need_encryption_key_;
    EncryptedRecords encrypted_records_;
    ScopedReservation encrypted_records_reservation_;

    uint64_t remaining_storage_capacity_;
    std::optional<uint64_t> new_events_rate_;

    UploadClient::HandleUploadResponseCallback response_cb_;
  };

  class RecordProcessor : public UploaderInterface {
   public:
    explicit RecordProcessor(DoneCb done_cb);
    RecordProcessor(const RecordProcessor& other) = delete;
    RecordProcessor& operator=(const RecordProcessor& other) = delete;
    ~RecordProcessor() override;

    void ProcessRecord(EncryptedRecord record,
                       ScopedReservation scoped_reservation,
                       base::OnceCallback<void(bool)> processed_cb) override;

    void ProcessGap(SequenceInformation start,
                    uint64_t count,
                    base::OnceCallback<void(bool)> processed_cb) override;

    void Completed(Status final_status) override;

   private:
    DoneCb done_cb_;

    EncryptedRecords encrypted_records_;
    ScopedReservation encrypted_records_reservation_;

    size_t current_size_{0};

    SEQUENCE_CHECKER(sequence_checker_);
  };

  UploadJob(const UploadJob& other) = delete;
  UploadJob& operator=(const UploadJob& other) = delete;

  static StatusOr<SmartPtr<UploadJob>> Create(
      scoped_refptr<UploadClient> upload_client,
      bool need_encryption_key,
      uint64_t remaining_storage_capacity,
      std::optional<uint64_t> new_events_rate,
      UploaderInterface::UploaderInterfaceResultCb start_cb,
      UploadClient::HandleUploadResponseCallback response_cb);

 protected:
  void StartImpl() override;
  void Done(StatusOr<EncryptedRecords> records_result,
            ScopedReservation records_reservation);

 private:
  UploadJob(std::unique_ptr<UploadDelegate> upload_delegate,
            scoped_refptr<base::SequencedTaskRunner> sequenced_task_runner,
            SetRecordsCb set_records_cb,
            UploaderInterface::UploaderInterfaceResultCb start_cb);

  SetRecordsCb set_records_cb_;
  UploaderInterface::UploaderInterfaceResultCb start_cb_;

  std::unique_ptr<UploadDelegate> upload_delegate_;
  base::WeakPtrFactory<UploadJob> weak_ptr_factory_{this};
};

}  // namespace reporting

#endif  // MISSIVE_SCHEDULER_UPLOAD_JOB_H_
