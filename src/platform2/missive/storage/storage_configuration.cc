// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "missive/storage/storage_configuration.h"

#include <base/containers/span.h>

#include "missive/proto/record_constants.pb.h"
#include "missive/resources/resource_manager.h"
#include "missive/util/status.h"

namespace reporting {

namespace {

// Parameters of individual queues.
// TODO(b/159352842): Deliver space and upload parameters from outside.

constexpr char kSecurityQueueSubdir[] = "Security";
constexpr char kSecurityQueuePrefix[] = "P_Security";

constexpr char kImmediateQueueSubdir[] = "Immediate";
constexpr char kImmediateQueuePrefix[] = "P_Immediate";

constexpr char kFastBatchQueueSubdir[] = "FastBatch";
constexpr char kFastBatchQueuePrefix[] = "P_FastBatch";
constexpr base::TimeDelta kFastBatchUploadPeriod = base::Seconds(1);

constexpr char kSlowBatchQueueSubdir[] = "SlowBatch";
constexpr char kSlowBatchQueuePrefix[] = "P_SlowBatch";
constexpr base::TimeDelta kSlowBatchUploadPeriod = base::Seconds(20);

constexpr char kBackgroundQueueSubdir[] = "Background";
constexpr char kBackgroundQueuePrefix[] = "P_Background";
constexpr base::TimeDelta kBackgroundQueueUploadPeriod = base::Minutes(1);

constexpr char kManualQueueSubdir[] = "Manual";
constexpr char kManualQueuePrefix[] = "P_Manual";
constexpr base::TimeDelta kManualUploadPeriod = base::TimeDelta::Max();

constexpr char kManualLacrosQueueSubdir[] = "ManualLacros";
constexpr char kManualLacrosQueuePrefix[] = "P_ManualLacros";

// Order of priorities
constexpr std::array<Priority, 7> kPriorityOrder = {
    MANUAL_BATCH_LACROS, MANUAL_BATCH, BACKGROUND_BATCH, SLOW_BATCH,
    FAST_BATCH,          IMMEDIATE,    SECURITY};

// Failed upload retry delay: if an upload fails and there are no more incoming
// events, collected events will not get uploaded for an indefinite time (see
// b/192666219).
constexpr base::TimeDelta kFailedUploadRetryDelay = base::Seconds(1);

}  // namespace

StorageOptions::StorageOptions(
    base::RepeatingCallback<void(Priority, QueueOptions&)>
        modify_queue_options_for_tests)
    : key_check_period_(kDefaultKeyCheckPeriod),  // 1 second by default
      memory_resource_(base::MakeRefCounted<ResourceManager>(
          4u * 1024uLL * 1024uLL)),  // 4 MiB by default
      disk_space_resource_(base::MakeRefCounted<ResourceManager>(
          64u * 1024uLL * 1024uLL)),  // 64 MiB by default.
      modify_queue_options_for_tests_(modify_queue_options_for_tests) {}
StorageOptions::StorageOptions(const StorageOptions& options) = default;
StorageOptions::~StorageOptions() = default;

QueueOptions StorageOptions::PopulateQueueOptions(Priority priority) const {
  switch (priority) {
    case MANUAL_BATCH_LACROS:
      return QueueOptions(*this)
          .set_subdirectory(kManualLacrosQueueSubdir)
          .set_file_prefix(kManualLacrosQueuePrefix)
          .set_upload_period(kManualUploadPeriod)
          .set_upload_retry_delay(kFailedUploadRetryDelay);
    case MANUAL_BATCH:
      return QueueOptions(*this)
          .set_subdirectory(kManualQueueSubdir)
          .set_file_prefix(kManualQueuePrefix)
          .set_upload_period(kManualUploadPeriod)
          .set_upload_retry_delay(kFailedUploadRetryDelay);
    case BACKGROUND_BATCH:
      return QueueOptions(*this)
          .set_subdirectory(kBackgroundQueueSubdir)
          .set_file_prefix(kBackgroundQueuePrefix)
          .set_upload_period(kBackgroundQueueUploadPeriod);
    case SLOW_BATCH:
      return QueueOptions(*this)
          .set_subdirectory(kSlowBatchQueueSubdir)
          .set_file_prefix(kSlowBatchQueuePrefix)
          .set_upload_period(kSlowBatchUploadPeriod);
    case FAST_BATCH:
      return QueueOptions(*this)
          .set_subdirectory(kFastBatchQueueSubdir)
          .set_file_prefix(kFastBatchQueuePrefix)
          .set_upload_period(kFastBatchUploadPeriod);
    case IMMEDIATE:
      return QueueOptions(*this)
          .set_subdirectory(kImmediateQueueSubdir)
          .set_file_prefix(kImmediateQueuePrefix)
          .set_upload_retry_delay(kFailedUploadRetryDelay);
    case SECURITY:
      return QueueOptions(*this)
          .set_subdirectory(kSecurityQueueSubdir)
          .set_file_prefix(kSecurityQueuePrefix)
          .set_upload_retry_delay(kFailedUploadRetryDelay)
          .set_can_shed_records(false);
    case UNDEFINED_PRIORITY:
      NOTREACHED() << "No QueueOptions for priority UNDEFINED_PRIORITY.";
      return QueueOptions(*this);
  }
}

QueueOptions StorageOptions::ProduceQueueOptions(Priority priority) const {
  QueueOptions queue_options(PopulateQueueOptions(priority));
  modify_queue_options_for_tests_.Run(priority, queue_options);
  return queue_options;
}

StorageOptions::QueuesOptionsList StorageOptions::ProduceQueuesOptionsList()
    const {
  QueuesOptionsList queue_options_list;
  // Create queue option for each priority and add to the list
  for (const auto priority : kPriorityOrder) {
    queue_options_list.emplace_back(priority, ProduceQueueOptions(priority));
  }
  return queue_options_list;
}

// static
base::span<const Priority> StorageOptions::GetPrioritiesOrder() {
  return base::make_span(kPriorityOrder);
}

QueueOptions::QueueOptions(const StorageOptions& storage_options)
    : storage_options_(storage_options) {}
QueueOptions::QueueOptions(const QueueOptions& options) = default;

}  // namespace reporting
