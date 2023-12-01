// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/cleanup/low_disk_space_handler.h"

#include <type_traits>

#include <base/check.h>
#include <base/logging.h>

#include "cryptohome/cleanup/disk_cleanup.h"
#include "cryptohome/cleanup/user_oldest_activity_timestamp_manager.h"
#include "cryptohome/platform.h"
#include "cryptohome/storage/homedirs.h"

namespace cryptohome {

namespace {

bool IsDiskSpaceLow(DiskCleanup::FreeSpaceState state) {
  switch (state) {
    case DiskCleanup::FreeSpaceState::kNeedNormalCleanup:
    case DiskCleanup::FreeSpaceState::kNeedAggressiveCleanup:
    case DiskCleanup::FreeSpaceState::kNeedCriticalCleanup:
      return true;
    case DiskCleanup::FreeSpaceState::kError:
    case DiskCleanup::FreeSpaceState::kAboveTarget:
    case DiskCleanup::FreeSpaceState::kAboveThreshold:
      return false;
  }
}

}  // namespace

LowDiskSpaceHandler::LowDiskSpaceHandler(
    HomeDirs* homedirs,
    Platform* platform,
    UserOldestActivityTimestampManager* timestamp_manager)
    : platform_(platform),
      default_cleanup_(new DiskCleanup(platform, homedirs, timestamp_manager)),
      cleanup_(default_cleanup_.get()),
      low_disk_notification_period_(kLowDiskNotificationPeriod),
      update_user_activity_timestamp_period_(kUpdateUserActivityPeriod) {}

LowDiskSpaceHandler::~LowDiskSpaceHandler() {
  DCHECK(stopped_);
}

void LowDiskSpaceHandler::Stop() {
  stopped_ = true;
}

bool LowDiskSpaceHandler::Init(
    base::RepeatingCallback<bool(const base::Location&,
                                 base::OnceClosure,
                                 const base::TimeDelta&)> post_delayed_task) {
  post_delayed_task_ = post_delayed_task;

  last_update_user_activity_timestamp_time_ = platform_->GetCurrentTime();

  // We need to mark "stopped_" as false BEFORE calling any of the following
  // methods, for the callbacks to work correctly; i.e. especially since the
  // default "base::TimeDelta()" is zero and the "post_delayed_task" could
  // call the callbacks from a different thread.
  stopped_ = false;

  if (!post_delayed_task_.Run(
          FROM_HERE,
          base::BindOnce(&LowDiskSpaceHandler::FreeDiskSpace,
                         weak_factory_.GetWeakPtr()),
          base::TimeDelta()))
    return false;

  if (!post_delayed_task_.Run(
          FROM_HERE,
          base::BindOnce(&LowDiskSpaceHandler::LowDiskSpaceCheck,
                         weak_factory_.GetWeakPtr()),
          base::TimeDelta()))
    return false;

  return true;
}

void LowDiskSpaceHandler::FreeDiskSpace() {
  if (stopped_)
    return;

  if (!cleanup_->FreeDiskSpace()) {
    LOG(ERROR) << "FreeDiskSpace encontered an error";
  }

  last_auto_cleanup_time_ = platform_->GetCurrentTime();
}

void LowDiskSpaceHandler::LowDiskSpaceCheck() {
  if (stopped_)
    return;

  bool low_disk_space_signal_emitted = false;
  auto free_disk_space = cleanup_->AmountOfFreeDiskSpace();
  auto free_space_state = cleanup_->GetFreeDiskSpaceState(free_disk_space);
  if (free_space_state == DiskCleanup::FreeSpaceState::kError) {
    LOG(ERROR) << "Error getting free disk space";
  } else {
    VLOG(1) << "Available free disk space " << *free_disk_space
            << "; FreeSpaceState="
            << static_cast<std::underlying_type_t<DiskCleanup::FreeSpaceState>>(
                   free_space_state);

    if (IsDiskSpaceLow(free_space_state)) {
      LOG(INFO) << "Available disk space: |" << free_disk_space.value()
                << "| bytes.  Emitting low disk space signal.";
      low_disk_space_callback_.Run(free_disk_space.value());
      low_disk_space_signal_emitted = true;
    }
  }

  const base::Time current_time = platform_->GetCurrentTime();

  const bool time_for_auto_cleanup =
      current_time - last_auto_cleanup_time_ > kAutoCleanupPeriod;

  // We shouldn't repeat cleanups on every minute if the disk space
  // stays below the threshold. Trigger it only if there was no notification
  // previously or if enterprise owned and free space can be reclaimed.
  const bool early_cleanup_needed = low_disk_space_signal_emitted &&
                                    (!low_disk_space_signal_was_emitted_ ||
                                     cleanup_->IsFreeableDiskSpaceAvailable());

  if (time_for_auto_cleanup || early_cleanup_needed)
    FreeDiskSpace();

  const bool time_for_update_user_activity_timestamp =
      current_time - last_update_user_activity_timestamp_time_ >
      update_user_activity_timestamp_period_;

  if (time_for_update_user_activity_timestamp) {
    last_update_user_activity_timestamp_time_ = current_time;

    cleanup_->CheckNumUserHomeDirectories();

    update_user_activity_timestamp_callback_.Run();
  }

  low_disk_space_signal_was_emitted_ = low_disk_space_signal_emitted;

  post_delayed_task_.Run(FROM_HERE,
                         base::BindOnce(&LowDiskSpaceHandler::LowDiskSpaceCheck,
                                        weak_factory_.GetWeakPtr()),
                         low_disk_notification_period_);
}

}  // namespace cryptohome
