// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// LowDiskSpaceHandler checks if the device has low disk space.
// Uses DiskCleanup to perform cleanup when space is low.

#ifndef CRYPTOHOME_CLEANUP_LOW_DISK_SPACE_HANDLER_H_
#define CRYPTOHOME_CLEANUP_LOW_DISK_SPACE_HANDLER_H_

#include <cstdint>
#include <memory>

#include <base/functional/callback.h>
#include <base/memory/weak_ptr.h>
#include <base/task/single_thread_task_runner.h>
#include <base/test/task_environment.h>
#include <base/time/time.h>

namespace cryptohome {

class DiskCleanup;
class HomeDirs;
class KeysetManagement;
class Platform;
class UserOldestActivityTimestampManager;

inline constexpr base::TimeDelta kAutoCleanupPeriod = base::Hours(1);
inline constexpr base::TimeDelta kUpdateUserActivityPeriod = base::Days(1);
inline constexpr base::TimeDelta kLowDiskNotificationPeriod = base::Minutes(1);

class LowDiskSpaceHandler {
 public:
  LowDiskSpaceHandler(HomeDirs* homedirs,
                      Platform* platform,
                      UserOldestActivityTimestampManager* timestamp_manager);
  virtual ~LowDiskSpaceHandler();

  // Initialize disk cleanup and low disk space checking.
  // Callbacks must be set before calling Init.
  // Only setters for disk cleanup thresholds can be called before Init.
  virtual bool Init(
      base::RepeatingCallback<bool(const base::Location&,
                                   base::OnceClosure,
                                   const base::TimeDelta&)> post_delayed_task);

  // Stop clears the post_delayed_task_ callback, ensuring the callback passed
  // to Init is no longer called.
  virtual void Stop();

  // Set the callback that will be invoked when the device is low on disk space.
  // Normally this is used to notify Chrome using DBUS.
  virtual void SetLowDiskSpaceCallback(
      const base::RepeatingCallback<void(uint64_t)>& callback) {
    low_disk_space_callback_ = callback;
  }

  // Set the callback that will be invoked periodically to update the current
  // users activity timestamps.
  virtual void SetUpdateUserActivityTimestampCallback(
      const base::RepeatingCallback<void()>& callback) {
    update_user_activity_timestamp_callback_ = callback;
  }

  virtual DiskCleanup* disk_cleanup() const { return cleanup_; }

  // Testing methods.
  base::TimeDelta low_disk_notification_period() const {
    return low_disk_notification_period_;
  }
  base::TimeDelta update_user_activity_timestamp_period() const {
    return update_user_activity_timestamp_period_;
  }
  // Does not take ownership of cleanup.
  void set_disk_cleanup(DiskCleanup* cleanup) { cleanup_ = cleanup; }

 private:
  void FreeDiskSpace();
  void LowDiskSpaceCheck();

  Platform* platform_ = nullptr;

  std::unique_ptr<DiskCleanup> default_cleanup_;
  DiskCleanup* cleanup_;

  base::TimeDelta low_disk_notification_period_;
  base::TimeDelta update_user_activity_timestamp_period_;

  // Callbacks.
  base::RepeatingCallback<void(uint64_t)> low_disk_space_callback_;
  base::RepeatingCallback<void()> update_user_activity_timestamp_callback_;
  base::RepeatingCallback<bool(
      const base::Location&, base::OnceClosure, const base::TimeDelta&)>
      post_delayed_task_;

  // Internal state.
  base::Time last_auto_cleanup_time_ = base::Time();
  base::Time last_update_user_activity_timestamp_time_ = base::Time();
  bool low_disk_space_signal_was_emitted_ = false;
  bool stopped_ = true;

  base::WeakPtrFactory<LowDiskSpaceHandler> weak_factory_{this};
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_CLEANUP_LOW_DISK_SPACE_HANDLER_H_
