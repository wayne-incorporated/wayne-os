// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// DiskCleanup contains methods used to free up disk space.
// Used by DiskCleanup to perform the actual cleanup.

#ifndef CRYPTOHOME_CLEANUP_DISK_CLEANUP_H_
#define CRYPTOHOME_CLEANUP_DISK_CLEANUP_H_

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <base/time/time.h>

#include "cryptohome/cleanup/disk_cleanup_routines.h"
#include "cryptohome/cleanup/user_oldest_activity_timestamp_manager.h"
#include "cryptohome/platform.h"
#include "cryptohome/storage/homedirs.h"

namespace cryptohome {

// Cleanup parameters in bytes.
inline constexpr int64_t kFreeSpaceThresholdToTriggerCleanup = 1LL << 30;
inline constexpr int64_t kFreeSpaceThresholdToTriggerAggressiveCleanup =
    768 * 1024 * 1024;
inline constexpr int64_t kFreeSpaceThresholdToTriggerCriticalCleanup =
    512 * 1024 * 1024;
inline constexpr int64_t kTargetFreeSpaceAfterCleanup = 2LL << 30;

class DiskCleanupRoutines;

class DiskCleanup {
 public:
  // Entries are sorted by the severity of the lack of free space. See
  // FreeDiskSpaceState for thresholds.
  enum class FreeSpaceState {
    kError,                  // error while determining the amount of free disk
                             // space
    kAboveTarget,            // above target free disk space for cleanup result
    kAboveThreshold,         // above cleanup threshold but below cleanup target
    kNeedNormalCleanup,      // below threshold for normal cleanup
    kNeedAggressiveCleanup,  // below threshold for aggressive cleanup
    kNeedCriticalCleanup,    // below threshold for critical cleanup
  };

  DiskCleanup() = default;
  DiskCleanup(Platform* platform,
              HomeDirs* homedirs,
              UserOldestActivityTimestampManager* timestamp_manager);
  virtual ~DiskCleanup() = default;

  // Return the available disk space in bytes for home directories, or nullopt
  // on failure.
  virtual std::optional<int64_t> AmountOfFreeDiskSpace() const;

  // Determines the state of the free disk space based on the following
  // thresholds:
  //   kAboveTarget: free_disk_space >= cleanup_target_
  //   kAboveThreshold: cleanup_target_ > free_disk_space =>
  //                      normal_cleanup_threshold_
  //   kNeedNormalCleanup: normal_cleanup_threshold_ >
  //                      free_disk_space =>
  //                      aggresive_cleanup_threshold_
  //   kNeedAggressiveCleanup: aggresive_cleanup_threshold_ >
  //                      free_disk_space >=
  //                      critical_cleanup_threshold_
  //   kNeedAggressiveCleanup: critical_cleanup_threshold_ >
  //                      free_disk_space
  virtual FreeSpaceState GetFreeDiskSpaceState(std::optional<int64_t>) const;

  // Uses AmountOfFreeDiskSpace to get the current amount of free disk space and
  // to determine the state of the free disk space.
  virtual FreeSpaceState GetFreeDiskSpaceState() const;

  // Report the number of user home directories.
  virtual void CheckNumUserHomeDirectories() const;

  // Returns true if there is now at least cleanup_target_
  // amount of free disk space or false otherwise.
  virtual bool HasTargetFreeSpace() const;

  // Checks if it is possible to free up disk space.
  virtual bool IsFreeableDiskSpaceAvailable();

  // Frees disk space for unused cryptohomes. If the available disk space is
  // below normal_cleanup_threshold_, attempts to free space until
  // it goes up to cleanup_target_.
  virtual bool FreeDiskSpace();

  // Frees disk space for unused cryptohomes to make sure enough space is
  // available during login.
  // If the available disk space is below critical_cleanup_threshold_, attempts
  // to free space until it goes up to normal_cleanup_threshold_.
  virtual bool FreeDiskSpaceDuringLogin(const ObfuscatedUsername& logging_in);

  // Setters for cleanup thresholds.
  virtual void set_cleanup_threshold(uint64_t cleanup_threshold) {
    normal_cleanup_threshold_ = cleanup_threshold;
  }
  virtual void set_aggressive_cleanup_threshold(
      uint64_t aggressive_cleanup_threshold) {
    aggressive_cleanup_threshold_ = aggressive_cleanup_threshold;
  }
  virtual void set_critical_cleanup_threshold(
      uint64_t critical_cleanup_threshold) {
    critical_cleanup_threshold_ = critical_cleanup_threshold;
  }
  virtual void set_target_free_space(uint64_t target_free_space) {
    target_free_space_ = target_free_space;
  }

  // Testing methods.
  void set_routines_for_testing(
      DiskCleanupRoutines* routines /* takes ownership */);

 private:
  // Actually performs disk cleanup. Called by FreeDiskSpace.
  bool FreeDiskSpaceInternal();

  // Actually performs disk cleanup. Called by FreeDiskSpaceDuringLogin.
  bool FreeDiskSpaceDuringLoginInternal(const ObfuscatedUsername& obfuscated);

  // Removes all mounted homedirs from the vector
  void FilterMountedHomedirs(std::vector<HomeDirs::HomeDir>* homedirs);
  // Removes all homedirs that have not been active since the cutoff
  void FilterHomedirsProcessedBeforeCutoff(
      base::Time cutoff, std::vector<HomeDirs::HomeDir>* homedirs);

  // Not owned. Must outlive DiskCleanup.
  Platform* platform_ = nullptr;
  HomeDirs* homedirs_ = nullptr;
  UserOldestActivityTimestampManager* timestamp_manager_ = nullptr;

  // Cleanup routines.
  std::unique_ptr<DiskCleanupRoutines> routines_;

  // Disk cleanup thresholds. Can be set using command line flags.
  uint64_t normal_cleanup_threshold_ = kFreeSpaceThresholdToTriggerCleanup;
  uint64_t aggressive_cleanup_threshold_ =
      kFreeSpaceThresholdToTriggerAggressiveCleanup;
  uint64_t critical_cleanup_threshold_ =
      kFreeSpaceThresholdToTriggerCriticalCleanup;

  uint64_t target_free_space_ = kTargetFreeSpaceAfterCleanup;

  // Cleanup times.
  std::optional<base::Time> last_free_disk_space_ = std::nullopt;
  std::optional<base::Time> last_normal_disk_cleanup_complete_ = std::nullopt;
  std::optional<base::Time> last_aggressive_disk_cleanup_complete_ =
      std::nullopt;
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_CLEANUP_DISK_CLEANUP_H_
