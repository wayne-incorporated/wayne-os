// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHAPS_SYSTEM_SHUTDOWN_BLOCKER_H_
#define CHAPS_SYSTEM_SHUTDOWN_BLOCKER_H_

#include <set>

#include <base/files/file_path.h>
#include <base/task/single_thread_task_runner.h>
#include <base/time/time.h>

namespace chaps {

// Blocks shutdown signal from powerd by creating a lock file for blocked slots
// in /run/lock/power_override.
class SystemShutdownBlocker {
 public:
  // |origin_thread_task_runner| should be chapsd's origin thread task runner.
  explicit SystemShutdownBlocker(
      const scoped_refptr<base::SingleThreadTaskRunner>&
          origin_thread_task_runner);
  SystemShutdownBlocker(const SystemShutdownBlocker&) = delete;
  SystemShutdownBlocker& operator=(const SystemShutdownBlocker&) = delete;

  // Unblocks all remaining blocked slots (see |blocked_slots_|).
  ~SystemShutdownBlocker();

  // Posts an immediate call to |PerformBlock()| and a delayed call to
  // |PerformUnblock()| on the |origin_thread_task_runner_|.
  void Block(int slot_id, base::TimeDelta fallback_timeout);

  // Posts an immediate call to |PerformUnblock()| on the
  // |origin_thread_task_runner_|.
  void Unblock(int slot_id);

 private:
  // Creates a lock file readable by powerd with chapsd's PID and marks the slot
  // as blocked in |blocked_slots|.
  void PerformBlock(int slot_id);

  // Calls |PerformUnblock()| and removes the block mark if the slot is marked
  // as blocked in |blocked_slots_|, otherwise no-op.
  void PerformUnblockIfBlocked(int slot_id);

  // Deletes the lock file and returns whether or not the slot is unblocked
  // (i.e. lock file removed).
  bool PerformUnblock(int slot_id);

  // Gets the corresponding lock file path for |slot_id|
  // (/run/lock/power_override/chapsd_token_init_slot_<<<SLOT_ID>>>.lock).
  base::FilePath GetPowerdLockFilePath(int slot_id) const;

  scoped_refptr<base::SingleThreadTaskRunner> origin_thread_task_runner_;
  std::set<int> blocked_slots_;
};

}  // namespace chaps

#endif  // CHAPS_SYSTEM_SHUTDOWN_BLOCKER_H_
