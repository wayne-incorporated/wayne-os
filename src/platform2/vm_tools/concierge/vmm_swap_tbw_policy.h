// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_CONCIERGE_VMM_SWAP_TBW_POLICY_H_
#define VM_TOOLS_CONCIERGE_VMM_SWAP_TBW_POLICY_H_

#include <cstdint>
#include <memory>
#include <utility>

#include <base/containers/ring_buffer.h>
#include <base/files/file.h>
#include <base/files/file_path.h>
#include <base/sequence_checker.h>
#include <base/time/time.h>

namespace vm_tools::concierge {

// VmmSwapTbwPolicy tracks the TBW (Total Bytes Written) from vmm-swap feature
// and decides whether it is able to swap out or not based on 28 days history
// not to exceeds the given target.
//
// Managing TBW is important because because swapping out too many memory into
// the swap file damages the disk.
//
// VmmSwapTbwPolicy persistes the history to the file specified by `Init()`.
// The file content is serialized by `TbwHistoryEntry` protobuf message.
//
// If the file does not exists, the policy creates the history file and
// initializing it pessimistically as if there were full target TBW through last
// 28 days. If any file related operation fails, VmmSwapTbwPolicy deletes the
// history file and stop writing to the file after that. When the concierge
// restarts, the policy restart from a pessimistic history.
//
// VmmSwapTbwPolicy rotates the history file before the file size reaches to
// 4096 bytes. During rotating, the policy creates another history file which
// has ".tmp" suffix to the original history file name temporarily and replace
// the original file with the new file.
//
// VmmSwapTbwPolicy is not thread-safe.
class VmmSwapTbwPolicy final {
 public:
  VmmSwapTbwPolicy();
  VmmSwapTbwPolicy(const VmmSwapTbwPolicy&) = delete;
  VmmSwapTbwPolicy& operator=(const VmmSwapTbwPolicy&) = delete;
  ~VmmSwapTbwPolicy() = default;

  // Set the target tbw per day.
  void SetTargetTbwPerDay(uint64_t target_tbw_per_day);
  // Get the target tbw per day.
  uint64_t GetTargetTbwPerDay();

  // Restore the tbw history from the history file.
  //
  // This creates the file if it does not exist.
  //
  // The `time` is injectable for testing purpose.
  bool Init(base::FilePath history_file_path,
            base::Time time = base::Time::Now());

  // Record a tbw history entry.
  //
  // The given `time` is expected to be later than previous Record() calls.
  // The `time` is injectable for testing purpose.
  void Record(uint64_t bytes_written, base::Time time = base::Time::Now());

  // Returns whether it is able to vmm-swap out the guest memory in terms of
  // TBW.
  //
  // The `time` is injectable for testing purpose.
  bool CanSwapOut(base::Time time = base::Time::Now()) const;

 private:
  static constexpr size_t kTbwHistoryLength = 28;
  // The first 1 byte indicates the entry message size. TbwHistoryEntry has at
  // most 22 (1+10 [tag+uint64] + 1+10 [tag+int64]) bytes/message.
  static constexpr int kEntrySize = 23;
  // The history file has 1 page size. This limit is bigger than kBufferSize.
  static constexpr int kMaxEntriesInFile = 4096 / kEntrySize;

  uint64_t target_tbw_per_day_ GUARDED_BY_CONTEXT(sequence_checker_) = 0;
  int entries_in_file_ = 0;
  base::RingBuffer<std::pair<base::Time, uint64_t>, kTbwHistoryLength>
      tbw_history_ GUARDED_BY_CONTEXT(sequence_checker_);
  base::FilePath history_file_path_ GUARDED_BY_CONTEXT(sequence_checker_);
  base::File history_file_ GUARDED_BY_CONTEXT(sequence_checker_);

  bool LoadFromFile(base::Time now);
  void AppendEntry(uint64_t bytes_written, base::Time time);
  bool RotateHistoryFile(base::Time time);
  void DeleteFile();

  // Ensure calls are made on the right thread.
  SEQUENCE_CHECKER(sequence_checker_);
};

}  // namespace vm_tools::concierge

#endif  // VM_TOOLS_CONCIERGE_VMM_SWAP_TBW_POLICY_H_
