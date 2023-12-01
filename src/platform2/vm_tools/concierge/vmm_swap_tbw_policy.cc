// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/concierge/vmm_swap_tbw_policy.h"

#include <algorithm>
#include <cstdint>
#include <memory>
#include <utility>

#include <base/check.h>
#include <base/containers/ring_buffer.h>
#include <base/files/file.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/time/time.h>
#include <brillo/files/file_util.h>
#include <google/protobuf/io/zero_copy_stream_impl.h>

#include "vm_concierge/vmm_swap_policy.pb.h"

namespace vm_tools::concierge {

namespace {
bool WriteEntry(base::File& file, uint64_t bytes_written, base::Time time) {
  TbwHistoryEntry entry;
  uint8_t message_size_buf[1];
  entry.set_time_us(time.ToDeltaSinceWindowsEpoch().InMicroseconds());
  entry.set_size(bytes_written);
  // TbwHistoryEntry message is less than 127 bytes. The MSB is reserved for
  // future extensibility.
  if (entry.ByteSizeLong() > 127) {
    LOG(ERROR) << "Tbw history message is bigger than 127 bytes: "
               << entry.ByteSizeLong() << " bytes";
    return false;
  }
  message_size_buf[0] = entry.ByteSizeLong();
  if (!base::WriteFileDescriptor(file.GetPlatformFile(), message_size_buf)) {
    LOG(ERROR) << "Failed to write tbw history entry size";
    return false;
  }
  return entry.SerializeToFileDescriptor(file.GetPlatformFile());
}
}  // namespace

VmmSwapTbwPolicy::VmmSwapTbwPolicy() {
  // Push a sentinel. VmmSwapTbwPolicy::AppendEntry() checks the latest entry by
  // `tbw_history_.MutableReadBuffer()` which fails if current index is 0.
  tbw_history_.SaveToBuffer(std::make_pair(base::Time(), 0));
}

void VmmSwapTbwPolicy::SetTargetTbwPerDay(uint64_t target_tbw_per_day) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  target_tbw_per_day_ = target_tbw_per_day;
}

uint64_t VmmSwapTbwPolicy::GetTargetTbwPerDay() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  return target_tbw_per_day_;
}

bool VmmSwapTbwPolicy::Init(base::FilePath path, base::Time now) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (history_file_.IsValid()) {
    LOG(ERROR) << "Tbw history file is already loaded";
    return false;
  }
  history_file_path_ = path;

  uint32_t flags = base::File::Flags::FLAG_READ | base::File::Flags::FLAG_WRITE;
  history_file_ = base::File(path, flags | base::File::Flags::FLAG_CREATE);
  if (history_file_.IsValid()) {
    LOG(INFO) << "Tbw history file is created at: " << path;

    // Add pessimistic entries as if there were max disk writes in last 28days.
    // This prevent it from causing damage if the history file is removed (e.g.
    // a user factory resets their device).
    for (int i = 0; i < kTbwHistoryLength; i++) {
      Record(target_tbw_per_day_, now - base::Days(kTbwHistoryLength - i - 1));
    }
    return true;
  } else if (history_file_.error_details() == base::File::FILE_ERROR_EXISTS) {
    LOG(INFO) << "Load tbw history from: " << path;

    history_file_ = base::File(path, flags | base::File::Flags::FLAG_OPEN);
    if (history_file_.IsValid()) {
      // Load entries in the file and move the file offset to the tail
      if (LoadFromFile(now)) {
        return true;
      } else {
        LOG(ERROR) << "Failed to load tbw history from file";
        DeleteFile();
      }
    } else {
      LOG(ERROR) << "Failed to open tbw history file: "
                 << history_file_.error_details();
    }
  } else {
    LOG(ERROR) << "Failed to create tbw history file: "
               << history_file_.error_details();
  }
  // Initialize pessimistic entries as fallback.
  for (int i = 0; i < kTbwHistoryLength; i++) {
    AppendEntry(target_tbw_per_day_,
                now - base::Days(kTbwHistoryLength - i - 1));
  }
  return false;
}

void VmmSwapTbwPolicy::Record(uint64_t bytes_written, base::Time time) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  AppendEntry(bytes_written, time);

  if (history_file_.IsValid()) {
    if (entries_in_file_ >= kMaxEntriesInFile) {
      if (!RotateHistoryFile(time)) {
        LOG(ERROR) << "Failed to rotate tbw file";
        // Stop writing a new entry to the history file.
        DeleteFile();
        return;
      }
    }
    if (WriteEntry(history_file_, bytes_written, time)) {
      entries_in_file_++;
    } else {
      LOG(ERROR) << "Failed to write tbw entry to file";
      // Delete the history file since the file content is now broken.
      DeleteFile();
    }
  }
}

bool VmmSwapTbwPolicy::CanSwapOut(base::Time time) const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  uint64_t tbw_28days = 0, tbw_7days = 0, tbw_1day = 0;
  for (auto iter = tbw_history_.Begin(); iter; ++iter) {
    if ((time - iter->first) < base::Days(28)) {
      tbw_28days += iter->second;
    }
    if ((time - iter->first) < base::Days(7)) {
      tbw_7days += iter->second;
    }
    if ((time - iter->first) < base::Days(1)) {
      tbw_1day += iter->second;
    }
  }

  // The targets for recent time ranges are eased using scale factor.
  // target_tbw_per_day_ * <num_days> * <scale_factor>
  uint64_t target_28days = target_tbw_per_day_ * 28 * 1;
  uint64_t target_7days = target_tbw_per_day_ * 7 * 2;
  uint64_t target_1day = target_tbw_per_day_ * 1 * 4;
  return tbw_28days < target_28days && tbw_7days < target_7days &&
         tbw_1day < target_1day;
}

bool VmmSwapTbwPolicy::LoadFromFile(base::Time now) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (!history_file_.IsValid()) {
    LOG(ERROR) << "History file is invalid to load";
    return false;
  }
  google::protobuf::io::FileInputStream input_stream(
      history_file_.GetPlatformFile());
  TbwHistoryEntry entry;
  base::Time previous_time;
  while (true) {
    // Load message size.
    uint8_t* message_size;
    int size;
    if (input_stream.Next((const void**)&message_size, &size)) {
      DCHECK_GT(size, 0);
      // TbwHistoryEntry message is less than 127 bytes. The MSB is reserved
      // for future extensibility.
      if (*message_size > 127) {
        LOG(ERROR) << "Tbw history message size is invalid: " << *message_size;
        return false;
      }
      // Consume 1 byte for message size field.
      input_stream.BackUp(size - 1);
    } else if (input_stream.GetErrno()) {
      LOG(ERROR) << "Failed to parse tbw history message size: errno: "
                 << input_stream.GetErrno();
      return false;
    } else {
      // EOF
      break;
    }

    if (!entry.ParseFromBoundedZeroCopyStream(&input_stream, *message_size)) {
      LOG(ERROR) << "Failed to parse tbw history entry";
      return false;
    }
    base::Time time = base::Time::FromDeltaSinceWindowsEpoch(
        base::Microseconds(entry.time_us()));
    if ((now - time).is_negative()) {
      LOG(WARNING) << "Tbw history file has invalid time (too new).";
      return false;
    } else if ((time - previous_time).is_negative()) {
      LOG(WARNING) << "Tbw history file has invalid time (old than lastest).";
      return false;
    }
    AppendEntry(entry.size(), time);
    entries_in_file_++;
    previous_time = time;
  }
  return true;
}

void VmmSwapTbwPolicy::AppendEntry(uint64_t bytes_written, base::Time time) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  auto latest_entry =
      tbw_history_.MutableReadBuffer(tbw_history_.BufferSize() - 1);

  if ((time - latest_entry->first) > base::Hours(24)) {
    tbw_history_.SaveToBuffer(std::make_pair(time, bytes_written));
  } else {
    latest_entry->second += bytes_written;
  }
}

bool VmmSwapTbwPolicy::RotateHistoryFile(base::Time time) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  base::FilePath tmp_file_path = history_file_path_.AddExtension("tmp");
  uint32_t flags = base::File::Flags::FLAG_CREATE_ALWAYS |
                   base::File::Flags::FLAG_READ | base::File::Flags::FLAG_WRITE;
  base::File tmp_file = base::File(tmp_file_path, flags);
  if (!tmp_file.IsValid()) {
    LOG(ERROR) << "Failed to create new tbw history file: "
               << history_file_.error_details();
    return false;
  }

  entries_in_file_ = 0;
  TbwHistoryEntry entry;
  for (auto iter = tbw_history_.Begin(); iter; ++iter) {
    if ((time - iter->first) < base::Days(28)) {
      if (WriteEntry(tmp_file, iter->second, iter->first)) {
        LOG(ERROR) << "Failed to write entries to new tbw history file";
        return false;
      }
      entries_in_file_++;
    }
  }

  base::File::Error error;
  if (!base::ReplaceFile(tmp_file_path, history_file_path_, &error)) {
    LOG(ERROR) << "Failed to replace history file: " << error;
    if (!brillo::DeleteFile(tmp_file_path)) {
      LOG(ERROR) << "Failed to delete tmp history file";
    }
    DeleteFile();
    return false;
  }

  // The obsolete history file is closed. The file is automatically disposed
  // since the file is already unlinked by rename(2).
  history_file_ = std::move(tmp_file);

  return true;
}

void VmmSwapTbwPolicy::DeleteFile() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (!brillo::DeleteFile(history_file_path_)) {
    LOG(ERROR) << "Failed to delete history file.";
  }
  // Stop writing entries to the file.
  history_file_.Close();
  entries_in_file_ = 0;
}

}  // namespace vm_tools::concierge
