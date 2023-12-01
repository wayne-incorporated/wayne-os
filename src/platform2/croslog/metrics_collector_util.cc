// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "croslog/metrics_collector_util.h"

#include <algorithm>
#include <deque>
#include <functional>
#include <string>
#include <utility>
#include <vector>

#include "base/files/file_enumerator.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"

#include "croslog/log_entry_reader.h"
#include "croslog/log_parser_syslog.h"

namespace croslog {

void CalculateLogMetrics(const base::FilePath& path,
                         const base::Time& count_after,
                         std::unique_ptr<LogParser> parser_in,
                         int64_t* byte_count_out,
                         int64_t* entry_count_out,
                         int64_t* max_throughput_out) {
  // Checks if the file exists.
  if (!base::PathExists(path)) {
    if (byte_count_out)
      *byte_count_out = -1;
    if (entry_count_out)
      *entry_count_out = -1;
    if (max_throughput_out)
      *max_throughput_out = -1;
    return;
  }

  if (byte_count_out)
    *byte_count_out = 0;
  if (entry_count_out)
    *entry_count_out = 0;
  if (max_throughput_out)
    *max_throughput_out = 0;

  LogEntryReader reader(path, std::move(parser_in), false);

  // Traverses reversely from the last.
  reader.SetPositionLast();

  std::deque<base::Time> recent_timestamps;
  while (true) {
    MaybeLogEntry entry = reader.GetPreviousEntry();
    if (!entry.has_value())
      return;

    if (!count_after.is_null() && entry->time() < count_after)
      return;

    if (byte_count_out && *byte_count_out >= 0) {
      *byte_count_out += entry->entire_line().size();
      // Adding 1 for a terminating LF.
      *byte_count_out += 1;
    }

    if (max_throughput_out) {
      // Resets the state, if the timestamps are in a wrong order.
      if (!recent_timestamps.empty() &&
          recent_timestamps.back() < entry->time()) {
        recent_timestamps.clear();
      }

      // Keeps the timestamps only within 1 minute.
      recent_timestamps.push_back(entry->time());
      while ((recent_timestamps.front() - entry->time()) > base::Minutes(1)) {
        recent_timestamps.pop_front();
      }

      // Get the current throughput (number of entries within the recent 1
      // minute).
      int64_t current_throughput =
          static_cast<int64_t>(recent_timestamps.size());

      *max_throughput_out = std::max(*max_throughput_out, current_throughput);
    }

    if (entry_count_out)
      (*entry_count_out)++;
  }
}

void CalculateMultipleLogMetrics(Multiplexer* multiplexer,
                                 const base::Time& count_after,
                                 int64_t* entry_count_out,
                                 int64_t* max_throughput_out) {
  multiplexer->SetLinesFromLast(0);

  if (entry_count_out)
    *entry_count_out = 0;
  if (max_throughput_out)
    *max_throughput_out = 0;

  std::deque<base::Time> recent_timestamps;
  while (true) {
    const MaybeLogEntry& entry = multiplexer->Backward();
    if (!entry.has_value())
      return;

    if (!count_after.is_null() && entry->time() < count_after)
      return;

    if (max_throughput_out) {
      // Resets the state, if the timestamp order is strange.
      if (!recent_timestamps.empty() &&
          recent_timestamps.back() < entry->time()) {
        recent_timestamps.clear();
      }

      // Keeps the timestamps only within 1 minute.
      recent_timestamps.push_back(entry->time());
      while ((recent_timestamps.front() - entry->time()) > base::Minutes(1)) {
        recent_timestamps.pop_front();
      }

      // Get the current throughput (number of entries with the recent 1
      // minute).
      int64_t current_throughput =
          static_cast<int64_t>(recent_timestamps.size());

      *max_throughput_out = std::max(*max_throughput_out, current_throughput);
    }

    if (entry_count_out)
      (*entry_count_out)++;
  }
}

void CalculateChromeLogMetrics(const base::FilePath& directory,
                               const char* filename_pattern,
                               const base::Time& count_after,
                               int64_t* byte_count_out,
                               int64_t* entry_count_out,
                               int64_t* max_throughput_out) {
  // This logic traverses the chrome logs, since the chrome logs are splitted
  // on every session, instead of daily rotation like other log files.

  if (entry_count_out)
    *entry_count_out = 0;
  if (byte_count_out)
    *byte_count_out = 0;
  if (max_throughput_out)
    *max_throughput_out = 0;

  std::vector<base::FilePath> file_path;
  base::FileEnumerator e(directory, false, base::FileEnumerator::FILES,
                         filename_pattern);
  // FileEnumerator doesn't guarantee order of results, so we put the result
  // into the vector and sort it.
  for (base::FilePath name = e.Next(); !name.empty(); name = e.Next()) {
    file_path.push_back(name);
  }
  // Sorting is in reverse lexicographic order, which will also sort the logs by
  // time (more recent file first), since the chrome logs contain date and time
  // in their filenames. For example, "chrome_20210115_123456.txt" comes before
  // "chrome_20210115_123456.txt".
  std::sort(
      file_path.begin(), file_path.end(),
      [](const auto& l, const auto& r) { return r.BaseName() < l.BaseName(); });

  for (const base::FilePath& name : file_path) {
    int64_t file_size;
    if (!GetFileSize(name, &file_size) || file_size == 0)
      continue;

    int64_t byte_count_temporary;
    int64_t entry_count_temporary;
    int64_t max_throughput_temporary;
    CalculateLogMetrics(name, count_after, std::make_unique<LogParserSyslog>(),
                        &byte_count_temporary, &entry_count_temporary,
                        &max_throughput_temporary);

    // Skips this file since the file doesn't exist (this rarely happens by
    // file remove/rename race).
    if (entry_count_temporary < 0)
      continue;

    // Stops the traversal. We found no entries newer than |count_after| in
    // this log files. So, we assume the later files contain older entries,
    // since the file list has been sorted (more recent file first).
    if (entry_count_temporary == 0)
      return;

    if (entry_count_out)
      *entry_count_out += entry_count_temporary;
    if (byte_count_out)
      *byte_count_out += byte_count_temporary;
    if (max_throughput_out) {
      *max_throughput_out =
          std::max(*max_throughput_out, max_throughput_temporary);
    }
  }
}

}  // namespace croslog
