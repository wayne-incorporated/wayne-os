// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CROSLOG_METRICS_COLLECTOR_UTIL_H_
#define CROSLOG_METRICS_COLLECTOR_UTIL_H_

#include <memory>

#include "base/files/file_path.h"
#include "base/time/time.h"

#include "croslog/log_parser.h"
#include "croslog/multiplexer.h"

namespace croslog {

// Calculate the log metrics from the specific file.
// The arguments of |byte_count_out|, |entry_count_out|, |max_throughput_out|
// are the output values. If they are not null, the values will be set.
void CalculateLogMetrics(const base::FilePath& path,
                         const base::Time& count_after,
                         std::unique_ptr<LogParser> parser_in,
                         int64_t* byte_count_out,
                         int64_t* entry_count_out,
                         int64_t* max_throughput_out);

// Calculate the log metrics from the multiple files with the multiplexer.
// The arguments of |entry_count_out|, |max_throughput_out| are the output
// values. If they are not null, the values will be set.
void CalculateMultipleLogMetrics(Multiplexer* multiplexer,
                                 const base::Time& count_after,
                                 int64_t* entry_count_out,
                                 int64_t* max_throughput_out);

// Calculate the log metrics from the multiple log files of chrome.
// The arguments of |byte_count_out|, |entry_count_out|, |max_throughput_out|
// are the output values. If they are not null, the values will be set.
void CalculateChromeLogMetrics(const base::FilePath& directory,
                               const char* filename_pattern,
                               const base::Time& count_after,
                               int64_t* byte_count_out,
                               int64_t* entry_count_out,
                               int64_t* max_throughput_out);

}  // namespace croslog

#endif  // CROSLOG_METRICS_COLLECTOR_UTIL_H_
