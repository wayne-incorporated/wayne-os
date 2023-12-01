// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BOOTID_LOGGER_TIMESTAMP_UTIL_H_
#define BOOTID_LOGGER_TIMESTAMP_UTIL_H_

#include <string>

#include <base/time/time.h>

#include <base/files/file_path.h>

// Retrieve the timestamp of the first (and oldest) entry in the file. If
// failed, return a null time,
base::Time GetFirstTimestamp(const base::FilePath& file);

// Retrieve the oldest timestamp from the file among the series of log files.
// For example, when "message.log" is given as |base_log_name|, this method
// checks the oldest file among "message.log", "message.log.1", "message.log.2"
// .... If failed, return a null time.
// Note that, if the entry doesn't exist in a file, use the timestamp one day
// prior to the last modifiled time of the file (assumeing the file is rotated
// daily).
base::Time GetOldestTimestampFromLogFiles(const base::FilePath& dir_path,
                                          const std::string& base_log_name);

// Retrieve the oldest timestamp from the multiple series of log files.
// |base_log_names| is a NULL-terminated array of base file names. This method
// calls |GetOldestTimestampFromLogFiles| for each file of |base_log_names|.
// If failed, return a null time.
base::Time GetOldestModifiedTime(base::FilePath log_directory,
                                 const char* base_log_names[]);

// Retrieve the oldest timestamp from the default log files. This method calls
// |GetOldestModifiedTime| with the default base file name list.
// If failed, return a null time.
base::Time GetOldestModifiedTime();

// Extract timestamp from a bootid log entry.
// If failed, return a null time.
base::Time ExtractTimestampString(const std::string& boot_id_entry);

#endif  // BOOTID_LOGGER_TIMESTAMP_UTIL_H_
