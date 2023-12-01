// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "bootid-logger/timestamp_util.h"

#include <memory>
#include <string>

#include <base/files/file_enumerator.h>
#include <base/files/file_util.h>

#include "bootid-logger/constants.h"
#include "croslog/log_entry_reader.h"
#include "croslog/log_parser_syslog.h"

// The list is coped from /platform2/init/chromeos-cleanup-logs
// TODO(crbug.com/1168393): share the list with the rotation script.
const char* kLogFiles[] = {"messages",
                           "secure",
                           "net.log",
                           "faillog",
                           "fwupd.log",
                           "session_manager",
                           "atrus.log",
                           "tlsdate.log",
                           "authpolicy.log",
                           "tpm-firmware-updater.log",
                           "arc.log",
                           "recover_duts/recover_duts.log",
                           "hammerd.log",
                           "upstart.log",
                           "typecd.log",
                           "bluetooth.log",
                           NULL};

base::FilePath kLogDir("/var/log");

base::Time GetFirstTimestamp(const base::FilePath& file) {
  croslog::LogEntryReader reader(
      file, std::make_unique<croslog::LogParserSyslog>(), false);
  croslog::MaybeLogEntry e = reader.GetNextEntry();
  if (e.has_value())
    return e->time();

  return base::Time();
}

base::Time GetOldestTimestampFromLogFiles(const base::FilePath& dir_path,
                                          const std::string& base_log_name) {
  base::Time oldest_last_modified;

  // Retrieve the path and the last modified date of the latest log file
  // (without a suffix).
  {
    base::FilePath log_file_path = dir_path.Append(base_log_name);
    if (base::PathExists(log_file_path))
      oldest_last_modified = GetFirstTimestamp(log_file_path);
  }

  // Pattern to match the older log files with suffix.
  std::string pattern = base_log_name + ".*";

  // Traverse the older log files.
  base::FileEnumerator e(dir_path, false, base::FileEnumerator::FILES, pattern);
  for (base::FilePath name = e.Next(); !name.empty(); name = e.Next()) {
    base::Time last_modified = GetFirstTimestamp(name);

    // If the first timestamp can't be retrieved, Use the timestamp one day
    // prior to the last modifiled time of the file (assumeing the file is
    // rotated daily).
    if (last_modified.is_null())
      last_modified = e.GetInfo().GetLastModifiedTime() - base::Days(1);

    if (last_modified.is_null())
      continue;

    if (oldest_last_modified.is_null() || oldest_last_modified > last_modified)
      oldest_last_modified = last_modified;
  }

  return oldest_last_modified;
}

base::Time GetOldestModifiedTime(base::FilePath log_directory,
                                 const char* log_files[]) {
  base::Time oldest_last_modified;

  for (int i = 0; log_files[i] != NULL; i++) {
    base::Time last_modified =
        GetOldestTimestampFromLogFiles(log_directory, log_files[i]);

    if (last_modified.is_null())
      continue;

    if (oldest_last_modified.is_null() || oldest_last_modified > last_modified)
      oldest_last_modified = last_modified;
  }

  return oldest_last_modified;
}

base::Time GetOldestModifiedTime() {
  return GetOldestModifiedTime(kLogDir, kLogFiles);
}

// Extracts the boot ID from the givin boot ID entry.
base::Time ExtractTimestampString(const std::string& boot_id_entry) {
  base::Time time;

  if (boot_id_entry[26] == 'Z') {
    // Case of UTC time format like "2020-05-25T00:00:00.000000Z".
    std::string log_time = boot_id_entry.substr(0, kTimestampLength);

    bool result = base::Time::FromString(log_time.c_str(), &time);
    if (!result)
      return base::Time();

    return time;
  } else if (boot_id_entry[26] == '+' || boot_id_entry[26] == '-') {
    // Case of format with time-zone like "2020-05-25T00:00:00.000000+00:00".
    std::string log_time = boot_id_entry.substr(0, kLocalTimeTimestampLength);

    bool result = base::Time::FromString(log_time.c_str(), &time);
    if (!result)
      return base::Time();

    return time;
  }

  // Returning a null time as an error.
  return base::Time();
}
