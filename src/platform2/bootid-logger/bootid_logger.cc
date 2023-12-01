// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <deque>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <utility>

#include <fcntl.h>
#include <stdio.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "base/files/file_util.h"
#include "base/files/scoped_file.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/time/time.h"

#include "bootid-logger/bootid_logger.h"
#include "bootid-logger/constants.h"
#include "bootid-logger/timestamp_util.h"

#include <base/check_op.h>
#include <base/logging.h>

namespace {

constexpr char kBootIdProcPath[] = "/proc/sys/kernel/random/boot_id";

// Generate an entry in the boot entry format.
std::string GenerateBootEntryString(const std::string current_boot_id,
                                    const base::Time boot_time) {
  // Boot id must be 32 hexadecimal digits.
  CHECK_EQ(32u, current_boot_id.length());

  // TODO(crbug.com): Change the timezone from local to UTC.

  base::Time::Exploded exploded;
  boot_time.UTCExplode(&exploded);

  const std::string boot_time_str(base::StringPrintf(
      "%04d-%02d-%02dT%02d:%02d:%02d.%03d000Z", exploded.year, exploded.month,
      exploded.day_of_month, exploded.hour, exploded.minute, exploded.second,
      exploded.millisecond));
  CHECK_LE(kTimestampLength, boot_time_str.size());

  const std::string boot_id_entry = boot_time_str + " " + kBootEntrySeverity +
                                    " " + kBootEntryPrefix +
                                    base::ToLowerASCII(current_boot_id);
  CHECK_LE(kBootEntryLength, boot_id_entry.length());
  return boot_id_entry;
}

// Validate the given boot entry is valid (as an entry with UTC timestap).
bool ValidateBootEntryWithUTC(const std::string& boot_id_entry) {
  if (boot_id_entry.length() != kBootEntryLength)
    return false;

  if (boot_id_entry[kBootEntrySeverityOffset - 1] != ' ' ||
      boot_id_entry[kBootEntryPrefixOffset - 1] != ' ' ||
      boot_id_entry[kBootEntryBootIdOffset - 1] != ' ')
    return false;

  return true;
}

// Validate the given boot entry is valid (as an entry with local timestap).
bool ValidateBootEntryWithTimezone(const std::string& boot_id_entry) {
  if (boot_id_entry.length() != kBootEntryLocalTimeLength)
    return false;

  if (boot_id_entry[kBootEntryLocalTimeSeverityOffset - 1] != ' ' ||
      boot_id_entry[kBootEntryLocalTimeMessageOffset - 1] != ' ' ||
      boot_id_entry[kBootEntryLocalTimeBootIdOffset - 1] != ' ')
    return false;

  return true;
}

// Read previous entries from the log file (FD).
std::optional<std::deque<std::string>> ReadPreviousBootEntries(
    const int fd,
    const base::Time first_timestamp_to_keep,
    size_t boot_log_max_entries) {
  std::deque<std::string> previous_boot_entries;

  struct stat st;
  fstat(fd, &st);
  const off_t length = st.st_size;

  if (length > 0) {
    // Here, we do mmap and stringstream to read lines.
    // We can't use ifstream here because we want to use fd for keeping locking
    // on the file.
    char* buffer =
        static_cast<char*>(mmap(NULL, length, PROT_READ, MAP_PRIVATE, fd, 0));
    if (buffer == NULL) {
      PLOG(FATAL) << "mmap failed";
      return std::nullopt;
    }

    // Set the buffer to the stream.
    std::istringstream ss(std::string(buffer, length));

    std::string s;
    while (std::getline(ss, s)) {
      // Skip an empty log.
      if (s.empty())
        continue;

      // Skip a duplicated entry.
      if (!previous_boot_entries.empty() && previous_boot_entries.back() == s)
        continue;

      // Skip an invalid entry.
      if (!ValidateBootEntry(s))
        continue;

      if (!first_timestamp_to_keep.is_null()) {
        base::Time time = ExtractTimestampString(s);
        // Skips the entry with older timestamp than |first_timestamp_to_keep|.
        if (!time.is_null() && time < first_timestamp_to_keep)
          continue;
      }

      previous_boot_entries.push_back(s);
    }

    munmap(buffer, length);

    // Truncate if the logs are overflown.
    while (boot_log_max_entries &&
           previous_boot_entries.size() > (boot_log_max_entries - 1)) {
      previous_boot_entries.pop_front();
    }
  }

  return previous_boot_entries;
}

base::Time GetCurrentBootTime() {
  struct timespec boot_timespec;
  if (clock_gettime(CLOCK_BOOTTIME, &boot_timespec) == -1) {
    PLOG(FATAL) << "clock_gettime failed";
    exit(EXIT_FAILURE);
  }

  return base::Time::Now() - base::TimeDelta::FromTimeSpec(boot_timespec);
}

}  // anonymous namespace

// Validate the given boot entry is valid.
bool ValidateBootEntry(const std::string& boot_id_entry) {
  return ValidateBootEntryWithUTC(boot_id_entry) ||
         ValidateBootEntryWithTimezone(boot_id_entry);
}

// Extracts the boot ID from the givin boot ID entry.
std::string ExtractBootId(const std::string& boot_id_entry) {
  if (boot_id_entry.length() == kBootEntryLength)
    return boot_id_entry.substr(kBootEntryBootIdOffset, kBootIdLength);

  if (boot_id_entry.length() == kBootEntryLocalTimeLength)
    return boot_id_entry.substr(kBootEntryLocalTimeBootIdOffset, kBootIdLength);

  return "";
}

std::string GetCurrentBootId() {
  std::string boot_id;
  if (!base::ReadFileToString(base::FilePath(kBootIdProcPath), &boot_id)) {
    LOG(FATAL) << "Reading the log file failed";
    exit(EXIT_FAILURE);
  }
  base::RemoveChars(boot_id, "-\r\n", &boot_id);
  CHECK_EQ(kBootIdLength, boot_id.length());
  return boot_id;
}

bool WriteCurrentBootEntry(const base::FilePath& bootid_log_path,
                           const base::Time first_timestamp_to_keep,
                           const size_t max_entries) {
  std::string boot_id = GetCurrentBootId();
  base::Time boot_time = GetCurrentBootTime();

  return WriteBootEntry(bootid_log_path, boot_id, boot_time,
                        first_timestamp_to_keep, max_entries);
}

bool WriteBootEntry(const base::FilePath& bootid_log_path,
                    const std::string& current_boot_id,
                    const base::Time boot_time,
                    const base::Time first_timestamp_to_keep,
                    const size_t max_entries) {
  // Open the log file.
  base::ScopedFD fd(HANDLE_EINTR(
      open(bootid_log_path.value().c_str(), O_RDWR | O_CREAT | O_CLOEXEC,
           S_IRUSR | S_IWUSR | S_IROTH | S_IRGRP /* 0644 */)));
  if (fd.get() == -1) {
    PLOG(FATAL) << "open failed";
    return false;
  }

  if (HANDLE_EINTR(flock(fd.get(), LOCK_EX)) == -1) {
    PLOG(FATAL) << "flock failed";
    return false;
  }

  auto ret =
      ReadPreviousBootEntries(fd.get(), first_timestamp_to_keep, max_entries);
  if (!ret.has_value()) {
    LOG(FATAL) << "Reading the log file failed";
    return false;
  }
  std::deque<std::string> previous_boot_entries = std::move(*ret);

  if (!previous_boot_entries.empty() &&
      ExtractBootId(previous_boot_entries.back()) == current_boot_id) {
    LOG(INFO) << "The current Boot ID does already exists in the log. New "
                 "entry is not added to prevent duplication.";
    // Returning true, since it is not an issue.
    return true;
  }

  const std::string boot_entry_str =
      GenerateBootEntryString(current_boot_id, boot_time);
  previous_boot_entries.push_back(boot_entry_str);

  // Update the current pos to the beginning of the file.
  if (lseek(fd.get(), 0, SEEK_SET) != 0) {
    PLOG(FATAL) << "lseek failed";
    return false;
  }

  // Shrink the file to zero.
  if (HANDLE_EINTR(ftruncate(fd.get(), 0)) != 0) {
    PLOG(FATAL) << "ftruncate failed";
    return false;
  }

  // Rewrite the existing entries.
  for (std::string boot_entry : previous_boot_entries) {
    boot_entry.append(1, '\n');

    if (!base::WriteFileDescriptor(fd.get(), boot_entry)) {
      PLOG(FATAL) << "Writing to the file failed";
      return false;
    }
  }

  // Automatically the file is closed and unlocked at the end of process.

  return true;
}
