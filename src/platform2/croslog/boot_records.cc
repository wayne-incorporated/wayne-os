// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "croslog/boot_records.h"

#include <optional>

#include <base/check_op.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>

#include "croslog/log_line_reader.h"
#include "croslog/log_parser_syslog.h"

namespace croslog {

namespace {

// The maximum length of the boot log. The log must be less than 1000 lines,
// since it is trancated to 500 lines in log-bootid-on-boot.conf.
constexpr size_t kBootEntryMaxLen = 1000;

std::vector<BootRecords::BootEntry> ReadBootLogs(base::FilePath file_path) {
  LogLineReader reader(LogLineReader::Backend::FILE);

  std::vector<BootRecords::BootEntry> boot_log_entries;
  if (!base::PathExists(file_path))
    return boot_log_entries;

  LogParserSyslog parser;
  reader.OpenFile(std::move(file_path));

  while (true) {
    auto [log, result] = reader.Forward();
    if (result != LogLineReader::ReadResult::NO_ERROR) {
      // EOF: finishes the read.
      break;
    }

    MaybeLogEntry e = parser.Parse(std::move(log));
    if (!e.has_value()) {
      // Parse error: continuing the next line.
      continue;
    }

    if (!BootRecords::IsValidBootId(e->message())) {
      continue;
    }

    boot_log_entries.emplace_back(e->time(), e->message());
  }
  return boot_log_entries;
}

std::vector<BootRecords::BootRange> ConvertBootEntriesToRanges(
    const std::vector<BootRecords::BootEntry>& boot_log_entries) {
  std::vector<BootRecords::BootRange> boot_log_ranges;

  for (int i = 0; i < boot_log_entries.size(); i++) {
    const auto& boot_entry = boot_log_entries[i];
    base::Time next_boot_time = (i < (boot_log_entries.size() - 1))
                                    ? boot_log_entries[i + 1].boot_time()
                                    : base::Time::Max();

    // Boot times should be in an increasing order.
    if (boot_entry.boot_time() >= next_boot_time) {
      LOG(WARNING) << "Boot entries must be in an incremental order, but not: "
                   << boot_entry.boot_time() << " -> " << next_boot_time
                   << ". This "
                   << "entry is ignored.";
      continue;
    }

    boot_log_ranges.emplace_back(boot_entry.boot_time(), next_boot_time,
                                 boot_entry.boot_id());
  }

  return boot_log_ranges;
}

std::vector<BootRecords::BootRange> ReadBootRecords(base::FilePath file_path) {
  return ConvertBootEntriesToRanges(ReadBootLogs(file_path));
}

}  // anonymous namespace

// ============================================================================
// BootRecords::BootEntry implementation:

BootRecords::BootEntry::BootEntry(base::Time boot_time, std::string boot_id)
    : boot_time_(boot_time), boot_id_(std::move(boot_id)) {}

// ============================================================================
// BootRecords::BootRange implementation:

BootRecords::BootRange::BootRange(base::Time boot_time,
                                  base::Time next_boot_time,
                                  std::string boot_id)
    : boot_time_(boot_time),
      next_boot_time_(next_boot_time),
      boot_id_(std::move(boot_id)) {}

bool BootRecords::BootRange::Contains(base::Time time) const {
  return boot_time_ <= time && time < next_boot_time_;
}

bool operator==(BootRecords::BootRange const& a,
                BootRecords::BootRange const& b) {
  return a.boot_id() == b.boot_id() && a.boot_time() == b.boot_time() &&
         a.next_boot_time() == b.next_boot_time();
}

// ============================================================================
// BootRecords implementation:

// static
bool BootRecords::IsValidBootId(const std::string& boot_id) {
  if (boot_id.size() != 32)
    return false;

  for (int i = 0; i < 32; i++) {
    if (!(boot_id[i] >= '0' && boot_id[i] <= '9') &&
        !(boot_id[i] >= 'a' && boot_id[i] <= 'f')) {
      return false;
    }
  }
  return true;
}

BootRecords::BootRecords()
    : BootRecords(base::FilePath("/var/log/boot_id.log")) {}

BootRecords::BootRecords(base::FilePath file_path)
    : boot_ranges_(ReadBootRecords(file_path)) {
  DCHECK_GT(kBootEntryMaxLen, boot_ranges_.size());
}

BootRecords::BootRecords(std::vector<BootRecords::BootEntry> entries)
    : boot_ranges_(ConvertBootEntriesToRanges(entries)) {}

std::optional<BootRecords::BootRange> BootRecords::GetBootRange(
    const std::string& boot_str) const {
  int boot_offset = 0;
  if (boot_str.empty() || base::StringToInt(boot_str, &boot_offset)) {
    if (boot_str.empty())
      boot_offset = 0;

    // The specified string may be a boot number.
    DCHECK_GT(kBootEntryMaxLen, boot_ranges_.size());

    int boot_offset_nth;
    if (boot_offset <= 0) {
      boot_offset_nth = boot_ranges_.size() + boot_offset - 1;
      if (boot_offset_nth < 0) {
        // Invalid offset.
        return std::nullopt;
      }
    } else {
      // Positive offset is not supported.
      // TODO(yoshiki): support positive offset values.
      return std::nullopt;
    }

    return boot_ranges_[boot_offset_nth];
  }

  if (IsValidBootId(boot_str)) {
    // The specified string may be a boot ID.
    for (int i = 0; i < boot_ranges_.size(); i++) {
      const auto& boot_entry = boot_ranges_[i];
      if (boot_entry.boot_id() != boot_str)
        continue;
      return boot_entry;
    }
  }

  // Invalid boot ID format, or no corresponding boot in the entries.
  return std::nullopt;
}

}  // namespace croslog
