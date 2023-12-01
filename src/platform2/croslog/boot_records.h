// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CROSLOG_BOOT_RECORDS_H_
#define CROSLOG_BOOT_RECORDS_H_

#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <base/time/time.h>
#include <base/files/file_path.h>
#include <gtest/gtest.h>

#include "croslog/log_entry.h"

namespace croslog {

class BootRecords {
 public:
  class BootEntry {
   public:
    BootEntry(base::Time boot_time, std::string boot_id);
    base::Time boot_time() const { return boot_time_; }
    const std::string& boot_id() const { return boot_id_; }

   private:
    const base::Time boot_time_;
    const std::string boot_id_;
  };

  class BootRange {
   public:
    BootRange(base::Time boot_time,
              base::Time next_boot_time,
              std::string boot_id);

    base::Time boot_time() const { return boot_time_; }
    base::Time next_boot_time() const { return next_boot_time_; }
    const std::string& boot_id() const { return boot_id_; }

    bool Contains(base::Time time) const;

    friend bool operator==(const BootRange& a, const BootRange& b);

   private:
    const base::Time boot_time_;
    const base::Time next_boot_time_;
    const std::string boot_id_;
  };

  // Checks if the given string is a correct format of boot id or not.
  static bool IsValidBootId(const std::string& boot_id);

  BootRecords();
  BootRecords(BootRecords&&) = default;

  const std::vector<BootRange>& boot_ranges() const { return boot_ranges_; }

  // Get the range data of the specified boot.
  // |boot_str| should be either of:
  //   - Empty string: for last boot
  //   - Zero or negative offset number from the last. Zero represents the last
  //     boot. (positive offset value is not supported yet)
  //   - Full boot ID
  std::optional<BootRange> GetBootRange(const std::string& boot_str) const;

 private:
  FRIEND_TEST(BootRecordsTest, Load);
  FRIEND_TEST(BootRecordsTest, GetBootRange);
  FRIEND_TEST(BootRecordsTest, LoadFromFile);
  FRIEND_TEST(BootRecordsTest, LoadFromInvalidFile);
  FRIEND_TEST(ViewerPlaintextTest, GetBootIdAt);
  FRIEND_TEST(ViewerPlaintextTest, ShouldFilterOutEntry);
  FRIEND_TEST(ViewerPlaintextTest, ShouldFilterOutEntryWithBootId);

  const std::vector<BootRange> boot_ranges_;

  // TEST ONLY: Get the boot log entries from the specified log file.
  explicit BootRecords(base::FilePath file_path);
  // TEST ONLY: Set the boot log entries.
  explicit BootRecords(std::vector<BootEntry>);
  BootRecords(const BootRecords&) = delete;
  BootRecords& operator=(const BootRecords&) = delete;
};

}  // namespace croslog

#endif  // CROSLOG_BOOT_RECORDS_H_
