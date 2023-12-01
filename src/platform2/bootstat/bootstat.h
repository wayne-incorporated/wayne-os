// Copyright 2010 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Public API for the C++ bindings to the Chromium OS
// 'bootstat' facility.  The facility is a simple timestamp
// mechanism to associate a named event with the time that it
// occurred and with other relevant statistics.

#ifndef BOOTSTAT_BOOTSTAT_H_
#define BOOTSTAT_BOOTSTAT_H_

#include <linux/rtc.h>
#include <time.h>

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/files/scoped_file.h>
#include <base/time/time.h>
#include <brillo/brillo_export.h>

namespace bootstat {

// Abstracts system operations in order to inject on testing.
class BootStatSystem {
 public:
  BootStatSystem();
  // Constructor for tests that may want to modify the root path.
  explicit BootStatSystem(const base::FilePath& root_path);
  BootStatSystem(const BootStatSystem&) = delete;
  BootStatSystem& operator=(const BootStatSystem&) = delete;
  virtual ~BootStatSystem() = default;

  // Returns the path representing the stats file for the root disk.
  // Returns an empty path on failure.
  virtual base::FilePath GetDiskStatisticsFilePath() const;

  // Returns the current uptime (clock_gettime's CLOCK_BOOTTIME),
  // std::nullopt on error.
  virtual std::optional<struct timespec> GetUpTime() const;

  // Returns the idle time since boot.
  std::optional<base::TimeDelta> GetIdleTime() const;

  // Returns a scoped FD to the RTC device (used by GetRtcTime below).
  virtual base::ScopedFD OpenRtc() const;
  // Reads and return RTC's time, std::nullopt on error.
  virtual std::optional<struct rtc_time> GetRtcTime(
      base::ScopedFD* rtc_fd) const;

 private:
  base::FilePath root_path_;
};

// Basic class for bootstat API interface.
class BRILLO_EXPORT BootStat {
 public:
  BootStat();
  // Constructor for external tests, that may want to modify the root path.
  explicit BootStat(const base::FilePath& root_path);
  // Constructor for testing purpose: changes the default output directory and
  // allows replacing BootStatSystem implementation with a fake one.
  BootStat(const base::FilePath& output_directory_path,
           std::unique_ptr<BootStatSystem> boot_stat_system);
  BootStat(const BootStat&) = delete;
  BootStat& operator=(const BootStat&) = delete;
  ~BootStat();

  // Logs an event.  Event names should be composed of characters drawn from
  // this subset of 7-bit ASCII:  Letters (upper- or lower-case), digits, dot
  // ('.'), dash ('-'), and underscore ('_').  Case is significant.  Behavior
  // in the presence of other characters is unspecified - Caveat Emptor!
  //
  // Applications are responsible for establishing higher-level naming
  // conventions to prevent name collisions.
  bool LogEvent(const std::string& event_name) const;

  // Logs an RTC sync event, used to synchronize RTC and boottime clocks.
  // RTC timezone is normally UTC (as reported by the device).
  bool LogRtcSync(const char* event_name);

  struct BootstatTiming {
    // Time since boot.
    base::TimeDelta uptime;

    // Time spent in the idle task since boot. Note that this accumulates for
    // each CPU, so on a multi-core system, a meaningful comparison of "idle
    // time" might normalize against the number of available CPUs in the
    // system.
    base::TimeDelta idle_time;
  };

  // Retrieves the event timings for a given event type (|event_name|). There
  // may be more than one such event in a given boot. Returns std::nullopt if
  // there is an error.
  std::optional<std::vector<BootstatTiming>> GetEventTimings(
      const std::string& event_name) const;

 private:
  base::FilePath output_directory_path_;

  std::unique_ptr<BootStatSystem> boot_stat_system_;

  base::FilePath GetEventPath(const std::string& prefix,
                              const std::string& event_name) const;

  // Figures out the event output file name, and open it.
  // Returns a scoped fd (negative on error).
  base::ScopedFD OpenEventFile(const std::string& output_name_prefix,
                               const std::string& event_name) const;
  // Logs a disk event containing root disk statistics.
  bool LogDiskEvent(const std::string& event_name) const;
  // Logs a uptime event indicating time since boot.
  bool LogUptimeEvent(const std::string& event_name) const;

  std::optional<std::vector<BootstatTiming>> ParseUptimeEvent(
      const std::string& contents) const;

  // Return data for GetRtcTick
  struct RtcTick {
    struct rtc_time rtc_time;
    struct timespec boottime_before;
    struct timespec boottime_after;
  };

  // Waits for a RTC tick (every second), put that in RtcTick.rtc_time, and
  // record CLOCK_BOOTTIME before and after the tick in
  // RtcTick.boottime_before/after. Return std::nullopt on error.
  std::optional<struct RtcTick> GetRtcTick() const;
};
}  // namespace bootstat

//
// Length of the longest valid string naming an event, including the
// terminating NUL character.  Clients of bootstat_log() can use
// this value for the size of buffers to hold event names; names
// that exceed this buffer size will be truncated.
//
// This value is arbitrarily chosen, but see comments in
// bootstat_log.c regarding implementation assumptions for this
// value.
//
// TODO(drinkcat): Rename this to a kConstant in the namespace
#define BOOTSTAT_MAX_EVENT_LEN 64

#endif  // BOOTSTAT_BOOTSTAT_H_
