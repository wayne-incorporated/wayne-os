// Copyright 2011 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Implementation of bootstat_log(), part of the Chromium OS 'bootstat'
// facility.

#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <linux/rtc.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

#include <optional>
#include <string>
#include <vector>

#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/stringprintf.h>
#include <base/time/time.h>
#include <rootdev/rootdev.h>

#include "bootstat/bootstat.h"

namespace bootstat {

namespace {
// Default root-relative path to directory where output statistics will be
// stored.
static const char kDefaultOutputDirectoryName[] = "tmp";

static constexpr char kProcUptime[] = "proc/uptime";

static constexpr int64_t kNsecsPerSec = 1e9;

// Parse a line of text containing one or more space-separated columns of
// decimal numbers. For example (without the quotes):
//   "12.76543 0.89"
//   "10.3333"
static std::optional<std::vector<base::TimeDelta>> ParseDecimalColumns(
    const base::StringPiece& line) {
  auto numbers = base::SplitStringPiece(line, " ", base::TRIM_WHITESPACE,
                                        base::SPLIT_WANT_NONEMPTY);
  if (numbers.empty()) {
    LOG(ERROR) << "Malformed line: " << line;
    return std::nullopt;
  }

  std::vector<base::TimeDelta> results;
  for (auto& number : numbers) {
    auto pieces = base::SplitStringPiece(number, ".", base::TRIM_WHITESPACE,
                                         base::SPLIT_WANT_NONEMPTY);
    if (pieces.size() != 2) {
      LOG(ERROR) << "Malformed number: " << line;
      return std::nullopt;
    }

    uint64_t secs;
    if (!base::StringToUint64(pieces[0], &secs)) {
      LOG(ERROR) << "Malformed seconds: " << line;
      return std::nullopt;
    }

    // We're looking for nanoseconds.
    if (pieces[1].size() > 9) {
      LOG(ERROR) << "Malformed decimal places: " << line;
      return std::nullopt;
    }
    // Pad to 9, with trailing zeroes.
    unsigned int nsecs;
    if (!base::StringToUint(pieces[1], &nsecs)) {
      LOG(ERROR) << "Malformed decimal: " << line;
      return std::nullopt;
    }
    for (int i = 0; i < 9 - pieces[1].size(); i++)
      nsecs *= 10;

    results.push_back(base::Seconds(secs) + base::Nanoseconds(nsecs));
  }

  return results;
}

}  // namespace

BootStatSystem::BootStatSystem() : BootStatSystem(base::FilePath("/")) {}

BootStatSystem::BootStatSystem(const base::FilePath& root_path)
    : root_path_(root_path) {}

// TODO(drinkcat): Cache function output (we only need to evaluate it once)
base::FilePath BootStatSystem::GetDiskStatisticsFilePath() const {
  char boot_path[PATH_MAX];
  int ret = rootdev(boot_path, sizeof(boot_path),
                    true,    // Do full resolution.
                    false);  // Do not remove partition number.
  if (ret != 0) {
    LOG(ERROR) << "Cannot get rootdev.";
    return base::FilePath();
  }

  // The general idea is to use the the root device's sysfs entry to
  // get the path to the root disk's sysfs entry.
  // Example:
  // - rootdev() returns "/dev/sda3"
  // - Use /sys/class/block/sda3/../ to get to root disk (sda) sysfs entry.
  //   This is because /sys/class/block/sda3 is a symlink that maps to:
  //     /sys/devices/pci.../.../ata./host./target.../.../block/sda/sda3
  base::FilePath root_device_name = base::FilePath(boot_path).BaseName();

  base::FilePath stat_path = base::FilePath("/sys/class/block")
                                 .Append(root_device_name)
                                 .Append("../stat");

  // Normalize the path as some functions refuse to follow symlink/`..`.
  base::FilePath norm;
  if (!base::NormalizeFilePath(stat_path, &norm)) {
    LOG(ERROR) << "Cannot normalize disk statistics file path.";
    return base::FilePath();
  }
  return norm;
}

std::optional<struct timespec> BootStatSystem::GetUpTime() const {
  struct timespec uptime;
  int ret = clock_gettime(CLOCK_BOOTTIME, &uptime);
  if (ret != 0) {
    PLOG(ERROR) << "Cannot get uptime (CLOCK_BOOTTIME).";
    return std::nullopt;
  }
  return uptime;
}

std::optional<base::TimeDelta> BootStatSystem::GetIdleTime() const {
  base::FilePath path = root_path_.Append(kProcUptime);
  std::string data;
  if (!base::ReadFileToString(path, &data)) {
    PLOG(ERROR) << "Cannot read uptime from: " << path;
    return std::nullopt;
  }

  auto numbers = ParseDecimalColumns(data);
  if (!numbers) {
    LOG(ERROR) << "Couldn't parse uptime: " << data;
    return std::nullopt;
  }
  if (numbers->size() != 2) {
    LOG(ERROR) << "Unexpected uptime contents: " << data;
    return std::nullopt;
  }
  // Second column is idle time.
  return (*numbers)[1];
}

base::ScopedFD BootStatSystem::OpenRtc() const {
  int rtc_fd = HANDLE_EINTR(open("/dev/rtc", O_RDONLY | O_CLOEXEC));
  if (rtc_fd < 0)
    PLOG(ERROR) << "Cannot open RTC";

  return base::ScopedFD(rtc_fd);
}

std::optional<struct rtc_time> BootStatSystem::GetRtcTime(
    base::ScopedFD* rtc_fd) const {
  struct rtc_time rtc_time;
  if (ioctl(rtc_fd->get(), RTC_RD_TIME, &rtc_time) < 0) {
    PLOG(ERROR) << "RTC ioctl error";
    return std::nullopt;
  }

  return rtc_time;
}

BootStat::BootStat() : BootStat(base::FilePath("/")) {}

BootStat::BootStat(const base::FilePath& root_path)
    : BootStat(root_path.Append(base::FilePath(kDefaultOutputDirectoryName)),
               std::make_unique<BootStatSystem>()) {}

BootStat::BootStat(const base::FilePath& output_directory_path,
                   std::unique_ptr<BootStatSystem> boot_stat_system)
    : output_directory_path_(output_directory_path),
      boot_stat_system_(std::move(boot_stat_system)) {}

BootStat::~BootStat() = default;

base::FilePath BootStat::GetEventPath(const std::string& prefix,
                                      const std::string& event_name) const {
  //
  // For those not up on the more esoteric features of printf
  // formats:  the "%.*s" format is used to truncate the event name
  // to the proper number of characters..
  //
  std::string output_file =
      base::StringPrintf("%s-%.*s", prefix.c_str(), BOOTSTAT_MAX_EVENT_LEN - 1,
                         event_name.c_str());

  return output_directory_path_.Append(output_file);
}

std::optional<struct BootStat::RtcTick> BootStat::GetRtcTick() const {
  base::ScopedFD rtc_fd = boot_stat_system_->OpenRtc();
  if (!rtc_fd.is_valid())
    return std::nullopt;

  // Record start time so that we can timeout if needed.
  std::optional<struct timespec> tps_start = boot_stat_system_->GetUpTime();
  if (!tps_start)
    return std::nullopt;

  std::optional<struct rtc_time> rtc_time[2];

  for (int i = 0;; i++) {
    int old = (i + 1) % 2;
    int cur = i % 2;

    std::optional<struct timespec> tps_cur = boot_stat_system_->GetUpTime();
    if (!tps_cur)
      return std::nullopt;

    rtc_time[cur] = boot_stat_system_->GetRtcTime(&rtc_fd);
    if (!rtc_time[cur])
      return std::nullopt;

    if (i > 0 && rtc_time[cur]->tm_sec != rtc_time[old]->tm_sec) {
      // RTC ticked, record "after" time.
      std::optional<struct timespec> tps_after = boot_stat_system_->GetUpTime();
      if (!tps_after)
        return std::nullopt;
      return {{*rtc_time[cur], *tps_cur, *tps_after}};
    }

    // Timeout after 1.5 seconds.
    if (difftime(tps_cur->tv_sec, tps_start->tv_sec) +
            (tps_cur->tv_nsec - tps_start->tv_nsec) * 1e-9 >
        1.5) {
      LOG(ERROR) << "Timeout waiting for RTC tick.";
      return std::nullopt;
    }

    // Don't hog the CPU too much, we don't care about sub-ms resolution
    // anyway.
    usleep(1000);
  }
}

base::ScopedFD BootStat::OpenEventFile(const std::string& output_name_prefix,
                                       const std::string& event_name) const {
  const mode_t kFileCreationMode =
      S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH;

  base::FilePath output_path = GetEventPath(output_name_prefix, event_name);

  int output_fd =
      HANDLE_EINTR(open(output_path.value().c_str(),
                        O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW | O_CLOEXEC,
                        kFileCreationMode));
  if (output_fd < 0) {
    PLOG(ERROR) << "Cannot open event file " << output_path.value() << ".";
    return base::ScopedFD();
  }

  base::stat_wrapper_t stat;
  if (base::File::Fstat(output_fd, &stat) < 0) {
    PLOG(ERROR) << "Failed to stat file " << output_path.value();
    return base::ScopedFD();
  }

  // Double check the read permissions, because umask may override us during
  // creation, and we need those. (We allow write permissions to be masked.)
  mode_t new_mode = stat.st_mode | S_IRGRP | S_IROTH;
  if (stat.st_mode == new_mode)
    return base::ScopedFD(output_fd);

  // We need to force the permissions again. There's a small race here, as the
  // file may exist with a umask()'ed (incorrect) mode briefly, so consumers
  // should still be prepared to handle EPERM errors.
  if (HANDLE_EINTR(fchmod(output_fd, new_mode)) == -1) {
    PLOG(ERROR) << "Failed to set permissions for event file "
                << output_path.value();
    return base::ScopedFD();
  }
  return base::ScopedFD(output_fd);
}

bool BootStat::LogDiskEvent(const std::string& event_name) const {
  base::FilePath disk_statistics_file_path =
      boot_stat_system_->GetDiskStatisticsFilePath();

  if (disk_statistics_file_path.empty())
    return false;

  std::string data;
  if (!base::ReadFileToString(disk_statistics_file_path, &data)) {
    LOG(ERROR) << "Cannot read disk statistics "
               << disk_statistics_file_path.value() << ".";
    return false;
  }

  base::ScopedFD output_fd = OpenEventFile("disk", event_name);
  if (!output_fd.is_valid())
    return false;

  bool ret = base::WriteFileDescriptor(output_fd.get(), data);
  LOG_IF(ERROR, !ret) << "Cannot write disk event.";
  return ret;
}

bool BootStat::LogUptimeEvent(const std::string& event_name) const {
  std::optional<struct timespec> uptime = boot_stat_system_->GetUpTime();
  if (!uptime)
    return false;

  std::optional<base::TimeDelta> idle = boot_stat_system_->GetIdleTime();
  if (!idle)
    return false;

  std::string data = base::StringPrintf(
      "%" PRId64 ".%09ld %" PRId64 ".%09" PRId64 "\n",
      static_cast<int64_t>(uptime->tv_sec), uptime->tv_nsec, idle->InSeconds(),
      idle->InNanoseconds() % kNsecsPerSec);

  base::ScopedFD output_fd = OpenEventFile("uptime", event_name);
  if (!output_fd.is_valid())
    return false;

  bool ret = base::WriteFileDescriptor(output_fd.get(), data);
  LOG_IF(ERROR, !ret) << "Cannot write uptime event.";
  return ret;
}

std::optional<std::vector<BootStat::BootstatTiming>> BootStat::ParseUptimeEvent(
    const std::string& contents) const {
  auto lines = base::SplitStringPiece(contents, "\n", base::TRIM_WHITESPACE,
                                      base::SPLIT_WANT_NONEMPTY);

  std::vector<BootStat::BootstatTiming> events;
  for (auto& line : lines) {
    auto result = ParseDecimalColumns(line);
    if (!result)
      return std::nullopt;
    if (result->size() != 2) {
      LOG(ERROR) << "Unexpected uptime line: " << line;
      return std::nullopt;
    }

    BootStat::BootstatTiming event = {
        .uptime = (*result)[0],
        .idle_time = (*result)[1],
    };
    events.push_back(std::move(event));
  }

  return events;
}

// API functions.
bool BootStat::LogEvent(const std::string& event_name) const {
  bool ret = true;

  ret &= LogDiskEvent(event_name);
  ret &= LogUptimeEvent(event_name);

  return ret;
}

bool BootStat::LogRtcSync(const char* event_name) {
  std::optional<struct RtcTick> tick = GetRtcTick();
  if (!tick)
    return false;

  base::ScopedFD output_fd = OpenEventFile("sync-rtc", event_name);
  if (!output_fd.is_valid())
    return false;

  std::string data = base::StringPrintf(
      "%" PRId64 ".%09ld %" PRId64 ".%09ld %04d-%02d-%02d %02d:%02d:%02d\n",
      static_cast<int64_t>(tick->boottime_before.tv_sec),
      tick->boottime_before.tv_nsec,
      static_cast<int64_t>(tick->boottime_after.tv_sec),
      tick->boottime_after.tv_nsec, tick->rtc_time.tm_year + 1900,
      tick->rtc_time.tm_mon + 1, tick->rtc_time.tm_mday, tick->rtc_time.tm_hour,
      tick->rtc_time.tm_min, tick->rtc_time.tm_sec);

  bool ret = base::WriteFileDescriptor(output_fd.get(), data);
  LOG_IF(ERROR, !ret) << "Cannot write rtc sync.";
  return ret;
}

std::optional<std::vector<BootStat::BootstatTiming>> BootStat::GetEventTimings(
    const std::string& event_name) const {
  base::FilePath event_path = GetEventPath("uptime", event_name);

  std::string data;
  if (!base::ReadFileToString(event_path, &data)) {
    PLOG(ERROR) << "Could not read event file: " << event_path;
    return std::nullopt;
  }

  auto result = ParseUptimeEvent(data);
  if (!result)
    LOG(ERROR) << "Failed to parse bootstat file for event: " << event_name;

  return result;
}

};  // namespace bootstat
