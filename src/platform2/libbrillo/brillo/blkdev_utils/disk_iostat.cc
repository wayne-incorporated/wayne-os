// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "brillo/blkdev_utils/disk_iostat.h"

#include <cstdint>
#include <limits>
#include <optional>
#include <sstream>
#include <string>

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/time/time.h>

namespace brillo {

namespace {

constexpr char kStatFile[] = "stat";

// base::TimeDelta is constructed from a signed integer, while iostat provides
// unsigned values. This function ensures safe conversion without negative
// overflow.
base::TimeDelta SafeTimeDeltaFromUint64(uint64_t value) {
  uint64_t safe_value = value & ~(1ULL << 63);
  // It is very unlikely that the read value of the iostat will overflow 2^63,
  // thus add this DCHECK to alert on an unrealistically high value.
  DCHECK(value == safe_value);
  return base::Milliseconds(static_cast<int64_t>(safe_value));
}

// Returns a difference between arguments, if both contain value.
std::optional<uint64_t> SafeDiffOptionalUint64(std::optional<uint64_t> v1,
                                               std::optional<uint64_t> v2) {
  if (!v1.has_value() || !v2.has_value()) {
    return std::nullopt;
  }
  return v1.value() - v2.value();
}

}  // namespace

DiskIoStat::DiskIoStat(const base::FilePath& dev_sys_path)
    : dev_sys_path_(dev_sys_path) {}

std::optional<DiskIoStat::Snapshot> DiskIoStat::GetSnapshot() {
  base::FilePath stat_path = dev_sys_path_.Append(kStatFile);
  Stat stat;

  std::string stat_string;
  if (!base::ReadFileToString(stat_path, &stat_string)) {
    PLOG(ERROR) << "Unable to read " << stat_path;
    return std::nullopt;
  }

  std::stringstream stat_stream(stat_string);
  stat_stream >> stat.read_ios >> stat.read_merges >> stat.read_sectors >>
      stat.read_ticks >> stat.write_ios >> stat.write_merges >>
      stat.write_sectors >> stat.write_ticks >> stat.in_flight >>
      stat.io_ticks >> stat.time_in_queue;

  if (stat_stream.fail() || stat_stream.bad()) {
    LOG(ERROR) << "Failed to parse " << stat_path;
    return std::nullopt;
  }

  // Might not be present on older kernels (<4.18), thus we consider those
  // fields best effort and ignore parsing errors.
  uint64_t discard_ios;
  uint64_t discard_merges;
  uint64_t discard_sectors;
  uint64_t discard_ticks;

  stat_stream >> discard_ios >> discard_merges >> discard_sectors >>
      discard_ticks;

  if (!stat_stream.fail() && !stat_stream.bad()) {
    stat.discard_ios = discard_ios;
    stat.discard_merges = discard_merges;
    stat.discard_sectors = discard_sectors;
    stat.discard_ticks = discard_ticks;
  }

  return DiskIoStat::Snapshot(base::Time::Now().since_origin(), stat);
}

#define DELTA_STAT(field, other) .field = stat_.field - other.stat_.field
#define DELTA_OPT_STAT(field, other) \
  .field = SafeDiffOptionalUint64(stat_.field, other.stat_.field)

DiskIoStat::Delta DiskIoStat::Snapshot::Delta(
    const DiskIoStat::Snapshot& snapshot) const {
  Stat delta = {
      DELTA_STAT(read_ios, snapshot),
      DELTA_STAT(read_merges, snapshot),
      DELTA_STAT(read_sectors, snapshot),
      DELTA_STAT(read_ticks, snapshot),
      DELTA_STAT(write_ios, snapshot),
      DELTA_STAT(write_merges, snapshot),
      DELTA_STAT(write_sectors, snapshot),
      DELTA_STAT(write_ticks, snapshot),
      DELTA_STAT(in_flight, snapshot),
      DELTA_STAT(io_ticks, snapshot),
      DELTA_STAT(time_in_queue, snapshot),
      DELTA_OPT_STAT(discard_ios, snapshot),
      DELTA_OPT_STAT(discard_merges, snapshot),
      DELTA_OPT_STAT(discard_sectors, snapshot),
      DELTA_OPT_STAT(discard_ticks, snapshot),
  };

  return DiskIoStat::Delta(
      DiskIoStat::Snapshot(timestamp_ - snapshot.timestamp_, delta));
}

base::TimeDelta DiskIoStat::Snapshot::GetTimestamp() const {
  return timestamp_;
}

const DiskIoStat::Stat& DiskIoStat::Snapshot::GetRawStat() const {
  return stat_;
}

base::TimeDelta DiskIoStat::Snapshot::GetReadTime() const {
  return SafeTimeDeltaFromUint64(stat_.read_ticks);
}

base::TimeDelta DiskIoStat::Snapshot::GetWriteTime() const {
  return SafeTimeDeltaFromUint64(stat_.write_ticks);
}

uint64_t DiskIoStat::Snapshot::GetReadSectors() const {
  return stat_.read_sectors;
}

uint64_t DiskIoStat::Snapshot::GetWrittenSectors() const {
  return stat_.write_sectors;
}

base::TimeDelta DiskIoStat::Snapshot::GetIoTime() const {
  return SafeTimeDeltaFromUint64(stat_.io_ticks);
}

std::optional<base::TimeDelta> DiskIoStat::Snapshot::GetDiscardTime() const {
  if (!stat_.discard_ticks.has_value()) {
    return std::nullopt;
  }
  return SafeTimeDeltaFromUint64(stat_.discard_ticks.value());
}

}  // namespace brillo
