// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "missive/resources/enqueuing_record_tallier.h"

#include <atomic>
#include <cstdint>
#include <optional>
#include <utility>

#include <base/sequence_checker.h>
#include <base/time/time.h>
#include <base/timer/timer.h>

#include "missive/proto/record.pb.h"
#include "missive/util/status_macros.h"
#include "missive/util/statusor.h"
#include "missive/util/time.h"

namespace reporting {

EnqueuingRecordTallier::EnqueuingRecordTallier(base::TimeDelta interval) {
  timer_.Start(FROM_HERE, interval, this,
               &EnqueuingRecordTallier::UpdateAverage);
}

EnqueuingRecordTallier::~EnqueuingRecordTallier() = default;

StatusOr<uint64_t> EnqueuingRecordTallier::GetCurrentWallTime() const {
  return GetCurrentTime(TimeType::kWall);
}

void EnqueuingRecordTallier::Tally(const Record& record) {
  cumulated_size_ += record.ByteSizeLong();
}

std::optional<uint64_t> EnqueuingRecordTallier::GetAverage() const {
  const uint64_t average = average_.load();
  if (average == kAverageNullOpt) {
    return std::nullopt;
  } else {
    return average;
  }
}

void EnqueuingRecordTallier::UpdateAverage() {
  if (auto average_status = ComputeAverage(); average_status.ok()) {
    average_ = average_status.ValueOrDie();
  } else {
    LOG(ERROR)
        << "The rate of new events (enqueuing events) cannot be computed: "
        << average_status.status();
    average_ = kAverageNullOpt;
  }
}

StatusOr<uint64_t> EnqueuingRecordTallier::ComputeAverage() {
  // Reset cumulated_size_ and last_wall_time_ here so no need to worry about
  // returning early.
  const uint64_t cumulated_size = cumulated_size_.exchange(0U);
  const auto last_wall_time = std::move(last_wall_time_);
  const auto wall_time = GetCurrentWallTime();
  last_wall_time_ = wall_time;

  // If either current wall time or last wall time is missing, return an error.
  if (!wall_time.ok()) {
    return wall_time;
  }
  if (!last_wall_time.ok()) {
    return last_wall_time;
  }

  // Both wall times were obtained. Return the average rate of enqueuing
  // records.
  DCHECK(wall_time.ValueOrDie() >= last_wall_time.ValueOrDie());
  return cumulated_size /
         std::max<uint64_t>(
             wall_time.ValueOrDie() - last_wall_time.ValueOrDie(), 1U);
}
}  // namespace reporting
