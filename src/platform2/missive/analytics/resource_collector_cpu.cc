// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "missive/analytics/resource_collector_cpu.h"

#include <algorithm>
#include <cstddef>
#include <ctime>
#include <string>

#include <base/logging.h>
#include <base/time/time.h>

#include "missive/util/status_macros.h"
#include "missive/util/statusor.h"
#include "missive/util/time.h"

namespace reporting::analytics {

ResourceCollectorCpu::ResourceCollectorCpu(base::TimeDelta interval)
    : ResourceCollector(interval) {}

ResourceCollectorCpu::~ResourceCollectorCpu() {
  StopTimer();
}

void ResourceCollectorCpu::Collect() {
  const auto cpu_percentage = tallier_->Tally();
  if (!cpu_percentage.ok()) {
    LOG(ERROR) << cpu_percentage.status();
    return;
  }
  SendCpuUsagePercentageToUma(cpu_percentage.ValueOrDie());
}

bool ResourceCollectorCpu::SendCpuUsagePercentageToUma(
    uint64_t cpu_percentage) {
  return Metrics::SendPercentageToUMA(
      /*name=*/kUmaName,
      /*sample=*/static_cast<int>(cpu_percentage));
}

StatusOr<uint64_t> ResourceCollectorCpu::CpuUsageTallier::Tally() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  ASSIGN_OR_RETURN(time_t cpu_time, GetCurrentTime(TimeType::kProcessCpu));
  ASSIGN_OR_RETURN(time_t wall_time, GetCurrentTime(TimeType::kWall));

  // We ignore the nanosecond part because we don't need that level of accuracy.
  uint64_t result = static_cast<uint64_t>(cpu_time - last_cpu_time_) * 100U /
                    std::max<uint64_t>(wall_time - last_wall_time_, 1U);

  // Update stored CPU time and wall time
  last_cpu_time_ = cpu_time;
  last_wall_time_ = wall_time;

  return result;
}

ResourceCollectorCpu::CpuUsageTallier::~CpuUsageTallier() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
}

}  // namespace reporting::analytics
