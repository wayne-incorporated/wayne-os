// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "missive/analytics/resource_collector_memory.h"

#include <utility>

#include <base/logging.h>
#include <base/memory/scoped_refptr.h>
#include <base/sequence_checker.h>

#include "missive/resources/resource_manager.h"

namespace reporting::analytics {

ResourceCollectorMemory::ResourceCollectorMemory(
    base::TimeDelta interval, scoped_refptr<ResourceManager> memory_resource)
    : ResourceCollector(interval),
      memory_resource_(std::move(memory_resource)) {
  DCHECK(memory_resource_);
}

ResourceCollectorMemory::~ResourceCollectorMemory() {
  StopTimer();
}

// static
int ResourceCollectorMemory::ConvertBytesTo0_1Mibs(int bytes) {
  static constexpr int k0_1mibs = 1024 * 1024 / 10;  // 0.1MiB
  return (bytes + k0_1mibs / 2) / k0_1mibs;
}

void ResourceCollectorMemory::Collect() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (!SendMemorySizeToUma(memory_resource_->GetUsed())) {
    LOG(ERROR) << "Failed to send memory size to UMA.";
  }
}

bool ResourceCollectorMemory::SendMemorySizeToUma(int memory_size) {
  // Use linear here because we also care about the detail of memory usage when
  // it's high.
  return Metrics::SendLinearToUMA(
      /*name=*/kUmaName,
      /*sample=*/ConvertBytesTo0_1Mibs(memory_size),
      /*max=*/kUmaMax);
}
}  // namespace reporting::analytics
