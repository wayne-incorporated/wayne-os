// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "missive/analytics/resource_collector_storage.h"

#include <algorithm>

#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/sequence_checker.h>

namespace reporting::analytics {

ResourceCollectorStorage::ResourceCollectorStorage(
    base::TimeDelta interval, const base::FilePath& storage_directory)
    : ResourceCollector(interval), storage_directory_(storage_directory) {}

ResourceCollectorStorage::~ResourceCollectorStorage() {
  StopTimer();
}

int ResourceCollectorStorage::ConvertBytesToMibs(int bytes) {
  // Round the result to the nearest MiB.
  // As a special circumstance, if the rounded size in MiB is zero, then we give
  // it 1.
  return std::max((bytes + 1024 * 1024 / 2) / (1024 * 1024), 1);
}

void ResourceCollectorStorage::Collect() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (!SendDirectorySizeToUma(base::ComputeDirectorySize(storage_directory_))) {
    LOG(ERROR) << "Failed to send directory size to UMA.";
  }
}

bool ResourceCollectorStorage::SendDirectorySizeToUma(int directory_size) {
  return Metrics::SendToUMA(
      /*name=*/kUmaName,
      /*sample=*/ConvertBytesToMibs(directory_size),
      /*min=*/kMin,
      /*max=*/kMax,
      /*nbuckets=*/kUmaNumberOfBuckets);
}
}  // namespace reporting::analytics
