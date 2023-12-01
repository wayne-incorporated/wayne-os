// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MISSIVE_ANALYTICS_RESOURCE_COLLECTOR_STORAGE_H_
#define MISSIVE_ANALYTICS_RESOURCE_COLLECTOR_STORAGE_H_

#include "missive/analytics/resource_collector.h"

#include <ctime>

#include <base/files/file_path.h>
#include <base/time/time.h>
#include <gtest/gtest_prod.h>

namespace reporting {

// Forward declarations for `friend class` directives.
class MissiveArgsTest;
class MissiveImplTest;

namespace analytics {

class ResourceCollectorStorage : public ResourceCollector {
 public:
  ResourceCollectorStorage(base::TimeDelta interval,
                           const base::FilePath& storage_directory);
  ~ResourceCollectorStorage() override;

 private:
  friend class ::reporting::MissiveArgsTest;
  friend class ::reporting::MissiveImplTest;
  friend class ResourceCollectorStorageTest;
  FRIEND_TEST(ResourceCollectorStorageTest, SuccessfullySend);

  // UMA name
  static constexpr char kUmaName[] = "Platform.Missive.StorageUsage";
  // The min of the storage usage in MiB that we are collecting: 1MiB
  static constexpr int kMin = 1;
  // The max of the storage usage in MiB that we are collecting: 301MiB.
  // Slightly larger than the limit we have to detect possible over usage.
  static constexpr int kMax = 301;
  // number of UMA buckets. Buckets are exponentially binned. Fixed to the
  // default in Chrome (50).
  static constexpr int kUmaNumberOfBuckets = 50;

  // Convert bytes into MiBs.
  static int ConvertBytesToMibs(int bytes);

  // Collect storage usage. This is not obtained from the memory resource
  // management in Missive. Rather, the storage directory is scanned once for
  // each fixed time interval as this method is called (see comments for
  // |ResourceCollector::Collect|).
  void Collect() override;
  // Send directory size data to UMA.
  bool SendDirectorySizeToUma(int directory_size);

  // The directory in which record files are saved.
  const base::FilePath storage_directory_;
};

}  // namespace analytics
}  // namespace reporting

#endif  // MISSIVE_ANALYTICS_RESOURCE_COLLECTOR_STORAGE_H_
