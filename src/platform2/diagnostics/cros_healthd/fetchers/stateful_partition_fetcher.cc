// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/fetchers/stateful_partition_fetcher.h"

#include <cstdint>
#include <string>

#include <base/files/file_path.h>
#include <base/system/sys_info.h>
#include <libmount/libmount.h>

#include "diagnostics/cros_healthd/utils/error_utils.h"

namespace diagnostics {

namespace mojom = ::ash::cros_healthd::mojom;

mojom::StatefulPartitionResultPtr
StatefulPartitionFetcher::FetchStatefulPartitionInfo() {
  const auto statefulPartitionPath =
      context_->root_dir().Append(kStatefulPartitionPath);
  const int64_t available_space =
      base::SysInfo::AmountOfFreeDiskSpace(statefulPartitionPath);
  const int64_t total_space =
      base::SysInfo::AmountOfTotalDiskSpace(statefulPartitionPath);

  const auto mtab = mnt_new_table();
  const auto mtabPath = context_->root_dir().Append(kMtabPath);
  mnt_table_parse_mtab(mtab, mtabPath.value().c_str());

  const auto fs = mnt_table_find_target(
      mtab, statefulPartitionPath.value().c_str(), MNT_ITER_FORWARD);

  if (available_space < 0 || total_space < 0) {
    mnt_free_table(mtab);
    return mojom::StatefulPartitionResult::NewError(
        CreateAndLogProbeError(mojom::ErrorType::kSystemUtilityError,
                               "Failed to collect stateful_partition info"));
  }

  if (!fs || !mnt_fs_get_fstype(fs) || !mnt_fs_get_source(fs)) {
    mnt_free_table(mtab);
    return mojom::StatefulPartitionResult::NewError(CreateAndLogProbeError(
        mojom::ErrorType::kSystemUtilityError,
        "Failed to collect stateful_partition info from mtab"));
  }

  std::string filesystem = mnt_fs_get_fstype(fs);
  std::string source = mnt_fs_get_source(fs);

  mnt_free_table(mtab);
  return mojom::StatefulPartitionResult::NewPartitionInfo(
      mojom::StatefulPartitionInfo::New(static_cast<uint64_t>(available_space),
                                        static_cast<uint64_t>(total_space),
                                        filesystem, source));
}

}  // namespace diagnostics
