// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_FETCHERS_STATEFUL_PARTITION_FETCHER_H_
#define DIAGNOSTICS_CROS_HEALTHD_FETCHERS_STATEFUL_PARTITION_FETCHER_H_

#include "diagnostics/cros_healthd/fetchers/base_fetcher.h"
#include "diagnostics/mojom/public/cros_healthd_probe.mojom.h"

namespace diagnostics {

constexpr auto kStatefulPartitionPath = "mnt/stateful_partition";
constexpr auto kMtabPath = "etc/mtab";

// The StatefulPartitionFetcher class is responsible for gathering stateful
// partition info.
class StatefulPartitionFetcher final : public BaseFetcher {
 public:
  using BaseFetcher::BaseFetcher;

  // Returns stateful partition data or the error
  // that occurred retrieving the information.
  ash::cros_healthd::mojom::StatefulPartitionResultPtr
  FetchStatefulPartitionInfo();
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_FETCHERS_STATEFUL_PARTITION_FETCHER_H_
