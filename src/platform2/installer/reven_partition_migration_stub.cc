// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "installer/reven_partition_migration.h"

// Always return true when the `reven_partition_migration` USE flag is
// not enabled.
bool RunRevenPartitionMigration(CgptManagerInterface& cgpt_manager,
                                MetricsInterface& metrics,
                                base::Environment& env) {
  return true;
}
