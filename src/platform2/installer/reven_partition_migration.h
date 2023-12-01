// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef INSTALLER_REVEN_PARTITION_MIGRATION_H_
#define INSTALLER_REVEN_PARTITION_MIGRATION_H_

#include <base/environment.h>

#include "installer/cgpt_manager.h"
#include "installer/metrics.h"

// Run a partition migration to increase the size of kernel partitions
// on the reven board. This is a no-op if the
// `reven_partition_migration` USE flag is not enabled.
//
// See `docs/reven_partition_migration.md` for details of the migration.
//
// Returns true if postinstall should be allowed to continue, or false
// on a fatal failure. Note that returning true does not necessarily
// indicate that the migration succeeded.
[[nodiscard]] bool RunRevenPartitionMigration(
    CgptManagerInterface& cgpt_manager,
    MetricsInterface& metrics,
    base::Environment& env);

#endif  // INSTALLER_REVEN_PARTITION_MIGRATION_H_
