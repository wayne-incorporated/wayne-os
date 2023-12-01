// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This header exposes some parts of the partition migration for unit
// testing.

#ifndef INSTALLER_REVEN_PARTITION_MIGRATION_PRIVATE_H_
#define INSTALLER_REVEN_PARTITION_MIGRATION_PRIVATE_H_

#include <cstdint>

#include "installer/cgpt_manager.h"
#include "installer/inst_util.h"
#include "installer/metrics.h"

// These values are persisted to logs. Entries should not be renumbered
// and numeric values should never be reused.
enum class [[nodiscard]] PartitionMigrationResult {
  kSuccess = 0,
  kNoMigrationNeeded = 1,
  kGptReadKernError = 2,
  kGptReadRootError = 3,
  kGptWriteKernError = 4,
  kGptWriteRootError = 5,
  kDiskOpenError = 6,
  kDiskReadError = 7,
  kDiskWriteError = 8,
  kRootPartitionUnexpectedSize = 9,
  kMigrationNotAllowed = 10,

  kMax = kMigrationNotAllowed,
};

// Plan for migrating one kernel partition (either slot A or slot B).
//
// This separates gathering the info needed to perform the migration
// from the migration itself. This allows the slot migration to be
// planned before running it; if anything fails when initializing a slot
// plan then the whole migration (for both slots) is canceled. This
// allows us to minimize the number of errors that can occur in the
// migration itself.
class SlotPlan {
 public:
  static SlotPlan ForSlotA(CgptManagerInterface& cgpt_manager);
  static SlotPlan ForSlotB(CgptManagerInterface& cgpt_manager);

  // Initialize the plan.
  //
  // * Returns `kSuccess` if the initialization is successful and a
  //   migration is needed.
  // * Returns `kNoMigrationNeeded` if the kernel partition is already
  //   big enough.
  // * Returns an error if the kernel or root partition entries can't be
  //   read, or if the root partition is too small for the migration.
  PartitionMigrationResult Initialize();

  // Write out the new kernel partition's data to disk.
  //
  // The new kernel data starts with a copy of the kernel data from the
  // original kernel partition.The rest of the data is initialized with
  // zeroes.
  //
  // This is not a destructive action since the data being written is
  // within the bounds of the current root partition, but outside the
  // region within the root partition that's actually used.
  //
  // * Returns `kSuccess` if the data is successfully copied.
  // * Returns an error if the disk couldn't be opened, or if reading
  //   the original data fails, or if writing out the data fails.
  PartitionMigrationResult WriteNewKernelData() const;

  // Shrink the root partition to make room for the new kernel
  // partition.
  //
  // * Returns `kSuccess` if the partition entry is successfully updated.
  // * Returns an error if the partition entry can't be updated.
  PartitionMigrationResult ShrinkRootPartition() const;

  // Move and expand the kernel partition.
  //
  // * Returns `kSuccess` if the partition entry is successfully updated.
  // * Returns an error if the partition entry can't be updated.
  PartitionMigrationResult UpdateKernelPartition() const;

  // Perform the slot's migration using `WriteNewKernelData`,
  // `ShrinkRootPartition`, and `UpdateKernelPartition`.
  //
  // * Returns `kSuccess` if all operations succeed.
  // * Returns an error if any operation fails.
  PartitionMigrationResult Run() const;

 private:
  SlotPlan(CgptManagerInterface& cgpt_manager,
           PartitionNum kern_num,
           PartitionNum root_num);

  CgptManagerInterface& cgpt_manager_;

  const PartitionNum kern_num_;
  const PartitionNum root_num_;

  // New (smaller) size of the root partition.
  uint64_t root_new_num_sectors_ = 0;

  // Sectors used by the original kernel partition.
  SectorRange kern_orig_sectors_;

  // New location and size of the kernel partition.
  SectorRange kern_new_sectors_;
};

// Plan for migrating both slots.
//
// This separates gathering the info needed to perform the migration
// from the migration itself. This allows the full migration to be
// planned before running it; if anything fails when initializing a slot
// plan then the whole migration (for both slots) is canceled. This
// allows us to minimize the number of errors that can occur in the
// migration itself.
class FullPlan {
 public:
  explicit FullPlan(CgptManagerInterface& cgpt_manager);

  // Initialize the plan.
  //
  // * Returns `kSuccess` if the initialization is successful and at
  // * least one slot needs to be migrated.
  // * Returns `kNoMigrationNeeded` if both slots have already been migrated.
  // * Returns an error if either slot plan failed to initialize.
  PartitionMigrationResult Initialize();

  // Perform the slot migrations.
  //
  // If a slot has already been migrated, it will be skipped.
  //
  // * Returns `kSuccess` if all operations succeed.
  // * Returns an error if any operation fails.
  PartitionMigrationResult Run();

 private:
  CgptManagerInterface& cgpt_manager_;

  // Result of initializing the slot plans.
  PartitionMigrationResult slot_a_result_;
  PartitionMigrationResult slot_b_result_;

  SlotPlan slot_a_plan_;
  SlotPlan slot_b_plan_;
};

// Convert from MiB to 512-byte disk sectors.
uint64_t MibToSectors(uint64_t mib);

// Convert from 512-byte disk sectors to bytes.
uint64_t SectorsToBytes(uint64_t sectors);

#endif  // INSTALLER_REVEN_PARTITION_MIGRATION_PRIVATE_H_
