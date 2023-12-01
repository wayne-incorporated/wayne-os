// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef INIT_UTILS_H_
#define INIT_UTILS_H_

#include <string>
#include <vector>

#include <base/files/file.h>
#include <base/files/file_path.h>

namespace utils {

// Try to set root to the root device filepath, optionally removing the
// partition number
bool GetRootDevice(base::FilePath* root, bool strip_partition);

// Helper function to read a file to int
bool ReadFileToInt(const base::FilePath& path, int* value);

// Run encrypted-reboot-vault --action=create
bool CreateEncryptedRebootVault();

// Run encrypted-reboot-vault --action=unlock
bool UnlockEncryptedRebootVault();

// Run shutdown.
void Reboot();

void Restorecon(const base::FilePath& path,
                const std::vector<base::FilePath>& exclude,
                bool is_recursive,
                bool set_digests);

// Searches `drive_name` for the partition labeled `partition_label` and
// returns its partition number if exactly one partition was found. Returns
// -1 on error.
int GetPartitionNumber(const base::FilePath& drive_name,
                       const std::string& partition_label);

// Reads successful and priority metadata from partition numbered
// `partition_number` on `disk`, storing the results in `successful_out` and
// `priority_out`, respectively. Returns true on success.
//
// successful is a 1 bit value indicating if a kernel partition
// has been successfully booted, while priority is a 4 bit value
// indicating what order the kernel partitions should be booted in, 15 being
// the highest, 1 the lowest, and 0 meaning not bootable.
// More information on partition metadata is available at.
// https://www.chromium.org/chromium-os/chromiumos-design-docs/disk-format
bool ReadPartitionMetadata(const base::FilePath& disk,
                           int partition_number,
                           bool* successful_out,
                           int* priority_out);

// Make sure the kernel partition numbered `kernel_partition` is still
// bootable after being wiped. The system may be in AU state that active
// kernel does not have "successful" bit set to 1, but the kernel has been
// successfully booted.
void EnsureKernelIsBootable(const base::FilePath root_disk,
                            int kernel_partition);

}  // namespace utils

#endif  // INIT_UTILS_H_
