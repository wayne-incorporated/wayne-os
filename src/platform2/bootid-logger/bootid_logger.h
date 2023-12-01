// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BOOTID_LOGGER_BOOTID_LOGGER_H_
#define BOOTID_LOGGER_BOOTID_LOGGER_H_

#include <string>

#include <base/files/file_path.h>
#include <base/time/time.h>

// Returns true if the boot entry is valid. The given boot id must not include
// trailing CR/LF.
bool ValidateBootEntry(const std::string& boot_id_entry);
// Returns the boot id extracted from the given boot entry.
std::string ExtractBootId(const std::string& boot_id_entry);
// Returns the current boot id.
std::string GetCurrentBootId();

// Write a boot entry with the current boot id and time to the given file.
bool WriteCurrentBootEntry(const base::FilePath& bootid_log_path,
                           const base::Time first_timestamp_to_keep,
                           const size_t max_entries);

// Write a boot entry with the given boot id and time to the given file.
bool WriteBootEntry(const base::FilePath& bootid_log_path,
                    const std::string& current_boot_id,
                    const base::Time boot_time,
                    const base::Time first_timestamp_to_keep,
                    const size_t max_entries);

#endif  // BOOTID_LOGGER_BOOTID_LOGGER_H_
