// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef OOBE_CONFIG_ENCRYPTION_PSTORE_STORAGE_H_
#define OOBE_CONFIG_ENCRYPTION_PSTORE_STORAGE_H_

#include <optional>
#include <string>

#include <base/files/file_path.h>

#include "oobe_config/filesystem/file_handler.h"

namespace oobe_config {

// These functions take advantage of a utility called pstore: Writes to /dev/
// pmsg0 are persisted in /sys/fs/pstore/pmsg-ramoops-[ID] across exactly one
// reboot.

// Prepares data to be stored in pstore across rollback by formatting and
// staging in a special file to be picked up by clobber. Returns whether
// staging was successful.
// Note that clobber_state does the actual appending to pstore right before
// wiping the device.
bool StageForPstore(const std::string& data,
                    const oobe_config::FileHandler& file_handler);

// Loads data directly from pstore. Returns `std::nullopt` if
// no rollback data was found.
std::optional<std::string> LoadFromPstore(
    const oobe_config::FileHandler& file_handler);

}  // namespace oobe_config

#endif  // OOBE_CONFIG_ENCRYPTION_PSTORE_STORAGE_H_
