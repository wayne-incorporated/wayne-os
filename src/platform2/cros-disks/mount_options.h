// Copyright 2011 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CROS_DISKS_MOUNT_OPTIONS_H_
#define CROS_DISKS_MOUNT_OPTIONS_H_

#include <string>
#include <utility>
#include <vector>

#include <base/strings/string_piece.h>

#include "cros-disks/platform.h"

namespace cros_disks {

// Checks if after applying all the "ro and "rw" options
// in order, the resulting mount should be read-only.
bool IsReadOnlyMount(const std::vector<std::string>& options);

// Finds the last value assigned to a parameter named |name|. Returns true if
// found.
[[nodiscard]] bool GetParamValue(const std::vector<std::string>& params,
                                 base::StringPiece name,
                                 std::string* value);

// Adds a '|name|=|value|' parameter to the container.
void SetParamValue(std::vector<std::string>* params,
                   base::StringPiece name,
                   base::StringPiece value);

// Returns whether params contain the exact param value.
bool HasExactParam(const std::vector<std::string>& params,
                   base::StringPiece param);

// Removes all elements equal to the provided and returns the count of
// removed elements.
size_t RemoveParamsEqualTo(std::vector<std::string>* params,
                           base::StringPiece param);

// Removes all elements like '|name|=|value|' with the name equal to the
// provided and returns the count of removed elements.
size_t RemoveParamsWithSameName(std::vector<std::string>* params,
                                base::StringPiece name);

// Joins params into a comma separated string. Returns false if comma is
// encountered in an element.
[[nodiscard]] bool JoinParamsIntoOptions(const std::vector<std::string>& params,
                                         std::string* out);

}  // namespace cros_disks

#endif  // CROS_DISKS_MOUNT_OPTIONS_H_
