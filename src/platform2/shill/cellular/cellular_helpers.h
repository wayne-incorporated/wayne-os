// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_CELLULAR_CELLULAR_HELPERS_H_
#define SHILL_CELLULAR_CELLULAR_HELPERS_H_

#include <string>

#include "shill/data_types.h"

namespace shill {

// Gets a printable value from a Stringmap without adding a value when it
// doesn't exist. Return an empty string as the default value.
std::string GetStringmapValue(const Stringmap& string_map,
                              const std::string& key,
                              const std::string& default_value = "");

// Gets a printable value from an APN Stringmap masked using the function
// |GetPrintableApnValue|.
std::string GetPrintableApnStringmap(const Stringmap& apn_info);

// Masks a value from the APN properties if the verbose level is lower than 3,
// or the APN Source is not from modem/MODB/fallback.
std::string GetPrintableApnValue(const Stringmap& apn_info,
                                 const std::string& key);
}  // namespace shill

#endif  // SHILL_CELLULAR_CELLULAR_HELPERS_H_
