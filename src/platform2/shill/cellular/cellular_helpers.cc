// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/cellular/cellular_helpers.h"

#include <set>
#include <string>
#include <vector>

#include <base/containers/contains.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <chromeos/dbus/shill/dbus-constants.h>

#include "shill/cellular/cellular_consts.h"
#include "shill/logging.h"

namespace shill {

std::string GetStringmapValue(const Stringmap& string_map,
                              const std::string& key,
                              const std::string& default_value) {
  if (!base::Contains(string_map, key))
    return default_value;

  return string_map.at(key);
}

std::string GetPrintableApnValue(const Stringmap& apn_info,
                                 const std::string& key) {
  std::string value = GetStringmapValue(apn_info, key, "");
  bool sensitive_info = (key == kApnProperty || key == kApnUsernameProperty ||
                         key == kApnPasswordProperty);

  // Masking is not needed if LOG_LEVEL >= 3, or the property is not sensitive,
  // or empty, or from the modem/MODB/fallback.
  bool print_unmasked =
      SLOG_IS_ON(Cellular, 3) || !sensitive_info || value.empty() ||
      (base::Contains(apn_info, kApnSourceProperty) &&
       (apn_info.at(kApnSourceProperty) == cellular::kApnSourceMoDb ||
        apn_info.at(kApnSourceProperty) == cellular::kApnSourceModem ||
        apn_info.at(kApnSourceProperty) == cellular::kApnSourceFallback));
  return print_unmasked ? value : "*****";
}

std::string GetPrintableApnStringmap(const Stringmap& apn_info) {
  std::vector<std::string> values;
  for (auto const& [key, _] : apn_info) {
    values.push_back(base::StringPrintf(
        "%s: %s", key.c_str(), GetPrintableApnValue(apn_info, key).c_str()));
  }
  return base::StringPrintf("(%s)", base::JoinString(values, ", ").c_str());
}

}  // namespace shill
