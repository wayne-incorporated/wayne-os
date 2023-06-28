// Copyright 2021 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This file contains utility to code for converting Chrome feature flags
// encoded as command line switch values back to feature flag names (the format
// chrome://flags uses for bookkeeping).
//
// In the past, chrome://flags would translate flag configuration set by the
// user to command line switches, pass these to session_manager via device
// settings, and session_manager would append the raw command line switches on
// chrome startup. This proved problematic due to the inability to validate
// whether command line switches referred to valid feature flags. Hence,
// session_manager and Chrome have been updated to store feature flags in the
// same format used by chrome://flags on other platforms and pass them around in
// that format.
//
// However, Chrome OS device settings files in the field may still contain
// feature flags expressed as raw command line switches. These can only be
// updated by the device owner (device settings are protected by a signature),
// so device settings can't be migrated on the fly. In order to keep existing
// persisted device settings working, the code here maps the command line switch
// format back to feature flags.
//
// TODO(crbug/1104193): Usage of the mapping scheme for converting between the
// representation is tracked by the Login.SwitchToFeatureFlagMappingStatus UMA
// histogram. Once the prevalence of the old format has become negligible in
// the field, this entire mechanism can be dropped.

#include "login_manager/feature_flags_util.h"

#include <algorithm>
#include <string>
#include <vector>

#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>

#include "login_manager/feature_flags_tables.h"

namespace login_manager {
namespace {

constexpr char kEnableFeaturesSwitch[] = "enable-features";
constexpr char kDisableFeaturesSwitch[] = "disable-features";

bool ParseSwitch(const std::string& switch_string,
                 std::string* name,
                 std::string* value) {
  static const std::string kSwitchPrefixes[] = {"--", "-"};
  size_t name_pos = std::string::npos;
  for (const auto& prefix : kSwitchPrefixes) {
    if (base::StartsWith(switch_string, prefix,
                         base::CompareCase::INSENSITIVE_ASCII)) {
      name_pos = prefix.length();
      break;
    }
  }

  if (name_pos == std::string::npos) {
    return false;
  }

  auto sep_pos = switch_string.find('=', name_pos);
  if (sep_pos == std::string::npos) {
    *name = switch_string.substr(name_pos);
    value->clear();
  } else {
    *name = switch_string.substr(name_pos, sep_pos - name_pos);
    *value = switch_string.substr(sep_pos + 1);
  }

  return true;
}

bool MapToFeatureFlag(const FeatureMappingEntry* table_begin,
                      const FeatureMappingEntry* table_end,
                      const std::string& name,
                      const std::string& value,
                      std::vector<std::string>* feature_flags) {
  auto entry = std::lower_bound(
      table_begin, table_end,
      FeatureMappingEntry{name.c_str(), value.c_str(), nullptr, 0});
  if (entry == table_end || entry->name != name || entry->value != value) {
    return false;
  }

  // Construct the feature flag name. For simple toggle items that enable or
  // disable something, this is just the "internal name" of the feature flag.
  // For multi-choice items, the index of the choice is appended after an '@'
  // separator. The two cases are distinguished by whether the variation value
  // is non-zero. This is possible because multi-choice items always have the
  // default choice (which doesn't imply any switches or features) at choice 0,
  // so their variation value will always be non-zero.
  std::string feature_flag = entry->feature_flag_name;
  if (entry->feature_flag_variation > 0) {
    feature_flag += base::StringPrintf("@%u", entry->feature_flag_variation);
  }
  feature_flags->push_back(feature_flag);
  return true;
}

bool MapToggleToFeatureFlags(const std::string& feature_toggles_list,
                             bool enable,
                             std::vector<std::string>* feature_flags) {
  bool mapping_ok = true;
  auto feature_toggles =
      base::SplitString(feature_toggles_list, ",", base::TRIM_WHITESPACE,
                        base::SPLIT_WANT_NONEMPTY);
  for (const auto& feature : feature_toggles) {
    mapping_ok &=
        MapToFeatureFlag(std::begin(kFeaturesMap), std::end(kFeaturesMap),
                         feature, enable ? "1" : "0", feature_flags);
  }

  return mapping_ok;
}

}  // namespace

bool MapSwitchToFeatureFlags(const std::string& switch_string,
                             std::vector<std::string>* feature_flags) {
  std::string name, value;
  if (!ParseSwitch(switch_string, &name, &value)) {
    return false;
  }

  if (name == kEnableFeaturesSwitch) {
    return MapToggleToFeatureFlags(value, true, feature_flags);
  } else if (name == kDisableFeaturesSwitch) {
    return MapToggleToFeatureFlags(value, false, feature_flags);
  } else {
    return MapToFeatureFlag(std::begin(kSwitchesMap), std::end(kSwitchesMap),
                            name, value, feature_flags);
  }
}

}  // namespace login_manager
