// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/technology.h"

#include <set>
#include <string>
#include <vector>

#include <base/check.h>
#include <base/containers/contains.h>
#include <base/strings/string_split.h>
#include <chromeos/dbus/service_constants.h>

#include "shill/error.h"
#include "shill/logging.h"

namespace shill {

bool GetTechnologyVectorFromString(const std::string& technologies_string,
                                   std::vector<Technology>* technologies_vector,
                                   Error* error) {
  CHECK(technologies_vector);
  CHECK(error);

  technologies_vector->clear();

  // Check if |technologies_string| is empty as some versions of
  // base::SplitString return a vector with one empty string when given an
  // empty string.
  if (technologies_string.empty()) {
    return true;
  }

  std::set<Technology> seen;
  const auto technology_parts = base::SplitString(
      technologies_string, ",", base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL);
  for (const auto& name : technology_parts) {
    auto technology = TechnologyFromName(name);

    if (technology == Technology::kUnknown) {
      Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidArguments,
                            name + " is an unknown technology name");
      return false;
    }

    if (base::Contains(seen, technology)) {
      Error::PopulateAndLog(FROM_HERE, error, Error::kInvalidArguments,
                            name + " is duplicated in the list");
      return false;
    }
    seen.insert(technology);
    technologies_vector->push_back(technology);
  }

  return true;
}

Technology TechnologyFromName(const std::string& name) {
  if (name == kTypeEthernet) {
    return Technology::kEthernet;
  } else if (name == kTypeEthernetEap) {
    return Technology::kEthernetEap;
  } else if (name == kTypeWifi) {
    return Technology::kWiFi;
  } else if (name == kTypeCellular) {
    return Technology::kCellular;
  } else if (name == kTypeVPN) {
    return Technology::kVPN;
  } else if (name == kTypeTunnel) {
    return Technology::kTunnel;
  } else if (name == kTypeLoopback) {
    return Technology::kLoopback;
  } else if (name == kTypePPP) {
    return Technology::kPPP;
  } else if (name == kTypeGuestInterface) {
    return Technology::kGuestInterface;
  } else {
    return Technology::kUnknown;
  }
}

Technology TechnologyFromStorageGroup(const std::string& group) {
  const auto group_parts = base::SplitString(group, "_", base::TRIM_WHITESPACE,
                                             base::SPLIT_WANT_ALL);
  if (group_parts.empty()) {
    return Technology::kUnknown;
  }
  return TechnologyFromName(group_parts[0]);
}

std::string TechnologyName(Technology technology) {
  switch (technology) {
    case Technology::kEthernet:
      return kTypeEthernet;
    case Technology::kEthernetEap:
      return kTypeEthernetEap;
    case Technology::kWiFi:
      return kTypeWifi;
    case Technology::kCellular:
      return kTypeCellular;
    case Technology::kVPN:
      return kTypeVPN;
    case Technology::kTunnel:
      return kTypeTunnel;
    case Technology::kLoopback:
      return kTypeLoopback;
    case Technology::kPPP:
      return kTypePPP;
    case Technology::kGuestInterface:
      return kTypeGuestInterface;
    case Technology::kUnknown:
    default:
      return kTypeUnknown;
  }
}

bool IsPrimaryConnectivityTechnology(Technology technology) {
  return technology == Technology::kCellular ||
         technology == Technology::kEthernet || technology == Technology::kWiFi;
}

std::ostream& operator<<(std::ostream& os, const Technology& technology) {
  os << TechnologyName(technology);
  return os;
}

}  // namespace shill
