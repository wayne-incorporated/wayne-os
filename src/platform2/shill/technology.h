// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_TECHNOLOGY_H_
#define SHILL_TECHNOLOGY_H_

#include <iostream>
#include <string>
#include <vector>

namespace shill {

class Error;

// A class representing a particular network technology type.
enum class Technology {
  kEthernet,
  kEthernetEap,
  kWiFi,
  kWiFiMonitor,
  kCellular,
  kVPN,
  kTunnel,
  kBlocked,
  kLoopback,
  kCDCEthernet,      // Only for internal use in DeviceInfo.
  kVirtioEthernet,   // Only for internal use in DeviceInfo.
  kNoDeviceSymlink,  // Only for internal use in DeviceInfo.
  kPPP,
  kArcBridge,
  // Virtual tap devices used by guest OS and clients getting Internet via
  // Chrome OS host kernel.
  kGuestInterface,
  kUnknown,
};

// Return a Technology instance given the technology name, or
// Technology::kUnknown if the technology name is unknown.
Technology TechnologyFromName(const std::string& name);

std::string TechnologyName(Technology technology);

// Return true if |technology| is a primary connectivity technology, i.e.
// Ethernet, Cellular, WiFi.
bool IsPrimaryConnectivityTechnology(Technology technology);

// Add the Technology name to the ostream.
std::ostream& operator<<(std::ostream& os, const Technology& technology);

// Return a Technology instance for a storage group identifier in |group|
// |group|, which should have the format of <technology name>_<suffix>, or
// Technology::kUnknown if |group| is not prefixed with a known technology
// name.
Technology TechnologyFromStorageGroup(const std::string& group);

// Convert a comma-separated list of technology names (with no whitespace
// around commas) into a vector of Technology instances output in
// |technologies_vector|. Returns true if the |technologies_string| contains a
// valid set of technologies with no duplicate elements, false otherwise.
bool GetTechnologyVectorFromString(const std::string& technologies_string,
                                   std::vector<Technology>* technologies_vector,
                                   Error* error);
}  // namespace shill

#endif  // SHILL_TECHNOLOGY_H_
