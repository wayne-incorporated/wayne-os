// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/wifi/wifi_security.h"
#include "shill/logging.h"

#include <algorithm>
#include <utility>

#include <chromeos/dbus/shill/dbus-constants.h>

namespace shill {

namespace Logging {
static auto kModuleLogScope = ScopeLogger::kWiFi;
}  // namespace Logging

static const std::pair<const char*, WiFiSecurity::Mode> modes_map[] = {
    {kSecurityNone, WiFiSecurity::kNone},
    {kSecurityWep, WiFiSecurity::kWep},
    {kSecurityWpa, WiFiSecurity::kWpa},
    {kSecurityWpaWpa2, WiFiSecurity::kWpaWpa2},
    {kSecurityWpaAll, WiFiSecurity::kWpaAll},
    {kSecurityWpa2, WiFiSecurity::kWpa2},
    {kSecurityWpa2Wpa3, WiFiSecurity::kWpa2Wpa3},
    {kSecurityWpa3, WiFiSecurity::kWpa3},
    {kSecurityWpaEnterprise, WiFiSecurity::kWpaEnterprise},
    {kSecurityWpaWpa2Enterprise, WiFiSecurity::kWpaWpa2Enterprise},
    {kSecurityWpaAllEnterprise, WiFiSecurity::kWpaAllEnterprise},
    {kSecurityWpa2Enterprise, WiFiSecurity::kWpa2Enterprise},
    {kSecurityWpa2Wpa3Enterprise, WiFiSecurity::kWpa2Wpa3Enterprise},
    {kSecurityWpa3Enterprise, WiFiSecurity::kWpa3Enterprise},
};

WiFiSecurity::WiFiSecurity(Mode m)
    : mode_(m), is_valid_(true), is_frozen_(false) {}

WiFiSecurity::WiFiSecurity(const std::string& security) {
  auto it = std::find_if(std::begin(modes_map), std::end(modes_map),
                         [&security](auto& p) { return p.first == security; });
  if (it == std::end(modes_map)) {
    SLOG(2) << __func__ << ": Invalid security name: " << security;
    mode_ = kNone;
    is_valid_ = false;
  } else {
    mode_ = it->second;
    is_valid_ = true;
  }
  is_frozen_ = false;
}

WiFiSecurity& WiFiSecurity::operator=(const WiFiSecurity& security) {
  is_valid_ = security.is_valid_;
  mode_ = security.mode_;
  // "frozen" status is kept on purpose - this is a sticky bit that should be
  // changed only by explicit Freeze() call.

  return *this;
}

std::string WiFiSecurity::SecurityClass(WiFiSecurity::Mode mode) {
  switch (mode) {
    case kNone:
      return kSecurityClassNone;
    case kWep:
      return kSecurityClassWep;
    case kWpa:
    case kWpaWpa2:
    case kWpaAll:
    case kWpa2:
    case kWpa2Wpa3:
    case kWpa3:
      return kSecurityClassPsk;
    case kWpaEnterprise:
    case kWpaWpa2Enterprise:
    case kWpaAllEnterprise:
    case kWpa2Enterprise:
    case kWpa2Wpa3Enterprise:
    case kWpa3Enterprise:
      return kSecurityClass8021x;
  }
}

bool WiFiSecurity::IsValid() const {
  return is_valid_;
}

bool WiFiSecurity::IsWpa() const {
  if (!IsValid())
    return false;

  switch (mode_) {
    case kNone:
    case kWep:
      return false;
    default:
      return true;
  }
}

bool WiFiSecurity::IsPsk() const {
  return IsWpa() && !IsEnterprise();
}

bool WiFiSecurity::IsEnterprise() const {
  if (!IsValid())
    return false;

  switch (mode_) {
    case kNone:
    case kWep:
    case kWpa:
    case kWpaWpa2:
    case kWpaAll:
    case kWpa2:
    case kWpa2Wpa3:
    case kWpa3:
      return false;
    case kWpaEnterprise:
    case kWpaWpa2Enterprise:
    case kWpaAllEnterprise:
    case kWpa2Enterprise:
    case kWpa2Wpa3Enterprise:
    case kWpa3Enterprise:
      return true;
  }
}

bool WiFiSecurity::IsSubsetOf(const WiFiSecurity& sec) const {
  if (IsValid() != sec.IsValid())
    return false;

  switch (sec.mode_) {
    case kNone:
    case kWep:
    case kWpa:
    case kWpa2:
    case kWpa3:
    case kWpaEnterprise:
    case kWpa2Enterprise:
    case kWpa3Enterprise:
      return mode_ == sec.mode_;
    case kWpaWpa2:
      return mode_ == kWpa || mode_ == kWpaWpa2 || mode_ == kWpa2;
    case kWpaAll:
      return mode_ == kWpa || mode_ == kWpaWpa2 || mode_ == kWpaAll ||
             mode_ == kWpa2 || mode_ == kWpa2Wpa3 || mode_ == kWpa3;
    case kWpa2Wpa3:
      return mode_ == kWpa2 || mode_ == kWpa2Wpa3 || mode_ == kWpa3;
    case kWpaWpa2Enterprise:
      return mode_ == kWpaEnterprise || mode_ == kWpaWpa2Enterprise ||
             mode_ == kWpa2Enterprise;
    case kWpaAllEnterprise:
      return mode_ == kWpaEnterprise || mode_ == kWpaWpa2Enterprise ||
             mode_ == kWpaAllEnterprise || mode_ == kWpa2Enterprise ||
             mode_ == kWpa2Wpa3Enterprise || mode_ == kWpa3Enterprise;
    case kWpa2Wpa3Enterprise:
      return mode_ == kWpa2Enterprise || mode_ == kWpa2Wpa3Enterprise ||
             mode_ == kWpa3Enterprise;
  }
}

bool WiFiSecurity::HasCommonMode(const WiFiSecurity& sec) const {
  if (IsValid() != sec.IsValid())
    return false;

  switch (sec.mode_) {
    case kNone:
    case kWep:
      return mode_ == sec.mode_;
    case kWpa:
      return mode_ == kWpa || mode_ == kWpaWpa2 || mode_ == kWpaAll;
    case kWpaWpa2:
      return mode_ == kWpa || mode_ == kWpaWpa2 || mode_ == kWpaAll ||
             mode_ == kWpa2 || mode_ == kWpa2Wpa3;
    case kWpaAll:
      return mode_ == kWpa || mode_ == kWpaWpa2 || mode_ == kWpaAll ||
             mode_ == kWpa2 || mode_ == kWpa2Wpa3 || mode_ == kWpa3;
    case kWpa2:
      return mode_ == kWpaWpa2 || mode_ == kWpaAll || mode_ == kWpa2 ||
             mode_ == kWpa2Wpa3;
    case kWpa2Wpa3:
      return mode_ == kWpaWpa2 || mode_ == kWpaAll || mode_ == kWpa2 ||
             mode_ == kWpa2Wpa3 || mode_ == kWpa3;
    case kWpa3:
      return mode_ == kWpaAll || mode_ == kWpa2Wpa3 || mode_ == kWpa3;
    case kWpaEnterprise:
      return mode_ == kWpaEnterprise || mode_ == kWpaWpa2Enterprise ||
             mode_ == kWpaAllEnterprise;
    case kWpaWpa2Enterprise:
      return mode_ == kWpaEnterprise || mode_ == kWpaWpa2Enterprise ||
             mode_ == kWpaAllEnterprise || mode_ == kWpa2Enterprise ||
             mode_ == kWpa2Wpa3Enterprise;
    case kWpaAllEnterprise:
      return mode_ == kWpaEnterprise || mode_ == kWpaWpa2Enterprise ||
             mode_ == kWpaAllEnterprise || mode_ == kWpa2Enterprise ||
             mode_ == kWpa2Wpa3Enterprise || mode_ == kWpa3Enterprise;
    case kWpa2Enterprise:
      return mode_ == kWpaWpa2Enterprise || mode_ == kWpaAllEnterprise ||
             mode_ == kWpa2Enterprise || mode_ == kWpa2Wpa3Enterprise;
    case kWpa2Wpa3Enterprise:
      return mode_ == kWpaAllEnterprise || mode_ == kWpaWpa2Enterprise ||
             mode_ == kWpa2Enterprise || mode_ == kWpa2Wpa3Enterprise ||
             mode_ == kWpa3Enterprise;
    case kWpa3Enterprise:
      return mode_ == kWpaAllEnterprise || mode_ == kWpa2Wpa3Enterprise ||
             mode_ == kWpa3Enterprise;
  }
}

void WiFiSecurity::Freeze() {
  if (!IsValid())
    return;
  is_frozen_ = true;
}

WiFiSecurity WiFiSecurity::Combine(WiFiSecurity::Mode mode) const {
  if (!IsValid()) {  // If we are not valid then mimic assignment.
    return mode;
  }

  // TODO(b/226138492): For initial phase of FGSec deployment we do not take
  // "frozen" state into account when combining securities.

  // Handle non-matching SecurityClasses
  if (SecurityClass() != SecurityClass(mode)) {
    return WiFiSecurity();
  }

  // Take care of simple cases
  if (mode_ == mode) {
    return *this;
  }

  // Now we should be handling only WPA* subclass so let's check it
  DCHECK(IsWpa() && WiFiSecurity(mode).IsWpa() &&
         IsEnterprise() == WiFiSecurity(mode).IsEnterprise());

  // Special case for initial phase of deployment - these WpaAll modes are catch
  // all modes equivalent to just using SecurityClass.
  // TODO(b/226138492): Remove afterwards.
  if (mode_ == kWpaAll || mode == kWpaAll) {
    return kWpaAll;
  }
  if (mode_ == kWpaAllEnterprise || mode == kWpaAllEnterprise) {
    return kWpaAllEnterprise;
  }

  switch (mode_) {
    case kWpa:
      if (mode == kWpaWpa2 || mode == kWpa2) {
        return kWpaWpa2;
      } else if (mode == kWpa2Wpa3 || mode == kWpa3) {
        return kWpaAll;
      }
      break;
    case kWpaWpa2:
      if (mode == kWpa || mode == kWpa2) {
        return kWpaWpa2;
      } else if (mode == kWpa2Wpa3 || mode == kWpa3) {
        return kWpaAll;
      }
      break;
    case kWpa2:
      if (mode == kWpa || mode == kWpaWpa2) {
        return kWpaWpa2;
      } else if (mode == kWpa2Wpa3 || mode == kWpa3) {
        return kWpa2Wpa3;
      }
      break;
    case kWpa2Wpa3:
      if (mode == kWpa || mode == kWpaWpa2) {
        return kWpaAll;
      } else if (mode == kWpa2 || mode == kWpa3) {
        return kWpa2Wpa3;
      }
      break;
    case kWpa3:
      if (mode == kWpa || mode == kWpaWpa2) {
        return kWpaAll;
      } else if (mode == kWpa2 || mode == kWpa2Wpa3) {
        return kWpa2Wpa3;
      }
      break;
    case kWpaEnterprise:
      if (mode == kWpaWpa2Enterprise || mode == kWpa2Enterprise) {
        return kWpaWpa2Enterprise;
      } else if (mode == kWpa2Wpa3Enterprise || mode == kWpa3Enterprise) {
        return kWpaAllEnterprise;
      }
      break;
    case kWpaWpa2Enterprise:
      if (mode == kWpaEnterprise || mode == kWpa2Enterprise) {
        return kWpaWpa2Enterprise;
      } else if (mode == kWpa2Wpa3Enterprise || mode == kWpa3Enterprise) {
        return kWpaAllEnterprise;
      }
      break;
    case kWpa2Enterprise:
      if (mode == kWpaEnterprise || mode == kWpaWpa2Enterprise) {
        return kWpaWpa2Enterprise;
      } else if (mode == kWpa2Wpa3Enterprise || mode == kWpa3Enterprise) {
        return kWpa2Wpa3Enterprise;
      }
      break;
    case kWpa2Wpa3Enterprise:
      if (mode == kWpaEnterprise || mode == kWpaWpa2Enterprise) {
        return kWpaAllEnterprise;
      } else if (mode == kWpa2Enterprise || mode == kWpa3Enterprise) {
        return kWpa2Wpa3Enterprise;
      }
      break;
    case kWpa3Enterprise:
      if (mode == kWpaEnterprise || mode == kWpaWpa2Enterprise) {
        return kWpaAllEnterprise;
      } else if (mode == kWpa2Enterprise || mode == kWpa2Wpa3Enterprise) {
        return kWpa2Wpa3Enterprise;
      }
      break;
    default:
      // It should be impossible for other modes to get here.
      NOTREACHED() << "Unhandled combination of " << *this << " and " << mode;
  }

  return WiFiSecurity();
}

std::string WiFiSecurity::ToString() const {
  if (!IsValid())
    return std::string();

  auto it = std::find_if(std::begin(modes_map), std::end(modes_map),
                         [this](auto& p) { return p.second == mode_; });
  DCHECK(it != std::end(modes_map));
  return it->first;
}

std::ostream& operator<<(std::ostream& stream, WiFiSecurity::Mode mode) {
  auto it = std::find_if(std::begin(modes_map), std::end(modes_map),
                         [=](auto& p) { return p.second == mode; });
  DCHECK(it != std::end(modes_map));
  return stream << it->first;
}

}  // namespace shill
