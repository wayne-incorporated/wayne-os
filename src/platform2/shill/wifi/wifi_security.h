// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_WIFI_WIFI_SECURITY_H_
#define SHILL_WIFI_WIFI_SECURITY_H_

#include <string>

namespace shill {

// This utility class captures the security mode of given
// WiFiEndpoint/WiFiService.  It is introduced in order to have a typefull
// difference between "security_class" and "security" property.
class WiFiSecurity {
 public:
  enum Mode {
    kNone,
    kWep,
    kWpa,
    kWpaWpa2,
    kWpaAll,  // TODO(b/226138492): Remove after initial phase (all modes
              // Wpa1/2/3)
    kWpa2,
    kWpa2Wpa3,
    kWpa3,
    kWpaEnterprise,
    kWpaWpa2Enterprise,
    kWpaAllEnterprise,  // TODO(b/226138492): Remove after initial phase (all
                        // modes Wpa1/2/3)
    kWpa2Enterprise,
    kWpa2Wpa3Enterprise,
    kWpa3Enterprise,
  };

  WiFiSecurity() = default;
  WiFiSecurity(Mode m);  // NOLINT(runtime/explicit)
  explicit WiFiSecurity(const std::string& security);

  WiFiSecurity(const WiFiSecurity&) = default;
  WiFiSecurity& operator=(const WiFiSecurity&);

  static std::string SecurityClass(Mode m);
  std::string SecurityClass() const { return SecurityClass(mode_); }

  bool IsValid() const;
  bool IsWpa() const;
  bool IsPsk() const;
  bool IsEnterprise() const;
  bool IsSubsetOf(const WiFiSecurity& sec) const;
  bool HasCommonMode(const WiFiSecurity& sec) const;

  // Security (of a Service) can be in two states: "flexible" and "frozen".
  // When we are discovering endpoints for unknown/new service then we keep
  // Security flexible, that is we allow upgrading/combining of Security to
  // include more endpoints).  However when we get Security from Chrome/User or
  // read it from storage then we keep it fixed/frozen (we also freeze Security
  // at the moment of connection).
  // Note: "frozen" security should allow new endpoints only if their security
  // is a subset (possibly improper) of the current value, however for the
  // initial deployment of FGSec feature we will allow that and will only track
  // security downgrades via metrics.
  bool IsFrozen() const { return is_frozen_; }
  void Freeze();

  // This function implements logic of matching/combining different endpoints
  // (with their own Security setting) into one Service with more
  // general/upgraded Security property.  For more information please see:
  // go/cros-wifi-finegrained-security
  // There are three cases to consider:
  // 1. When we can simply combine the two into one Security.  For example Wpa
  //    + Wpa2 => WpaWpa2.  In this case result is returned.
  // 2. When the endpoint is from the same SecurityClass but cannot be combined
  //    into single Security then best target Security is returned.  For
  //    example: WpaWpa2 + Wpa3 => Wpa2Wpa3 + Wpa (meaning that if we have
  //    Service with WpaWpa2 security and want to add Wpa3 endpoint then it
  //    would be best to upgrade Service to Wpa2Wpa3 (returned value) and create
  //    separate Service with Security set to Wpa.  In that case just find the
  //    endpoints with security_mode() that is not a subset of current value.
  // 3. When the two Securities cannot be combined then "invalid" security is
  //    returned.
  // Note: During initial deployment phase we will accept all WPA modes from PSK
  // class, so the 2nd point above describes future behaviour.
  WiFiSecurity Combine(WiFiSecurity::Mode mode) const;

  std::string ToString() const;

  Mode mode() const { return mode_; }

 private:
  friend bool operator==(const WiFiSecurity& lhs, const WiFiSecurity& rhs);
  Mode mode_ = kNone;
  bool is_valid_ = false;
  bool is_frozen_ = false;
};

inline bool operator==(const WiFiSecurity& lhs, const WiFiSecurity& rhs) {
  // Ignore "frozen" status for comparison (it is a bit like 'const')
  return lhs.is_valid_ == rhs.is_valid_ && lhs.mode_ == rhs.mode_;
}

inline bool operator!=(const WiFiSecurity& lhs, const WiFiSecurity& rhs) {
  return !(lhs == rhs);
}

std::ostream& operator<<(std::ostream& stream, WiFiSecurity::Mode mode);

inline std::ostream& operator<<(std::ostream& stream,
                                const WiFiSecurity& security) {
  return stream << security.ToString();
}

}  // namespace shill

#endif  // SHILL_WIFI_WIFI_SECURITY_H_
