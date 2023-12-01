// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/geolocation_info.h"

#include <inttypes.h>

#include <base/check.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/stringprintf.h>
#include <chromeos/dbus/service_constants.h>

namespace {

// This key is special, because we will look for it and transform it into
// an up-to-date age property when D-Bus calls are made asking for geolocation
// objects. It should not be exported outside of shill.
constexpr char kLastSeenKey[] = "lastSeen";

base::TimeDelta LastSeenToAge(int64_t last_seen) {
  return base::Time::Now() -
         base::Time::FromDeltaSinceWindowsEpoch(base::Seconds(last_seen));
}

}  // namespace

namespace shill {

void AddLastSeenTime(GeolocationInfo* info, const base::Time& time) {
  DCHECK(info);
  (*info)[kLastSeenKey] = base::StringPrintf(
      "%" PRId64, time.ToDeltaSinceWindowsEpoch().InSeconds());
}

GeolocationInfo PrepareGeolocationInfoForExport(const GeolocationInfo& info) {
  const auto& it = info.find(kLastSeenKey);
  if (it == info.end())
    return info;

  int64_t last_seen;
  if (!base::StringToInt64(it->second, &last_seen)) {
    DLOG(ERROR) << "Invalid last seen time: " << it->second;
    return GeolocationInfo();
  }

  // Calculate the age based on the current time. We have to reconstitute
  // last_seen into base::Time so we can get a TimeDelta.
  base::TimeDelta age = LastSeenToAge(last_seen);

  GeolocationInfo new_info(info);
  new_info.erase(kLastSeenKey);
  new_info[kGeoAgeProperty] = base::StringPrintf("%" PRId64, age.InSeconds());
  return new_info;
}

bool IsGeolocationInfoOlderThan(const GeolocationInfo& geoinfo,
                                base::TimeDelta expiration) {
  int64_t last_seen;
  auto it = geoinfo.find(kLastSeenKey);
  if (it == geoinfo.end() || !base::StringToInt64(it->second, &last_seen)) {
    return true;
  }
  return LastSeenToAge(last_seen) > expiration;
}

void GeolocationInfoAgeRange(const std::vector<GeolocationInfo>& geoinfos,
                             base::Time* oldest_timestamp,
                             base::Time* newest_timestamp) {
  *oldest_timestamp = base::Time::Max();
  *newest_timestamp = base::Time::Min();
  for (const auto& geoinfo : geoinfos) {
    int64_t last_seen;
    auto it = geoinfo.find(kLastSeenKey);
    if (it == geoinfo.end() || !base::StringToInt64(it->second, &last_seen)) {
      continue;
    }
    base::Time last_timestamp =
        base::Time::FromDeltaSinceWindowsEpoch(base::Seconds(last_seen));

    *oldest_timestamp =
        *oldest_timestamp < last_timestamp ? *oldest_timestamp : last_timestamp;
    *newest_timestamp =
        *newest_timestamp > last_timestamp ? *newest_timestamp : last_timestamp;
  }
}

std::string GeolocationInfoToString(const GeolocationInfo& geoinfo) {
  std::string geoinfo_str = "WiFi endpoint OUI:";
  auto it = geoinfo.find(kGeoMacAddressProperty);
  if (it != geoinfo.end()) {
    geoinfo_str += std::string(" ") + it->second.substr(0, 8);
  }
  for (auto key : {kGeoChannelProperty, kGeoAgeProperty, kLastSeenKey,
                   kGeoSignalStrengthProperty}) {
    it = geoinfo.find(key);
    if (it != geoinfo.end()) {
      geoinfo_str += std::string(" ") + key + ": " + it->second;
    }
  }
  return geoinfo_str;
}

}  // namespace shill
