// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "authpolicy/auth_data_cache.h"

#include <optional>
#include <utility>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include "base/time/clock.h"
#include "base/time/default_clock.h"

#include "authpolicy/log_colors.h"

namespace authpolicy {
namespace {

constexpr char kLogHeader[] = "Auth Data Cache: ";

#define LOG_START(severity) \
  LOG_IF(severity, flags_->log_caches()) << kColorCaches << kLogHeader
#define PLOG_START(severity) \
  PLOG_IF(severity, flags_->log_caches()) << kColorCaches << kLogHeader
#define LOG_END kColorReset

// Size limit when loading the cached data file (256 kb).
constexpr size_t kCacheSizeLimit = 256 * 1024;

}  // namespace

AuthDataCache::AuthDataCache(const protos::DebugFlags* flags)
    : flags_(flags), clock_(std::make_unique<base::DefaultClock>()) {}

AuthDataCache::~AuthDataCache() = default;

bool AuthDataCache::Load(const base::FilePath& path) {
  data_.Clear();
  if (!enabled_)
    return true;

  if (!base::PathExists(path)) {
    LOG_START(ERROR) << "File '" << path.value() << "' does not exist"
                     << LOG_END;
    return false;
  }

  std::string data_blob;
  if (!base::ReadFileToStringWithMaxSize(path, &data_blob, kCacheSizeLimit)) {
    PLOG_START(ERROR) << "Failed to read '" << path.value() << "'" << LOG_END;
    return false;
  }

  if (!data_.ParseFromString(data_blob)) {
    LOG_START(ERROR) << "Failed to parse data from string" << LOG_END;
    return false;
  }

  LOG_START(INFO) << "Read '" << path.value() << "'" << LOG_END;
  return true;
}

bool AuthDataCache::Save(const base::FilePath& path) {
  if (!enabled_)
    return true;

  std::string data_blob;
  if (!data_.SerializeToString(&data_blob)) {
    LOG_START(ERROR) << "Failed to serialize data to string" << LOG_END;
    return false;
  }

  const int data_size = static_cast<int>(data_blob.size());
  if (base::WriteFile(path, data_blob.data(), data_size) != data_size) {
    LOG_START(ERROR) << "Failed to write '" << path.value() << "'" << LOG_END;
    return false;
  }

  // Lock access to authpolicyd rw.
  int mode =
      base::FILE_PERMISSION_READ_BY_USER | base::FILE_PERMISSION_WRITE_BY_USER;
  if (!base::SetPosixFilePermissions(path, mode)) {
    LOG_START(ERROR) << "Failed to set permissions on '" << path.value() << "'"
                     << LOG_END;
    return false;
  }

  LOG_START(INFO) << "Wrote '" << path.value() << "'" << LOG_END;
  return true;
}

void AuthDataCache::Clear() {
  data_.Clear();
}

std::optional<std::string> AuthDataCache::GetWorkgroup(
    const std::string& realm) const {
  const protos::CachedRealmData* realm_data = GetRealmDataForRead(realm);
  if (!realm_data || !realm_data->has_workgroup()) {
    LOG_START(INFO) << "No workgroup cached" << LOG_END;
    return std::nullopt;
  }
  LOG_START(INFO) << "Using cached workgroup" << LOG_END;
  return realm_data->workgroup();
}

std::optional<std::string> AuthDataCache::GetKdcIp(
    const std::string& realm) const {
  const protos::CachedRealmData* realm_data = GetRealmDataForRead(realm);
  if (!realm_data || !realm_data->has_kdc_ip()) {
    LOG_START(INFO) << "No KDC IP cached" << LOG_END;
    return std::nullopt;
  }
  LOG_START(INFO) << "Using cached KDC IP" << LOG_END;
  return realm_data->kdc_ip();
}

std::optional<std::string> AuthDataCache::GetDcName(
    const std::string& realm) const {
  const protos::CachedRealmData* realm_data = GetRealmDataForRead(realm);
  if (!realm_data || !realm_data->has_dc_name()) {
    LOG_START(INFO) << "No DC name cached" << LOG_END;
    return std::nullopt;
  }
  LOG_START(INFO) << "Using cached DC name" << LOG_END;
  return realm_data->dc_name();
}

std::optional<bool> AuthDataCache::GetIsAffiliated(
    const std::string& realm) const {
  const protos::CachedRealmData* realm_data = GetRealmDataForRead(realm);
  if (!realm_data || !realm_data->has_is_affiliated()) {
    LOG_START(INFO) << "No affiliation flag cached" << LOG_END;
    return std::nullopt;
  }
  LOG_START(INFO) << "Using cached affiliation flag" << LOG_END;
  return realm_data->is_affiliated();
}

void AuthDataCache::SetWorkgroup(const std::string& realm,
                                 const std::string& workgroup) {
  protos::CachedRealmData* realm_data = GetRealmDataForWrite(realm);
  if (realm_data) {
    LOG_START(INFO) << "Setting workgroup" << LOG_END;
    realm_data->set_workgroup(workgroup);
  }
}

void AuthDataCache::SetKdcIp(const std::string& realm,
                             const std::string& kdc_ip) {
  protos::CachedRealmData* realm_data = GetRealmDataForWrite(realm);
  if (realm_data) {
    LOG_START(INFO) << "Setting KDC IP" << LOG_END;
    realm_data->set_kdc_ip(kdc_ip);
  }
}

void AuthDataCache::SetDcName(const std::string& realm,
                              const std::string& dc_name) {
  protos::CachedRealmData* realm_data = GetRealmDataForWrite(realm);
  if (realm_data) {
    LOG_START(INFO) << "Setting DC name" << LOG_END;
    realm_data->set_dc_name(dc_name);
  }
}

void AuthDataCache::SetIsAffiliated(const std::string& realm,
                                    bool is_affiliated) {
  protos::CachedRealmData* realm_data = GetRealmDataForWrite(realm);
  if (realm_data) {
    realm_data->set_is_affiliated(is_affiliated);
    LOG_START(INFO) << "Setting affiliation flag" << LOG_END;
  }
}

void AuthDataCache::RemoveEntriesOlderThan(base::TimeDelta max_age) {
  base::Time now = clock_->Now();
  auto realm_data_map = data_.mutable_realm_data();
  for (auto it = realm_data_map->begin(); it != realm_data_map->end();
       /* empty */) {
    // Note: If the clock goes backwards for some reason, clear cache as well
    // just in case the clock was reset.
    protos::CachedRealmData& realm_data = it->second;
    base::TimeDelta age =
        now - base::Time::FromInternalValue(realm_data.cache_time());
    if (age < base::TimeDelta() || age >= max_age) {
      LOG_START(INFO) << "Removing entry from cache (age=" << age << ")"
                      << LOG_END;
      it = realm_data_map->erase(it);
    } else {
      ++it;
    }
  }
}

void AuthDataCache::SetClockForTesting(std::unique_ptr<base::Clock> clock) {
  clock_ = std::move(clock);
}

const protos::CachedRealmData* AuthDataCache::GetRealmDataForRead(
    const std::string& realm) const {
  if (!enabled_)
    return nullptr;
  auto it = data_.realm_data().find(realm);
  if (it == data_.realm_data().end())
    return nullptr;
  return &it->second;
}

protos::CachedRealmData* AuthDataCache::GetRealmDataForWrite(
    const std::string& realm) {
  if (!enabled_)
    return nullptr;
  protos::CachedRealmData* realm_data = &(*data_.mutable_realm_data())[realm];

  // Set cache time only on creation, but not on updates.
  if (!realm_data->has_cache_time())
    realm_data->set_cache_time(clock_->Now().ToInternalValue());

  return realm_data;
}

}  // namespace authpolicy
