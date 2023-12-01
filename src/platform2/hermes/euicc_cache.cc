// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "hermes/euicc_cache.h"

#include <string>

#include <base/logging.h>

namespace {

constexpr std::string_view kCachePath = "/var/cache/hermes/";

base::FilePath GetCachePath(int physical_slot) {
  return base::FilePath(std::string(kCachePath))
      .Append(std::to_string(physical_slot));
}

}  // namespace

namespace hermes {

bool EuiccCache::CacheExists(int physical_slot) {
  return base::PathExists(GetCachePath(physical_slot));
}

bool EuiccCache::Read(int physical_slot, CachedEuicc* cached_euicc) {
  base::File journal_file(GetCachePath(physical_slot),
                          base::File::FLAG_OPEN | base::File::FLAG_READ);

  if (!journal_file.IsValid()) {
    LOG(ERROR) << "Could not open cache file";
    return false;
  }
  return brillo::ReadTextProtobuf(journal_file.GetPlatformFile(), cached_euicc);
}

bool EuiccCache::Write(int physical_slot, CachedEuicc euicc) {
  base::File journal_file(
      GetCachePath(physical_slot),
      base::File::FLAG_CREATE_ALWAYS | base::File::FLAG_WRITE);
  if (!journal_file.IsValid()) {
    LOG(ERROR) << "Could not open journal file";
    return false;
  }
  journal_file.Seek(base::File::FROM_BEGIN, 0);
  return brillo::WriteTextProtobuf(journal_file.GetPlatformFile(), euicc);
}

}  // namespace hermes
