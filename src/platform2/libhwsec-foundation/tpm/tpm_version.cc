// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec-foundation/tpm/tpm_version.h"

#include <optional>
#include <string>
#include <type_traits>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <base/synchronization/lock.h>

namespace hwsec_foundation {
namespace tpm {

#if USE_TPM_DYNAMIC

namespace {
constexpr char kTPMVersionMajonPath[] = "/sys/class/tpm/tpm0/tpm_version_major";
}  // namespace

TPMVer RuntimeTPMVer(std::optional<TPMVer> set_value_for_testing) {
  static base::Lock cache_lock;
  static std::optional<TPMVer> cache_version;
  static_assert(std::is_trivially_destructible<std::optional<TPMVer>>::value,
                "std::optional<TPMVer> must be trivially destructible");

  {
    base::AutoLock lock(cache_lock);
    if (set_value_for_testing) {
      cache_version = *set_value_for_testing;
    }
    if (cache_version) {
      return *cache_version;
    }
  }

  base::FilePath tpm_ver_path(kTPMVersionMajonPath);
  std::string ver_str;
  if (!base::ReadFileToString(tpm_ver_path, &ver_str)) {
    base::AutoLock lock(cache_lock);
    cache_version = TPMVer::kNoTPM;
    return TPMVer::kNoTPM;
  }
  int ver = 0;
  if (!base::StringToInt(base::TrimWhitespaceASCII(ver_str, base::TRIM_ALL),
                         &ver)) {
    base::AutoLock lock(cache_lock);
    cache_version = TPMVer::kUnknown;
    return TPMVer::kUnknown;
  }
  switch (ver) {
    case 1: {
      base::AutoLock lock(cache_lock);
      cache_version = TPMVer::kTPM1;
      return TPMVer::kTPM1;
    }
    case 2: {
      base::AutoLock lock(cache_lock);
      cache_version = TPMVer::kTPM2;
      return TPMVer::kTPM2;
    }
  }
  base::AutoLock lock(cache_lock);
  cache_version = TPMVer::kUnknown;
  return TPMVer::kUnknown;
}

#endif

}  // namespace tpm
}  // namespace hwsec_foundation
