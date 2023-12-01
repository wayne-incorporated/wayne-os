// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <rmad/utils/sys_utils_impl.h>

#include <string>

#include <base/files/file_enumerator.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/strings/string_util.h>

namespace {

constexpr char kPowerSupplyDirPath[] = "class/power_supply";
constexpr char kType[] = "type";
constexpr char kOnline[] = "online";

}  // namespace

namespace rmad {

SysUtilsImpl::SysUtilsImpl() : SysUtils(), sys_path_("/sys") {}

SysUtilsImpl::SysUtilsImpl(const base::FilePath& sys_path)
    : SysUtils(), sys_path_(sys_path) {}

bool SysUtilsImpl::IsPowerSourcePresent() const {
  // Check if there's an online, non-battery power supply.
  // The logic is copied from platform/factory/sh/cutoff/cutoff.sh.
  base::FilePath power_supply_dir_path =
      sys_path_.AppendASCII(kPowerSupplyDirPath);
  base::FileEnumerator enumerator(power_supply_dir_path, false,
                                  base::FileEnumerator::DIRECTORIES);
  for (base::FilePath p = enumerator.Next(); !p.empty();
       p = enumerator.Next()) {
    std::string type, online;
    if (base::ReadFileToString(p.AppendASCII(kType), &type) &&
        base::TrimWhitespaceASCII(type, base::TRIM_TRAILING) != "Battery" &&
        base::ReadFileToString(p.AppendASCII(kOnline), &online) &&
        base::TrimWhitespaceASCII(online, base::TRIM_TRAILING) == "1") {
      return true;
    }
  }
  return false;
}

}  // namespace rmad
