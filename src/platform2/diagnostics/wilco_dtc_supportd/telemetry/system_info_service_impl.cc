// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/wilco_dtc_supportd/telemetry/system_info_service_impl.h"

#include <base/check.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/system/sys_info.h>

namespace diagnostics {
namespace wilco {

SystemInfoServiceImpl::SystemInfoServiceImpl() = default;

SystemInfoServiceImpl::~SystemInfoServiceImpl() = default;

bool SystemInfoServiceImpl::GetOsVersion(std::string* version_out) {
  DCHECK(version_out);

  if (!base::SysInfo::GetLsbReleaseValue("CHROMEOS_RELEASE_VERSION",
                                         version_out)) {
    LOG(ERROR) << "Could not read the release version";
    return false;
  }

  return true;
}

bool SystemInfoServiceImpl::GetOsMilestone(int* milestone_out) {
  DCHECK(milestone_out);

  std::string milestone_str;

  if (!base::SysInfo::GetLsbReleaseValue("CHROMEOS_RELEASE_CHROME_MILESTONE",
                                         &milestone_str)) {
    LOG(ERROR) << "Could not read the release milestone";
    return false;
  }

  if (!base::StringToInt(milestone_str, milestone_out)) {
    LOG(ERROR) << "Failed to convert the milestone '" << milestone_str
               << "' to integer.";
    return false;
  }

  return true;
}

}  // namespace wilco
}  // namespace diagnostics
