// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_WILCO_DTC_SUPPORTD_TELEMETRY_SYSTEM_INFO_SERVICE_IMPL_H_
#define DIAGNOSTICS_WILCO_DTC_SUPPORTD_TELEMETRY_SYSTEM_INFO_SERVICE_IMPL_H_

#include <string>

#include "diagnostics/wilco_dtc_supportd/telemetry/system_info_service.h"

namespace diagnostics {
namespace wilco {

class SystemInfoServiceImpl : public SystemInfoService {
 public:
  SystemInfoServiceImpl();
  ~SystemInfoServiceImpl() override;

  SystemInfoServiceImpl(const SystemInfoServiceImpl&) = delete;
  SystemInfoServiceImpl& operator=(const SystemInfoServiceImpl&) = delete;

  // SystemInfoService overrides:
  bool GetOsVersion(std::string* version_out) override;
  bool GetOsMilestone(int* milestone_out) override;
};

}  // namespace wilco
}  // namespace diagnostics

#endif  // DIAGNOSTICS_WILCO_DTC_SUPPORTD_TELEMETRY_SYSTEM_INFO_SERVICE_IMPL_H_
