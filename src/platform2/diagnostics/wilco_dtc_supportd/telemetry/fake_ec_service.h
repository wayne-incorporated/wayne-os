// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_WILCO_DTC_SUPPORTD_TELEMETRY_FAKE_EC_SERVICE_H_
#define DIAGNOSTICS_WILCO_DTC_SUPPORTD_TELEMETRY_FAKE_EC_SERVICE_H_

#include "diagnostics/wilco_dtc_supportd/telemetry/ec_service.h"

namespace diagnostics {
namespace wilco {

class FakeEcService : public EcService {
 public:
  FakeEcService();
  FakeEcService(const FakeEcService&) = delete;
  FakeEcService& operator=(const FakeEcService&) = delete;

  ~FakeEcService() override;

  void EmitEcEvent(const EcService::EcEvent& ec_event) const;
};

}  // namespace wilco
}  // namespace diagnostics

#endif  // DIAGNOSTICS_WILCO_DTC_SUPPORTD_TELEMETRY_FAKE_EC_SERVICE_H_
