// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_WILCO_EC_FAKE_EC_SERVICE_H_
#define DIAGNOSTICS_CROS_HEALTHD_WILCO_EC_FAKE_EC_SERVICE_H_

#include "diagnostics/cros_healthd/wilco_ec/ec_service.h"

namespace diagnostics {

class FakeEcService : public EcService {
 public:
  FakeEcService();
  FakeEcService(const FakeEcService&) = delete;
  FakeEcService& operator=(const FakeEcService&) = delete;

  ~FakeEcService() override;

  void EmitEcEvent(const EcService::EcEvent& ec_event) const;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_WILCO_EC_FAKE_EC_SERVICE_H_
