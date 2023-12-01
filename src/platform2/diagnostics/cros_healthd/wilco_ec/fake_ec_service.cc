// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/wilco_ec/fake_ec_service.h"

namespace diagnostics {

FakeEcService::FakeEcService() = default;
FakeEcService::~FakeEcService() = default;

void FakeEcService::EmitEcEvent(const EcService::EcEvent& ec_event) const {
  for (auto& observer : observers_) {
    observer.OnEcEvent(ec_event);
  }
}

}  // namespace diagnostics
