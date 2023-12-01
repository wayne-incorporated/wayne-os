// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/wilco_dtc_supportd/telemetry/fake_powerd_event_service.h"

namespace diagnostics {
namespace wilco {

FakePowerdEventService::FakePowerdEventService() = default;
FakePowerdEventService::~FakePowerdEventService() = default;

// PowerdAdapter overrides:
void FakePowerdEventService::AddObserver(Observer* observer) {
  observers_.AddObserver(observer);
}
void FakePowerdEventService::RemoveObserver(Observer* observer) {
  observers_.RemoveObserver(observer);
}

bool FakePowerdEventService::HasObserver(Observer* observer) const {
  return observers_.HasObserver(observer);
}

void FakePowerdEventService::EmitPowerEvent(
    PowerdEventService::Observer::PowerEventType type) const {
  for (auto& observer : observers_) {
    observer.OnPowerdEvent(type);
  }
}

}  // namespace wilco
}  // namespace diagnostics
