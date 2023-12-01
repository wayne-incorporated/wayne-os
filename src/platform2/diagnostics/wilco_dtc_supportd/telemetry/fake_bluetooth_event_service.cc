// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/wilco_dtc_supportd/telemetry/fake_bluetooth_event_service.h"

namespace diagnostics {
namespace wilco {

FakeBluetoothEventService::FakeBluetoothEventService() = default;

FakeBluetoothEventService::~FakeBluetoothEventService() = default;

const std::vector<BluetoothEventService::AdapterData>&
FakeBluetoothEventService::GetLatestEvent() {
  return last_adapters_data_;
}

void FakeBluetoothEventService::EmitBluetoothAdapterDataChanged(
    const std::vector<BluetoothEventService::AdapterData>& adapters) {
  last_adapters_data_ = adapters;

  for (auto& observer : observers_) {
    observer.BluetoothAdapterDataChanged(adapters);
  }
}

}  // namespace wilco
}  // namespace diagnostics
