// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/wilco_dtc_supportd/telemetry/bluetooth_event_service.h"

#include <base/check.h>
#include <base/logging.h>

namespace diagnostics {
namespace wilco {

BluetoothEventService::AdapterData::AdapterData() = default;
BluetoothEventService::AdapterData::~AdapterData() = default;

bool BluetoothEventService::AdapterData::operator==(
    const AdapterData& data) const {
  return name == data.name && address == data.address &&
         powered == data.powered &&
         connected_devices_count == data.connected_devices_count;
}

BluetoothEventService::BluetoothEventService() = default;

BluetoothEventService::~BluetoothEventService() = default;

void BluetoothEventService::AddObserver(Observer* observer) {
  DCHECK(observer);
  observers_.AddObserver(observer);
}

void BluetoothEventService::RemoveObserver(Observer* observer) {
  DCHECK(observer);
  observers_.RemoveObserver(observer);
}

}  // namespace wilco
}  // namespace diagnostics
