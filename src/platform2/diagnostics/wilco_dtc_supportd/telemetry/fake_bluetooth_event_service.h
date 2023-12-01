// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_WILCO_DTC_SUPPORTD_TELEMETRY_FAKE_BLUETOOTH_EVENT_SERVICE_H_
#define DIAGNOSTICS_WILCO_DTC_SUPPORTD_TELEMETRY_FAKE_BLUETOOTH_EVENT_SERVICE_H_

#include <vector>

#include "diagnostics/wilco_dtc_supportd/telemetry/bluetooth_event_service.h"

namespace diagnostics {
namespace wilco {

class FakeBluetoothEventService : public BluetoothEventService {
 public:
  FakeBluetoothEventService();
  FakeBluetoothEventService(const FakeBluetoothEventService&) = delete;
  FakeBluetoothEventService& operator=(const FakeBluetoothEventService&) =
      delete;

  ~FakeBluetoothEventService() override;

  const std::vector<AdapterData>& GetLatestEvent() override;

  void EmitBluetoothAdapterDataChanged(
      const std::vector<BluetoothEventService::AdapterData>& adapters);

 private:
  std::vector<BluetoothEventService::AdapterData> last_adapters_data_;
};

}  // namespace wilco
}  // namespace diagnostics

#endif  // DIAGNOSTICS_WILCO_DTC_SUPPORTD_TELEMETRY_FAKE_BLUETOOTH_EVENT_SERVICE_H_
