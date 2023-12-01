// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/wilco_dtc_supportd/core_delegate_impl.h"

#include <utility>

#include <base/check.h>
#include <base/logging.h>

#include "debugd/dbus-proxies.h"
#include "diagnostics/wilco_dtc_supportd/probe_service_impl.h"
#include "diagnostics/wilco_dtc_supportd/telemetry/bluetooth_event_service_impl.h"
#include "diagnostics/wilco_dtc_supportd/telemetry/ec_service.h"
#include "diagnostics/wilco_dtc_supportd/telemetry/powerd_event_service_impl.h"
#include "diagnostics/wilco_dtc_supportd/utils/system/bluetooth_client_impl.h"
#include "diagnostics/wilco_dtc_supportd/utils/system/debugd_adapter_impl.h"
#include "diagnostics/wilco_dtc_supportd/utils/system/powerd_adapter_impl.h"

namespace diagnostics {
namespace wilco {

CoreDelegateImpl::CoreDelegateImpl() = default;

CoreDelegateImpl::~CoreDelegateImpl() = default;

std::unique_ptr<BluetoothClient> CoreDelegateImpl::CreateBluetoothClient(
    const scoped_refptr<dbus::Bus>& bus) {
  DCHECK(bus);
  return std::make_unique<BluetoothClientImpl>(bus);
}

std::unique_ptr<DebugdAdapter> CoreDelegateImpl::CreateDebugdAdapter(
    const scoped_refptr<dbus::Bus>& bus) {
  DCHECK(bus);
  return std::make_unique<DebugdAdapterImpl>(
      std::make_unique<org::chromium::debugdProxy>(bus));
}

std::unique_ptr<PowerdAdapter> CoreDelegateImpl::CreatePowerdAdapter(
    const scoped_refptr<dbus::Bus>& bus) {
  DCHECK(bus);
  return std::make_unique<PowerdAdapterImpl>(bus);
}

std::unique_ptr<BluetoothEventService>
CoreDelegateImpl::CreateBluetoothEventService(
    BluetoothClient* bluetooth_client) {
  DCHECK(bluetooth_client);
  return std::make_unique<BluetoothEventServiceImpl>(bluetooth_client);
}

std::unique_ptr<EcService> CoreDelegateImpl::CreateEcService() {
  return std::make_unique<EcService>();
}

std::unique_ptr<PowerdEventService> CoreDelegateImpl::CreatePowerdEventService(
    PowerdAdapter* powerd_adapter) {
  DCHECK(powerd_adapter);
  return std::make_unique<PowerdEventServiceImpl>(powerd_adapter);
}

std::unique_ptr<ProbeService> CoreDelegateImpl::CreateProbeService(
    ProbeService::Delegate* delegate) {
  DCHECK(delegate);
  return std::make_unique<ProbeServiceImpl>(delegate);
}

}  // namespace wilco
}  // namespace diagnostics
