// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/system/mock_context.h"

#include <memory>

#include <attestation/proto_bindings/interface.pb.h>
#include <attestation-client-test/attestation/dbus-proxy-mocks.h>
#include <cras/dbus-proxy-mocks.h>
#include <debugd/dbus-proxy-mocks.h>
#include <fwupd/dbus-proxy-mocks.h>
#include <power_manager/dbus-proxy-mocks.h>
#include <tpm_manager/proto_bindings/tpm_manager.pb.h>
#include <tpm_manager-client-test/tpm_manager/dbus-proxy-mocks.h>
#include <gmock/gmock.h>

#include "diagnostics/cros_healthd/system/fake_mojo_service.h"
#include "diagnostics/cros_healthd/utils/resource_queue.h"

namespace diagnostics {

MockContext::MockContext() {
  attestation_proxy_ = std::make_unique<
      testing::StrictMock<org::chromium::AttestationProxyMock>>();
  cros_config_ = std::make_unique<brillo::FakeCrosConfig>();
  cras_proxy_ = std::make_unique<
      testing::StrictMock<org::chromium::cras::ControlProxyMock>>();
  debugd_proxy_ =
      std::make_unique<testing::StrictMock<org::chromium::debugdProxyMock>>();
  fwupd_proxy_ =
      std::make_unique<testing::StrictMock<org::freedesktop::fwupdProxyMock>>();
  mojo_service_ = std::make_unique<FakeMojoService>();
  network_health_adapter_ = std::make_unique<FakeNetworkHealthAdapter>();
  network_diagnostics_adapter_ =
      std::make_unique<MockNetworkDiagnosticsAdapter>();
  power_manager_proxy_ = std::make_unique<
      testing::StrictMock<org::chromium::PowerManagerProxyMock>>();
  powerd_adapter_ = std::make_unique<FakePowerdAdapter>();
  system_config_ = std::make_unique<FakeSystemConfig>();
  system_utils_ = std::make_unique<FakeSystemUtilities>();
  bluetooth_event_hub_ = std::make_unique<FakeBluetoothEventHub>();
  bluetooth_info_manager_ = std::make_unique<MockBluetoothInfoManager>();
  tick_clock_ = std::make_unique<base::SimpleTestTickClock>();
  tpm_manager_proxy_ = std::make_unique<
      testing::StrictMock<org::chromium::TpmManagerProxyMock>>();
  udev_ = std::make_unique<brillo::MockUdev>();
  udev_monitor_ = std::make_unique<brillo::MockUdevMonitor>();

  CHECK(temp_dir_.CreateUniqueTempDir());
  root_dir_ = temp_dir_.GetPath();

  memory_cpu_resource_queue_ = std::make_unique<ResourceQueue>();
}

std::unique_ptr<PciUtil> MockContext::CreatePciUtil() {
  return std::unique_ptr<PciUtil>(new FakePciUtil(fake_pci_util_));
}

org::chromium::AttestationProxyMock* MockContext::mock_attestation_proxy()
    const {
  return static_cast<testing::StrictMock<org::chromium::AttestationProxyMock>*>(
      attestation_proxy_.get());
}

ash::cros_healthd::mojom::Executor* MockContext::executor() {
  return &mock_executor_;
}

brillo::FakeCrosConfig* MockContext::fake_cros_config() const {
  return static_cast<brillo::FakeCrosConfig*>(cros_config_.get());
}

org::chromium::debugdProxyMock* MockContext::mock_debugd_proxy() const {
  return static_cast<testing::StrictMock<org::chromium::debugdProxyMock>*>(
      debugd_proxy_.get());
}

org::chromium::PowerManagerProxyMock* MockContext::mock_power_manager_proxy()
    const {
  return static_cast<
      testing::StrictMock<org::chromium::PowerManagerProxyMock>*>(
      power_manager_proxy_.get());
}

org::chromium::cras::ControlProxyMock* MockContext::mock_cras_proxy() const {
  return static_cast<
      testing::StrictMock<org::chromium::cras::ControlProxyMock>*>(
      cras_proxy_.get());
}

org::freedesktop::fwupdProxyMock* MockContext::mock_fwupd_proxy() const {
  return static_cast<testing::StrictMock<org::freedesktop::fwupdProxyMock>*>(
      fwupd_proxy_.get());
}

FakeMojoService* MockContext::fake_mojo_service() const {
  return static_cast<FakeMojoService*>(mojo_service_.get());
}

FakeNetworkHealthAdapter* MockContext::fake_network_health_adapter() const {
  return static_cast<FakeNetworkHealthAdapter*>(network_health_adapter_.get());
}

MockNetworkDiagnosticsAdapter* MockContext::network_diagnostics_adapter()
    const {
  return static_cast<MockNetworkDiagnosticsAdapter*>(
      network_diagnostics_adapter_.get());
}

FakePowerdAdapter* MockContext::fake_powerd_adapter() const {
  return static_cast<FakePowerdAdapter*>(powerd_adapter_.get());
}

FakeSystemConfig* MockContext::fake_system_config() const {
  return static_cast<FakeSystemConfig*>(system_config_.get());
}

FakeSystemUtilities* MockContext::fake_system_utils() const {
  return static_cast<FakeSystemUtilities*>(system_utils_.get());
}

FakeBluetoothEventHub* MockContext::fake_bluetooth_event_hub() const {
  return static_cast<FakeBluetoothEventHub*>(bluetooth_event_hub_.get());
}

MockBluetoothInfoManager* MockContext::mock_bluetooth_info_manager() const {
  return static_cast<MockBluetoothInfoManager*>(bluetooth_info_manager_.get());
}

MockExecutor* MockContext::mock_executor() {
  return &mock_executor_;
}

base::SimpleTestTickClock* MockContext::mock_tick_clock() const {
  return static_cast<base::SimpleTestTickClock*>(tick_clock_.get());
}

org::chromium::TpmManagerProxyMock* MockContext::mock_tpm_manager_proxy()
    const {
  return static_cast<testing::StrictMock<org::chromium::TpmManagerProxyMock>*>(
      tpm_manager_proxy_.get());
}

brillo::MockUdev* MockContext::mock_udev() const {
  return static_cast<brillo::MockUdev*>(udev_.get());
}

brillo::MockUdevMonitor* MockContext::mock_udev_monitor() const {
  return static_cast<brillo::MockUdevMonitor*>(udev_monitor_.get());
}

}  // namespace diagnostics
