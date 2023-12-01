// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_SYSTEM_MOCK_CONTEXT_H_
#define DIAGNOSTICS_CROS_HEALTHD_SYSTEM_MOCK_CONTEXT_H_

#include <memory>

#include <base/files/scoped_temp_dir.h>
#include <base/memory/scoped_refptr.h>
#include <base/test/simple_test_tick_clock.h>
#include <brillo/udev/mock_udev.h>
#include <brillo/udev/mock_udev_device.h>
#include <brillo/udev/mock_udev_monitor.h>
#include <chromeos/chromeos-config/libcros_config/fake_cros_config.h>

#include "diagnostics/cros_healthd/executor/mock_executor.h"
#include "diagnostics/cros_healthd/network/fake_network_health_adapter.h"
#include "diagnostics/cros_healthd/network_diagnostics/mock_network_diagnostics_adapter.h"
#include "diagnostics/cros_healthd/system/context.h"
#include "diagnostics/cros_healthd/system/fake_bluetooth_event_hub.h"
#include "diagnostics/cros_healthd/system/fake_pci_util.h"
#include "diagnostics/cros_healthd/system/fake_powerd_adapter.h"
#include "diagnostics/cros_healthd/system/fake_system_config.h"
#include "diagnostics/cros_healthd/system/fake_system_utilities.h"
#include "diagnostics/cros_healthd/system/mock_bluetooth_info_manager.h"

namespace org {
namespace chromium {
class AttestationProxyMock;
class debugdProxyMock;
class PowerManagerProxyMock;
class TpmManagerProxyMock;

namespace cras {
class ControlProxyMock;
}  // namespace cras
}  // namespace chromium

namespace freedesktop {
class fwupdProxyMock;
}  // namespace freedesktop
}  // namespace org

namespace diagnostics {

class FakeMojoService;

// A mock context class for testing.
class MockContext final : public Context {
 public:
  MockContext();
  MockContext(const MockContext&) = delete;
  MockContext& operator=(const MockContext&) = delete;
  ~MockContext() override = default;

  std::unique_ptr<PciUtil> CreatePciUtil() override;

  ash::cros_healthd::mojom::Executor* executor() override;

  // Accessors to the fake and mock objects held by MockContext:
  org::chromium::AttestationProxyMock* mock_attestation_proxy() const;
  brillo::FakeCrosConfig* fake_cros_config() const;
  org::chromium::debugdProxyMock* mock_debugd_proxy() const;
  org::chromium::PowerManagerProxyMock* mock_power_manager_proxy() const;
  org::chromium::cras::ControlProxyMock* mock_cras_proxy() const;
  org::freedesktop::fwupdProxyMock* mock_fwupd_proxy() const;
  FakeMojoService* fake_mojo_service() const;
  FakeNetworkHealthAdapter* fake_network_health_adapter() const;
  MockNetworkDiagnosticsAdapter* network_diagnostics_adapter() const;
  FakePowerdAdapter* fake_powerd_adapter() const;
  FakeSystemConfig* fake_system_config() const;
  FakeSystemUtilities* fake_system_utils() const;
  FakeBluetoothEventHub* fake_bluetooth_event_hub() const;
  MockBluetoothInfoManager* mock_bluetooth_info_manager() const;
  MockExecutor* mock_executor();
  base::SimpleTestTickClock* mock_tick_clock() const;
  org::chromium::TpmManagerProxyMock* mock_tpm_manager_proxy() const;
  brillo::MockUdev* mock_udev() const;
  brillo::MockUdevMonitor* mock_udev_monitor() const;

  MOCK_METHOD(const base::Time, time, (), (const, override));

 private:
  // Used to create a temporary root directory.
  base::ScopedTempDir temp_dir_;
  // Used to create a fake pci util.
  FakePciUtil fake_pci_util_;
  // Mock executor.
  MockExecutor mock_executor_;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_SYSTEM_MOCK_CONTEXT_H_
