// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/system/context.h"

#include <memory>
#include <utility>

#include <attestation/proto_bindings/interface.pb.h>
#include <attestation-client/attestation/dbus-proxies.h>
#include <base/check.h>
#include <base/logging.h>
#include <base/time/default_tick_clock.h>
#include <brillo/udev/udev.h>
#include <chromeos/chromeos-config/libcros_config/cros_config.h>
#include <chromeos/dbus/service_constants.h>
#include <cras/dbus-proxies.h>
#include <debugd/dbus-proxies.h>
#include <fwupd/dbus-proxies.h>
#include <mojo/public/cpp/system/invitation.h>
#include <power_manager/dbus-proxies.h>
#include <tpm_manager/proto_bindings/tpm_manager.pb.h>
#include <tpm_manager-client/tpm_manager/dbus-proxies.h>

#include "diagnostics/cros_healthd/network/network_health_adapter_impl.h"
#include "diagnostics/cros_healthd/network_diagnostics/network_diagnostics_adapter_impl.h"
#include "diagnostics/cros_healthd/system/bluetooth_event_hub.h"
#include "diagnostics/cros_healthd/system/bluetooth_info_manager.h"
#include "diagnostics/cros_healthd/system/mojo_service_impl.h"
#include "diagnostics/cros_healthd/system/pci_util_impl.h"
#include "diagnostics/cros_healthd/system/powerd_adapter_impl.h"
#include "diagnostics/cros_healthd/system/system_config.h"
#include "diagnostics/cros_healthd/system/system_utilities_impl.h"
#include "diagnostics/cros_healthd/utils/resource_queue.h"

namespace diagnostics {

namespace {

namespace mojom = ::ash::cros_healthd::mojom;

constexpr char kFwupdServiceName[] = "org.freedesktop.fwupd";

mojo::PendingRemote<mojom::Executor> SendInvitationAndConnectToExecutor(
    mojo::PlatformChannelEndpoint endpoint) {
  // This sends invitation to the executor process. Must be the outgoing
  // invitation because cros_healthd is the process which connects to the mojo
  // broker. This must be run after the mojo ipc thread is initialized.
  mojo::OutgoingInvitation invitation;
  // Always use 0 as the default pipe name.
  mojo::ScopedMessagePipeHandle pipe = invitation.AttachMessagePipe(0);
  mojo::OutgoingInvitation::Send(std::move(invitation),
                                 base::kNullProcessHandle, std::move(endpoint));
  return mojo::PendingRemote<mojom::Executor>(std::move(pipe),
                                              /*version=*/0);
}

}  // namespace

Context::Context() = default;

Context::Context(mojo::PlatformChannelEndpoint executor_endpoint,
                 std::unique_ptr<brillo::UdevMonitor>&& udev_monitor,
                 base::OnceClosure shutdown_callback) {
  // Initiailize static member
  root_dir_ = base::FilePath("/");
  udev_monitor_ = std::move(udev_monitor);

  // Initialize the D-Bus connection.
  auto dbus_bus = connection_.Connect();
  CHECK(dbus_bus) << "Failed to connect to the D-Bus system bus.";

  // Create D-Bus clients:
  attestation_proxy_ =
      std::make_unique<org::chromium::AttestationProxy>(dbus_bus);
  bluez_proxy_ = std::make_unique<org::bluezProxy>(dbus_bus);
  cras_proxy_ = std::make_unique<org::chromium::cras::ControlProxy>(
      dbus_bus, cras::kCrasServiceName,
      dbus::ObjectPath(cras::kCrasServicePath));
  debugd_proxy_ = std::make_unique<org::chromium::debugdProxy>(dbus_bus);
  fwupd_proxy_ = std::make_unique<org::freedesktop::fwupdProxy>(
      dbus_bus, kFwupdServiceName);
  power_manager_proxy_ =
      std::make_unique<org::chromium::PowerManagerProxy>(dbus_bus);
  tpm_manager_proxy_ =
      std::make_unique<org::chromium::TpmManagerProxy>(dbus_bus);

  // Create the mojo clients which will be initialized after connecting with
  // chrome.
  network_health_adapter_ = std::make_unique<NetworkHealthAdapterImpl>();
  network_diagnostics_adapter_ =
      std::make_unique<NetworkDiagnosticsAdapterImpl>();
  mojo_service_ = MojoServiceImpl::Create(std::move(shutdown_callback),
                                          network_health_adapter_.get(),
                                          network_diagnostics_adapter_.get());

  // Connect to the root-level executor. Must after creating mojo services
  // because we need to wait the mojo broker (the service manager) being
  // connected.
  executor_.Bind(
      SendInvitationAndConnectToExecutor(std::move(executor_endpoint)));
  executor_.set_disconnect_handler(base::BindOnce([]() {
    LOG(ERROR) << "The executor disconnected unexpectedly which should not "
                  "happen. It could have crashed.";
    // Exit immediately without any clean up because this should not happen in
    // normal case. Don't use LOG(FATAL) to prevent a crashdump disturb the real
    // crash in the executor.
    std::exit(EXIT_FAILURE);
  }));

  // Create others.
  cros_config_ = std::make_unique<brillo::CrosConfig>();

  powerd_adapter_ =
      std::make_unique<PowerdAdapterImpl>(power_manager_proxy_.get());
  system_config_ =
      std::make_unique<SystemConfig>(cros_config_.get(), debugd_proxy_.get());
  system_utils_ = std::make_unique<SystemUtilitiesImpl>();
  bluetooth_info_manager_ =
      std::make_unique<BluetoothInfoManager>(bluez_proxy_.get());
  bluetooth_event_hub_ =
      std::make_unique<BluetoothEventHub>(bluez_proxy_.get());
  tick_clock_ = std::make_unique<base::DefaultTickClock>();
  udev_ = brillo::Udev::Create();
  memory_cpu_resource_queue_ = std::make_unique<ResourceQueue>();

  // TODO(b/270471793): Remove this workaround after the Bluez issue is fixed.
  base::SingleThreadTaskRunner::GetCurrentDefault()->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&Context::BootstrapBluezProxy,
                     weak_ptr_factory_.GetWeakPtr()),
      base::Seconds(10));
}

Context::~Context() = default;

void Context::BootstrapBluezProxy() {
  bluetooth_info_manager_.reset();
  bluez_proxy_.reset();
  if (!connection_.Connect()->RemoveObjectManager(
          "org.bluez", dbus::ObjectPath{"/"},
          base::BindOnce(&Context::UpdateBluezProxy,
                         weak_ptr_factory_.GetWeakPtr()))) {
    LOG(ERROR) << "Failed to remove Bluez object manager";
  }
}

void Context::UpdateBluezProxy() {
  bluez_proxy_ = std::make_unique<org::bluezProxy>(connection_.Connect());
  bluetooth_info_manager_ =
      std::make_unique<BluetoothInfoManager>(bluez_proxy_.get());
  bluetooth_event_hub_->UpdateProxy(bluez_proxy_.get());
}

std::unique_ptr<PciUtil> Context::CreatePciUtil() {
  return std::unique_ptr<PciUtil>(new PciUtilImpl());
}

const base::Time Context::time() const {
  return base::Time().Now();
}

}  // namespace diagnostics
