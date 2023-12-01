// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
#include "lorgnette/dbus_service_adaptor.h"

#include <signal.h>
#include <utility>

#include <chromeos/dbus/service_constants.h>

#include "lorgnette/firewall_manager.h"

namespace lorgnette {

namespace {
class ScopeLogger {
 public:
  explicit ScopeLogger(std::string name) : name_(std::move(name)) {
    LOG(INFO) << name_ << ": Enter";
  }

  ~ScopeLogger() { LOG(INFO) << name_ << ": Exit"; }

 private:
  std::string name_;
};

}  // namespace

DBusServiceAdaptor::DBusServiceAdaptor(
    std::unique_ptr<Manager> manager,
    DeviceTracker* device_tracker,
    base::RepeatingCallback<void()> debug_change_callback)
    : org::chromium::lorgnette::ManagerAdaptor(this),
      manager_(std::move(manager)),
      device_tracker_(device_tracker),
      debug_change_callback_(std::move(debug_change_callback)) {
  // Set signal sender to be the real D-Bus call by default.
  manager_->SetScanStatusChangedSignalSender(base::BindRepeating(
      [](base::WeakPtr<DBusServiceAdaptor> adaptor,
         const ScanStatusChangedSignal& signal) {
        if (adaptor) {
          adaptor->SendScanStatusChangedSignal(signal);
        }
      },
      weak_factory_.GetWeakPtr()));

  DCHECK(device_tracker_);
  device_tracker_->SetScannerListChangedSignalSender(base::BindRepeating(
      [](base::WeakPtr<DBusServiceAdaptor> adaptor,
         const ScannerListChangedSignal& signal) {
        if (adaptor) {
          adaptor->SendScannerListChangedSignal(signal);
        }
      },
      weak_factory_.GetWeakPtr()));
}

DBusServiceAdaptor::~DBusServiceAdaptor() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
}

void DBusServiceAdaptor::RegisterAsync(
    brillo::dbus_utils::ExportedObjectManager* object_manager,
    brillo::dbus_utils::AsyncEventSequencer* sequencer) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  CHECK(!dbus_object_) << "Already registered";
  scoped_refptr<dbus::Bus> bus =
      object_manager ? object_manager->GetBus() : nullptr;
  dbus_object_.reset(new brillo::dbus_utils::DBusObject(
      object_manager, bus, dbus::ObjectPath(kManagerServicePath)));
  RegisterWithDBusObject(dbus_object_.get());
  dbus_object_->RegisterAsync(sequencer->GetHandler(
      "DBusServiceAdaptor.RegisterAsync() failed.", true));

  firewall_manager_.reset(new FirewallManager(""));
  firewall_manager_->Init(
      std::make_unique<org::chromium::PermissionBrokerProxy>(bus));
  manager_->SetFirewallManager(firewall_manager_.get());
  device_tracker_->SetFirewallManager(firewall_manager_.get());
}

bool DBusServiceAdaptor::ListScanners(brillo::ErrorPtr* error,
                                      ListScannersResponse* scanner_list_out) {
  ScopeLogger scope("DBusServiceAdaptor::ListScanners");
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  return manager_->ListScanners(error, scanner_list_out);
}

bool DBusServiceAdaptor::GetScannerCapabilities(
    brillo::ErrorPtr* error,
    const std::string& device_name,
    ScannerCapabilities* capabilities) {
  ScopeLogger scope("DBusServiceAdaptor::GetScannerCapabilities");
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  return manager_->GetScannerCapabilities(error, device_name, capabilities);
}

StartScanResponse DBusServiceAdaptor::StartScan(
    const StartScanRequest& request) {
  ScopeLogger scope("DBusServiceAdaptor::StartScan");
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  return manager_->StartScan(request);
}

void DBusServiceAdaptor::GetNextImage(
    std::unique_ptr<DBusMethodResponse<GetNextImageResponse>> response,
    const GetNextImageRequest& request,
    const base::ScopedFD& out_fd) {
  ScopeLogger scope("DBusServiceAdaptor::GetNextImage");
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  return manager_->GetNextImage(std::move(response), request, out_fd);
}

CancelScanResponse DBusServiceAdaptor::CancelScan(
    const CancelScanRequest& request) {
  ScopeLogger scope("DBusServiceAdaptor::CancelScan");
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  return manager_->CancelScan(request);
}

SetDebugConfigResponse DBusServiceAdaptor::SetDebugConfig(
    const SetDebugConfigRequest& request) {
  ScopeLogger scope("DBusServiceAdaptor::SetDebugConfig");
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DebugLogManager logman;
  SetDebugConfigResponse response = logman.UpdateDebugConfig(request);
  if (response.old_enabled() != request.enabled()) {
    debug_change_callback_.Run();
  }
  return response;
}

StartScannerDiscoveryResponse DBusServiceAdaptor::StartScannerDiscovery(
    const StartScannerDiscoveryRequest& request) {
  ScopeLogger scope("DBusServiceAdaptor::StartScannerDiscovery");
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  return device_tracker_->StartScannerDiscovery(request);
}

StopScannerDiscoveryResponse DBusServiceAdaptor::StopScannerDiscovery(
    const StopScannerDiscoveryRequest& request) {
  ScopeLogger scope("DBusServiceAdaptor::StopScannerDiscovery");
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  return device_tracker_->StopScannerDiscovery(request);
}

}  // namespace lorgnette
