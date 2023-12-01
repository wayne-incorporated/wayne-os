// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LORGNETTE_DBUS_SERVICE_ADAPTOR_H_
#define LORGNETTE_DBUS_SERVICE_ADAPTOR_H_

#include <memory>
#include <string>

#include <base/functional/callback.h>
#include <brillo/dbus/async_event_sequencer.h>
#include <brillo/dbus/dbus_method_response.h>
#include <brillo/dbus/exported_object_manager.h>
#include <brillo/errors/error.h>
#include <lorgnette/proto_bindings/lorgnette_service.pb.h>

#include "lorgnette/dbus_adaptors/org.chromium.lorgnette.Manager.h"
#include "lorgnette/debug_log.h"
#include "lorgnette/device_tracker.h"
#include "lorgnette/manager.h"

namespace lorgnette {

class FirewallManager;

class DBusServiceAdaptor : public org::chromium::lorgnette::ManagerAdaptor,
                           public org::chromium::lorgnette::ManagerInterface {
 public:
  explicit DBusServiceAdaptor(
      std::unique_ptr<Manager> manager,
      DeviceTracker* device_tracker,
      base::RepeatingCallback<void()> debug_change_callback);
  DBusServiceAdaptor(const DBusServiceAdaptor&) = delete;
  DBusServiceAdaptor& operator=(const DBusServiceAdaptor&) = delete;
  virtual ~DBusServiceAdaptor();

  // Implementation of org::chromium::lorgnette::ManagerAdaptor.
  void RegisterAsync(brillo::dbus_utils::ExportedObjectManager* object_manager,
                     brillo::dbus_utils::AsyncEventSequencer* sequencer);

  // Implementation of org::chromium::lorgnette::ManagerInterface.
  bool ListScanners(brillo::ErrorPtr* error,
                    ListScannersResponse* scanner_list_out) override;
  bool GetScannerCapabilities(brillo::ErrorPtr* error,
                              const std::string& device_name,
                              ScannerCapabilities* capabilities) override;
  StartScanResponse StartScan(const StartScanRequest& request) override;
  void GetNextImage(std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<
                        GetNextImageResponse>> response,
                    const GetNextImageRequest& request,
                    const base::ScopedFD& out_fd) override;
  CancelScanResponse CancelScan(const CancelScanRequest& request) override;
  SetDebugConfigResponse SetDebugConfig(
      const SetDebugConfigRequest& request) override;
  StartScannerDiscoveryResponse StartScannerDiscovery(
      const StartScannerDiscoveryRequest& request) override;
  StopScannerDiscoveryResponse StopScannerDiscovery(
      const StopScannerDiscoveryRequest& request) override;

 private:
  SEQUENCE_CHECKER(sequence_checker_);

  std::unique_ptr<brillo::dbus_utils::DBusObject> dbus_object_
      GUARDED_BY_CONTEXT(sequence_checker_);
  std::unique_ptr<Manager> manager_ GUARDED_BY_CONTEXT(sequence_checker_);
  std::unique_ptr<FirewallManager> firewall_manager_
      GUARDED_BY_CONTEXT(sequence_checker_);

  // Not owned.
  DeviceTracker* device_tracker_ GUARDED_BY_CONTEXT(sequence_checker_);

  base::RepeatingCallback<void()> debug_change_callback_
      GUARDED_BY_CONTEXT(sequence_checker_);

  // Keep as the last member variable.
  base::WeakPtrFactory<DBusServiceAdaptor> weak_factory_
      GUARDED_BY_CONTEXT(sequence_checker_){this};
};

}  // namespace lorgnette

#endif  // LORGNETTE_DBUS_SERVICE_ADAPTOR_H_
