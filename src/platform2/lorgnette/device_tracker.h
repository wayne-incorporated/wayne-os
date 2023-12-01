// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LORGNETTE_DEVICE_TRACKER_H_
#define LORGNETTE_DEVICE_TRACKER_H_

#include <stdint.h>

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <base/containers/flat_map.h>
#include <base/functional/callback.h>
#include <base/functional/callback_helpers.h>
#include <base/memory/weak_ptr.h>
#include <base/sequence_checker.h>
#include <base/time/time.h>
#include <brillo/errors/error.h>
#include <lorgnette/proto_bindings/lorgnette_service.pb.h>
#include <metrics/metrics_library.h>

#include "lorgnette/dbus_adaptors/org.chromium.lorgnette.Manager.h"

using brillo::dbus_utils::DBusMethodResponse;

namespace brillo {

namespace dbus_utils {
class ExportedObjectManager;
}  // namespace dbus_utils

}  // namespace brillo

namespace lorgnette {

using ScannerListChangedSignalSender =
    base::RepeatingCallback<void(const ScannerListChangedSignal&)>;

class FirewallManager;
class LibusbWrapper;
class SaneClient;
class UsbDevice;

// DeviceTracker is responsible for keeping track of which scanners are
// available and which ones are in use at any given time.
class DeviceTracker {
 public:
  DeviceTracker(SaneClient* sane_client, LibusbWrapper* libusb);
  DeviceTracker(const DeviceTracker&) = delete;
  DeviceTracker& operator=(const DeviceTracker&) = delete;
  virtual ~DeviceTracker();

  void SetScannerListChangedSignalSender(ScannerListChangedSignalSender sender);
  void SetFirewallManager(FirewallManager* firewall_manager);
  size_t NumActiveDiscoverySessions() const;
  base::Time LastDiscoverySessionActivity() const;

  // StartScannerDiscovery kicks off a new scanner discovery session.  The
  // session as a whole follows roughly these phases:
  // 1. If network detection is requested, open the firewall ports.
  // 2. If DLC policy is set to always download, start downloading the backend
  //    DLC in the background.
  // 3. Enumerate USB devices
  //    3a. If a device supports IPP-USB, post a task to probe it for eSCL
  //        support.  If it supports eSCL, add an entry and send a scanner
  //        added signal.
  //    3b. If a device requires a DLC backend and DLC isn't already
  //        downloading, start downloading the backend DLC in the background.
  // 4. Wait for DLC to be downloaded and mounted as needed.
  // 5. Enumerate the SANE devices
  //    5a. For each device, post a task to try to match it to one of the
  //        previously found IPP-USB entries.  Add a scanner entry and send
  //        a scanner added signal.
  // 6. Send a "local enum complete" signal.
  virtual StartScannerDiscoveryResponse StartScannerDiscovery(
      const StartScannerDiscoveryRequest& request);

  // StopScannerDiscovery closes an existing scanner discovery session.
  // ScannerListChanged signals may continue to be sent if other sessions are
  // still open.
  virtual StopScannerDiscoveryResponse StopScannerDiscovery(
      const StopScannerDiscoveryRequest& request);

 private:
  struct DiscoverySessionState {
    std::string client_id;
    base::Time start_time;
    BackendDownloadPolicy dlc_policy;
    bool dlc_started;
    bool local_only;
  };

  std::optional<DiscoverySessionState*> GetSession(
      const std::string& session_id);

  // Individual phases of discovery.  Each function is posted as a separate task
  // on the event loop to break up the amount of time spent blocking.
  // Because other events can be processed in between, each function needs to
  // re-check if its `session_id` still refers to an active session before doing
  // any processing.
  void StartDiscoverySessionInternal(std::string session_id);
  void EnumerateUSBDevices(std::string session_id);
  void ProbeIPPUSBDevice(std::string session_id,
                         std::unique_ptr<UsbDevice> device);
  void EnumerateSANEDevices(std::string session_id);
  void ProbeSANEDevice(std::string session_id);
  void SendEnumerationCompletedSignal(std::string session_id);
  void SendSessionEndingSignal(std::string session_id);

  SEQUENCE_CHECKER(sequence_checker_);

  // Manages connection to SANE for listing and connecting to scanners.
  // Not owned.
  SaneClient* sane_client_ GUARDED_BY_CONTEXT(sequence_checker_);

  // Manages port access for receiving replies from network scanners.
  // Not owned.
  FirewallManager* firewall_manager_ GUARDED_BY_CONTEXT(sequence_checker_);

  // Manages a libusb context for querying USB devices.
  // Not owned.
  LibusbWrapper* libusb_ GUARDED_BY_CONTEXT(sequence_checker_);

  // All the previously discovered devices.  Used to match subsequent SANE
  // entries for the same device and to accelerate subsequent discovery
  // sessions.
  std::vector<ScannerInfo> known_devices_ GUARDED_BY_CONTEXT(sequence_checker_);

  // A callback to call when we attempt to send a D-Bus signal. This is used
  // for testing in order to track the signals sent from StartScan.
  ScannerListChangedSignalSender signal_sender_;

  // Mapping from discovery session IDs to session state.
  // The session_id is passed around instead of a pointer to avoid creating
  // dangling pointers if a session is closed while discovery events are
  // pending.
  base::flat_map<std::string, DiscoverySessionState> discovery_sessions_
      GUARDED_BY_CONTEXT(sequence_checker_);

  // Keep as the last member variable.
  base::WeakPtrFactory<DeviceTracker> weak_factory_
      GUARDED_BY_CONTEXT(sequence_checker_){this};
};

}  // namespace lorgnette

#endif  // LORGNETTE_DEVICE_TRACKER_H_
