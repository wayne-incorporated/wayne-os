// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_BLUETOOTH_BLUETOOTH_MANAGER_INTERFACE_H_
#define SHILL_BLUETOOTH_BLUETOOTH_MANAGER_INTERFACE_H_

#include <cstdint>
#include <vector>

namespace shill {

// |BluetoothManagerInterface| is the primary interface that shill uses to
// communicate with the BT stack over D-Bus. Implementations will automatically
// use the appropriate D-Bus interface depending on the BT stack that's
// currently in use (Floss or BlueZ). However, some of the methods are not
// supported on BlueZ and will return errors if the device is using BlueZ.
class BluetoothManagerInterface {
 public:
  static constexpr int32_t kInvalidHCI = -1;

  enum class BTProfile {
    kHFP,
    kA2DPSink,
  };

  enum class BTProfileConnectionState {
    kDisconnected,
    kDisconnecting,
    kConnecting,
    kConnected,
    kActive,
    kInvalid,
  };

  virtual ~BluetoothManagerInterface() = default;

  // Start() sets up the D-Bus proxies used to communicate with the BT stack.
  // It must be called before any query.
  virtual bool Start() = 0;

  // Tear down the D-Bus proxies.
  virtual void Stop() = 0;

  struct BTAdapterWithEnabled {
    int32_t hci_interface;
    bool enabled;
  };

  // Query the BT stack to get the list of adapters present on the system.
  // Returns true if the query was successful, false otherwise.
  // If the query was successful, |is_floss| is set to true if the device is
  // using Floss, false if the device is using BlueZ. After a successful call
  // |adapters| will contain the list of BT adapters available.
  virtual bool GetAvailableAdapters(
      bool* is_floss, std::vector<BTAdapterWithEnabled>* adapters) const = 0;

  // Query the BT stack to know which of the BT adapters present on the system
  // is the default one.
  // This is only supported on Floss. Before using this function, callers must:
  // - ensure that the device is using Floss rather than BlueZ
  // - ensure that the BT adapter is enabled
  //
  // Returns true if the query was successful, false otherwise.
  // If the query was successful, |hci| is set to the index of the default
  // adapter.
  virtual bool GetDefaultAdapter(int32_t* hci) const = 0;

  // Query the BT stack to know the connection state of a particular BT profile
  // (HFP, A2DP, ...).
  // This is only supported on Floss. Before using this function, callers must:
  // - ensure that the device is using Floss rather than BlueZ
  // - ensure that the BT adapter is enabled
  //
  // |hci| is the index of the BT adapter that will be queried. It must
  // correspond to the default adapter that is currently enabled. To find out
  // the correct HCI, use |GetAvailableAdapters()|. If more than 1 adapter is
  // enabled, use |GetDefaultAdapter()|.
  //
  // On success, |state| will be populated with the connection state of the
  // profile.
  virtual bool GetProfileConnectionState(
      int32_t hci,
      BTProfile profile,
      BTProfileConnectionState* state) const = 0;

  // Query the BT stack to know if the adapter is currently scanning.
  // This is only supported on Floss. The function will return false if the
  // device is not using Floss or if BT is not enabled. Before using this
  // function, callers must:
  // - ensure that the device is using Floss rather than BlueZ
  // - ensure that the BT adapter is enabled.
  //
  // |hci| is the index of the BT adapter that will be queried. It must
  // correspond to the default adapter that is currently enabled. To find out
  // the correct HCI, use |GetAvailableAdapters()|. If more than 1 adapter is
  // enabled, use |GetDefaultAdapter()|.
  virtual bool IsDiscovering(int32_t hci, bool* discovering) const = 0;
};

}  // namespace shill

#endif  //  SHILL_BLUETOOTH_BLUETOOTH_MANAGER_INTERFACE_H_
