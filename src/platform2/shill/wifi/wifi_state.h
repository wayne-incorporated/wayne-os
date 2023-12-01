// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_WIFI_WIFI_STATE_H_
#define SHILL_WIFI_WIFI_STATE_H_

#include <string>

namespace shill {

// WiFiState stores and tracks state for the WiFi subsystem.  It provides the
// ability to dump a stack trace of state transitions.
class WiFiState {
 public:
  WiFiState();

  // Represents the state of an "ensured" queued scan
  enum class EnsuredScanState {
    kIdle,     // No queued scan
    kWaiting,  // Queued scan
    kScanning  // Queued scan in progress
  };

  // Represents the state of the Phy
  enum class PhyState {
    kIdle,
    kScanning,
    kBackgroundScanning,
    kTransitionToConnecting,
    kConnecting,
    kConnected,
    kFoundNothing
  };

  // Represents the last scan method used
  // TODO(b/266814915): Remove this once it provides no value.
  enum class ScanMethod {
    kFull,
    kNone,
  };

  EnsuredScanState GetEnsuredScanState() const;
  PhyState GetPhyState() const;
  ScanMethod GetScanMethod() const;

  std::string GetEnsuredScanStateString() const;
  std::string GetPhyStateString() const;
  std::string GetScanMethodString() const;

  // Get the State string in the legacy format expected by wifi.cc.
  // TODO(b/266814915): Remove this once it provides no value.
  static std::string LegacyStateString(PhyState state, ScanMethod method);

  void SetEnsuredScanState(EnsuredScanState state);
  void SetPhyState(PhyState state, ScanMethod method);

 private:
  // Represents the current state of the WiFi abstraction
  struct State {
    PhyState phy_state;
    EnsuredScanState ensured_scan_state;
    ScanMethod scan_method;
  };

  State state_;
};
}  // namespace shill

#endif  // SHILL_WIFI_WIFI_STATE_H_
