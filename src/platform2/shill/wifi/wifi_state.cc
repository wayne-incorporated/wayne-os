// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <map>
#include <string>

#include <base/logging.h>
#include <base/notreached.h>

#include "shill/wifi/wifi_state.h"

namespace {
constexpr char kIdle[] = "Idle";
constexpr char kScanning[] = "Scanning";
constexpr char kBackgroundScanning[] = "BackgroundScanning";
constexpr char kTransitionToConnecting[] = "TransitionToConnecting";
constexpr char kConnecting[] = "Connecting";
constexpr char kConnected[] = "Connected";
constexpr char kFoundNothing[] = "FoundNothing";
constexpr char kWaiting[] = "Waiting";
constexpr char kFull[] = "Full";
constexpr char kNone[] = "None";

std::map<shill::WiFiState::PhyState, const char*> phy_state_map = {
    {shill::WiFiState::PhyState::kIdle, kIdle},
    {shill::WiFiState::PhyState::kScanning, kScanning},
    {shill::WiFiState::PhyState::kBackgroundScanning, kBackgroundScanning},
    {shill::WiFiState::PhyState::kTransitionToConnecting,
     kTransitionToConnecting},
    {shill::WiFiState::PhyState::kConnecting, kConnecting},
    {shill::WiFiState::PhyState::kConnected, kConnected},
    {shill::WiFiState::PhyState::kFoundNothing, kFoundNothing}};
std::map<shill::WiFiState::EnsuredScanState, const char*>
    ensured_scan_state_map = {
        {shill::WiFiState::EnsuredScanState::kIdle, kIdle},
        {shill::WiFiState::EnsuredScanState::kScanning, kScanning},
        {shill::WiFiState::EnsuredScanState::kWaiting, kWaiting}};
std::map<shill::WiFiState::ScanMethod, const char*> scan_method_map = {
    {shill::WiFiState::ScanMethod::kFull, kFull},
    {shill::WiFiState::ScanMethod::kNone, kNone}};

std::string GetScanMethodString(shill::WiFiState::ScanMethod method) {
  return scan_method_map[method];
}

std::string GetPhyStateString(shill::WiFiState::PhyState state) {
  return phy_state_map[state];
}

std::string GetEnsuredScanStateString(
    shill::WiFiState::EnsuredScanState state) {
  return ensured_scan_state_map[state];
}
}  // namespace

namespace shill {

WiFiState::WiFiState() {
  state_.phy_state = PhyState::kIdle;
  state_.ensured_scan_state = EnsuredScanState::kIdle;
  state_.scan_method = ScanMethod::kNone;
}

WiFiState::EnsuredScanState WiFiState::GetEnsuredScanState() const {
  return state_.ensured_scan_state;
}

WiFiState::PhyState WiFiState::GetPhyState() const {
  return state_.phy_state;
}

WiFiState::ScanMethod WiFiState::GetScanMethod() const {
  return state_.scan_method;
}

std::string WiFiState::GetEnsuredScanStateString() const {
  return ::GetEnsuredScanStateString(GetEnsuredScanState());
}

std::string WiFiState::GetPhyStateString() const {
  return ::GetPhyStateString(GetPhyState());
}

std::string WiFiState::GetScanMethodString() const {
  return ::GetScanMethodString(GetScanMethod());
}

void WiFiState::SetEnsuredScanState(WiFiState::EnsuredScanState state) {
  state_.ensured_scan_state = state;
}

void WiFiState::SetPhyState(WiFiState::PhyState state,
                            WiFiState::ScanMethod method) {
  state_.scan_method = method;
  state_.phy_state = state;
}

// TODO(b/266814915): Remove this method when removing ScanMethod.
// static
std::string WiFiState::LegacyStateString(WiFiState::PhyState state,
                                         WiFiState::ScanMethod method) {
  switch (state) {
    case PhyState::kIdle:
      return "IDLE";
    case PhyState::kScanning:
      DCHECK(method != ScanMethod::kNone) << "Scanning with no scan method.";
      switch (method) {
        case ScanMethod::kFull:
          return "FULL_START";
        default:
          NOTREACHED();
      }
      // TODO(denik): Remove break after fall-through check
      // is fixed with NOTREACHED(), https://crbug.com/973960.
      break;
    case PhyState::kBackgroundScanning:
      return "BACKGROUND_START";
    case PhyState::kTransitionToConnecting:
      return "TRANSITION_TO_CONNECTING";
    case PhyState::kConnecting:
      switch (method) {
        case ScanMethod::kNone:
          return "CONNECTING (not scan related)";
        case ScanMethod::kFull:
          return "FULL_CONNECTING";
        default:
          NOTREACHED();
      }
      // TODO(denik): Remove break after fall-through check
      // is fixed with NOTREACHED(), https://crbug.com/973960.
      break;
    case PhyState::kConnected:
      switch (method) {
        case ScanMethod::kNone:
          return "CONNECTED (not scan related; e.g., from a supplicant roam)";
        case ScanMethod::kFull:
          return "FULL_CONNECTED";
        default:
          NOTREACHED();
      }
      // TODO(denik): Remove break after fall-through check
      // is fixed with NOTREACHED(), https://crbug.com/973960.
      break;
    case PhyState::kFoundNothing:
      switch (method) {
        case ScanMethod::kNone:
          return "CONNECT FAILED (not scan related)";
        case ScanMethod::kFull:
          return "FULL_NOCONNECTION";
        default:
          NOTREACHED();
      }
      // TODO(denik): Remove break after fall-through check
      // is fixed with NOTREACHED(), https://crbug.com/973960.
      break;
    default:
      NOTREACHED();
  }
  return "";  // To shut up the compiler (that doesn't understand NOTREACHED).
}

}  // namespace shill
