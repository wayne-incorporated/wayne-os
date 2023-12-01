// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "typecd/port_manager.h"

#include <string>

#include <base/threading/platform_thread.h>
#include <base/time/time.h>
#include <base/logging.h>
#include <dbus/typecd/dbus-constants.h>
#include <re2/re2.h>

namespace {

// Give enough time for the EC to complete the ExitMode command. Calculated as
// follows:
// (tVDMWaitModeExit (50ms) * 3 possible signalling types (SOP, SOP', SOP''))
// + 5 ms (typical ectool command)
//
// That gives us 155ms, so we double that to factor in scheduler and other
// delays.
constexpr uint32_t kExitModeWaitMs = 300;

// Helper function to print the TypeCMode.
std::string ModeToString(typecd::TypeCMode mode) {
  int val = static_cast<int>(mode);
  switch (val) {
    case 0:
      return "DP";
    case 1:
      return "TBT";
    case 2:
      return "USB4";
    default:
      return "none";
  }
}

}  // namespace

namespace typecd {

PortManager::PortManager()
    : mode_entry_supported_(true),
      supports_usb4_(true),
      dbus_mgr_(nullptr),
      features_client_(nullptr),
      user_active_(false),
      peripheral_data_access_(true),
      port_num_previously_sink(-1),
      metrics_(nullptr) {}

void PortManager::SetModeEntrySupported(bool supported) {
  // Run mode entry when switching from unsupported to supported.
  bool run_mode_entry = !mode_entry_supported_ && supported;

  mode_entry_supported_ = supported;
  if (run_mode_entry) {
    for (int i = 0; i < ports_.size(); i++)
      RunModeEntry(i);
  }
}

void PortManager::OnPortAddedOrRemoved(const base::FilePath& path,
                                       int port_num,
                                       bool added) {
  auto it = ports_.find(port_num);
  if (added) {
    if (it != ports_.end()) {
      LOG(WARNING) << "Attempting to add an already added port.";
      return;
    }

    auto new_port = std::make_unique<Port>(path, port_num);
    new_port->SetSupportsUSB4(supports_usb4_);
    new_port->SetECUtil(ec_util_);
    ports_.emplace(port_num, std::move(new_port));
  } else {
    if (it == ports_.end()) {
      LOG(WARNING) << "Attempting to remove a non-existent port.";
      return;
    }

    ports_.erase(it);
  }
}

void PortManager::OnPartnerAddedOrRemoved(const base::FilePath& path,
                                          int port_num,
                                          bool added,
                                          bool is_hotplug) {
  auto it = ports_.find(port_num);
  if (it == ports_.end()) {
    LOG(WARNING) << "Partner add/remove attempted for non-existent port "
                 << port_num;
    return;
  }

  auto port = it->second.get();
  if (added) {
    port->AddPartner(path);
    RunModeEntry(port_num);
    ReportMetrics(port_num, is_hotplug);
  } else {
    port->RemovePartner();
    port->SetCurrentMode(TypeCMode::kNone);
    port->CancelMetricsTask();
  }
}

void PortManager::OnPartnerAltModeAddedOrRemoved(const base::FilePath& path,
                                                 int port_num,
                                                 bool added) {
  auto it = ports_.find(port_num);
  if (it == ports_.end()) {
    LOG(WARNING)
        << "Partner alt mode add/remove attempted for non-existent port "
        << port_num;
    return;
  }

  auto port = it->second.get();
  port->AddRemovePartnerAltMode(path, added);
  if (added)
    RunModeEntry(port_num);
}

void PortManager::OnCableAddedOrRemoved(const base::FilePath& path,
                                        int port_num,
                                        bool added) {
  auto it = ports_.find(port_num);
  if (it == ports_.end()) {
    LOG(WARNING) << "Cable add/remove attempted for non-existent port "
                 << port_num;
    return;
  }

  auto port = it->second.get();
  if (added) {
    port->AddCable(path);
  } else {
    port->RemoveCable();
  }
}

void PortManager::OnPdDeviceAddedOrRemoved(const base::FilePath& path,
                                           bool added) {
  auto device_path = path.Append("device");
  base::FilePath target;
  if (!base::ReadSymbolicLink(device_path, &target)) {
    PLOG(ERROR) << "Failed to read symlink at path: " << device_path;
    return;
  }

  int port_num;
  if (!RE2::FullMatch(target.BaseName().value(), kPartnerRegex, &port_num))
    return;

  auto it = ports_.find(port_num);
  if (it == ports_.end()) {
    LOG(WARNING)
        << "Partner PD device modification attempted for non-existent port "
        << port_num;
    return;
  }

  auto port = it->second.get();
  port->AddRemovePartnerPowerProfile(added);
}

void PortManager::OnCablePlugAdded(const base::FilePath& path, int port_num) {
  auto it = ports_.find(port_num);
  if (it == ports_.end()) {
    LOG(WARNING) << "Cable plug (SOP') add attempted for non-existent port "
                 << port_num;
    return;
  }

  auto port = it->second.get();
  port->AddCablePlug(path);
  RunModeEntry(port_num);
}

void PortManager::OnCableAltModeAdded(const base::FilePath& path,
                                      int port_num) {
  auto it = ports_.find(port_num);
  if (it == ports_.end()) {
    LOG(WARNING) << "Cable alt mode add attempted for non-existent port "
                 << port_num;
    return;
  }

  auto port = it->second.get();
  port->AddCableAltMode(path);
  RunModeEntry(port_num);
}

void PortManager::OnPartnerChanged(int port_num) {
  auto it = ports_.find(port_num);
  if (it == ports_.end()) {
    LOG(WARNING) << "Partner change detected for non-existent port "
                 << port_num;
    return;
  }

  auto port = it->second.get();
  port->PartnerChanged();
  RunModeEntry(port_num);
}

void PortManager::OnPortChanged(int port_num) {
  auto it = ports_.find(port_num);
  if (it == ports_.end()) {
    LOG(WARNING) << "Port change detected for non-existent port " << port_num;
    return;
  }

  auto port = it->second.get();
  port->PortChanged();
}

void PortManager::OnScreenIsLocked() {
  SetUserActive(false);
}

void PortManager::OnScreenIsUnlocked() {
  HandleUnlock();
}

void PortManager::OnSessionStarted() {
  // Session started is handled similarly to "screen unlocked".
  HandleUnlock();
}

void PortManager::OnSessionStopped() {
  HandleSessionStopped();
}

void PortManager::HandleSessionStopped() {
  if (!GetModeEntrySupported())
    return;

  SetUserActive(false);
  for (auto const& x : ports_) {
    Port* port = x.second.get();
    int port_num = x.first;

    // Since we've logged out, we can reset all expectations about active
    // state during mode entry.
    port->SetActiveStateOnModeEntry(GetUserActive());

    // If the current mode is anything other than kTBT, we don't care about
    // changing modes.
    if (port->GetCurrentMode() != TypeCMode::kTBT)
      continue;

    // If DP mode entry isn't supported, there is nothing left to do.
    if (!port->CanEnterDPAltMode(nullptr))
      continue;

    // First try exiting the alt mode.
    if (ec_util_->ExitMode(port_num)) {
      port->SetCurrentMode(TypeCMode::kNone);
      LOG(INFO) << "Exited TBT mode on port " << port_num;
    } else {
      LOG(ERROR) << "Attempt to call ExitMode failed for port " << port_num;
      continue;
    }

    base::PlatformThread::Sleep(base::Milliseconds(kExitModeWaitMs));

    // Now run mode entry again.
    RunModeEntry(port_num);
  }
}

void PortManager::HandleUnlock() {
  if (!GetModeEntrySupported())
    return;

  if (features_client_)
    SetPeripheralDataAccess(features_client_->GetPeripheralDataAccessEnabled());

  SetUserActive(true);
  for (auto const& x : ports_) {
    Port* port = x.second.get();
    int port_num = x.first;
    // If the current mode is anything other than DP, we don't care about
    // changing modes.
    if (port->GetCurrentMode() != TypeCMode::kDP)
      continue;

    // If TBT mode entry isn't supported, there is nothing left to do.
    if (port->CanEnterTBTCompatibilityMode() != ModeEntryResult::kSuccess)
      continue;

    // If peripheral data access is disabled, we shouldn't switch modes at all.
    if (!GetPeripheralDataAccess())
      continue;

    // If the port had initially entered the mode during an unlocked state,
    // we shouldn't change modes now. Doing so will abruptly kick storage
    // devices off the peripheral without a safe unmount.
    if (port->GetActiveStateOnModeEntry())
      continue;

    // First try exiting the alt mode.
    if (ec_util_->ExitMode(port_num)) {
      port->SetCurrentMode(TypeCMode::kNone);
      LOG(INFO) << "Exited DP mode on port " << port_num;
    } else {
      LOG(ERROR) << "Attempt to call ExitMode failed for port " << port_num;
      continue;
    }

    base::PlatformThread::Sleep(base::Milliseconds(kExitModeWaitMs));

    // Now run mode entry again.
    RunModeEntry(port_num);
  }
}

void PortManager::RunModeEntry(int port_num) {
  if (!ec_util_) {
    LOG(ERROR) << "No EC Util implementation registered, mode entry aborted.";
    return;
  }

  auto it = ports_.find(port_num);
  if (it == ports_.end()) {
    LOG(WARNING) << "Mode entry attempted for non-existent port " << port_num;
    return;
  }

  auto port = it->second.get();

  if (port->GetDataRole() != DataRole::kHost) {
    LOG(WARNING) << "Can't enter mode; data role is not DFP on port "
                 << port_num;
    return;
  }

  if (!port->IsPartnerDiscoveryComplete()) {
    LOG(INFO) << "Can't enter mode; partner discovery not complete for port "
              << port_num;
    return;
  }

  if (!port->IsCableDiscoveryComplete()) {
    LOG(INFO) << "Can't enter mode; cable discovery not complete for port "
              << port_num;
    return;
  }

  if (port->GetCurrentMode() != TypeCMode::kNone) {
    LOG(INFO) << "Mode entry already executed for port " << port_num
              << ", mode: " << ModeToString(port->GetCurrentMode());
    return;
  }

  if (!GetModeEntrySupported()) {
    if (!dbus_mgr_)
      return;

    // If mode entry is not attempted because the AP cannot enter modes, still
    // check for cable notifications.
    bool invalid_dpalt_cable = false;
    bool can_enter_dp_alt_mode = port->CanEnterDPAltMode(&invalid_dpalt_cable);
    if (can_enter_dp_alt_mode && invalid_dpalt_cable)
      dbus_mgr_->NotifyCableWarning(CableWarningType::kInvalidDpCable);

    return;
  }

  // Send TBT device-connected notification.
  // While we can probably optimize this to avoid the repeat CanEnter* calls, we
  // handle the notification calls ahead, in order to prevent the logic from
  // becoming difficult to follow.
  if (dbus_mgr_) {
    if (port->CanEnterTBTCompatibilityMode() == ModeEntryResult::kSuccess) {
      auto notif = port->CanEnterDPAltMode(nullptr)
                       ? DeviceConnectedType::kThunderboltDp
                       : DeviceConnectedType::kThunderboltOnly;
      dbus_mgr_->NotifyConnected(notif);
    }
  }

  port->SetActiveStateOnModeEntry(GetUserActive());

  if (features_client_)
    SetPeripheralDataAccess(features_client_->GetPeripheralDataAccessEnabled());

  // If the host supports USB4 and we can enter USB4 in this partner, do so.
  auto can_enter_usb4 = port->CanEnterUSB4();
  if (can_enter_usb4 == ModeEntryResult::kSuccess) {
    if (ec_util_->EnterMode(port_num, TypeCMode::kUSB4)) {
      port->SetCurrentMode(TypeCMode::kUSB4);
      LOG(INFO) << "Entered USB4 mode on port " << port_num;
    } else {
      LOG(ERROR) << "Attempt to call Enter USB4 failed for port " << port_num;
    }

    // If the cable limits USB speed, warn the user.
    if (port->CableLimitingUSBSpeed(false)) {
      LOG(INFO) << "Cable limiting USB speed on port " << port_num;
      if (dbus_mgr_)
        dbus_mgr_->NotifyCableWarning(CableWarningType::kSpeedLimitingCable);
    }

    return;
  }

  auto can_enter_thunderbolt = port->CanEnterTBTCompatibilityMode();
  if (can_enter_thunderbolt == ModeEntryResult::kSuccess) {
    // Check if DP alt mode can be entered. If so:
    // - If the user is not active: enter DP.
    // - If the user is active: if peripheral data access is disabled, enter DP,
    //   else enter TBT.
    //
    // If DP alt mode cannot be entered, proceed to enter TBT in all cases.
    TypeCMode cur_mode = TypeCMode::kTBT;
    if (port->CanEnterDPAltMode(nullptr) &&
        (!GetUserActive() || (GetUserActive() && !GetPeripheralDataAccess()))) {
      cur_mode = TypeCMode::kDP;
      LOG(INFO) << "Not entering TBT compat mode since user_active: "
                << GetUserActive()
                << ", peripheral data access: " << GetPeripheralDataAccess()
                << ", port " << port_num;
    }

    if (ec_util_->EnterMode(port_num, cur_mode)) {
      port->SetCurrentMode(cur_mode);
      LOG(INFO) << "Entered " << ModeToString(cur_mode) << " mode on port "
                << port_num;
    } else {
      LOG(ERROR) << "Attempt to call enter " << ModeToString(cur_mode)
                 << " failed for port " << port_num;
    }

    if (can_enter_usb4 == ModeEntryResult::kCableError) {
      // If TBT is entered due to a USB4 cable error, warn the user.
      LOG(WARNING) << "USB4 partner with TBT cable on port " << port_num;
      if (dbus_mgr_)
        dbus_mgr_->NotifyCableWarning(
            CableWarningType::kInvalidUSB4ValidTBTCable);
    } else if (port->CableLimitingUSBSpeed(true)) {
      // Cable limits the speed of TBT3 partner.
      LOG(INFO) << "Cable limiting USB speed on port " << port_num;
      if (dbus_mgr_)
        dbus_mgr_->NotifyCableWarning(CableWarningType::kSpeedLimitingCable);
    }

    return;
  }

  bool invalid_dpalt_cable = false;
  if (port->CanEnterDPAltMode(&invalid_dpalt_cable)) {
    if (ec_util_->EnterMode(port_num, TypeCMode::kDP)) {
      port->SetCurrentMode(TypeCMode::kDP);
      LOG(INFO) << "Entered DP mode on port " << port_num;
    } else {
      LOG(ERROR) << "Attempt to call Enter DP failed for port " << port_num;
    }
  }

  // CableWarningType to track possible cable notifications.
  CableWarningType cable_warning = CableWarningType::kOther;
  if (can_enter_usb4 == ModeEntryResult::kCableError) {
    cable_warning = CableWarningType::kInvalidUSB4Cable;
    LOG(WARNING) << "USB4 partner with incompatible cable on port " << port_num;
  } else if (can_enter_thunderbolt == ModeEntryResult::kCableError) {
    cable_warning = CableWarningType::kInvalidTBTCable;
    LOG(WARNING) << "TBT partner with incompatible cable on port " << port_num;
  } else if (invalid_dpalt_cable) {
    cable_warning = CableWarningType::kInvalidDpCable;
    LOG(WARNING) << "DPAltMode partner with incompatible cable on port "
                 << port_num;
  } else if (port->CableLimitingUSBSpeed(false)) {
    cable_warning = CableWarningType::kSpeedLimitingCable;
    LOG(INFO) << "Cable limiting USB speed on port " << port_num;
  }

  // Notify user of potential cable issue.
  if (dbus_mgr_ && cable_warning != CableWarningType::kOther)
    dbus_mgr_->NotifyCableWarning(cable_warning);

  return;
}

void PortManager::ReportMetrics(int port_num, bool is_hotplug) {
  if (!metrics_)
    return;

  auto it = ports_.find(port_num);
  if (it == ports_.end()) {
    LOG(WARNING) << "Metrics reporting attempted for non-existent port "
                 << port_num;
    return;
  }

  auto port = it->second.get();
  port->EnqueueMetricsTask(metrics_, GetModeEntrySupported());

  if (port->GetPanel() != Panel::kUnknown) {
    metrics_->ReportPartnerLocation(
        GetPartnerLocationMetric(port_num, is_hotplug));
    if (port->GetPowerRole() == PowerRole::kSink)
      metrics_->ReportPowerSourceLocation(
          GetPowerSourceLocationMetric(port_num));
  }
}

PartnerLocationMetric PortManager::GetPartnerLocationMetric(int port_num,
                                                            bool is_hotplug) {
  auto it = ports_.find(port_num);
  if (it == ports_.end()) {
    LOG(WARNING)
        << "Port location metric reporting attempted for non-existent port "
        << port_num;
    return PartnerLocationMetric::kOther;
  }
  auto port = it->second.get();

  PartnerLocationMetric ret = PartnerLocationMetric::kOther;
  Panel panel = port->GetPanel();
  int num_ports_already_in_use = 0;
  Panel panel_already_in_use = Panel::kUnknown;
  int num_available_ports_on_left = 0;
  int num_available_ports_on_right = 0;

  if (!is_hotplug && panel == Panel::kLeft) {
    ret = PartnerLocationMetric::kLeftColdplugged;
    goto end;
  } else if (!is_hotplug && panel == Panel::kRight) {
    ret = PartnerLocationMetric::kRightColdplugged;
    goto end;
  }

  for (auto it = ports_.begin(); it != ports_.end(); it++) {
    if (it->first == port_num)
      continue;
    auto port_to_check = it->second.get();
    if (port_to_check->HasPartner()) {
      num_ports_already_in_use++;
      // It is okay to overwrite panel_already_in_use because when multiple
      // partners are in use, the metric won't track previous port connections.
      panel_already_in_use = port_to_check->GetPanel();
    } else if (port_to_check->GetPanel() == Panel::kLeft) {
      num_available_ports_on_left++;
    } else if (port_to_check->GetPanel() == Panel::kRight) {
      num_available_ports_on_right++;
    }
  }

  if (panel == Panel::kLeft) {
    if (num_available_ports_on_right == 0)
      ret = PartnerLocationMetric::kUserHasNoChoice;
    else if (num_ports_already_in_use == 0)
      ret = PartnerLocationMetric::kLeftFirst;
    else if (num_ports_already_in_use == 1 &&
             panel_already_in_use == Panel::kLeft)
      ret = PartnerLocationMetric::kLeftSecondSameSideWithFirst;
    else if (num_ports_already_in_use == 1 &&
             panel_already_in_use == Panel::kRight)
      ret = PartnerLocationMetric::kLeftSecondOppositeSideToFirst;
    else if (num_ports_already_in_use >= 2)
      ret = PartnerLocationMetric::kLeftThirdOrLater;
  } else if (panel == Panel::kRight) {
    if (num_available_ports_on_left == 0)
      ret = PartnerLocationMetric::kUserHasNoChoice;
    else if (num_ports_already_in_use == 0)
      ret = PartnerLocationMetric::kRightFirst;
    else if (num_ports_already_in_use == 1 &&
             panel_already_in_use == Panel::kRight)
      ret = PartnerLocationMetric::kRightSecondSameSideWithFirst;
    else if (num_ports_already_in_use == 1 &&
             panel_already_in_use == Panel::kLeft)
      ret = PartnerLocationMetric::kRightSecondOppositeSideToFirst;
    else if (num_ports_already_in_use >= 2)
      ret = PartnerLocationMetric::kRightThirdOrLater;
  }

end:
  return ret;
}

PowerSourceLocationMetric PortManager::GetPowerSourceLocationMetric(
    int port_num) {
  auto it = ports_.find(port_num);
  if (it == ports_.end()) {
    LOG(WARNING)
        << "Port location metric reporting attempted for non-existent port "
        << port_num;
    return PowerSourceLocationMetric::kOther;
  }
  auto port = it->second.get();

  Panel panel = port->GetPanel();
  int num_ports_on_left = 0;
  int num_ports_on_right = 0;
  Panel panel_prev = Panel::kUnknown;

  for (auto it = ports_.begin(); it != ports_.end(); it++) {
    auto port_to_check = it->second.get();
    if (port_to_check->GetPanel() == Panel::kLeft) {
      num_ports_on_left++;
    } else if (port_to_check->GetPanel() == Panel::kRight) {
      num_ports_on_right++;
    }
  }

  it = ports_.find(port_num_previously_sink);
  if (it != ports_.end()) {
    auto port_prev = it->second.get();
    panel_prev = port_prev->GetPanel();
  }

  PowerSourceLocationMetric ret = PowerSourceLocationMetric::kOther;
  if (panel == Panel::kLeft) {
    if (num_ports_on_right == 0)
      ret = PowerSourceLocationMetric::kUserHasNoChoice;
    else if (panel_prev == Panel::kUnknown)
      ret = PowerSourceLocationMetric::kLeftFirst;
    else if (panel_prev == Panel::kRight)
      ret = PowerSourceLocationMetric::kLeftSwitched;
    else if (panel_prev == Panel::kLeft)
      ret = PowerSourceLocationMetric::kLeftConstant;
  } else if (panel == Panel::kRight) {
    if (num_ports_on_left == 0)
      ret = PowerSourceLocationMetric::kUserHasNoChoice;
    else if (panel_prev == Panel::kUnknown)
      ret = PowerSourceLocationMetric::kRightFirst;
    else if (panel_prev == Panel::kLeft)
      ret = PowerSourceLocationMetric::kRightSwitched;
    else if (panel_prev == Panel::kRight)
      ret = PowerSourceLocationMetric::kRightConstant;
  }

  port_num_previously_sink = port_num;
  return ret;
}

void PortManager::SetPortsUsingDisplays(
    const std::vector<uint32_t>& port_nums) {
  for (auto port_num : port_nums) {
    auto it = ports_.find(port_num);
    if (it == ports_.end()) {
      LOG(WARNING) << "Display connection for non-existent port " << port_num;
      return;
    }
  }

  for (auto it = ports_.begin(); it != ports_.end(); it++) {
    auto port_num = it->first;
    auto port = it->second.get();
    port->SetIsDisplayConnected(std::find(port_nums.begin(), port_nums.end(),
                                          port_num) != port_nums.end());
  }
}

}  // namespace typecd
