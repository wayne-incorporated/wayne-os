// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/power_supply.h"

#include <algorithm>
#include <cmath>
#include <cstdlib>
#include <memory>
#include <optional>
#include <utility>

#include <fcntl.h>

#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file.h>
#include <base/files/file_enumerator.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/notreached.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <base/task/single_thread_task_runner.h>
#include <base/time/time.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/message.h>
#include <libec/display_soc_command.h>

#include "power_manager/common/battery_percentage_converter.h"
#include "power_manager/common/clock.h"
#include "power_manager/common/metrics_constants.h"
#include "power_manager/common/power_constants.h"
#include "power_manager/common/prefs.h"
#include "power_manager/common/tracing.h"
#include "power_manager/common/util.h"
#include "power_manager/powerd/system/dbus_wrapper.h"
#include "power_manager/powerd/system/udev.h"
#include "power_manager/proto_bindings/power_supply_properties.pb.h"

namespace power_manager::system {

namespace {

// sysfs reports only integer values.  For non-integral values, it scales them
// up by 10^6.  This factor scales them back down accordingly.
const double kDoubleScaleFactor = 0.000001;

// Default time interval between polls.
constexpr base::TimeDelta kDefaultPoll = base::Seconds(30);

// Default time interval between polls when the number of samples is less than
// |kMaxCurrentSamplesPref|.
constexpr base::TimeDelta kDefaultPollInitial = base::Seconds(1);

// Default values for |battery_stabilized_after_*_delay_|.
constexpr base::TimeDelta kDefaultBatteryStabilizedAfterStartupDelay =
    base::Seconds(5);
constexpr base::TimeDelta
    kDefaultBatteryStabilizedAfterLinePowerConnectedDelay = base::Seconds(5);
constexpr base::TimeDelta
    kDefaultBatteryStabilizedAfterLinePowerDisconnectedDelay = base::Seconds(5);
constexpr base::TimeDelta kDefaultBatteryStabilizedAfterResumeDelay =
    base::Seconds(5);

// Reads the contents of |filename| within |directory| into |out|, trimming
// trailing whitespace.  Returns true on success.
bool ReadAndTrimString(const base::FilePath& directory,
                       const std::string& filename,
                       std::string* out) {
  return util::MaybeReadStringFile(directory.Append(filename), out);
}

// Reads a 64-bit integer value from a file and returns true on success.
bool ReadInt64(const base::FilePath& directory,
               const std::string& filename,
               int64_t* out) {
  std::string buffer;
  if (!ReadAndTrimString(directory, filename, &buffer))
    return false;
  return base::StringToInt64(buffer, out);
}

// Reads an integer value and scales it to a double (see |kDoubleScaleFactor|.
// Returns 0.0 on failure.
double ReadScaledDouble(const base::FilePath& directory,
                        const std::string& filename) {
  int64_t value = 0;
  if (!ReadInt64(directory, filename, &value))
    return 0.0;

  return kDoubleScaleFactor * static_cast<double>(value);
}

// Returns the string surrounded by brackets via the |out| parameter.
// For example, returns "fun" given the string: "This format is not so [fun]"
// The return value is a boolean indicating true on success or false on failure.
bool ReadBracketSelectedString(const base::FilePath& directory,
                               const std::string& filename,
                               std::string* out) {
  std::string buffer;

  DCHECK(out);

  if (!ReadAndTrimString(directory, filename, &buffer))
    return false;
  size_t start = buffer.find("[");
  if (start == std::string::npos)
    return false;
  start++;
  size_t end = buffer.find("]", start);
  if (end == std::string::npos)
    return false;
  *out = buffer.substr(start, end - start);
  return true;
}

// Returns true if |type|, a power supply type read from a "type" file in
// sysfs, indicates USB BC1.2 types.
bool IsLowPowerUsbChargerType(const std::string& type) {
  return type == PowerSupply::kUsbType || type == PowerSupply::kUsbDcpType ||
         type == PowerSupply::kUsbCdpType || type == PowerSupply::kUsbAcaType;
}

// Returns true if |type| ends with with the PD_DRP common suffix.
bool IsPdDrpType(const std::string& type) {
  return base::EndsWith(type, PowerSupply::kUsbPdDrpType,
                        base::CompareCase::SENSITIVE);
}

// Returns the type of connection for the power supply. If the type
// cannot be read, kUnknownType is returned.
std::string ReadPowerSupplyType(const base::FilePath& path) {
  std::string type;
  if (!ReadAndTrimString(path, "type", &type))
    return PowerSupply::kUnknownType;

  if (type != PowerSupply::kUsbType)
    return type;

  // Some drivers in newer kernels (4.19+) report a static type of USB,
  // and separately report all supported connection types in a usb_type
  // file, with the active value in brackets. For example:
  // "Unknown SDP DCP CDP C PD [PD_DRP] BrickID".
  std::string usb_type;
  if (!ReadBracketSelectedString(path, "usb_type", &usb_type))
    return PowerSupply::kUsbType;

  // The exact type is unknown, but we still know it's USB.
  if (usb_type == PowerSupply::kUnknownType || usb_type.empty())
    return PowerSupply::kUsbType;

  // For compatibility with the old dynamic type, prepend "USB_"
  // to the type. The only exception is for the BrickId type,
  // which is unprefixed.
  if (usb_type != PowerSupply::kBrickIdType)
    usb_type = "USB_" + usb_type;

  return usb_type;
}

// Returns true if |path|, a sysfs directory, corresponds to an external
// peripheral (e.g. a wireless mouse or keyboard).
bool IsExternalPeripheral(const base::FilePath& path) {
  std::string scope;
  return ReadAndTrimString(path, "scope", &scope) && scope == "Device";
}

// Returns true if |path|, a sysfs directory, corresponds to a battery.
bool IsBatteryPresent(const base::FilePath& path) {
  int64_t present = 0;
  return ReadInt64(path, "present", &present) && present != 0;
}

// Returns a string describing |type|.
const char* ExternalPowerToString(PowerSupplyProperties::ExternalPower type) {
  switch (type) {
    case PowerSupplyProperties_ExternalPower_AC:
      return "AC";
    case PowerSupplyProperties_ExternalPower_USB:
      return "USB";
    case PowerSupplyProperties_ExternalPower_DISCONNECTED:
      return "none";
  }
  return "unknown";
}

/**
 * ExternalPowerType
 * ExternalPowerUnknown:      The external power type is unknown
 * ExternalPowerAC:           The device is connected to AC power (mains)
 * ExternalPowerUSB:          The device is connected to low-input USB power
 * ExternalPowerDisconnected: The device is not connected to external power
 *
 * A list of possible external line power types.
 * This list was created with the intention of being independent from
 *   changes to system_api. Do not change without updating fwupd to match.
 **/
enum class ExternalPowerType {
  ExternalPowerUnknown,
  ExternalPowerAC,
  ExternalPowerUSB,
  ExternalPowerDisconnected
};

// Returns an enum val of |type|.
ExternalPowerType ExternalPowerToExternalPowerEnum(
    PowerSupplyProperties::ExternalPower type) {
  switch (type) {
    case PowerSupplyProperties_ExternalPower_AC:
      return ExternalPowerType::ExternalPowerAC;
    case PowerSupplyProperties_ExternalPower_USB:
      return ExternalPowerType::ExternalPowerUSB;
    case PowerSupplyProperties_ExternalPower_DISCONNECTED:
      return ExternalPowerType::ExternalPowerDisconnected;
    default:
      return ExternalPowerType::ExternalPowerUnknown;
  }
}

/**
 * UpowerBatteryState:
 * @UpowerUnknown:        The device has an unknown battery state
 * @UpowerCharging:       The device is charging
 * @UpowerDischarging:    The device is discharging
 * @UpowerEmpty:          The device's battery is empty (no powerd mapping)
 * @UpowerFullyCharged:   The device is fully charged
 *
 * A subset of the possible battery states used in upower:
 *   https://upower.freedesktop.org/docs/Device.html#Device:State
 * Do not change without updating fwupd to match.
 **/
enum class UpowerBatteryState {
  UpowerUnknown,
  UpowerCharging,
  UpowerDischarging,
  UpowerEmpty,
  UpowerFullyCharged
};

// Returns a mapping of |curr_state| to its equivalent upower enum.
UpowerBatteryState BatteryStateToUpowerEnum(std::string curr_state) {
  if (curr_state == PowerSupply::kBatteryStatusCharging)
    return UpowerBatteryState::UpowerCharging;
  else if (curr_state == PowerSupply::kBatteryStatusDischarging)
    return UpowerBatteryState::UpowerDischarging;
  else if (curr_state == PowerSupply::kBatteryStatusFull)
    return UpowerBatteryState::UpowerFullyCharged;
  else
    return UpowerBatteryState::UpowerUnknown;
}

// Returns true if |port| is connected to a dedicated power source or dual-role
// device.
bool PortHasSourceOrDualRole(const PowerStatus::Port& port) {
  return port.role == PowerStatus::Port::Role::DEDICATED_SOURCE ||
         port.role == PowerStatus::Port::Role::DUAL_ROLE;
}

// Less-than comparator for PowerStatus::Port structs.
struct PortComparator {
  bool operator()(const PowerStatus::Port& a, const PowerStatus::Port& b) {
    return a.id < b.id;
  }
};

// Maps names read from kChargingPortsPref to the corresponding
// PowerSupplyProperties::PowerSource::Port values.
PowerSupplyProperties::PowerSource::Port GetPortLocationFromString(
    const std::string& name) {
  if (name == "LEFT")
    return PowerSupplyProperties_PowerSource_Port_LEFT;
  else if (name == "RIGHT")
    return PowerSupplyProperties_PowerSource_Port_RIGHT;
  else if (name == "BACK")
    return PowerSupplyProperties_PowerSource_Port_BACK;
  else if (name == "FRONT")
    return PowerSupplyProperties_PowerSource_Port_FRONT;
  else if (name == "LEFT_FRONT")
    return PowerSupplyProperties_PowerSource_Port_LEFT_FRONT;
  else if (name == "LEFT_BACK")
    return PowerSupplyProperties_PowerSource_Port_LEFT_BACK;
  else if (name == "RIGHT_FRONT")
    return PowerSupplyProperties_PowerSource_Port_RIGHT_FRONT;
  else if (name == "RIGHT_BACK")
    return PowerSupplyProperties_PowerSource_Port_RIGHT_BACK;
  else if (name == "BACK_LEFT")
    return PowerSupplyProperties_PowerSource_Port_BACK_LEFT;
  else if (name == "BACK_RIGHT")
    return PowerSupplyProperties_PowerSource_Port_BACK_RIGHT;
  else
    return PowerSupplyProperties_PowerSource_Port_UNKNOWN;
}

// Maps names read from power supply |type| sysfs nodes to the corresponding
// PowerSupplyProperties::PowerSource::Type values.
PowerSupplyProperties::PowerSource::Type GetPowerSourceTypeFromString(
    const std::string& type) {
  if (type == PowerSupply::kMainsType) {
    return PowerSupplyProperties_PowerSource_Type_MAINS;
  } else if (type == PowerSupply::kUsbCType ||
             type == PowerSupply::kUsbPdType || IsPdDrpType(type) ||
             type == PowerSupply::kBrickIdType) {
    return PowerSupplyProperties_PowerSource_Type_USB_C;
  } else if (type == PowerSupply::kUsbType ||
             type == PowerSupply::kUsbAcaType ||
             type == PowerSupply::kUsbCdpType ||
             type == PowerSupply::kUsbDcpType) {
    return PowerSupplyProperties_PowerSource_Type_USB_BC_1_2;
  }
  return PowerSupplyProperties_PowerSource_Type_OTHER;
}

}  // namespace

void CopyPowerStatusToProtocolBuffer(const PowerStatus& status,
                                     PowerSupplyProperties* proto) {
  DCHECK(proto);
  proto->Clear();
  proto->set_external_power(status.external_power);
  proto->set_battery_state(status.battery_state);
  proto->set_supports_dual_role_devices(status.supports_dual_role_devices);

  if (status.battery_state != PowerSupplyProperties_BatteryState_NOT_PRESENT) {
    proto->set_battery_percent(status.display_battery_percentage);

    // Show the user the time until powerd will shut down the system
    // automatically rather than the time until the battery is completely empty.
    proto->set_battery_time_to_empty_sec(
        status.battery_time_to_shutdown.InSeconds());
    proto->set_battery_time_to_full_sec(
        status.battery_time_to_full.InSeconds());
    proto->set_is_calculating_battery_time(status.is_calculating_battery_time);

    if (status.battery_state == PowerSupplyProperties_BatteryState_FULL ||
        status.battery_state == PowerSupplyProperties_BatteryState_CHARGING) {
      proto->set_battery_discharge_rate(-status.battery_energy_rate);
    } else {
      proto->set_battery_discharge_rate(status.battery_energy_rate);
    }

    // Parameters for the Adaptive Charging UI
    proto->set_adaptive_charging_supported(status.adaptive_charging_supported);
    proto->set_adaptive_charging_heuristic_enabled(
        status.adaptive_charging_heuristic_enabled);
    proto->set_adaptive_delaying_charge(status.adaptive_delaying_charge);

    // Cros_healthd is interested in the following items for reporting
    // telemetry data.
    proto->set_battery_vendor(status.battery_vendor);
    proto->set_battery_voltage(status.battery_voltage);
    proto->set_battery_cycle_count(status.battery_cycle_count);
    proto->set_battery_serial_number(status.battery_serial_number);
    proto->set_battery_charge_full_design(status.battery_charge_full_design);
    proto->set_battery_charge_full(status.battery_charge_full);
    proto->set_battery_voltage_min_design(status.battery_voltage_min_design);
    proto->set_battery_charge(status.battery_charge);
    proto->set_battery_model_name(status.battery_model_name);
    proto->set_battery_current(status.battery_current);
    proto->set_battery_technology(status.battery_technology);
    proto->set_battery_status(status.battery_status_string);
  }

  for (auto port : status.ports) {
    // Chrome is only interested in ports that are currently in a state where
    // they can deliver power.
    if (!PortHasSourceOrDualRole(port))
      continue;

    PowerSupplyProperties::PowerSource* source =
        proto->add_available_external_power_source();
    source->set_id(port.id);
    source->set_port(port.location);
    source->set_type(GetPowerSourceTypeFromString(port.type));
    source->set_manufacturer_id(port.manufacturer_id);
    source->set_model_id(port.model_id);
    source->set_max_power(port.max_power);
    source->set_active_by_default(port.active_by_default);
  }
  if (!status.external_power_source_id.empty())
    proto->set_external_power_source_id(status.external_power_source_id);

  proto->set_preferred_minimum_external_power(
      status.preferred_minimum_external_power);
}

std::string GetPowerStatusBatteryDebugString(const PowerStatus& status) {
  if (!status.battery_is_present)
    return std::string();

  std::string output;
  switch (status.external_power) {
    case PowerSupplyProperties_ExternalPower_AC:
    case PowerSupplyProperties_ExternalPower_USB: {
      output = base::StringPrintf("On %s (%s",
                                  ExternalPowerToString(status.external_power),
                                  status.line_power_type.c_str());

      // Add details in the form ", 1.253A at 14.7V, max 2.0A at 15.0V",
      // omitting unavailable data.
      std::string details;
      if (status.has_line_power_current)
        details = base::StringPrintf("%.3fA", status.line_power_current);
      if (status.has_line_power_voltage) {
        details += (details.empty() ? "" : " at ") +
                   base::StringPrintf("%.1fV", status.line_power_voltage);
      }
      if (status.line_power_max_current && status.line_power_max_voltage) {
        details += (details.empty() ? "" : ", ") +
                   base::StringPrintf("max %.1fA at %.1fV",
                                      status.line_power_max_current,
                                      status.line_power_max_voltage);
      }
      if (!details.empty())
        output += ", " + details;

      output += ") with battery at ";
    } break;
    case PowerSupplyProperties_ExternalPower_DISCONNECTED:
      output = "On battery at ";
      break;
  }

  int rounded_actual = lround(status.battery_percentage);
  int rounded_display = lround(status.display_battery_percentage);
  output += base::StringPrintf("%d%%", rounded_actual);
  if (rounded_actual != rounded_display)
    output += base::StringPrintf(" (displayed as %d%%)", rounded_display);
  output +=
      base::StringPrintf(", %.3f/%.3fAh at %.3fA", status.battery_charge,
                         status.battery_charge_full, status.battery_current);

  switch (status.battery_state) {
    case PowerSupplyProperties_BatteryState_FULL:
      output += ", full";
      break;
    case PowerSupplyProperties_BatteryState_CHARGING:
      if (status.battery_time_to_full >= base::TimeDelta()) {
        output += ", " + util::TimeDeltaToString(status.battery_time_to_full) +
                  " until full";
        if (status.is_calculating_battery_time)
          output += " (calculating)";
      } else {
        output += ", no estimate due to low averaged current";
      }
      break;
    case PowerSupplyProperties_BatteryState_DISCHARGING:
      if (status.battery_time_to_empty >= base::TimeDelta()) {
        output += ", " + util::TimeDeltaToString(status.battery_time_to_empty) +
                  " until empty";
        if (status.is_calculating_battery_time) {
          output += " (calculating)";
        } else if (status.battery_time_to_shutdown !=
                   status.battery_time_to_empty) {
          output += base::StringPrintf(
              " (%s until shutdown)",
              util::TimeDeltaToString(status.battery_time_to_shutdown).c_str());
        }
      } else {
        output += ", no estimate due to low averaged current";
      }
      break;
    case PowerSupplyProperties_BatteryState_NOT_PRESENT:
      break;
  }

  return output;
}

metrics::PowerSupplyType GetPowerSupplyTypeMetric(const std::string& type) {
  if (type == PowerSupply::kMainsType)
    return metrics::PowerSupplyType::MAINS;
  else if (type == PowerSupply::kUsbType)
    return metrics::PowerSupplyType::USB;
  else if (type == PowerSupply::kUsbAcaType)
    return metrics::PowerSupplyType::USB_ACA;
  else if (type == PowerSupply::kUsbCdpType)
    return metrics::PowerSupplyType::USB_CDP;
  else if (type == PowerSupply::kUsbDcpType)
    return metrics::PowerSupplyType::USB_DCP;
  else if (type == PowerSupply::kUsbCType)
    return metrics::PowerSupplyType::USB_C;
  else if (type == PowerSupply::kUsbPdType)
    return metrics::PowerSupplyType::USB_PD;
  else if (IsPdDrpType(type))
    return metrics::PowerSupplyType::USB_PD_DRP;
  else if (type == PowerSupply::kBrickIdType)
    return metrics::PowerSupplyType::BRICK_ID;
  else
    return metrics::PowerSupplyType::OTHER;
}

bool PowerStatus::Port::operator==(const Port& o) const {
  return id == o.id && role == o.role && type == o.type &&
         manufacturer_id == o.manufacturer_id && model_id == o.model_id &&
         active_by_default == o.active_by_default;
}

// static
bool PowerSupply::ConnectedSourcesAreEqual(const PowerStatus& a,
                                           const PowerStatus& b) {
  auto a_it = a.ports.begin();
  auto b_it = b.ports.begin();

  while (true) {
    // Walk each iterator forward to the next port with something connected that
    // can supply power.
    for (; a_it != a.ports.end() && !PortHasSourceOrDualRole(*a_it); ++a_it) {
    }
    for (; b_it != b.ports.end() && !PortHasSourceOrDualRole(*b_it); ++b_it) {
    }

    // If we reached the ends of both lists without finding any mismatches,
    // report equality.
    const bool a_done = a_it == a.ports.end();
    const bool b_done = b_it == b.ports.end();
    if (a_done && b_done)
      return true;

    // If we reached the end of one list but have a connected port in the other,
    // or if the connected ports don't match, report inequality.
    if (a_done != b_done || !(*a_it == *b_it))
      return false;

    a_it++;
    b_it++;
  }
  NOTREACHED();
}

base::TimeTicks PowerSupply::TestApi::GetCurrentTime() const {
  return power_supply_->clock_->GetCurrentTime();
}

void PowerSupply::TestApi::SetCurrentTime(base::TimeTicks now) {
  power_supply_->clock_->set_current_time_for_testing(now);
}

void PowerSupply::TestApi::AdvanceTime(base::TimeDelta interval) {
  power_supply_->clock_->set_current_time_for_testing(GetCurrentTime() +
                                                      interval);
}

bool PowerSupply::TestApi::TriggerPollTimeout() {
  if (!power_supply_->poll_timer_.IsRunning())
    return false;

  power_supply_->poll_timer_.Stop();
  power_supply_->OnPollTimeout();
  return true;
}

const char PowerSupply::kUdevSubsystem[] = "power_supply";
const char PowerSupply::kChargeControlLimitMaxFile[] =
    "charge_control_limit_max";

const char PowerSupply::kBatteryType[] = "Battery";
const char PowerSupply::kUnknownType[] = "Unknown";
const char PowerSupply::kMainsType[] = "Mains";
const char PowerSupply::kUsbType[] = "USB";
const char PowerSupply::kUsbAcaType[] = "USB_ACA";
const char PowerSupply::kUsbCdpType[] = "USB_CDP";
const char PowerSupply::kUsbDcpType[] = "USB_DCP";
const char PowerSupply::kUsbCType[] = "USB_C";
const char PowerSupply::kUsbPdType[] = "USB_PD";
// Cover both USB_PD_DRP in the "type" file of older kernels, as well as
// PD_DRP in the "usb_type" file of 4.19+ kernels.
const char PowerSupply::kUsbPdDrpType[] = "PD_DRP";
const char PowerSupply::kBrickIdType[] = "BrickID";

const char PowerSupply::kBatteryStatusCharging[] = "Charging";
const char PowerSupply::kBatteryStatusDischarging[] = "Discharging";
const char PowerSupply::kBatteryStatusNotCharging[] = "Not charging";
const char PowerSupply::kBatteryStatusFull[] = "Full";
const char PowerSupply::kLinePowerStatusCharging[] = "Charging";

const double PowerSupply::kLowBatteryShutdownSafetyPercent = 5.0;

PowerSupply::PowerSupply()
    : clock_(std::make_unique<Clock>()), weak_ptr_factory_(this) {
  // TODO(b/207716926): Temporary change to find FD leaks in powerd.
  temp_file_ = base::OpenFile(base::FilePath("/dev/null"), "r");
}

PowerSupply::~PowerSupply() {
  if (udev_)
    udev_->RemoveSubsystemObserver(kUdevSubsystem, this);

  if (temp_file_ != nullptr) {
    base::CloseFile(temp_file_);
    temp_file_ = nullptr;
  }
}

void PowerSupply::Init(
    const base::FilePath& power_supply_path,
    const base::FilePath& cros_ec_path,
    ec::EcCommandFactoryInterface* ec_command_factory,
    PrefsInterface* prefs,
    UdevInterface* udev,
    system::DBusWrapperInterface* dbus_wrapper,
    BatteryPercentageConverter* battery_percentage_converter) {
  udev_ = udev;
  udev_->AddSubsystemObserver(kUdevSubsystem, this);

  prefs_ = prefs;
  power_supply_path_ = power_supply_path;
  cros_ec_path_ = cros_ec_path;
  ec_command_factory_ = ec_command_factory;

  dbus_wrapper_ = dbus_wrapper;
  dbus_wrapper->ExportMethod(
      kGetPowerSupplyPropertiesMethod,
      base::BindRepeating(&PowerSupply::OnGetPowerSupplyPropertiesMethodCall,
                          weak_ptr_factory_.GetWeakPtr()));
  dbus_wrapper->ExportMethod(
      kGetBatteryStateMethod,
      base::BindRepeating(&PowerSupply::OnGetBatteryStateMethodCall,
                          weak_ptr_factory_.GetWeakPtr()));
  dbus_wrapper->ExportMethod(
      kSetPowerSourceMethod,
      base::BindRepeating(&PowerSupply::OnSetPowerSourceMethodCall,
                          weak_ptr_factory_.GetWeakPtr()));

  battery_percentage_converter_ = battery_percentage_converter;

  prefs_->GetBool(kFactoryModePref, &factory_mode_);
  prefs_->GetBool(kMultipleBatteriesPref, &allow_multiple_batteries_);
  prefs_->GetBool(kHasBarreljackPref, &has_barreljack_);

  poll_delay_ = GetMsPref(kBatteryPollIntervalPref).value_or(kDefaultPoll);
  poll_delay_initial_ =
      GetMsPref(kBatteryPollIntervalInitialPref).value_or(kDefaultPollInitial);
  battery_stabilized_after_startup_delay_ =
      GetMsPref(kBatteryStabilizedAfterStartupMsPref)
          .value_or(kDefaultBatteryStabilizedAfterStartupDelay);
  battery_stabilized_after_line_power_connected_delay_ =
      GetMsPref(kBatteryStabilizedAfterLinePowerConnectedMsPref)
          .value_or(kDefaultBatteryStabilizedAfterLinePowerConnectedDelay);
  battery_stabilized_after_line_power_disconnected_delay_ =
      GetMsPref(kBatteryStabilizedAfterLinePowerDisconnectedMsPref)
          .value_or(kDefaultBatteryStabilizedAfterLinePowerDisconnectedDelay);
  battery_stabilized_after_resume_delay_ =
      GetMsPref(kBatteryStabilizedAfterResumeMsPref)
          .value_or(kDefaultBatteryStabilizedAfterResumeDelay);

  prefs_->GetDouble(kUsbMinAcWattsPref, &usb_min_ac_watts_);

  int64_t shutdown_time_sec = 0;
  if (prefs_->GetInt64(kLowBatteryShutdownTimePref, &shutdown_time_sec)) {
    low_battery_shutdown_time_ = base::Seconds(shutdown_time_sec);
  }

  prefs_->GetDouble(kPowerSupplyFullFactorPref, &full_factor_);
  full_factor_ = std::min(std::max(kEpsilon, full_factor_), 1.0);
  prefs_->GetDouble(kLowBatteryShutdownPercentPref,
                    &low_battery_shutdown_percent_);

  // The percentage-based threshold takes precedence over the time-based
  // threshold. This behavior is duplicated in check_powerd_config.
  if (low_battery_shutdown_percent_ > 0.0) {
    low_battery_shutdown_time_ = base::TimeDelta();
  }

  LOG(INFO) << "Using full factor of " << full_factor_;

  import_display_soc_ = GetDisplayStateOfChargeFromEC(nullptr);

  int64_t samples = 0;
  CHECK(prefs_->GetInt64(kMaxCurrentSamplesPref, &samples));
  current_samples_on_line_power_ = std::make_unique<RollingAverage>(samples);
  current_samples_on_battery_power_ = std::make_unique<RollingAverage>(samples);

  CHECK(prefs_->GetInt64(kMaxChargeSamplesPref, &samples));
  charge_samples_ = std::make_unique<RollingAverage>(samples);

  LOG(INFO) << "Using low battery time threshold of "
            << low_battery_shutdown_time_.InSeconds()
            << " secs and using low battery percent threshold of "
            << low_battery_shutdown_percent_;

  std::string ports_string;
  if (prefs_->GetString(kChargingPortsPref, &ports_string)) {
    base::TrimWhitespaceASCII(ports_string, base::TRIM_TRAILING, &ports_string);
    base::StringPairs pairs;
    if (!base::SplitStringIntoKeyValuePairs(ports_string, ' ', '\n', &pairs))
      LOG(FATAL) << "Failed parsing " << kChargingPortsPref << " pref";
    for (const auto& pair : pairs) {
      const PowerSupplyProperties::PowerSource::Port location =
          GetPortLocationFromString(pair.second);
      if (location == PowerSupplyProperties_PowerSource_Port_UNKNOWN) {
        LOG(FATAL) << "Unrecognized port \"" << pair.second << "\" for \""
                   << pair.first << "\" in " << kChargingPortsPref << " pref";
      }
      if (!port_names_.insert(std::make_pair(pair.first, location)).second) {
        LOG(FATAL) << "Duplicate entry for \"" << pair.first << "\" in "
                   << kChargingPortsPref << " pref";
      }
    }
  }

  DeferBatterySampling(battery_stabilized_after_startup_delay_);
  SchedulePoll();
}

void PowerSupply::AddObserver(PowerSupplyObserver* observer) {
  DCHECK(observer);
  observers_.AddObserver(observer);
}

void PowerSupply::RemoveObserver(PowerSupplyObserver* observer) {
  DCHECK(observer);
  observers_.RemoveObserver(observer);
}

PowerStatus PowerSupply::GetPowerStatus() const {
  return power_status_;
}

bool PowerSupply::RefreshImmediately() {
  return PerformUpdate(UpdatePolicy::UNCONDITIONALLY,
                       NotifyPolicy::ASYNCHRONOUSLY);
}

void PowerSupply::SetSuspended(bool suspended) {
  if (is_suspended_ == suspended)
    return;

  is_suspended_ = suspended;
  if (is_suspended_) {
    VLOG(1) << "Stopping polling due to suspend";
    poll_timer_.Stop();
    current_poll_delay_for_testing_ = base::TimeDelta();
  } else {
    DeferBatterySampling(battery_stabilized_after_resume_delay_);
    charge_samples_->Clear();
    current_samples_on_line_power_->Clear();
    has_max_samples_ = false;
    PerformUpdate(UpdatePolicy::UNCONDITIONALLY, NotifyPolicy::ASYNCHRONOUSLY);
  }
}

void PowerSupply::SetAdaptiveChargingSupported(bool supported) {
  adaptive_charging_supported_ = supported;
}

void PowerSupply::SetAdaptiveChargingHeuristicEnabled(bool enabled) {
  adaptive_charging_heuristic_enabled_ = enabled;
}

void PowerSupply::SetAdaptiveCharging(
    const base::TimeDelta& target_time_to_full, double hold_percent) {
  DCHECK(adaptive_charging_supported_);
  adaptive_charging_target_time_to_full_ = target_time_to_full;
  adaptive_charging_hold_percent_ = hold_percent;
  adaptive_delaying_charge_ = true;
}

void PowerSupply::ClearAdaptiveChargingChargeDelay() {
  adaptive_delaying_charge_ = false;
  adaptive_charging_heuristic_enabled_ = false;
  adaptive_charging_target_time_to_full_ = base::TimeDelta();
}

void PowerSupply::OnUdevEvent(const UdevEvent& event) {
  VLOG(1) << "Got udev event for " << event.device_info.sysname;
  // Bail out of the update if the available power sources didn't actually
  // change to avoid recording new samples and updating battery estimates in
  // response to spurious udev events (see http://crosbug.com/p/37403).
  if (!is_suspended_ && !IsSupplyIgnored(event.device_info.sysname)) {
    PerformUpdate(UpdatePolicy::ONLY_IF_STATE_CHANGED,
                  NotifyPolicy::SYNCHRONOUSLY);
  }
}

bool PowerSupply::GetDisplayStateOfChargeFromEC(double* display_soc) {
  if (!import_display_soc_)
    return false;

  base::ScopedFD ec_fd =
      base::ScopedFD(open(cros_ec_path_.value().c_str(), O_RDWR));

  if (!ec_fd.is_valid()) {
    // This is expect on systems without the CrOS EC.
    LOG(INFO) << "Failed to open " << cros_ec_path_;
    return false;
  }

  auto cmd = ec_command_factory_->DisplayStateOfChargeCommand();
  if (!cmd->Run(ec_fd.get())) {
    // This is expected if EC doesn't export display SoC.
    LOG(INFO) << "Failed to read display SoC from EC";
    return false;
  }

  if (display_soc != nullptr) {
    *display_soc = cmd->CurrentPercentCharge();
  }

  return true;
}

std::string PowerSupply::GetIdForPath(const base::FilePath& path) const {
  DCHECK(power_supply_path_.IsParent(path))
      << path.value() << " isn't a child of " << power_supply_path_.value();
  return path.BaseName().value();
}

base::FilePath PowerSupply::GetPathForId(const std::string& id) const {
  // Double-check that nobody's playing games with bogus IDs.
  if (id.empty() || id == "." || id == ".." ||
      id.find('/') != std::string::npos) {
    LOG(WARNING) << "Got invalid ID \"" << id << "\"";
    return base::FilePath();
  }
  base::FilePath path = power_supply_path_.Append(id);
  if (!base::DirectoryExists(path)) {
    LOG(WARNING) << "Got invalid ID \"" << id << "\"";
    return base::FilePath();
  }
  return path;
}

std::optional<base::TimeDelta> PowerSupply::GetMsPref(
    const std::string& pref_name) const {
  int64_t duration_ms;
  if (prefs_->GetInt64(pref_name, &duration_ms))
    return base::Milliseconds(duration_ms);
  return std::nullopt;
}

void PowerSupply::DeferBatterySampling(base::TimeDelta stabilized_delay) {
  const base::TimeTicks now = clock_->GetCurrentTime();
  battery_stabilized_timestamp_ =
      std::max(battery_stabilized_timestamp_, now + stabilized_delay);
  VLOG(1) << "Waiting "
          << (battery_stabilized_timestamp_ - now).InMilliseconds()
          << " ms for battery current and charge to stabilize";
}

bool PowerSupply::UpdatePowerStatus(UpdatePolicy policy) {
  CHECK(prefs_) << "PowerSupply::Init() wasn't called";

  VLOG(1) << "Updating power status";
  PowerStatus status;

  // Track whether we found at least one (possibly offline) power source.
  bool saw_power_source = false;

  std::vector<base::FilePath> battery_paths;

  // Iterate through sysfs's power supply information.
  base::FileEnumerator file_enum(power_supply_path_, false,
                                 base::FileEnumerator::DIRECTORIES);
  for (base::FilePath path = file_enum.Next(); !path.empty();
       path = file_enum.Next()) {
    if (IsExternalPeripheral(path))
      continue;

    if (IsSupplyIgnored(path.BaseName().value()))
      continue;

    std::string type;
    if (!base::ReadFileToString(path.Append("type"), &type))
      continue;
    base::TrimWhitespaceASCII(type, base::TRIM_TRAILING, &type);

    saw_power_source = true;

    // The battery state is dependent on the line power state, so defer reading
    // it until all other directories have been examined.
    if (type == kBatteryType)
      battery_paths.push_back(path);
    else
      ReadLinePowerDirectory(path, &status);
  }

  // If no battery was found, assume that the system is actually on AC power.
  if (!status.line_power_on &&
      (battery_paths.empty() || !IsBatteryPresent(battery_paths[0]))) {
    if (saw_power_source) {
      // Batteryless Chromeboxes sometimes don't report any power sources. If we
      // saw at least one source but it wasn't online, the battery status might
      // be getting misreported, though; log a warning.
      LOG(WARNING) << "Found neither line power nor a battery; assuming that "
                   << "line power is connected";
    }
    status.line_power_on = true;
    status.line_power_type = kMainsType;
    status.external_power = PowerSupplyProperties_ExternalPower_AC;
  }

  // Sort the port list as needed by ConnectedSourcesAreEqual().
  std::sort(status.ports.begin(), status.ports.end(), PortComparator());

  status.preferred_minimum_external_power = usb_min_ac_watts_;

  // Even though we haven't successfully finished initializing the status yet,
  // save what we have so far so that if we bail out early due to a messed-up
  // battery we'll at least start out knowing whether line power is connected.
  if (!power_status_initialized_)
    power_status_ = status;

  // Finally, read the battery status.
  std::sort(battery_paths.begin(), battery_paths.end());
  if (!allow_multiple_batteries_ && battery_paths.size() > 1) {
    for (size_t i = 1; i < battery_paths.size(); i++)
      LOG(WARNING) << "Ignoring extra battery " << battery_paths[i].value();
    battery_paths.resize(1);
  }
  if (battery_paths.size() == 1) {
    if (!ReadBatteryDirectory(battery_paths[0], &status,
                              false /* allow_empty */))
      return false;
  } else if (battery_paths.size() > 1) {
    if (!ReadMultipleBatteryDirectories(battery_paths, &status))
      return false;
  }

  // Bail out before recording charge and current samples if this was a spurious
  // update request. A change in |battery_charge_full| is used as a proxy for a
  // battery being added or removed.
  if (policy == UpdatePolicy::ONLY_IF_STATE_CHANGED &&
      power_status_initialized_ &&
      status.external_power == power_status_.external_power &&
      status.battery_state == power_status_.battery_state &&
      status.battery_percentage == power_status_.battery_percentage &&
      ConnectedSourcesAreEqual(status, power_status_) &&
      status.battery_charge_full == power_status_.battery_charge_full)
    return false;

  // Update running averages and use them to compute battery estimates.
  if (status.battery_is_present) {
    if (power_status_initialized_ &&
        status.line_power_on != power_status_.line_power_on) {
      DeferBatterySampling(
          status.line_power_on
              ? battery_stabilized_after_line_power_connected_delay_
              : battery_stabilized_after_line_power_disconnected_delay_);
      charge_samples_->Clear();
      has_max_samples_ = false;

      // Chargers can deliver highly-variable currents depending on various
      // factors (e.g. negotiated current for USB chargers, charge level, etc.).
      // If one was just connected, throw away the previous average.
      if (status.line_power_on)
        current_samples_on_line_power_->Clear();
    }

    base::TimeTicks now = clock_->GetCurrentTime();
    if (now >= battery_stabilized_timestamp_) {
      charge_samples_->AddSample(status.battery_charge, now);

      if (status.battery_current > 0.0) {
        const double signed_current =
            (status.battery_state ==
             PowerSupplyProperties_BatteryState_DISCHARGING)
                ? -status.battery_current
                : status.battery_current;

        const auto& current_samples = status.line_power_on
                                          ? current_samples_on_line_power_
                                          : current_samples_on_battery_power_;
        current_samples->AddSample(signed_current, now);
        if (!has_max_samples_)
          has_max_samples_ = current_samples->HasMaxSamples();
        num_zero_samples_ = 0;
      } else {
        num_zero_samples_++;
      }
    }

    UpdateObservedBatteryChargeRate(&status);
    status.is_calculating_battery_time = !UpdateBatteryTimeEstimates(&status);
    status.battery_below_shutdown_threshold =
        status.battery_is_present && IsBatteryBelowShutdownThreshold(status);

    // Update and modify values based on Adaptive Charging
    status.adaptive_charging_supported = adaptive_charging_supported_;
    status.adaptive_charging_heuristic_enabled =
        adaptive_charging_heuristic_enabled_;
    status.adaptive_delaying_charge = adaptive_delaying_charge_;

    if (adaptive_delaying_charge_) {
      status.display_battery_percentage = adaptive_charging_hold_percent_;
      // If `adaptive_charging_target_time_to_full_` is the zero value, there's
      // no current target for fully charging.
      status.battery_time_to_full = adaptive_charging_target_time_to_full_;
    }
  }

  power_status_ = status;
  power_status_initialized_ = true;
  return true;
}

void PowerSupply::ReadLinePowerDirectory(const base::FilePath& path,
                                         PowerStatus* status) {
  // Add the port and fill in its details as we go.
  status->ports.emplace_back();
  PowerStatus::Port* port = &status->ports.back();
  port->id = GetIdForPath(path);
  const auto location_it = port_names_.find(path.BaseName().value());
  if (location_it != port_names_.end())
    port->location = location_it->second;

  // Bidirectional/dual-role ports export a "status" field.
  std::string line_status;
  ReadAndTrimString(path, "status", &line_status);
  const bool dual_role_port = !line_status.empty();
  if (dual_role_port)
    status->supports_dual_role_devices = true;

  // An "Unknown" type indicates a sink-only device that can't supply power.
  port->type = ReadPowerSupplyType(path);
  if (port->type == kUnknownType)
    return;

  const bool dual_role_connected = IsPdDrpType(port->type);

  // If "online" is 0, nothing is connected unless it is USB_PD_DRP, in which
  // case a value of 0 indicates we're connected to a dual-role device but not
  // sinking power.
  int64_t online = 0;
  if ((!ReadInt64(path, "online", &online) || !online) && !dual_role_connected)
    return;

  // If we've made it this far, there's a dedicated source or dual-role device
  // connected.
  port->role = dual_role_connected ? PowerStatus::Port::Role::DUAL_ROLE
                                   : PowerStatus::Port::Role::DEDICATED_SOURCE;

  // Chargers connected to non-dual-role Chromebook systems are always active by
  // default. The USB PD kernel driver will report "USB_PD_DRP" for dual-role
  // devices (which aren't active by default). See http://crbug.com/459412 for
  // additional discussion.
  port->active_by_default = !dual_role_port || !dual_role_connected;

  ReadAndTrimString(path, "manufacturer", &port->manufacturer_id);
  ReadAndTrimString(path, "model_name", &port->model_id);

  const double max_voltage = ReadScaledDouble(path, "voltage_max_design");
  const double max_current = ReadScaledDouble(path, "current_max");
  port->max_power = max_voltage * max_current;  // watts

  VLOG(1) << "Added power source " << port->id << ":"
          << " location=" << port->location
          << " manufacturer=" << port->manufacturer_id
          << " model=" << port->model_id << " max_power=" << port->max_power
          << " active_by_default=" << port->active_by_default;

  // If this is a dual-role device, make sure that we're actually getting
  // charged by it.
  if (dual_role_port && line_status != kLinePowerStatusCharging)
    return;

  // We don't support (or expect) multiple online line power sources, but an
  // extra "Mains" source can be reported if a system supports both Type-C and
  // barrel jack charging and is using the ACPI driver. Favor the non-Mains
  // source in this case.
  if (!status->line_power_path.empty()) {
    if (port->type == PowerSupply::kMainsType)
      return;

    if (status->line_power_type != PowerSupply::kMainsType) {
      LOG(WARNING) << "Skipping additional line power source at "
                   << path.value() << " (previously saw "
                   << status->line_power_path << ")";
      return;
    }

    // If we get here, then we're replacing an already-seen Mains source with
    // this new non-Mains source.
  }

  status->line_power_on = true;
  status->line_power_path = path.value();
  status->line_power_type = port->type;
  status->line_power_max_voltage = max_voltage;
  status->line_power_max_current = max_current;
  if (base::PathExists(path.Append("voltage_now"))) {
    status->line_power_voltage = ReadScaledDouble(path, "voltage_now");
    status->has_line_power_voltage = true;
  }
  if (base::PathExists(path.Append("current_now"))) {
    status->line_power_current = ReadScaledDouble(path, "current_now");
    status->has_line_power_current = true;
  }
  if (base::PathExists(path.Append("voltage_max_design"))) {
    status->line_power_max_voltage =
        ReadScaledDouble(path, "voltage_max_design");
    status->has_line_power_max_voltage = true;
  }
  if (base::PathExists(path.Append("current_max"))) {
    status->line_power_max_current = ReadScaledDouble(path, "current_max");
    status->has_line_power_max_current = true;
  }

  // The USB PD driver reports the maximum power as being 0 watts while it's
  // being determined; avoid reporting a low-power charger in that case.
  const bool max_power_is_less_than_ac_min =
      port->max_power > 0.0 && port->max_power < usb_min_ac_watts_;

  if (!dual_role_port && IsLowPowerUsbChargerType(port->type)) {
    // On spring, report all non-official chargers (which are reported as type
    // USB* rather than Mains) as being low-power.
    status->external_power = PowerSupplyProperties_ExternalPower_USB;
  } else if (dual_role_port && max_power_is_less_than_ac_min) {
    // For dual-role USB PD devices, check whether the maximum supported power
    // is below the configured threshold.
    status->external_power = PowerSupplyProperties_ExternalPower_USB;
  } else {
    // Otherwise, report a high-power source.
    status->external_power = PowerSupplyProperties_ExternalPower_AC;
  }
  status->external_power_source_id = port->id;

  VLOG(1) << "Found line power of type \"" << status->line_power_type
          << "\" at " << path.value();
}

bool PowerSupply::ReadBatteryDirectory(const base::FilePath& path,
                                       PowerStatus* status,
                                       bool allow_empty) {
  VLOG(1) << "Reading battery status from " << path.value();
  status->battery_path = path.value();
  status->battery_is_present = IsBatteryPresent(path);
  if (!status->battery_is_present)
    return true;

  ReadAndTrimString(path, "status", &status->battery_status_string);

  // POWER_SUPPLY_PROP_VENDOR does not seem to be a valid property
  // defined in <linux/power_supply.h>.
  ReadAndTrimString(
      path,
      base::PathExists(path.Append("manufacturer")) ? "manufacturer" : "vendor",
      &status->battery_vendor);
  ReadAndTrimString(path, "model_name", &status->battery_model_name);
  ReadAndTrimString(path, "technology", &status->battery_technology);

  double voltage = ReadScaledDouble(path, "voltage_now");
  status->battery_voltage = voltage;

  int64_t cycle_count = 0;
  if (ReadInt64(path, "cycle_count", &cycle_count)) {
    status->battery_cycle_count = cycle_count;
  }

  ReadAndTrimString(path, "serial_number", &status->battery_serial_number);

  // Attempt to determine nominal voltage for time-remaining calculations. This
  // may or may not be the same as the instantaneous voltage |battery_voltage|,
  // as voltage levels vary over the time the battery is charged or discharged.
  // Some batteries don't have a voltage_min/max_design attribute, so just use
  // the current voltage in that case.
  double nominal_voltage = voltage;
  // TODO(khegde): https://crbug.com/980246
  if (base::PathExists(path.Append("voltage_min_design"))) {
    status->battery_voltage_min_design =
        ReadScaledDouble(path, "voltage_min_design");
    nominal_voltage = status->battery_voltage_min_design;
  } else if (base::PathExists(path.Append("voltage_max_design"))) {
    nominal_voltage = ReadScaledDouble(path, "voltage_max_design");
  }

  // Nominal voltage is not required to obtain the charge level; if it's
  // missing, just use |battery_voltage|.
  if (nominal_voltage <= 0) {
    if (voltage <= 0) {
      // Avoid passing bad time-to-empty estimates to Chrome:
      // http://crbug.com/671374
      LOG(WARNING) << "Ignoring reading with bad or missing nominal ("
                   << nominal_voltage << ") and instantaneous (" << voltage
                   << ") voltages";
      return false;
    } else {
      LOG(WARNING) << "Got nominal voltage " << nominal_voltage << "; using "
                   << "instantaneous voltage " << voltage << " instead";
      nominal_voltage = voltage;
    }
  }

  DCHECK_GT(nominal_voltage, 0);
  status->nominal_voltage = nominal_voltage;

  // ACPI has two different battery types: charge_battery and energy_battery.
  // The main difference is that charge_battery type exposes
  // 1. current_now in A
  // 2. charge_{now, full, full_design} in Ah
  // while energy_battery type exposes
  // 1. power_now W
  // 2. energy_{now, full, full_design} in Wh
  // Change all the energy readings to charge format.
  // If both energy and charge reading are present (some non-ACPI drivers
  // expose both readings), read only the charge format.
  //
  // Some other batteries have more than that. If it has the charge attributes,
  // just read those and the energy_now attribute.
  double charge_full = 0;
  double charge_full_design = 0;
  double energy_full = 0;
  double energy_full_design = 0;
  double charge = 0;
  double energy = 0;

  if (base::PathExists(path.Append("energy_now")))
    energy = ReadScaledDouble(path, "energy_now");

  if (base::PathExists(path.Append("charge_full"))) {
    charge_full = ReadScaledDouble(path, "charge_full");
    charge_full_design = ReadScaledDouble(path, "charge_full_design");
    energy_full = charge_full * nominal_voltage;
    energy_full_design = charge_full_design * nominal_voltage;
    charge = ReadScaledDouble(path, "charge_now");
    if (energy <= 0.0)
      energy = charge * nominal_voltage;
  } else if (base::PathExists(path.Append("energy_full"))) {
    energy_full = ReadScaledDouble(path, "energy_full");
    energy_full_design = ReadScaledDouble(path, "energy_full_design");
    charge_full = energy_full / nominal_voltage;
    charge_full_design = energy_full_design / nominal_voltage;
    charge = energy / nominal_voltage;
  } else {
    LOG(WARNING) << "Ignoring reading without battery charge/energy";
    return false;
  }

  // Drop bogus readings (sometimes seen during firmware updates) that can
  // confuse users: https://crbug.com/924869
  if (charge_full <= 0.0 || charge < 0.0 || (charge == 0.0 && !allow_empty)) {
    LOG(WARNING) << "Ignoring reading with battery charge " << charge
                 << " and battery-full charge " << charge_full;
    return false;
  }

  status->battery_charge_full = charge_full;
  status->battery_charge_full_design = charge_full_design;
  status->battery_energy_full = energy_full;
  status->battery_energy_full_design = energy_full_design;
  status->battery_charge = charge;
  status->battery_energy = energy;

  // The current can be reported as negative on some systems but not on others,
  // so it can't be used to determine whether the battery is charging or
  // discharging.
  double current = base::PathExists(path.Append("power_now"))
                       ? fabs(ReadScaledDouble(path, "power_now")) / voltage
                       : fabs(ReadScaledDouble(path, "current_now"));
  status->battery_current = current;
  status->battery_energy_rate = current * voltage;

  return UpdateBatteryPercentagesAndState(status);
}

bool PowerSupply::UpdateBatteryPercentagesAndState(PowerStatus* status) {
  DCHECK(status);
  status->battery_percentage = util::ClampPercent(
      100.0 * status->battery_charge / status->battery_charge_full);

  double display_soc;
  bool is_full;
  if (GetDisplayStateOfChargeFromEC(&display_soc)) {
    // Error out for bad display percentages. We'll try again later.
    if (display_soc < 0.0 || 100.0 < display_soc) {
      LOG(ERROR) << "Received bad value of display SoC: " << display_soc;
      return false;
    }

    // If |display_soc| is 0, check that it's not a false 0 reading by comparing
    // it to |status->battery_percentage|. |low_battery_shutdown_percent_| maps
    // to a |display_soc| value of 0, so if |status->battery_percentage_| is
    // greater than that (plus 1.0 for race conditions), error out.
    if (display_soc == 0.0 &&
        status->battery_percentage > (low_battery_shutdown_percent_ + 1.0)) {
      LOG(ERROR) << "Display and battery percentage values have too much of a "
                 << "discrepancy. battery_percentage is "
                 << status->battery_percentage
                 << " and display_battery_percentage is " << display_soc;
      return false;
    }

    status->display_battery_percentage = display_soc;
    is_full = status->display_battery_percentage >= 100.0;
  } else {
    // Deprecated way
    status->display_battery_percentage =
        battery_percentage_converter_->ConvertActualToDisplay(
            status->battery_percentage);
    is_full =
        status->battery_charge >= status->battery_charge_full * full_factor_;
  }

  if (status->line_power_on) {
    if (is_full) {
      status->battery_state = PowerSupplyProperties_BatteryState_FULL;
    } else if (status->battery_current > 0.0 &&
               (status->battery_status_string == kBatteryStatusCharging ||
                status->battery_status_string == kBatteryStatusFull)) {
      status->battery_state = PowerSupplyProperties_BatteryState_CHARGING;
    } else {
      status->battery_state = PowerSupplyProperties_BatteryState_DISCHARGING;
    }
  } else {
    status->battery_state = PowerSupplyProperties_BatteryState_DISCHARGING;
  }

  return true;
}

bool PowerSupply::ReadMultipleBatteryDirectories(
    const std::vector<base::FilePath>& paths, PowerStatus* status) {
  DCHECK_GE(paths.size(), 2);
  std::vector<PowerStatus> battery_statuses;
  for (const auto& path : paths) {
    PowerStatus battery_status(*status);
    if (ReadBatteryDirectory(path, &battery_status, true /* allow_empty */))
      battery_statuses.push_back(battery_status);
    else
      LOG(WARNING) << "Ignoring battery at " << path.value();
  }

  if (battery_statuses.empty()) {
    LOG(WARNING) << "No functional batteries found";
    return false;
  }

  // Sum data across all directories.
  *status = battery_statuses[0];
  for (size_t i = 1; i < battery_statuses.size(); ++i) {
    const PowerStatus& s = battery_statuses[i];
    status->battery_energy += s.battery_energy;
    status->battery_energy_rate += s.battery_energy_rate;
    status->battery_voltage += s.battery_voltage;
    status->battery_current += s.battery_current;
    status->battery_charge += s.battery_charge;
    status->battery_charge_full += s.battery_charge_full;
    status->battery_charge_full_design += s.battery_charge_full_design;
    status->nominal_voltage += s.nominal_voltage;

    if (s.battery_is_present)
      status->battery_is_present = true;

    // If any battery is charging or full, use charging as the combined status.
    // Note that UpdateBatteryPercentagesAndState may still choose to report the
    // battery as full (if the combined charge is high enough) or even
    // discharging (if the current is zero or negative, or line power is
    // disconnected and one battery is just charging from another).
    if (s.battery_status_string == kBatteryStatusCharging ||
        s.battery_status_string == kBatteryStatusFull)
      status->battery_status_string = kBatteryStatusCharging;
  }

  // If all batteries reported being empty, something is likely wrong:
  // https://crbug.com/924869
  if (status->battery_charge == 0.0) {
    LOG(WARNING) << "Ignoring zero summed battery charge";
    return false;
  }

  // Compute percentages and state based on the combined values.
  UpdateBatteryPercentagesAndState(status);

  return true;
}

bool PowerSupply::UpdateBatteryTimeEstimates(PowerStatus* status) {
  DCHECK(status);
  status->battery_time_to_full = base::TimeDelta();
  status->battery_time_to_empty = base::TimeDelta();
  status->battery_time_to_shutdown = base::TimeDelta();

  if (!has_max_samples_)
    return false;

  if (clock_->GetCurrentTime() < battery_stabilized_timestamp_)
    return false;

  // Positive if the battery is charging and negative if it's discharging.
  const double signed_current =
      status->line_power_on ? current_samples_on_line_power_->GetAverage()
                            : current_samples_on_battery_power_->GetAverage();

  switch (status->battery_state) {
    case PowerSupplyProperties_BatteryState_CHARGING:
      if (signed_current <= kEpsilon) {
        status->battery_time_to_full = base::Seconds(-1);
      } else {
        const double charge_to_full =
            std::max(0.0, status->battery_charge_full * full_factor_ -
                              status->battery_charge);
        status->battery_time_to_full =
            base::Seconds(roundl(3600 * charge_to_full / signed_current));
      }
      break;
    case PowerSupplyProperties_BatteryState_DISCHARGING:
      if (signed_current >= -kEpsilon) {
        status->battery_time_to_empty = base::Seconds(-1);
        status->battery_time_to_shutdown = base::Seconds(-1);
      } else {
        status->battery_time_to_empty = base::Seconds(
            roundl(3600 * (status->battery_charge * status->nominal_voltage) /
                   (-signed_current * status->battery_voltage)));

        const double shutdown_charge =
            status->battery_charge_full * low_battery_shutdown_percent_ / 100.0;
        const double available_charge =
            std::max(0.0, status->battery_charge - shutdown_charge);
        status->battery_time_to_shutdown =
            base::Seconds(
                roundl(3600 * (available_charge * status->nominal_voltage) /
                       (-signed_current * status->battery_voltage))) -
            low_battery_shutdown_time_;
        status->battery_time_to_shutdown =
            std::max(base::TimeDelta(), status->battery_time_to_shutdown);
      }
      break;
    case PowerSupplyProperties_BatteryState_FULL:
      break;
    default:
      NOTREACHED() << "Unhandled battery state "
                   << static_cast<int>(status->battery_state);
  }

  return true;
}

void PowerSupply::UpdateObservedBatteryChargeRate(PowerStatus* status) const {
  DCHECK(status);
  const base::TimeDelta time_delta = charge_samples_->GetTimeDelta();
  status->observed_battery_charge_rate =
      (time_delta < kObservedBatteryChargeRateMin)
          ? 0.0
          : charge_samples_->GetValueDelta() / (time_delta.InSecondsF() / 3600);
}

bool PowerSupply::IsBatteryBelowShutdownThreshold(
    const PowerStatus& status) const {
  if (low_battery_shutdown_time_ == base::TimeDelta() &&
      low_battery_shutdown_percent_ <= kEpsilon)
    return false;

  const bool below_threshold =
      (status.battery_time_to_empty > base::TimeDelta() &&
       status.battery_time_to_empty <= low_battery_shutdown_time_ &&
       status.battery_percentage <= kLowBatteryShutdownSafetyPercent) ||
      (import_display_soc_
           ? status.display_battery_percentage <= 0
           : status.battery_percentage <= low_battery_shutdown_percent_);

  if (below_threshold && factory_mode_) {
    LOG(INFO) << "Battery is low, but not shutting down in factory mode";
    return false;
  }
  // Most AC chargers can deliver enough current to prevent the battery from
  // discharging while the device is in use; other chargers (e.g. USB) may not
  // be able to, though. The observed charge rate is checked to verify whether
  // the battery's charge is increasing or decreasing.
  if (status.line_power_on)
    return below_threshold && status.observed_battery_charge_rate < 0.0;

  return below_threshold;
}

bool PowerSupply::IsSupplyIgnored(const std::string& sysname) const {
  if (sysname == "AC" && !has_barreljack_) {
    return true;
  }

  return false;
}

bool PowerSupply::PerformUpdate(UpdatePolicy update_policy,
                                NotifyPolicy notify_policy) {
  TRACE_EVENT("power", "PowerSupply::PerformUpdate", "update_policy",
              update_policy, "notify_policy", notify_policy);
  const bool success = UpdatePowerStatus(update_policy);
  if (!is_suspended_)
    SchedulePoll();

  if (!success)
    return false;

  if (notify_policy == NotifyPolicy::SYNCHRONOUSLY) {
    NotifyObservers();
  } else {
    notify_observers_task_.Reset(
        base::BindOnce(&PowerSupply::NotifyObservers, base::Unretained(this)));
    base::SingleThreadTaskRunner::GetCurrentDefault()->PostTask(
        FROM_HERE, notify_observers_task_.callback());
  }

  PowerSupplyProperties protobuf;
  CopyPowerStatusToProtocolBuffer(power_status_, &protobuf);
  dbus_wrapper_->EmitSignalWithProtocolBuffer(kPowerSupplyPollSignal, protobuf);

  dbus::Signal signal(kPowerManagerInterface, kBatteryStatePollSignal);
  dbus::MessageWriter writer(&signal);
  writer.AppendUint32(static_cast<uint32_t>(
      ExternalPowerToExternalPowerEnum(power_status_.external_power)));
  UpowerBatteryState battery_state =
      power_status_.battery_percentage == 100
          ? UpowerBatteryState::UpowerFullyCharged
          : BatteryStateToUpowerEnum(power_status_.battery_status_string);
  writer.AppendUint32(static_cast<uint32_t>(battery_state));
  writer.AppendDouble(power_status_.battery_percentage);
  dbus_wrapper_->EmitSignal(&signal);

  return true;
}

void PowerSupply::SchedulePoll() {
  base::TimeDelta delay;
  base::TimeTicks now = clock_->GetCurrentTime();
  int64_t samples = 0;
  // TODO(b/207716926): Temporary change to find FD leaks in powerd.
  bool ok = prefs_->GetInt64(kMaxCurrentSamplesPref, &samples);
  if (!ok) {
    if (temp_file_ != nullptr) {
      base::CloseFile(temp_file_);  // Release pre-allocated FD.
      temp_file_ = nullptr;
    }
    base::FilePath fdpath;
    base::FileEnumerator it(
        base::FilePath("/proc/self/fd"), false,
        base::FileEnumerator::FILES | base::FileEnumerator::SHOW_SYM_LINKS,
        "*");
    for (base::FilePath name = it.Next(); !name.empty(); name = it.Next()) {
      if (base::ReadSymbolicLink(name, &fdpath)) {
        LOG(ERROR) << "b/207716926: " << fdpath.value();
      }
    }
  }
  CHECK(ok);

  // Wait |kBatteryStabilizedSlack| after |battery_stabilized_timestamp_| to
  // start polling for the current and charge to stabilized.
  // Poll every |poll_delay_initial_| ms until having |kMaxCurrentSamplesPref|
  // samples then poll every |poll_delay_|.
  if (battery_stabilized_timestamp_ > now) {
    delay = battery_stabilized_timestamp_ - now + kBatteryStabilizedSlack;
  } else if (!has_max_samples_ && num_zero_samples_ < samples) {
    delay = poll_delay_initial_;
  } else {
    delay = poll_delay_;
  }

  VLOG(1) << "Scheduling update in " << delay.InMilliseconds() << " ms";
  poll_timer_.Start(FROM_HERE, delay, this, &PowerSupply::OnPollTimeout);
  current_poll_delay_for_testing_ = delay;
}

void PowerSupply::OnPollTimeout() {
  TRACE_EVENT("power", "PowerSupply::OnPollTimeout");
  current_poll_delay_for_testing_ = base::TimeDelta();
  PerformUpdate(UpdatePolicy::UNCONDITIONALLY, NotifyPolicy::SYNCHRONOUSLY);
}

void PowerSupply::NotifyObservers() {
  TRACE_EVENT("power", "PowerSupply::NotifyObservers");
  for (PowerSupplyObserver& observer : observers_)
    observer.OnPowerStatusUpdate();
}

void PowerSupply::OnGetPowerSupplyPropertiesMethodCall(
    dbus::MethodCall* method_call,
    dbus::ExportedObject::ResponseSender response_sender) {
  if (!power_status_initialized_) {
    std::move(response_sender)
        .Run(dbus::ErrorResponse::FromMethodCall(
            method_call, DBUS_ERROR_FAILED,
            "PowerSupplyProperties has not been initialized."));
    return;
  }
  PowerSupplyProperties protobuf;
  CopyPowerStatusToProtocolBuffer(power_status_, &protobuf);
  std::unique_ptr<dbus::Response> response =
      dbus::Response::FromMethodCall(method_call);
  dbus::MessageWriter writer(response.get());
  writer.AppendProtoAsArrayOfBytes(protobuf);
  std::move(response_sender).Run(std::move(response));
}

void PowerSupply::OnGetBatteryStateMethodCall(
    dbus::MethodCall* method_call,
    dbus::ExportedObject::ResponseSender response_sender) {
  std::unique_ptr<dbus::Response> response =
      dbus::Response::FromMethodCall(method_call);
  dbus::MessageWriter writer(response.get());
  writer.AppendUint32(static_cast<uint32_t>(
      ExternalPowerToExternalPowerEnum(power_status_.external_power)));
  UpowerBatteryState battery_state =
      power_status_.battery_percentage == 100
          ? UpowerBatteryState::UpowerFullyCharged
          : BatteryStateToUpowerEnum(power_status_.battery_status_string);
  writer.AppendUint32(static_cast<uint32_t>(battery_state));
  writer.AppendDouble(power_status_.battery_percentage);
  std::move(response_sender).Run(std::move(response));
}

void PowerSupply::OnSetPowerSourceMethodCall(
    dbus::MethodCall* method_call,
    dbus::ExportedObject::ResponseSender response_sender) {
  std::string id;
  dbus::MessageReader reader(method_call);
  if (!reader.PopString(&id)) {
    LOG(ERROR) << "Unable to read " << kSetPowerSourceMethod << " args";
    std::move(response_sender)
        .Run(dbus::ErrorResponse::FromMethodCall(
            method_call, DBUS_ERROR_INVALID_ARGS, "Expected string"));
    return;
  }

  LOG(INFO) << "Received request to switch to power source \"" << id << "\"";
  if (!SetPowerSource(id)) {
    std::move(response_sender)
        .Run(dbus::ErrorResponse::FromMethodCall(method_call, DBUS_ERROR_FAILED,
                                                 "Couldn't set power source"));
    return;
  }
  std::move(response_sender).Run(dbus::Response::FromMethodCall(method_call));
}

bool PowerSupply::SetPowerSource(const std::string& id) {
  // An empty ID means we should write -1 to any power source (we'll use the
  // active one) to ask the kernel to use the battery as the power source.
  // Otherwise, write 0 to the requested power source to activate it.
  const base::FilePath device_path =
      GetPathForId(id.empty() ? power_status_.external_power_source_id : id);
  if (device_path.empty())
    return false;

  const base::FilePath limit_path =
      device_path.Append(kChargeControlLimitMaxFile);
  const std::string value = id.empty() ? "-1" : "0";
  if (!util::WriteFileFully(limit_path, value.c_str(), value.size())) {
    LOG(ERROR) << "Failed to write " << value << " to " << limit_path.value();
    return false;
  }
  return true;
}

}  // namespace power_manager::system
