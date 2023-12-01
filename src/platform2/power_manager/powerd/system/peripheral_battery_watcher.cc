// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/peripheral_battery_watcher.h"

#include <fcntl.h>

#include <cerrno>
#include <string>
#include <utility>

#include <base/files/file_enumerator.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <base/time/time.h>
#include <chromeos/dbus/service_constants.h>
#include <re2/re2.h>

#include "power_manager/common/metrics_constants.h"
#include "power_manager/common/metrics_sender.h"
#include "power_manager/common/tracing.h"
#include "power_manager/powerd/system/dbus_wrapper.h"
#include "power_manager/proto_bindings/peripheral_battery_status.pb.h"

namespace power_manager::system {

namespace {

// Default path examined for peripheral battery directories.
const char kDefaultPeripheralBatteryPath[] = "/sys/class/power_supply/";

// Default interval for polling the device battery info.
constexpr base::TimeDelta kDefaultPollInterval = base::Minutes(10);

constexpr char kBluetoothAddressRegex[] =
    "^([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2})$";

// TODO(b/215381232): Temporarily support both 'PCHG' name and 'peripheral' name
// till upstream kernel driver is merged.
constexpr LazyRE2 kPeripheralChargerRegex = {
    R"(/(?:peripheral|PCHG)(?:[0-9]+)$)"};

// Reads |path| to |value_out| and trims trailing whitespace. False is returned
// if the file doesn't exist or can't be read.
bool ReadStringFromFile(const base::FilePath& path, std::string* value_out) {
  if (!base::ReadFileToString(path, value_out))
    return false;

  base::TrimWhitespaceASCII(*value_out, base::TRIM_TRAILING, value_out);
  return true;
}

bool ExtractBluetoothAddress(const base::FilePath& path, std::string* address) {
  // Standard HID devices have the convention of "hid-{btaddr}-battery"
  // file name in /sys/class/power_supply."
  if (RE2::FullMatch(path.value(), ".*hid-(.+)-battery", address))
    return true;

  if (path.value().find("wacom") == std::string::npos)
    return false;

  // Handle wacom specifically, the Bluetooth address is in
  // /sys/class/power_suply/wacom_xxx/powers/uevent having HID_UNIQ= prefix.
  std::string uevent;
  return (ReadStringFromFile(path.Append("powers/uevent"), &uevent) &&
          RE2::PartialMatch(uevent, "HID_UNIQ=(.+)", address));
}

bool IsSysfsBatteryBlocked(const std::string& model_name) {
  // Keychron keyboards don't send reliable battery values (b/177593938).
  if (model_name.find("Keychron") != std::string::npos)
    return true;

  return false;
}

}  // namespace

const char PeripheralBatteryWatcher::kScopeFile[] = "scope";
const char PeripheralBatteryWatcher::kScopeValueDevice[] = "Device";
const char PeripheralBatteryWatcher::kStatusFile[] = "status";
const char PeripheralBatteryWatcher::kPowersUeventFile[] = "powers/uevent";
const char PeripheralBatteryWatcher::kStatusValueUnknown[] = "Unknown";
const char PeripheralBatteryWatcher::kStatusValueFull[] = "Full";
const char PeripheralBatteryWatcher::kStatusValueCharging[] = "Charging";
const char PeripheralBatteryWatcher::kStatusValueDischarging[] = "Discharging";
const char PeripheralBatteryWatcher::kStatusValueNotcharging[] = "Not charging";
const char PeripheralBatteryWatcher::kModelNameFile[] = "model_name";
const char PeripheralBatteryWatcher::kHealthFile[] = "health";
const char PeripheralBatteryWatcher::kHealthValueUnknown[] = "Unknown";
const char PeripheralBatteryWatcher::kHealthValueGood[] = "Good";
const char PeripheralBatteryWatcher::kCapacityFile[] = "capacity";
const char PeripheralBatteryWatcher::kSerialNumberFile[] = "serial_number";
const char PeripheralBatteryWatcher::kUdevSubsystem[] = "power_supply";

PeripheralBatteryWatcher::PeripheralBatteryWatcher()
    : peripheral_battery_path_(kDefaultPeripheralBatteryPath),
      bluez_battery_provider_(std::make_unique<BluezBatteryProvider>()),
      weak_ptr_factory_(this) {}

PeripheralBatteryWatcher::~PeripheralBatteryWatcher() {
  if (udev_)
    udev_->RemoveSubsystemObserver(kUdevSubsystem, this);
}

void PeripheralBatteryWatcher::Init(DBusWrapperInterface* dbus_wrapper,
                                    UdevInterface* udev) {
  udev_ = udev;
  udev_->AddSubsystemObserver(kUdevSubsystem, this);

  dbus_wrapper_ = dbus_wrapper;
  ReadBatteryStatusesTimer();

  dbus_wrapper->ExportMethod(
      kRefreshAllPeripheralBatteryMethod,
      base::BindRepeating(
          &PeripheralBatteryWatcher::OnRefreshAllPeripheralBatteryMethodCall,
          weak_ptr_factory_.GetWeakPtr()));

  bluez_battery_provider_->Init(dbus_wrapper_->GetBus());
}

void PeripheralBatteryWatcher::OnUdevEvent(const UdevEvent& event) {
  base::FilePath path = base::FilePath(peripheral_battery_path_)
                            .Append(event.device_info.sysname);
  if (event.action == UdevEvent::Action::REMOVE || !IsPeripheralDevice(path))
    return;

  // An event of a peripheral device is detected through udev, Refresh the
  // battery status of that device.
  ReadBatteryStatus(path, true);
}

bool PeripheralBatteryWatcher::IsPeripheralDevice(
    const base::FilePath& device_path) const {
  // Peripheral batteries have device scopes.
  std::string scope;
  return (ReadStringFromFile(device_path.Append(kScopeFile), &scope) &&
          scope == kScopeValueDevice);
}

bool PeripheralBatteryWatcher::IsPeripheralChargerDevice(
    const base::FilePath& device_path) const {
  // Peripheral chargers have specific names.
  return (RE2::PartialMatch(device_path.value(), *kPeripheralChargerRegex));
}

void PeripheralBatteryWatcher::GetBatteryList(
    std::vector<base::FilePath>* battery_list) {
  battery_list->clear();
  base::FileEnumerator dir_enumerator(peripheral_battery_path_, false,
                                      base::FileEnumerator::DIRECTORIES);

  for (base::FilePath device_path = dir_enumerator.Next(); !device_path.empty();
       device_path = dir_enumerator.Next()) {
    if (!IsPeripheralDevice(device_path))
      continue;

    // Some devices may initially have an unknown status; avoid reporting
    // them: http://b/64392016. Unknown status for chargers is always
    // interesting.
    std::string status;
    if (!IsPeripheralChargerDevice(device_path) &&
        ReadStringFromFile(device_path.Append(kStatusFile), &status) &&
        status == kStatusValueUnknown)
      continue;

    battery_list->push_back(device_path);
  }
}

int PeripheralBatteryWatcher::ReadChargeStatus(
    const base::FilePath& path) const {
  // sysfs entry "status" has the current charge status, "health" has battery
  // health.
  base::FilePath status_path = path.Append(kStatusFile);
  base::FilePath health_path = path.Append(kHealthFile);

  // NOTE: This code is assuming that the status and health sysfs files are
  // relatively fast to read, and will not trigger significant delays, i.e.,
  // do not involve Bluetooth traffic to possibly non-responsive receivers.

  // First check health; if it is known and not good, report an error.
  std::string health;
  if (ReadStringFromFile(health_path, &health)) {
    if (health != kHealthValueUnknown && health != kHealthValueGood) {
      return PeripheralBatteryStatus_ChargeStatus_CHARGE_STATUS_ERROR;
    }
  }

  // Then check general status, looking for known states.
  std::string status;
  if (!ReadStringFromFile(status_path, &status))
    return PeripheralBatteryStatus_ChargeStatus_CHARGE_STATUS_UNKNOWN;

  if (status == kStatusValueCharging)
    return PeripheralBatteryStatus_ChargeStatus_CHARGE_STATUS_CHARGING;
  else if (status == kStatusValueDischarging)
    return PeripheralBatteryStatus_ChargeStatus_CHARGE_STATUS_DISCHARGING;
  else if (status == kStatusValueNotcharging)
    return PeripheralBatteryStatus_ChargeStatus_CHARGE_STATUS_NOT_CHARGING;
  else if (status == kStatusValueFull)
    return PeripheralBatteryStatus_ChargeStatus_CHARGE_STATUS_FULL;
  else
    return PeripheralBatteryStatus_ChargeStatus_CHARGE_STATUS_UNKNOWN;
}

std::string PeripheralBatteryWatcher::ReadSerialNumber(
    const base::FilePath& path) const {
  base::FilePath sn_path = path.Append(kSerialNumberFile);

  // NOTE: This code is assuming that the serial_number sysfs file is
  // relatively fast to read, and will not trigger significant delays, i.e.,
  // does not involve Bluetooth traffic to possibly non-responsive receivers.

  std::string result;
  if (ReadStringFromFile(sn_path, &result)) {
    return result;
  } else {
    return "";
  }
}

void PeripheralBatteryWatcher::ReadBatteryStatus(const base::FilePath& path,
                                                 bool active_update) {
  // sysfs entry "capacity" has the current battery level.
  base::FilePath capacity_path = path.Append(kCapacityFile);
  if (!base::PathExists(capacity_path))
    return;

  std::string model_name;
  if (!IsPeripheralChargerDevice(path) &&
      !ReadStringFromFile(path.Append(kModelNameFile), &model_name))
    return;

  if (IsSysfsBatteryBlocked(model_name))
    return;

  int status;
  std::string sn;
  status = ReadChargeStatus(path);
  sn = ReadSerialNumber(path);

  battery_readers_[path] = std::make_unique<AsyncFileReader>();
  AsyncFileReader* reader = battery_readers_[path].get();

  base::TimeTicks start_time = base::TimeTicks::Now();
  if (reader->Init(capacity_path)) {
    reader->StartRead(
        base::BindOnce(&PeripheralBatteryWatcher::ReadCallback,
                       base::Unretained(this), path, model_name, status, sn,
                       active_update, start_time),
        base::BindOnce(&PeripheralBatteryWatcher::ErrorCallback,
                       base::Unretained(this), path, model_name, start_time));
  } else {
    LOG(ERROR) << "Can't read battery capacity " << capacity_path.value();
  }
}

void PeripheralBatteryWatcher::ReadBatteryStatuses() {
  TRACE_EVENT("power", "PeripheralBatteryWatcher::ReadBatteryStatuses");
  battery_readers_.clear();

  std::vector<base::FilePath> new_battery_list;
  GetBatteryList(&new_battery_list);

  for (const base::FilePath& path : new_battery_list) {
    ReadBatteryStatus(path, false);
  }
}

void PeripheralBatteryWatcher::ReadBatteryStatusesTimer() {
  ReadBatteryStatuses();

  poll_timer_.Start(
      FROM_HERE, kDefaultPollInterval,
      base::BindRepeating(&PeripheralBatteryWatcher::ReadBatteryStatuses,
                          weak_ptr_factory_.GetWeakPtr()));
}

void PeripheralBatteryWatcher::SendBatteryStatus(
    const base::FilePath& path,
    const std::string& model_name,
    int level,
    int charge_status,
    const std::string& serial_number,
    bool active_update) {
  std::string address;
  if (ExtractBluetoothAddress(path, &address) &&
      RE2::FullMatch(address, kBluetoothAddressRegex)) {
    // Bluetooth batteries is reported separately to BlueZ.
    bluez_battery_provider_->UpdateDeviceBattery(address, level);
    return;
  }

  PeripheralBatteryStatus proto;
  proto.set_path(path.value());
  proto.set_name(model_name);
  proto.set_charge_status(
      (power_manager::PeripheralBatteryStatus_ChargeStatus)charge_status);
  if (level >= 0)
    proto.set_level(level);
  if (!serial_number.empty())
    proto.set_serial_number(serial_number);
  proto.set_active_update(active_update);

  dbus_wrapper_->EmitSignalWithProtocolBuffer(kPeripheralBatteryStatusSignal,
                                              proto);
}

void PeripheralBatteryWatcher::ReadCallback(const base::FilePath& path,
                                            const std::string& model_name,
                                            int status,
                                            const std::string& serial_number,
                                            bool active_update,
                                            base::TimeTicks start_time,
                                            const std::string& data) {
  base::TimeDelta latency = base::TimeTicks::Now() - start_time;
  std::string trimmed_data;
  base::TrimWhitespaceASCII(data, base::TRIM_ALL, &trimmed_data);
  int level = -1;
  if (base::StringToInt(trimmed_data, &level)) {
    SendBatteryStatus(path, model_name, level, status, serial_number,
                      active_update);
  } else {
    LOG(ERROR) << "Invalid battery level reading : [" << data << "]"
               << " from " << path.value();
  }
  base::SequencedTaskRunner::GetCurrentDefault()->DeleteSoon(
      FROM_HERE, std::move(battery_readers_.extract(path).mapped()));
  SendMetric(metrics::kPeripheralReadLatencyMs,
             static_cast<int>(round(latency.InMillisecondsF())),
             metrics::kPeripheralReadLatencyMsMin,
             metrics::kPeripheralReadLatencyMsMax, metrics::kDefaultBuckets);
}

void PeripheralBatteryWatcher::ErrorCallback(const base::FilePath& path,
                                             const std::string& model_name,
                                             base::TimeTicks start_time) {
  base::TimeDelta latency = base::TimeTicks::Now() - start_time;
  SendBatteryStatus(path, model_name, -1,
                    PeripheralBatteryStatus_ChargeStatus_CHARGE_STATUS_UNKNOWN,
                    "", false);
  base::SequencedTaskRunner::GetCurrentDefault()->DeleteSoon(
      FROM_HERE, std::move(battery_readers_.extract(path).mapped()));
  SendMetric(metrics::kPeripheralReadErrorLatencyMs,
             static_cast<int>(round(latency.InMillisecondsF())),
             metrics::kPeripheralReadLatencyMsMin,
             metrics::kPeripheralReadLatencyMsMax, metrics::kDefaultBuckets);
}

void PeripheralBatteryWatcher::OnRefreshAllPeripheralBatteryMethodCall(
    dbus::MethodCall* method_call,
    dbus::ExportedObject::ResponseSender response_sender) {
  dbus::MessageReader reader(method_call);

  ReadBatteryStatuses();

  // Best effort, always return success.
  std::unique_ptr<dbus::Response> response =
      dbus::Response::FromMethodCall(method_call);
  std::move(response_sender).Run(std::move(response));
}

}  // namespace power_manager::system
