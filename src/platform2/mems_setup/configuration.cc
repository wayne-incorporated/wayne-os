// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "mems_setup/configuration.h"

#include <algorithm>
#include <initializer_list>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/files/file_util.h>
#include <base/files/file_path.h>
#include <base/json/json_reader.h>
#include <base/logging.h>
#include <base/process/launch.h>
#include <base/stl_util.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/stringprintf.h>
#include <re2/re2.h>

#include <libmems/common_types.h>
#include <libmems/iio_channel.h>
#include <libmems/iio_context.h>
#include <libmems/iio_device.h>
#include <libmems/iio_device_impl.h>
#include <libsar/sar_config_reader.h>

#include "mems_setup/sensor_location.h"

namespace mems_setup {

namespace {

struct ImuVpdCalibrationEntry {
  std::string name;
  std::string calib;
  std::optional<int> max_value;
  std::optional<int> value;
  bool missing_is_error;
};

struct LightVpdCalibrationEntry {
  std::string vpd_name;
  std::string iio_name;
};

struct LightColorCalibrationEntry {
  std::string iio_name;
  std::optional<double> value;
  libmems::IioChannel* chn;
};

constexpr char kPowerGroupName[] = "power";
constexpr char kIioServiceGroupName[] = "iioservice";

constexpr char kCalibrationBias[] = "bias";
constexpr char kCalibrationScale[] = "scale";
constexpr char kSysfsTriggerPrefix[] = "sysfstrig";

constexpr int kGyroMaxVpdCalibration = 16384;  // 16dps
constexpr int kAccelMaxVpdCalibration = 256;   // .250g
constexpr int kAccelSysfsTriggerId = 0;

constexpr int kSysfsTriggerId = -1;

constexpr std::initializer_list<const char*> kAccelAxes = {
    "x",
    "y",
    "z",
};

constexpr char kTriggerString[] = "trigger";

constexpr char kDevlinkPrefix[] = "/dev/proximity";

constexpr char kFilesToSetReadAndOwnership[][28] = {
    "buffer/hwfifo_timeout", "buffer/hwfifo_watermark_max", "buffer/enable",
    "buffer/length", "trigger/current_trigger"};
constexpr char kFilesToSetWriteAndOwnership[][24] = {"sampling_frequency",
                                                     "buffer/hwfifo_timeout",
                                                     "buffer/hwfifo_flush",
                                                     "buffer/enable",
                                                     "buffer/length",
                                                     "trigger/current_trigger",
                                                     "flush",
                                                     "frequency"};

constexpr char kScanElementsString[] = "scan_elements";

constexpr char kEventsString[] = "events";

}  // namespace

const char* Configuration::GetGroupNameForSysfs() {
  // TODO(chenghaoyang): Remove it when iioservice owns proximity sensors.
  if (kind_ == SensorKind::PROXIMITY)
    return kPowerGroupName;

  return kIioServiceGroupName;
}

Configuration::Configuration(libmems::IioContext* context,
                             libmems::IioDevice* sensor,
                             Delegate* del)
    : delegate_(del), sensor_(sensor), context_(context) {
  DCHECK(sensor_);

  kind_ = mems_setup::SensorKindFromString(
      sensor_->GetName() ? sensor_->GetName() : "");
}

bool Configuration::Configure() {
  iioservice_gid_ = delegate_->FindGroupId(GetGroupNameForSysfs());
  if (!iioservice_gid_.has_value()) {
    LOG(ERROR) << "iioservice group not found";
    return false;
  }

  if (!ConfigureOnKind())
    return false;

  if (!SetupPermissions())
    return false;

  // If the buffer is enabled, which means mems_setup has already been used on
  // this sensor and iioservice is reading the samples from it, skip setting the
  // frequency.
  if (!sensor_->IsBufferEnabled()) {
    sensor_->WriteDoubleAttribute(libmems::kSamplingFrequencyAttr, 0.0);
    for (auto& channel : sensor_->GetAllChannels())
      channel->WriteDoubleAttribute(libmems::kSamplingFrequencyAttr, 0.0);
  }

  // Ignores the error as it may fail on kernel 4.4 or HID stack sensors.
  sensor_->WriteStringAttribute("current_timestamp_clock", "boottime");

  return true;
}

bool Configuration::CopyLightCalibrationFromVpd() {
  std::vector<LightVpdCalibrationEntry> calib_attributes = {
      {"als_cal_intercept", "calibbias"},
      {"als_cal_slope", "calibscale"},
  };

  auto chn = sensor_->GetChannel("illuminance");
  if (!chn) {
    LOG(ERROR) << "No channel illuminance";
    return false;
  }

  for (auto& calib_attribute : calib_attributes) {
    auto attrib_value = delegate_->ReadVpdValue(calib_attribute.vpd_name);
    if (!attrib_value.has_value()) {
      LOG(ERROR) << "VPD missing calibration value "
                 << calib_attribute.vpd_name;
      continue;
    }

    double value;
    if (!base::StringToDouble(attrib_value.value(), &value)) {
      LOG(ERROR) << "VPD calibration value " << calib_attribute.vpd_name
                 << " has invalid value " << attrib_value.value();
      continue;
    }
    if (!chn->WriteDoubleAttribute(calib_attribute.iio_name, value))
      LOG(ERROR) << "failed to set calibration value "
                 << calib_attribute.iio_name;
  }

  /*
   * RGB sensors may need per channel calibration.
   */
  std::vector<LightColorCalibrationEntry> calib_color_entries = {
      {"illuminance_red", std::nullopt, nullptr},
      {"illuminance_green", std::nullopt, nullptr},
      {"illuminance_blue", std::nullopt, nullptr},
  };
  for (auto& color_entry : calib_color_entries) {
    color_entry.chn = sensor_->GetChannel(color_entry.iio_name);
    if (!color_entry.chn)
      return true;
  }

  auto attrib_value = delegate_->ReadVpdValue("als_cal_slope_color");
  if (attrib_value.has_value()) {
    /*
     * Split the attributes in 3 doubles.
     */
    std::vector<std::string> attrs =
        base::SplitString(attrib_value.value(), " ", base::TRIM_WHITESPACE,
                          base::SPLIT_WANT_NONEMPTY);

    if (attrs.size() == 3) {
      for (int i = 0; i < 3; i++) {
        double value;
        if (!base::StringToDouble(attrs[i], &value)) {
          LOG(ERROR) << "VPD_entry " << i << " of als_cal_slope_color "
                     << "is not a float: " << attrs[i];
          break;
        }
        calib_color_entries[i].value = value;
      }

      for (auto& color_entry : calib_color_entries) {
        if (!color_entry.value) {
          LOG(ERROR) << "No value set for " << color_entry.iio_name;
          continue;
        }
        if (!color_entry.chn->WriteDoubleAttribute("calibscale",
                                                   *color_entry.value))
          LOG(WARNING) << "failed to to set calibration value "
                       << color_entry.iio_name << " to " << *color_entry.value;
      }
    } else {
      LOG(ERROR) << "VPD_entry als_cal_slope_color is malformed : "
                 << attrib_value.value();
    }
  }
  return true;
}

bool Configuration::CopyImuCalibationFromVpd(int max_value) {
  if (sensor_->IsSingleSensor()) {
    auto location = sensor_->GetLocation();
    if (!location || location->empty()) {
      LOG(ERROR) << "cannot read a valid sensor location";
      return false;
    }
    return CopyImuCalibationFromVpd(max_value, location->c_str());
  } else {
    bool base_config = CopyImuCalibationFromVpd(max_value, kBaseSensorLocation);
    bool lid_config = CopyImuCalibationFromVpd(max_value, kLidSensorLocation);
    return base_config && lid_config;
  }
}

bool Configuration::CopyImuCalibationFromVpd(int max_value,
                                             const std::string& location) {
  const bool is_single_sensor = sensor_->IsSingleSensor();
  std::string kind = SensorKindToString(kind_);

  std::vector<ImuVpdCalibrationEntry> calib_attributes = {
      {"x", kCalibrationBias, max_value, std::nullopt, true},
      {"y", kCalibrationBias, max_value, std::nullopt, true},
      {"z", kCalibrationBias, max_value, std::nullopt, true},

      {"x", kCalibrationScale, std::nullopt, std::nullopt, false},
      {"y", kCalibrationScale, std::nullopt, std::nullopt, false},
      {"z", kCalibrationScale, std::nullopt, std::nullopt, false},
  };

  for (auto& calib_attribute : calib_attributes) {
    auto attrib_name = base::StringPrintf(
        "in_%s_%s_%s_calib%s", kind.c_str(), calib_attribute.name.c_str(),
        location.c_str(), calib_attribute.calib.c_str());
    auto attrib_value = delegate_->ReadVpdValue(attrib_name.c_str());
    LOG(INFO) << attrib_name
              << " attrib_value: " << attrib_value.value_or("nan");
    if (!attrib_value.has_value()) {
      if (calib_attribute.missing_is_error)
        LOG(ERROR) << "VPD missing calibration value " << attrib_name;
      continue;
    }

    int value;
    if (!base::StringToInt(attrib_value.value(), &value)) {
      LOG(ERROR) << "VPD calibration value " << attrib_name
                 << " has invalid value " << attrib_value.value();
      // TODO(crbug/1039454: gwendal): Add uma stats.
      continue;
    }
    if (calib_attribute.max_value && abs(value) > calib_attribute.max_value) {
      LOG(ERROR) << "VPD calibration value " << attrib_name
                 << " has out-of-range value " << attrib_value.value();
      // TODO(crbug/1039454: gwendal): Add uma stats.
      return false;
    } else {
      calib_attribute.value = value;
    }
  }

  for (const auto& calib_attribute : calib_attributes) {
    if (!calib_attribute.value)
      continue;
    auto chn_id =
        base::StringPrintf("%s_%s", kind.c_str(), calib_attribute.name.c_str());

    if (!is_single_sensor)
      chn_id = base::StringPrintf("%s_%s", chn_id.c_str(), location.c_str());

    auto chn = sensor_->GetChannel(chn_id);
    if (!chn) {
      LOG(ERROR) << "No channel with id " << chn_id;
      return false;
    }
    auto attrib_name =
        base::StringPrintf("calib%s", calib_attribute.calib.c_str());
    if (!chn->WriteNumberAttribute(attrib_name, *calib_attribute.value)) {
      LOG(ERROR) << "failed to set calibration value " << attrib_name;
      return false;
    }
    LOG(INFO) << attrib_name << ": "
              << chn->ReadNumberAttribute(attrib_name).value_or(-88888);
  }

  LOG(INFO) << "VPD calibration complete";
  return true;
}

bool Configuration::AddSysfsTrigger(int sysfs_trigger_id) {
  std::string dev_name =
      libmems::IioDeviceImpl::GetStringFromId(sensor_->GetId());
  // /sys/bus/iio/devices/iio:deviceX
  base::FilePath sys_dev_path = sensor_->GetPath();

  if (!delegate_->Exists(sys_dev_path.Append(kTriggerString))) {
    // Uses FIFO and doesn't need a trigger.
    return true;
  }

  // There is a potential cross-process race here, where multiple instances
  // of this tool may be trying to access the trigger at once. To solve this,
  // first see if the trigger is already there. If not, try to create it, and
  // then try to access it again. Only if the latter access fails then
  // error out.
  auto trigger_name =
      base::StringPrintf("%s%d", kSysfsTriggerPrefix, sysfs_trigger_id);
  auto triggers = context_->GetTriggersByName(trigger_name);

  if (triggers.size() > 1) {
    LOG(ERROR) << "Several triggers with the same name " << trigger_name
               << " is not expected.";
    return false;
  }
  if (triggers.size() == 0) {
    LOG(INFO) << "trigger " << trigger_name << " not found; adding";

    auto iio_sysfs_trigger = context_->GetTriggerById(kSysfsTriggerId);
    if (iio_sysfs_trigger == nullptr) {
      LOG(ERROR) << "cannot find iio_trig_sysfs kernel module";
      return false;
    }

    if (!iio_sysfs_trigger->WriteNumberAttribute("add_trigger",
                                                 sysfs_trigger_id)) {
      // It may happen if another instance of mems_setup is running in parallel.
      LOG(WARNING) << "cannot instantiate trigger " << trigger_name;
    }

    context_->Reload();
    triggers = context_->GetTriggersByName(trigger_name);
    if (triggers.size() != 1) {
      LOG(ERROR) << "Trigger " << trigger_name << " not been created properly";
      return false;
    }
  }

  if (!sensor_->SetTrigger(triggers[0])) {
    LOG(ERROR) << "cannot set sensor's trigger to " << trigger_name;
    return false;
  }

  base::FilePath trigger_now = triggers[0]->GetPath().Append("trigger_now");

  std::optional<gid_t> chronos_gid = delegate_->FindGroupId("chronos");
  if (!chronos_gid) {
    LOG(ERROR) << "chronos group not found";
    return false;
  }

  if (!delegate_->SetOwnership(trigger_now, -1, chronos_gid.value())) {
    LOG(ERROR) << "cannot configure ownership on the trigger";
    return false;
  }

  int permission = delegate_->GetPermissions(trigger_now);
  permission |= base::FILE_PERMISSION_WRITE_BY_GROUP;
  if (!delegate_->SetPermissions(trigger_now, permission)) {
    LOG(ERROR) << "cannot configure permissions on the trigger";
    return false;
  }

  LOG(INFO) << "sysfs trigger setup complete";
  return true;
}

bool Configuration::EnableAccelScanElements() {
  auto timestamp = sensor_->GetChannel("timestamp");
  if (!timestamp) {
    LOG(ERROR) << "cannot find timestamp channel";
    return false;
  }
  if (!timestamp->SetScanElementsEnabled(false)) {
    LOG(ERROR) << "failed to disable timestamp channel";
    return false;
  }

  std::vector<std::string> channels_to_enable;

  if (sensor_->IsSingleSensor()) {
    for (const auto& axis : kAccelAxes) {
      channels_to_enable.push_back(base::StringPrintf("accel_%s", axis));
    }
  } else {
    for (const auto& axis : kAccelAxes) {
      channels_to_enable.push_back(
          base::StringPrintf("accel_%s_%s", axis, kBaseSensorLocation));
      channels_to_enable.push_back(
          base::StringPrintf("accel_%s_%s", axis, kLidSensorLocation));
    }
  }

  for (const auto& chan_name : channels_to_enable) {
    auto channel = sensor_->GetChannel(chan_name);
    if (!channel) {
      LOG(ERROR) << "cannot find channel " << chan_name;
      return false;
    }
    if (!channel->SetScanElementsEnabled(true)) {
      LOG(ERROR) << "failed to enable channel " << chan_name;
      return false;
    }
  }

  sensor_->EnableBuffer(1);
  if (!sensor_->IsBufferEnabled()) {
    LOG(ERROR) << "failed to enable buffer";
    return false;
  }

  LOG(INFO) << "buffer enabled";
  return true;
}

bool Configuration::EnableCalibration(bool enable) {
  auto calibration = sensor_->GetChannel("calibration");
  if (!calibration) {
    LOG(ERROR) << "cannot find calibration channel";
    return false;
  }
  return calibration->SetScanElementsEnabled(enable);
}

bool Configuration::EnableKeyboardAngle() {
  base::FilePath kb_wake_angle =
      base::FilePath("/sys/class/chromeos/cros_ec/kb_wake_angle");

  if (!delegate_->Exists(kb_wake_angle)) {
    LOG(INFO) << kb_wake_angle.value()
              << " not found; will not enable EC wake angle";
    return true;
  }

  std::optional<gid_t> power_gid = delegate_->FindGroupId("power");
  if (!power_gid) {
    LOG(ERROR) << "cannot configure ownership on the wake angle file";
    return false;
  }

  delegate_->SetOwnership(kb_wake_angle, -1, power_gid.value());
  int permission = delegate_->GetPermissions(kb_wake_angle);
  permission |= base::FILE_PERMISSION_WRITE_BY_GROUP;
  delegate_->SetPermissions(kb_wake_angle, permission);

  LOG(INFO) << "keyboard angle enabled";
  return true;
}

bool Configuration::ConfigureOnKind() {
  switch (kind_) {
    case SensorKind::ACCELEROMETER:
      return ConfigAccelerometer();
    case SensorKind::GYROSCOPE:
      return ConfigGyro();
    case SensorKind::LIGHT:
      return ConfigIlluminance();
    case SensorKind::SYNC:
      // No other configs needed.
      return true;
    case SensorKind::MAGNETOMETER:
      // No other configs needed.
      return true;
    case SensorKind::LID_ANGLE:
      // No other configs needed.
      return true;
    case SensorKind::PROXIMITY:
      return ConfigProximity();
    case SensorKind::BAROMETER:
      // TODO(chenghaoyang): Setup calibrations for the barometer.
      return true;
    case SensorKind::HID_OTHERS:
      // No other configs needed.
      return true;
    default:
      CHECK(kind_ == SensorKind::OTHERS);
      LOG(ERROR) << sensor_->GetName() << " unimplemented";
      return false;
  }
}

bool Configuration::ConfigGyro() {
  CopyImuCalibationFromVpd(kGyroMaxVpdCalibration);

  LOG(INFO) << "gyroscope configuration complete";
  return true;
}

bool Configuration::ConfigAccelerometer() {
  CopyImuCalibationFromVpd(kAccelMaxVpdCalibration);

  if (!AddSysfsTrigger(kAccelSysfsTriggerId))
    return false;

  if (!EnableKeyboardAngle())
    return false;

  /*
   * Gather gyroscope. If one of them is on the same plane, set
   * accelerometer range to 4g to meet Android 10 CCD Requirements
   * (Section 7.1.4, C.1.4).
   * If no gyro found, set range to 4g on the lid accel if there are 2 accels
   */
  int range = 0;
  auto location = sensor_->GetLocation();
  if (location && !location->empty()) {
    auto gyros = context_->GetDevicesByName("cros-ec-gyro");
    if (gyros.size() > 1) {
      range = 4;
    } else if (gyros.size() == 1) {
      if (strcmp(location->c_str(), gyros[0]->GetLocation()->c_str()) == 0)
        range = 4;
      else
        range = 2;
    } else {
      auto accels = context_->GetDevicesByName("cros-ec-accel");
      if (accels.size() == 1)
        range = 4;
      else if (accels.size() > 1 &&
               strcmp(location->c_str(), kLidSensorLocation) == 0)
        range = 4;
      else
        range = 2;
    }

    if (!sensor_->WriteNumberAttribute(kCalibrationScale, range))
      return false;
  }

  LOG(INFO) << "accelerometer configuration complete";
  return true;
}

bool Configuration::ConfigIlluminance() {
  if (strcmp(sensor_->GetName(), "acpi-als") == 0) {
    std::string trigger_name =
        base::StringPrintf(libmems::kHrtimerNameFormatString, sensor_->GetId());
    if (context_->GetTriggersByName(trigger_name).empty()) {
      base::FilePath hrtimer_path("/sys/kernel/config/iio/triggers/hrtimer");
      hrtimer_path = hrtimer_path.Append(trigger_name);

      if (!delegate_->Exists(hrtimer_path) &&
          !delegate_->ProbeKernelModule("iio-trig-hrtimer")) {
        LOG(ERROR) << "cannot load iio-trig-hrtimer module";
        return false;
      }

      if (!delegate_->CreateDirectory(hrtimer_path)) {
        LOG(ERROR) << "cannot mkdir " << hrtimer_path.value()
                   << " to create the hrtimer device";
        return false;
      }
    }

    context_->Reload();
    auto triggers = context_->GetTriggersByName(trigger_name);
    if (triggers.empty()) {
      LOG(ERROR) << "cannot find acpi-als's trigger";
      return false;
    }

    // Don't set |trigger| as |sensor_|'s trigger, or else the samples start
    // flowing.
    auto trigger = triggers.front();
    // /sys/bus/iio/devices/triggerX
    base::FilePath sys_trg_path =
        trigger->GetPath().Append(libmems::kSamplingFrequencyAttr);
    SetReadPermissionAndOwnership(sys_trg_path);
    SetWritePermissionAndOwnership(sys_trg_path);
  }

  if (!CopyLightCalibrationFromVpd())
    return false;

  // Disable calibration: it can fail if the light sensor does not support
  // calibration mode.
  EnableCalibration(false);

  LOG(INFO) << "light configuration complete";
  return true;
}

bool Configuration::ConfigProximity() {
  auto* cros_config = delegate_->GetCrosConfig();

  auto sys_path = sensor_->GetAbsoluteSysPath();
  if (!sys_path.has_value()) {
    LOG(ERROR) << "Invalid absolute SysPath";
    return false;
  }

  bool isSar;

  auto devlink_opt = delegate_->GetIioSarSensorDevlink(sys_path->value());
  if (devlink_opt.has_value())
    isSar = true;
  else if (IsIioActivitySensor(sys_path->value()))
    isSar = false;
  else
    return false;

  if (isSar) {
    // |devlink_opt.value()| should have prefix "/dev/proximity_" or
    // "/dev/proximity-".
    if (devlink_opt.value().compare(0, std::strlen(kDevlinkPrefix),
                                    kDevlinkPrefix) != 0) {
      LOG(ERROR) << "Devlink isn't in the proper format: "
                 << devlink_opt.value();
      return false;
    }

    auto sar_config_reader =
        libsar::SarConfigReader(cros_config, devlink_opt.value(),
                                delegate_->GetSarConfigReaderDelegate());

    if (!sar_config_reader.isCellular() && !sar_config_reader.isWifi()) {
      LOG(ERROR) << "Invalid devlink: " << devlink_opt.value()
                 << ", neither lte nor wifi";
      return false;
    }

    auto config_dict_opt = sar_config_reader.GetSarConfigDict();
    if (!config_dict_opt.has_value())
      return false;

    const base::Value::Dict& config_dict = config_dict_opt.value();

    std::optional<double> sampling_frequency =
        config_dict.FindDouble("samplingFrequency");
    if (sampling_frequency.has_value()) {
      if (!sensor_->WriteDoubleAttribute(libmems::kSamplingFrequencyAttr,
                                         sampling_frequency.value())) {
        LOG(ERROR) << "Could not set proximity sensor sampling frequency";
        return false;
      }
    }

    const base::Value::List* channel_list =
        config_dict.FindList("channelConfig");
    if (channel_list) {
      // Semtech supports multiple channels, a given observer may received
      // FAR/NEAR message from multiple channels.
      for (const base::Value& channel : *channel_list) {
        const base::Value::Dict& channel_dict = channel.GetDict();
        const std::string* channel_name = channel_dict.FindString("channel");
        if (!channel_name) {
          LOG(ERROR) << "channel identifier required";
          return false;
        }
        int channel_int;
        if (!base::StringToInt(*channel_name, &channel_int)) {
          LOG(ERROR) << "Invalid channel_name: " << channel_name;
          return false;
        }

        std::optional<int> hardwaregain = channel_dict.FindInt("hardwaregain");
        if (hardwaregain.has_value()) {
          auto* iio_channel = sensor_->GetChannel("proximity" + *channel_name);
          if (!iio_channel || !iio_channel->WriteNumberAttribute(
                                  "hardwaregain", hardwaregain.value())) {
            LOG(ERROR) << "Could not set proximity sensor hardware gain";
            return false;
          }
        }

        if (!SetIioRisingFallingValue(
                channel_dict, "", "events/in_proximity" + *channel_name + "_",
                "_value")) {
          return false;
        }

        if (!SetIioRisingFallingValue(
                channel_dict, "Hysteresis",
                "events/in_proximity" + *channel_name + "_", "_hysteresis")) {
          return false;
        }
      }
    }

    if (!SetIioRisingFallingValue(config_dict, "Period", "events/", "_period"))
      return false;
  }

  LOG(INFO) << "proximity configuration complete";
  return true;
}

bool Configuration::IsIioActivitySensor(const std::string& sys_path) {
  return sys_path.find("-activity") != std::string::npos;
}

bool Configuration::SetIioRisingFallingValue(
    const base::Value::Dict& config_dict,
    const std::string& config_postfix,
    const std::string& path_prefix,
    const std::string& postfix) {
  std::string rising_config = "threshRising" + config_postfix;
  std::string falling_config = "threshFalling" + config_postfix;
  std::optional<int> rising_value = config_dict.FindInt(rising_config);
  std::optional<int> falling_value = config_dict.FindInt(falling_config);

  if (!rising_value.has_value() && !falling_value.has_value())
    return true;

  bool try_either = rising_value.has_value() && falling_value.has_value() &&
                    falling_value.value() == rising_value.value();

  std::string prefix = path_prefix + "thresh_";
  std::string falling_path = prefix + "falling" + postfix;
  std::string rising_path = prefix + "rising" + postfix;
  std::string either_path = prefix + "either" + postfix;

  if (!try_either ||
      !sensor_->WriteNumberAttribute(either_path, rising_value.value())) {
    if (rising_value.has_value() &&
        !sensor_->WriteNumberAttribute(rising_path, rising_value.value())) {
      LOG(ERROR) << "Could not set proximity sensor " << rising_path << " to "
                 << rising_value.value();
      return false;
    }
    if (falling_value.has_value() &&
        !sensor_->WriteNumberAttribute(falling_path, falling_value.value())) {
      LOG(ERROR) << "Could not set proximity sensor " << falling_path << " to "
                 << falling_value.value();
      return false;
    }
  }

  return true;
}

bool Configuration::SetupPermissions() {
  std::vector<base::FilePath> files_to_set_read_own;
  std::vector<base::FilePath> files_to_set_write_own;

  std::string dev_name =
      libmems::IioDeviceImpl::GetStringFromId(sensor_->GetId());
  // /dev/iio:deviceX
  base::FilePath dev_path =
      base::FilePath(libmems::kDevString).Append(dev_name.c_str());
  if (!delegate_->Exists(dev_path)) {
    LOG(ERROR) << "Missing path: " << dev_path.value();
    return false;
  }

  files_to_set_read_own.push_back(dev_path);
  files_to_set_write_own.push_back(dev_path);

  // /sys/bus/iio/devices/iio:deviceX
  base::FilePath sys_dev_path = sensor_->GetPath();

  // Files under /sys/bus/iio/devices/iio:deviceX/.
  auto files = delegate_->EnumerateAllFiles(sys_dev_path);
  files_to_set_read_own.insert(files_to_set_read_own.end(), files.begin(),
                               files.end());
  for (const base::FilePath& file : files) {
    std::string name = file.BaseName().value();
    if (RE2::FullMatch(name, "in_.*_sampling_frequency"))
      files_to_set_write_own.push_back(file);
  }

  // Files under /sys/bus/iio/devices/iio:deviceX/scan_elements/.
  files =
      delegate_->EnumerateAllFiles(sys_dev_path.Append(kScanElementsString));
  files_to_set_read_own.insert(files_to_set_read_own.end(), files.begin(),
                               files.end());
  for (const base::FilePath& file : files) {
    std::string name = file.BaseName().value();
    if (RE2::FullMatch(name, "in_.*_en"))
      files_to_set_write_own.push_back(file);
  }

  // Files under /sys/bus/iio/devices/iio:deviceX/events/.
  files = delegate_->EnumerateAllFiles(sys_dev_path.Append(kEventsString));
  files_to_set_read_own.insert(files_to_set_read_own.end(), files.begin(),
                               files.end());
  for (const base::FilePath& file : files) {
    std::string name = file.BaseName().value();
    if (RE2::FullMatch(name, "in_.*_en"))
      files_to_set_write_own.push_back(file);
  }

  for (auto file : kFilesToSetReadAndOwnership)
    files_to_set_read_own.push_back(sys_dev_path.Append(file));

  for (auto file : kFilesToSetWriteAndOwnership)
    files_to_set_write_own.push_back(sys_dev_path.Append(file));

  // Set permissions and ownerships.
  bool result = true;

  for (base::FilePath path : files_to_set_read_own)
    result &= SetReadPermissionAndOwnership(path);

  for (base::FilePath path : files_to_set_write_own)
    result &= SetWritePermissionAndOwnership(path);

  return result;
}

bool Configuration::SetReadPermissionAndOwnership(base::FilePath file_path) {
  DCHECK(iioservice_gid_.has_value());

  if (!delegate_->Exists(file_path))
    return true;

  bool result = true;

  int permission = delegate_->GetPermissions(file_path);
  permission |= base::FILE_PERMISSION_READ_BY_GROUP;

  if (!delegate_->SetPermissions(file_path, permission)) {
    LOG(ERROR) << "cannot configure permissions on " << file_path.value();
    result = false;
  }

  if (!delegate_->SetOwnership(file_path, -1, iioservice_gid_.value())) {
    LOG(ERROR) << "cannot configure ownership on " << file_path.value();
    result = false;
  }

  return result;
}

bool Configuration::SetWritePermissionAndOwnership(base::FilePath file_path) {
  DCHECK(iioservice_gid_.has_value());

  if (!delegate_->Exists(file_path))
    return true;

  bool result = true;

  int permission = delegate_->GetPermissions(file_path);
  permission |= base::FILE_PERMISSION_WRITE_BY_GROUP;

  if (!delegate_->SetPermissions(file_path, permission)) {
    LOG(ERROR) << "cannot configure permissions on " << file_path.value();
    result = false;
  }

  if (!delegate_->SetOwnership(file_path, -1, iioservice_gid_.value())) {
    LOG(ERROR) << "cannot configure ownership on " << file_path.value();
    result = false;
  }

  return result;
}

}  // namespace mems_setup
