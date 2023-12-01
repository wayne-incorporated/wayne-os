// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_health_tool/telem/telem.h"

#include <sys/types.h>

#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <map>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include <base/json/json_writer.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/values.h>
#include <brillo/flag_helper.h>
#include <mojo/public/cpp/bindings/remote.h>
#include <mojo/service_constants.h>

#include "diagnostics/cros_health_tool/mojo_util.h"
#include "diagnostics/cros_health_tool/output_util.h"
#include "diagnostics/mojom/external/network_health_types.mojom.h"
#include "diagnostics/mojom/external/network_types.mojom.h"
#include "diagnostics/mojom/public/cros_healthd.mojom.h"
#include "diagnostics/mojom/public/cros_healthd_probe.mojom.h"

namespace diagnostics {

namespace {

namespace mojom = ::ash::cros_healthd::mojom;
namespace network_config_mojom = ::chromeos::network_config::mojom;
namespace network_health_mojom = ::chromeos::network_health::mojom;

constexpr std::pair<const char*, mojom::ProbeCategoryEnum> kCategorySwitches[] =
    {
        {"battery", mojom::ProbeCategoryEnum::kBattery},
        {"storage", mojom::ProbeCategoryEnum::kNonRemovableBlockDevices},
        {"cpu", mojom::ProbeCategoryEnum::kCpu},
        {"timezone", mojom::ProbeCategoryEnum::kTimezone},
        {"memory", mojom::ProbeCategoryEnum::kMemory},
        {"backlight", mojom::ProbeCategoryEnum::kBacklight},
        {"fan", mojom::ProbeCategoryEnum::kFan},
        {"stateful_partition", mojom::ProbeCategoryEnum::kStatefulPartition},
        {"bluetooth", mojom::ProbeCategoryEnum::kBluetooth},
        {"system", mojom::ProbeCategoryEnum::kSystem},
        {"network", mojom::ProbeCategoryEnum::kNetwork},
        {"audio", mojom::ProbeCategoryEnum::kAudio},
        {"boot_performance", mojom::ProbeCategoryEnum::kBootPerformance},
        {"bus", mojom::ProbeCategoryEnum::kBus},
        {"network_interface", mojom::ProbeCategoryEnum::kNetworkInterface},
        {"tpm", mojom::ProbeCategoryEnum::kTpm},
        {"graphics", mojom::ProbeCategoryEnum::kGraphics},
        {"display", mojom::ProbeCategoryEnum::kDisplay},
        {"input", mojom::ProbeCategoryEnum::kInput},
        {"audio_hardware", mojom::ProbeCategoryEnum::kAudioHardware},
        {"sensor", mojom::ProbeCategoryEnum::kSensor},
};

void DisplayError(const mojom::ProbeErrorPtr& error) {
  base::Value::Dict output;
  SET_DICT(type, error, &output);
  SET_DICT(msg, error, &output);

  OutputJson(output);
}

void DisplayProcessInfo(const mojom::ProcessResultPtr& result) {
  if (result.is_null())
    return;

  if (result->is_error()) {
    DisplayError(result->get_error());
    return;
  }

  const auto& info = result->get_process_info();

  base::Value::Dict output;
  SET_DICT(bytes_read, info, &output);
  SET_DICT(bytes_written, info, &output);
  SET_DICT(cancelled_bytes_written, info, &output);
  SET_DICT(command, info, &output);
  SET_DICT(free_memory_kib, info, &output);
  SET_DICT(name, info, &output);
  SET_DICT(nice, info, &output);
  SET_DICT(parent_process_id, info, &output);
  SET_DICT(process_group_id, info, &output);
  SET_DICT(process_id, info, &output);
  SET_DICT(physical_bytes_read, info, &output);
  SET_DICT(physical_bytes_written, info, &output);
  SET_DICT(priority, info, &output);
  SET_DICT(read_system_calls, info, &output);
  SET_DICT(resident_memory_kib, info, &output);
  SET_DICT(state, info, &output);
  SET_DICT(threads, info, &output);
  SET_DICT(total_memory_kib, info, &output);
  SET_DICT(uptime_ticks, info, &output);
  SET_DICT(user_id, info, &output);
  SET_DICT(write_system_calls, info, &output);

  OutputJson(output);
}

void DisplayMultipleProcessInfo(const mojom::MultipleProcessResultPtr& result) {
  if (result.is_null())
    return;

  const auto& info = result;

  base::Value::Dict output;
  base::Value::Dict process_infos;
  if (!info->process_infos.empty()) {
    for (const auto& process_info_key_value : info->process_infos) {
      base::Value::Dict process_info;
      SET_DICT(bytes_read, process_info_key_value.second, &process_info);
      SET_DICT(bytes_written, process_info_key_value.second, &process_info);
      SET_DICT(cancelled_bytes_written, process_info_key_value.second,
               &process_info);
      SET_DICT(command, process_info_key_value.second, &process_info);
      SET_DICT(free_memory_kib, process_info_key_value.second, &process_info);
      SET_DICT(name, process_info_key_value.second, &process_info);
      SET_DICT(nice, process_info_key_value.second, &process_info);
      SET_DICT(parent_process_id, process_info_key_value.second, &process_info);
      SET_DICT(process_group_id, process_info_key_value.second, &process_info);
      SET_DICT(process_id, process_info_key_value.second, &process_info);
      SET_DICT(physical_bytes_read, process_info_key_value.second,
               &process_info);
      SET_DICT(physical_bytes_written, process_info_key_value.second,
               &process_info);
      SET_DICT(priority, process_info_key_value.second, &process_info);
      SET_DICT(read_system_calls, process_info_key_value.second, &process_info);
      SET_DICT(resident_memory_kib, process_info_key_value.second,
               &process_info);
      SET_DICT(state, process_info_key_value.second, &process_info);
      SET_DICT(threads, process_info_key_value.second, &process_info);
      SET_DICT(total_memory_kib, process_info_key_value.second, &process_info);
      SET_DICT(uptime_ticks, process_info_key_value.second, &process_info);
      SET_DICT(user_id, process_info_key_value.second, &process_info);
      SET_DICT(write_system_calls, process_info_key_value.second,
               &process_info);
      process_infos.Set(base::NumberToString(process_info_key_value.first),
                        std::move(process_info));
    }
  }
  output.Set("process_infos", std::move(process_infos));

  base::Value::Dict errors;
  if (!info->errors.empty()) {
    for (const auto& error_key_value : info->errors) {
      base::Value::Dict error;
      SET_DICT(type, error_key_value.second, &error);
      SET_DICT(msg, error_key_value.second, &error);
      errors.Set(base::NumberToString(error_key_value.first), std::move(error));
    }
  }
  output.Set("errors", std::move(errors));

  OutputJson(output);
}

void DisplayBatteryInfo(const mojom::BatteryResultPtr& result) {
  if (result->is_error()) {
    DisplayError(result->get_error());
    return;
  }

  const auto& info = result->get_battery_info();
  // There might be no battery if it's AC only.
  // Run the following command on DUT to see if the device is configured to AC
  // only.
  // # cros_config /hardware-properties psu-type
  if (info.is_null()) {
    return;
  }

  base::Value::Dict output;
  SET_DICT(charge_full, info, &output);
  SET_DICT(charge_full_design, info, &output);
  SET_DICT(charge_now, info, &output);
  SET_DICT(current_now, info, &output);
  SET_DICT(cycle_count, info, &output);
  SET_DICT(model_name, info, &output);
  SET_DICT(serial_number, info, &output);
  SET_DICT(status, info, &output);
  SET_DICT(technology, info, &output);
  SET_DICT(vendor, info, &output);
  SET_DICT(voltage_min_design, info, &output);
  SET_DICT(voltage_now, info, &output);

  // Optional fields
  SET_DICT(manufacture_date, info, &output);
  SET_DICT(temperature, info, &output);

  OutputJson(output);
}

void DisplayAudioInfo(const mojom::AudioResultPtr& audio_result) {
  if (audio_result->is_error()) {
    DisplayError(audio_result->get_error());
    return;
  }

  const auto& audio = audio_result->get_audio_info();
  if (audio.is_null()) {
    std::cout << "Device does not have audio info" << std::endl;
    return;
  }

  base::Value::Dict output;
  SET_DICT(input_device_name, audio, &output);
  SET_DICT(output_device_name, audio, &output);
  SET_DICT(input_mute, audio, &output);
  SET_DICT(output_mute, audio, &output);
  SET_DICT(input_gain, audio, &output);
  SET_DICT(output_volume, audio, &output);
  SET_DICT(severe_underruns, audio, &output);
  SET_DICT(underruns, audio, &output);

  base::Value::List output_nodes;
  if (audio->output_nodes.has_value()) {
    for (const auto& node : audio->output_nodes.value()) {
      base::Value::Dict node_info;
      SET_DICT(id, node, &node_info);
      SET_DICT(name, node, &node_info);
      SET_DICT(device_name, node, &node_info);
      SET_DICT(active, node, &node_info);
      SET_DICT(node_volume, node, &node_info);
      output_nodes.Append(std::move(node_info));
    }
  }
  output.Set("output_nodes", std::move(output_nodes));

  base::Value::List input_nodes;
  if (audio->input_nodes.has_value()) {
    for (const auto& node : audio->input_nodes.value()) {
      base::Value::Dict node_info;
      SET_DICT(id, node, &node_info);
      SET_DICT(name, node, &node_info);
      SET_DICT(device_name, node, &node_info);
      SET_DICT(active, node, &node_info);
      SET_DICT(node_volume, node, &node_info);
      SET_DICT(input_node_gain, node, &node_info);
      input_nodes.Append(std::move(node_info));
    }
  }
  output.Set("input_nodes", std::move(input_nodes));

  OutputJson(output);
}

void DisplayDisplayInfo(const mojom::DisplayResultPtr& display_result) {
  if (display_result->is_error()) {
    DisplayError(display_result->get_error());
    return;
  }

  const auto& display = display_result->get_display_info();
  if (display.is_null()) {
    std::cout << "Device does not have display info" << std::endl;
    return;
  }

  const auto& edp_info = display->edp_info;
  base::Value::Dict output;
  base::Value::Dict edp;
  SET_DICT(privacy_screen_supported, edp_info, &edp);
  SET_DICT(privacy_screen_enabled, edp_info, &edp);
  SET_DICT(display_width, edp_info, &edp);
  SET_DICT(display_height, edp_info, &edp);
  SET_DICT(resolution_horizontal, edp_info, &edp);
  SET_DICT(resolution_vertical, edp_info, &edp);
  SET_DICT(refresh_rate, edp_info, &edp);
  SET_DICT(manufacturer, edp_info, &edp);
  SET_DICT(model_id, edp_info, &edp);
  SET_DICT(serial_number, edp_info, &edp);
  SET_DICT(manufacture_week, edp_info, &edp);
  SET_DICT(manufacture_year, edp_info, &edp);
  SET_DICT(edid_version, edp_info, &edp);
  SET_DICT(input_type, edp_info, &edp);
  SET_DICT(display_name, edp_info, &edp);
  output.Set("edp", std::move(edp));

  if (display->dp_infos) {
    const auto& dp_infos = display->dp_infos;
    base::Value::List dp;
    for (const auto& dp_info : *dp_infos) {
      base::Value::Dict data;
      SET_DICT(display_width, dp_info, &data);
      SET_DICT(display_height, dp_info, &data);
      SET_DICT(resolution_horizontal, dp_info, &data);
      SET_DICT(resolution_vertical, dp_info, &data);
      SET_DICT(refresh_rate, dp_info, &data);
      SET_DICT(manufacturer, dp_info, &data);
      SET_DICT(model_id, dp_info, &data);
      SET_DICT(serial_number, dp_info, &data);
      SET_DICT(manufacture_week, dp_info, &data);
      SET_DICT(manufacture_year, dp_info, &data);
      SET_DICT(edid_version, dp_info, &data);
      SET_DICT(input_type, dp_info, &data);
      SET_DICT(display_name, dp_info, &data);
      dp.Append(std::move(data));
    }
    output.Set("dp", std::move(dp));
  }

  OutputJson(output);
}

void DisplayBootPerformanceInfo(const mojom::BootPerformanceResultPtr& result) {
  if (result->is_error()) {
    DisplayError(result->get_error());
    return;
  }

  const auto& info = result->get_boot_performance_info();
  CHECK(!info.is_null());

  base::Value::Dict output;
  SET_DICT(shutdown_reason, info, &output);
  SET_DICT(boot_up_seconds, info, &output);
  SET_DICT(boot_up_timestamp, info, &output);
  SET_DICT(shutdown_seconds, info, &output);
  SET_DICT(shutdown_timestamp, info, &output);
  SET_DICT(tpm_initialization_seconds, info, &output);

  OutputJson(output);
}

void DisplayBlockDeviceInfo(
    const mojom::NonRemovableBlockDeviceResultPtr& result) {
  if (result->is_error()) {
    DisplayError(result->get_error());
    return;
  }

  const auto& infos = result->get_block_device_info();

  base::Value::Dict output;
  base::Value::List block_devices;
  for (const auto& info : infos) {
    base::Value::Dict data;
    SET_DICT(bytes_read_since_last_boot, info, &data);
    SET_DICT(bytes_written_since_last_boot, info, &data);
    SET_DICT(io_time_seconds_since_last_boot, info, &data);
    SET_DICT(name, info, &data);
    SET_DICT(path, info, &data);
    SET_DICT(read_time_seconds_since_last_boot, info, &data);
    SET_DICT(serial, info, &data);
    SET_DICT(size, info, &data);
    SET_DICT(type, info, &data);
    SET_DICT(write_time_seconds_since_last_boot, info, &data);
    SET_DICT(manufacturer_id, info, &data);
    SET_DICT(firmware_string, info, &data);

    // optional field
    SET_DICT(discard_time_seconds_since_last_boot, info, &data);

    // DeviceInfo is only available on NVMe, eMMC and UFS.
    const auto& device_info = info->device_info;
    if (!device_info.is_null()) {
      base::Value::Dict device_info_out;
      if (device_info->is_nvme_device_info()) {
        base::Value::Dict nvme_device_info_out;
        SET_DICT(subsystem_vendor, device_info->get_nvme_device_info(),
                 &nvme_device_info_out);
        SET_DICT(subsystem_device, device_info->get_nvme_device_info(),
                 &nvme_device_info_out);
        SET_DICT(pcie_rev, device_info->get_nvme_device_info(),
                 &nvme_device_info_out);
        SET_DICT(firmware_rev, device_info->get_nvme_device_info(),
                 &nvme_device_info_out);
        device_info_out.Set("nvme_device_info",
                            std::move(nvme_device_info_out));
      } else if (device_info->is_emmc_device_info()) {
        base::Value::Dict emmc_device_info_out;
        SET_DICT(manfid, device_info->get_emmc_device_info(),
                 &emmc_device_info_out);
        SET_DICT(pnm, device_info->get_emmc_device_info(),
                 &emmc_device_info_out);
        SET_DICT(prv, device_info->get_emmc_device_info(),
                 &emmc_device_info_out);
        SET_DICT(fwrev, device_info->get_emmc_device_info(),
                 &emmc_device_info_out);
        device_info_out.Set("emmc_device_info",
                            std::move(emmc_device_info_out));
      } else if (device_info->is_ufs_device_info()) {
        base::Value::Dict ufs_device_info_out;
        SET_DICT(jedec_manfid, device_info->get_ufs_device_info(),
                 &ufs_device_info_out);
        SET_DICT(fwrev, device_info->get_ufs_device_info(),
                 &ufs_device_info_out);
        device_info_out.Set("ufs_device_info", std::move(ufs_device_info_out));
      }
      data.Set("device_info", std::move(device_info_out));
    }

    block_devices.Append(std::move(data));
  }
  output.Set("block_devices", std::move(block_devices));

  OutputJson(output);
}

void DisplayBluetoothInfo(const mojom::BluetoothResultPtr& result) {
  if (result->is_error()) {
    DisplayError(result->get_error());
    return;
  }

  const auto& infos = result->get_bluetooth_adapter_info();

  base::Value::Dict output;
  base::Value::List adapters;
  for (const auto& info : infos) {
    base::Value::Dict data;
    SET_DICT(address, info, &data);
    SET_DICT(name, info, &data);
    SET_DICT(num_connected_devices, info, &data);
    SET_DICT(powered, info, &data);

    base::Value::List connected_devices;
    if (info->connected_devices.has_value()) {
      for (const auto& device : info->connected_devices.value()) {
        base::Value::Dict device_data;
        SET_DICT(address, device, &device_data);
        SET_DICT(name, device, &device_data);
        SET_DICT(type, device, &device_data);
        SET_DICT(appearance, device, &device_data);
        SET_DICT(modalias, device, &device_data);
        SET_DICT(rssi, device, &device_data);
        SET_DICT(mtu, device, &device_data);
        SET_DICT(uuids, device, &device_data);
        SET_DICT(battery_percentage, device, &device_data);
        SET_DICT(bluetooth_class, device, &device_data);
        connected_devices.Append(std::move(device_data));
      }
    }
    data.Set("connected_devices", std::move(connected_devices));

    SET_DICT(discoverable, info, &data);
    SET_DICT(discovering, info, &data);
    SET_DICT(uuids, info, &data);
    SET_DICT(modalias, info, &data);
    SET_DICT(service_allow_list, info, &data);
    if (info->supported_capabilities) {
      base::Value::Dict out_capabilities;
      SET_DICT(max_adv_len, info->supported_capabilities, &out_capabilities);
      SET_DICT(max_scn_rsp_len, info->supported_capabilities,
               &out_capabilities);
      SET_DICT(min_tx_power, info->supported_capabilities, &out_capabilities);
      SET_DICT(max_tx_power, info->supported_capabilities, &out_capabilities);
      data.Set("supported_capabilities", std::move(out_capabilities));
    }
    adapters.Append(std::move(data));
  }
  output.Set("adapters", std::move(adapters));

  OutputJson(output);
}

void DisplayCpuInfo(const mojom::CpuResultPtr& result) {
  if (result->is_error()) {
    DisplayError(result->get_error());
    return;
  }

  const auto& info = result->get_cpu_info();

  base::Value::Dict output;
  base::Value::List physical_cpus;
  for (const auto& physical_cpu : info->physical_cpus) {
    base::Value::Dict physical_cpu_data;
    base::Value::List logical_cpus;
    for (const auto& logical_cpu : physical_cpu->logical_cpus) {
      base::Value::Dict logical_cpu_data;

      SET_DICT(idle_time_user_hz, logical_cpu, &logical_cpu_data);
      SET_DICT(max_clock_speed_khz, logical_cpu, &logical_cpu_data);
      SET_DICT(scaling_current_frequency_khz, logical_cpu, &logical_cpu_data);
      SET_DICT(scaling_max_frequency_khz, logical_cpu, &logical_cpu_data);
      SET_DICT(system_time_user_hz, logical_cpu, &logical_cpu_data);
      SET_DICT(user_time_user_hz, logical_cpu, &logical_cpu_data);
      SET_DICT(core_id, logical_cpu, &logical_cpu_data);

      base::Value::List c_states;
      for (const auto& c_state : logical_cpu->c_states) {
        base::Value::Dict c_state_data;
        SET_DICT(name, c_state, &c_state_data);
        SET_DICT(time_in_state_since_last_boot_us, c_state, &c_state_data);
        c_states.Append(std::move(c_state_data));
      }
      logical_cpu_data.Set("c_states", std::move(c_states));

      logical_cpus.Append(std::move(logical_cpu_data));
    }
    physical_cpu_data.Set("logical_cpus", std::move(logical_cpus));

    if (physical_cpu->flags) {
      base::Value::List cpu_flags;
      for (const auto& flag : *(physical_cpu->flags)) {
        cpu_flags.Append(std::move(flag));
      }
      physical_cpu_data.Set("flags", std::move(cpu_flags));
    }

    if (!physical_cpu->virtualization.is_null()) {
      base::Value::Dict cpu_virtualization;
      SET_DICT(type, physical_cpu->virtualization, &cpu_virtualization);
      SET_DICT(is_enabled, physical_cpu->virtualization, &cpu_virtualization);
      SET_DICT(is_locked, physical_cpu->virtualization, &cpu_virtualization);
      physical_cpu_data.Set("cpu_virtualization",
                            std::move(cpu_virtualization));
    }

    // Optional field
    SET_DICT(model_name, physical_cpu, &physical_cpu_data);

    physical_cpus.Append(std::move(physical_cpu_data));
  }
  output.Set("physical_cpus", std::move(physical_cpus));

  base::Value::List temperature_channels;
  for (const auto& channel : info->temperature_channels) {
    base::Value::Dict data;

    SET_DICT(temperature_celsius, channel, &data);

    // Optional field
    SET_DICT(label, channel, &data);

    temperature_channels.Append(std::move(data));
  }
  output.Set("temperature_channels", std::move(temperature_channels));

  SET_DICT(num_total_threads, info, &output);
  SET_DICT(architecture, info, &output);

  base::Value::Dict vulnerabilities;
  for (const auto& vulnerability_key_value : *(info->vulnerabilities)) {
    base::Value::Dict vulnerability;
    SET_DICT(status, vulnerability_key_value.second, &vulnerability);
    SET_DICT(message, vulnerability_key_value.second, &vulnerability);
    vulnerabilities.Set(vulnerability_key_value.first,
                        std::move(vulnerability));
  }

  if (info->virtualization) {
    base::Value::Dict virtualization_info;
    SET_DICT(has_kvm_device, info->virtualization, &virtualization_info);
    SET_DICT(is_smt_active, info->virtualization, &virtualization_info);
    SET_DICT(smt_control, info->virtualization, &virtualization_info);
    output.Set("virtualization", std::move(virtualization_info));
  }

  if (info->keylocker_info) {
    base::Value::Dict out_keylocker;
    SET_DICT(keylocker_configured, info->keylocker_info, &out_keylocker);
    output.Set("keylocker_info", std::move(out_keylocker));
  }

  output.Set("vulnerabilities", std::move(vulnerabilities));
  OutputJson(output);
}

void DisplayFanInfo(const mojom::FanResultPtr& result) {
  if (result->is_error()) {
    DisplayError(result->get_error());
    return;
  }

  const auto& infos = result->get_fan_info();

  base::Value::Dict output;
  base::Value::List fans;
  for (const auto& info : infos) {
    base::Value::Dict data;
    SET_DICT(speed_rpm, info, &data);

    fans.Append(std::move(data));
  }
  output.Set("fans", std::move(fans));

  OutputJson(output);
}

void DisplayNetworkInfo(const mojom::NetworkResultPtr& result) {
  if (result->is_error()) {
    DisplayError(result->get_error());
    return;
  }

  const auto& infos = result->get_network_health()->networks;

  base::Value::Dict output;
  base::Value::List networks;
  for (const auto& info : infos) {
    base::Value::Dict data;
    SET_DICT(portal_state, info, &data);
    SET_DICT(state, info, &data);
    SET_DICT(type, info, &data);

    // Optional fields
    SET_DICT(guid, info, &data);
    SET_DICT(name, info, &data);
    SET_DICT(mac_address, info, &data);
    SET_DICT(ipv4_address, info, &data);
    SET_DICT(signal_strength, info, &data);
    if (info->signal_strength_stats) {
      base::Value::Dict stats;
      SET_DICT(average, info->signal_strength_stats, &stats);
      SET_DICT(deviation, info->signal_strength_stats, &stats);
      data.Set("signal_strength_stats", std::move(stats));
    }
    if (info->ipv6_addresses.size()) {
      SetJsonDictValue("ipv6_addresses",
                       base::JoinString(info->ipv6_addresses, ":"), &data);
    }

    networks.Append(std::move(data));
  }
  output.Set("networks", std::move(networks));

  OutputJson(output);
}

void DisplayNetworkInterfaceInfo(
    const mojom::NetworkInterfaceResultPtr& result) {
  if (result->is_error()) {
    DisplayError(result->get_error());
    return;
  }

  const auto& infos = result->get_network_interface_info();

  base::Value::Dict output;
  base::Value::List out_network_interfaces;

  for (const auto& network_interface : infos) {
    base::Value::Dict out_network_interface;
    switch (network_interface->which()) {
      case mojom::NetworkInterfaceInfo::Tag::kWirelessInterfaceInfo: {
        const auto& wireless_interface =
            network_interface->get_wireless_interface_info();
        base::Value::Dict out_wireless_interface;
        base::Value::Dict data;
        SET_DICT(interface_name, wireless_interface, &out_wireless_interface);
        SET_DICT(power_management_on, wireless_interface,
                 &out_wireless_interface);
        const auto& link_info = wireless_interface->wireless_link_info;
        if (link_info) {
          base::Value::Dict out_link;
          SET_DICT(access_point_address_str, link_info, &out_link);
          SET_DICT(tx_bit_rate_mbps, link_info, &out_link);
          SET_DICT(rx_bit_rate_mbps, link_info, &out_link);
          SET_DICT(tx_power_dBm, link_info, &out_link);
          SET_DICT(encyption_on, link_info, &out_link);
          SET_DICT(link_quality, link_info, &out_link);
          SET_DICT(signal_level_dBm, link_info, &out_link);
          out_wireless_interface.Set("link_info", std::move(out_link));
        }
        out_network_interface.Set("wireless_interface",
                                  std::move(out_wireless_interface));
        break;
      }
    }
    out_network_interfaces.Append(std::move(out_network_interface));
  }
  output.Set("network_interfaces", std::move(out_network_interfaces));

  OutputJson(output);
}

void DisplayTimezoneInfo(const mojom::TimezoneResultPtr& result) {
  if (result->is_error()) {
    DisplayError(result->get_error());
    return;
  }

  const auto& info = result->get_timezone_info();
  CHECK(!info.is_null());

  base::Value::Dict output;
  SET_DICT(posix, info, &output);
  SET_DICT(region, info, &output);

  OutputJson(output);
}

void DisplayMemoryInfo(const mojom::MemoryResultPtr& result) {
  if (result->is_error()) {
    DisplayError(result->get_error());
    return;
  }

  const auto& info = result->get_memory_info();
  CHECK(!info.is_null());

  base::Value::Dict output;
  SET_DICT(available_memory_kib, info, &output);
  SET_DICT(free_memory_kib, info, &output);
  SET_DICT(page_faults_since_last_boot, info, &output);
  SET_DICT(total_memory_kib, info, &output);

  const auto& memory_encryption_info = info->memory_encryption_info;
  if (memory_encryption_info) {
    base::Value::Dict out_mem_encryption;
    SET_DICT(encryption_state, memory_encryption_info, &out_mem_encryption);
    SET_DICT(max_key_number, memory_encryption_info, &out_mem_encryption);
    SET_DICT(key_length, memory_encryption_info, &out_mem_encryption);
    SET_DICT(active_algorithm, memory_encryption_info, &out_mem_encryption);
    output.Set("memory_encryption_info", std::move(out_mem_encryption));
  }

  OutputJson(output);
}

void DisplayBacklightInfo(const mojom::BacklightResultPtr& result) {
  if (result->is_error()) {
    DisplayError(result->get_error());
    return;
  }

  const auto& infos = result->get_backlight_info();

  base::Value::Dict output;
  base::Value::List backlights;

  for (const auto& info : infos) {
    base::Value::Dict data;
    SET_DICT(brightness, info, &data);
    SET_DICT(max_brightness, info, &data);
    SET_DICT(path, info, &data);
    backlights.Append(std::move(data));
  }
  output.Set("backlights", std::move(backlights));

  OutputJson(output);
}

void DisplayStatefulPartitionInfo(
    const mojom::StatefulPartitionResultPtr& result) {
  if (result->is_error()) {
    DisplayError(result->get_error());
    return;
  }

  const auto& info = result->get_partition_info();
  CHECK(!info.is_null());

  base::Value::Dict output;
  SET_DICT(available_space, info, &output);
  SET_DICT(filesystem, info, &output);
  SET_DICT(mount_source, info, &output);
  SET_DICT(total_space, info, &output);

  OutputJson(output);
}

void DisplaySystemInfo(const mojom::SystemResultPtr& system_result) {
  if (system_result->is_error()) {
    DisplayError(system_result->get_error());
    return;
  }
  const auto& system_info = system_result->get_system_info();
  base::Value::Dict output;

  const auto& os_info = system_info->os_info;
  base::Value::Dict out_os_info;
  SET_DICT(code_name, os_info, &out_os_info);
  SET_DICT(marketing_name, os_info, &out_os_info);
  SET_DICT(oem_name, os_info, &out_os_info);
  SET_DICT(boot_mode, os_info, &out_os_info);
  SET_DICT(efi_platform_size, os_info, &out_os_info);
  const auto& os_version = os_info->os_version;
  base::Value::Dict out_os_version;
  SET_DICT(release_milestone, os_version, &out_os_version);
  SET_DICT(build_number, os_version, &out_os_version);
  SET_DICT(branch_number, os_version, &out_os_version);
  SET_DICT(patch_number, os_version, &out_os_version);
  SET_DICT(release_channel, os_version, &out_os_version);
  out_os_info.Set("os_version", std::move(out_os_version));
  output.Set("os_info", std::move(out_os_info));

  const auto& vpd_info = system_info->vpd_info;
  if (vpd_info) {
    base::Value::Dict out_vpd_info;
    SET_DICT(serial_number, vpd_info, &out_vpd_info);
    SET_DICT(region, vpd_info, &out_vpd_info);
    SET_DICT(mfg_date, vpd_info, &out_vpd_info);
    SET_DICT(activate_date, vpd_info, &out_vpd_info);
    SET_DICT(sku_number, vpd_info, &out_vpd_info);
    SET_DICT(model_name, vpd_info, &out_vpd_info);
    SET_DICT(oem_name, vpd_info, &out_vpd_info);
    output.Set("vpd_info", std::move(out_vpd_info));
  }

  const auto& dmi_info = system_info->dmi_info;
  if (dmi_info) {
    base::Value::Dict out_dmi_info;
    SET_DICT(bios_vendor, dmi_info, &out_dmi_info);
    SET_DICT(bios_version, dmi_info, &out_dmi_info);
    SET_DICT(board_name, dmi_info, &out_dmi_info);
    SET_DICT(board_vendor, dmi_info, &out_dmi_info);
    SET_DICT(board_version, dmi_info, &out_dmi_info);
    SET_DICT(chassis_vendor, dmi_info, &out_dmi_info);
    SET_DICT(chassis_type, dmi_info, &out_dmi_info);
    SET_DICT(product_family, dmi_info, &out_dmi_info);
    SET_DICT(product_name, dmi_info, &out_dmi_info);
    SET_DICT(product_version, dmi_info, &out_dmi_info);
    SET_DICT(sys_vendor, dmi_info, &out_dmi_info);
    output.Set("dmi_info", std::move(out_dmi_info));
  }

  const auto& psr_info = system_info->psr_info;
  if (psr_info) {
    base::Value::Dict out_psr_info;
    SET_DICT(log_state, psr_info, &out_psr_info);
    SET_DICT(uuid, psr_info, &out_psr_info);
    SET_DICT(upid, psr_info, &out_psr_info);
    SET_DICT(log_start_date, psr_info, &out_psr_info);
    SET_DICT(oem_name, psr_info, &out_psr_info);
    SET_DICT(oem_make, psr_info, &out_psr_info);
    SET_DICT(oem_model, psr_info, &out_psr_info);
    SET_DICT(manufacture_country, psr_info, &out_psr_info);
    SET_DICT(oem_data, psr_info, &out_psr_info);
    SET_DICT(uptime_seconds, psr_info, &out_psr_info);
    SET_DICT(s5_counter, psr_info, &out_psr_info);
    SET_DICT(s4_counter, psr_info, &out_psr_info);
    SET_DICT(s3_counter, psr_info, &out_psr_info);
    SET_DICT(warm_reset_counter, psr_info, &out_psr_info);

    base::Value::List out_events;
    for (const auto& event : psr_info->events) {
      base::Value::Dict out_event;
      SET_DICT(type, event, &out_event);
      SET_DICT(time, event, &out_event)
      SET_DICT(data, event, &out_event)
      out_events.Append(std::move(out_event));
    }
    out_psr_info.Set("events", std::move(out_events));

    output.Set("psr_info", std::move(out_psr_info));
  }

  OutputJson(output);
}

base::Value::Dict GetBusDeviceJson(const mojom::BusDevicePtr& device) {
  base::Value::Dict out_device;
  SET_DICT(vendor_name, device, &out_device);
  SET_DICT(product_name, device, &out_device);
  SET_DICT(device_class, device, &out_device);
  base::Value::Dict out_bus_info;
  switch (device->bus_info->which()) {
    case mojom::BusInfo::Tag::kPciBusInfo: {
      base::Value::Dict out_pci_info;
      const auto& pci_info = device->bus_info->get_pci_bus_info();
      SET_DICT(class_id, pci_info, &out_pci_info);
      SET_DICT(subclass_id, pci_info, &out_pci_info);
      SET_DICT(prog_if_id, pci_info, &out_pci_info);
      SET_DICT(vendor_id, pci_info, &out_pci_info);
      SET_DICT(device_id, pci_info, &out_pci_info);
      SET_DICT(driver, pci_info, &out_pci_info);
      SET_DICT(sub_vendor_id, pci_info, &out_pci_info);
      SET_DICT(sub_device_id, pci_info, &out_pci_info);
      out_bus_info.Set("pci_bus_info", std::move(out_pci_info));
      break;
    }
    case mojom::BusInfo::Tag::kUsbBusInfo: {
      const auto& usb_info = device->bus_info->get_usb_bus_info();
      base::Value::Dict out_usb_info;

      SET_DICT(class_id, usb_info, &out_usb_info);
      SET_DICT(subclass_id, usb_info, &out_usb_info);
      SET_DICT(protocol_id, usb_info, &out_usb_info);
      SET_DICT(vendor_id, usb_info, &out_usb_info);
      SET_DICT(product_id, usb_info, &out_usb_info);
      SET_DICT(version, usb_info, &out_usb_info);
      SET_DICT(spec_speed, usb_info, &out_usb_info);

      base::Value::List out_usb_ifs;
      for (const auto& usb_if_info : usb_info->interfaces) {
        base::Value::Dict out_usb_if;
        SET_DICT(interface_number, usb_if_info, &out_usb_if);
        SET_DICT(class_id, usb_if_info, &out_usb_if);
        SET_DICT(subclass_id, usb_if_info, &out_usb_if);
        SET_DICT(protocol_id, usb_if_info, &out_usb_if);
        SET_DICT(driver, usb_if_info, &out_usb_if);
        out_usb_ifs.Append(std::move(out_usb_if));
      }
      out_usb_info.Set("interfaces", std::move(out_usb_ifs));

      if (usb_info->fwupd_firmware_version_info) {
        base::Value::Dict out_usb_firmware;
        SET_DICT(version, usb_info->fwupd_firmware_version_info,
                 &out_usb_firmware);
        SET_DICT(version_format, usb_info->fwupd_firmware_version_info,
                 &out_usb_firmware);
        out_usb_info.Set("fwupd_firmware_version_info",
                         std::move(out_usb_firmware));
      }
      out_bus_info.Set("usb_bus_info", std::move(out_usb_info));
      break;
    }
    case mojom::BusInfo::Tag::kThunderboltBusInfo: {
      const auto& thunderbolt_info =
          device->bus_info->get_thunderbolt_bus_info();
      base::Value::Dict out_thunderbolt_info;

      SET_DICT(security_level, thunderbolt_info, &out_thunderbolt_info);
      base::Value::List out_thunderbolt_interfaces;
      for (const auto& thunderbolt_interface :
           thunderbolt_info->thunderbolt_interfaces) {
        base::Value::Dict out_thunderbolt_interface;
        SET_DICT(vendor_name, thunderbolt_interface,
                 &out_thunderbolt_interface);
        SET_DICT(device_name, thunderbolt_interface,
                 &out_thunderbolt_interface);
        SET_DICT(device_type, thunderbolt_interface,
                 &out_thunderbolt_interface);
        SET_DICT(device_uuid, thunderbolt_interface,
                 &out_thunderbolt_interface);
        SET_DICT(tx_speed_gbs, thunderbolt_interface,
                 &out_thunderbolt_interface);
        SET_DICT(rx_speed_gbs, thunderbolt_interface,
                 &out_thunderbolt_interface);
        SET_DICT(authorized, thunderbolt_interface, &out_thunderbolt_interface);
        SET_DICT(device_fw_version, thunderbolt_interface,
                 &out_thunderbolt_interface);
        out_thunderbolt_interfaces.Append(std::move(out_thunderbolt_interface));
      }
      out_thunderbolt_info.Set("thunderbolt_interfaces",
                               std::move(out_thunderbolt_interfaces));
      out_bus_info.Set("thunderbolt_bus_info", std::move(out_thunderbolt_info));
      break;
    }
    case mojom::BusInfo::Tag::kUnmappedField: {
      NOTREACHED();
      break;
    }
  }
  out_device.Set("bus_info", std::move(out_bus_info));
  return out_device;
}

void DisplayBusDevices(const mojom::BusResultPtr& bus_result) {
  if (bus_result->is_error()) {
    DisplayError(bus_result->get_error());
    return;
  }

  const auto& devices = bus_result->get_bus_devices();

  base::Value::Dict output;
  base::Value::List out_devices;
  for (const auto& device : devices) {
    out_devices.Append(GetBusDeviceJson(device));
  }
  output.Set("devices", std::move(out_devices));

  OutputJson(output);
}

void DisplayTpmInfo(const mojom::TpmResultPtr& result) {
  if (result->is_error()) {
    DisplayError(result->get_error());
    return;
  }

  const auto& info = result->get_tpm_info();
  base::Value::Dict output;

  const auto& version = info->version;
  base::Value::Dict out_version;
  SET_DICT(gsc_version, version, &out_version);
  SET_DICT(family, version, &out_version);
  SET_DICT(spec_level, version, &out_version);
  SET_DICT(manufacturer, version, &out_version);
  SET_DICT(tpm_model, version, &out_version);
  SET_DICT(firmware_version, version, &out_version);
  SET_DICT(vendor_specific, version, &out_version);
  output.Set("version", std::move(out_version));

  const auto& status = info->status;
  base::Value::Dict out_status;
  SET_DICT(enabled, status, &out_status);
  SET_DICT(owned, status, &out_status);
  SET_DICT(owner_password_is_present, status, &out_status);
  output.Set("status", std::move(out_status));

  const auto& dictionary_attack = info->dictionary_attack;
  base::Value::Dict out_dictionary_attack;
  SET_DICT(counter, dictionary_attack, &out_dictionary_attack);
  SET_DICT(threshold, dictionary_attack, &out_dictionary_attack);
  SET_DICT(lockout_in_effect, dictionary_attack, &out_dictionary_attack);
  SET_DICT(lockout_seconds_remaining, dictionary_attack,
           &out_dictionary_attack);
  output.Set("dictionary_attack", std::move(out_dictionary_attack));

  const auto& attestation = info->attestation;
  base::Value::Dict out_attestation;
  SET_DICT(prepared_for_enrollment, attestation, &out_attestation);
  SET_DICT(enrolled, attestation, &out_attestation);
  output.Set("attestation", std::move(out_attestation));

  const auto& supported_features = info->supported_features;
  base::Value::Dict out_supported_features;
  SET_DICT(support_u2f, supported_features, &out_supported_features);
  SET_DICT(support_pinweaver, supported_features, &out_supported_features);
  SET_DICT(support_runtime_selection, supported_features,
           &out_supported_features);
  SET_DICT(is_allowed, supported_features, &out_supported_features);
  output.Set("supported_features", std::move(out_supported_features));

  SET_DICT(did_vid, info, &output);

  OutputJson(output);
}

void DisplayGraphicsInfo(const mojom::GraphicsResultPtr& graphics_result) {
  if (graphics_result->is_error()) {
    DisplayError(graphics_result->get_error());
    return;
  }

  const auto& info = graphics_result->get_graphics_info();
  CHECK(!info.is_null());

  base::Value::Dict output;
  const auto& gles_info = info->gles_info;
  base::Value::Dict out_gles_info;
  SET_DICT(version, gles_info, &out_gles_info);
  SET_DICT(shading_version, gles_info, &out_gles_info);
  SET_DICT(vendor, gles_info, &out_gles_info);
  SET_DICT(renderer, gles_info, &out_gles_info);
  SET_DICT(extensions, gles_info, &out_gles_info);
  output.Set("gles_info", std::move(out_gles_info));

  const auto& egl_info = info->egl_info;
  base::Value::Dict out_egl_info;
  SET_DICT(version, egl_info, &out_egl_info);
  SET_DICT(vendor, egl_info, &out_egl_info);
  SET_DICT(client_api, egl_info, &out_egl_info);
  SET_DICT(extensions, egl_info, &out_egl_info);
  output.Set("egl_info", std::move(out_egl_info));

  OutputJson(output);
}

void DisplayInputInfo(const mojom::InputResultPtr& input_result) {
  if (input_result->is_error()) {
    DisplayError(input_result->get_error());
    return;
  }

  const auto& info = input_result->get_input_info();
  CHECK(!info.is_null());

  base::Value::Dict output;
  SET_DICT(touchpad_library_name, info, &output);

  base::Value::List out_touchscreen_devices;
  for (const auto& touchscreen_device : info->touchscreen_devices) {
    base::Value::Dict out_touchscreen_device;
    SET_DICT(touch_points, touchscreen_device, &out_touchscreen_device);
    SET_DICT(has_stylus, touchscreen_device, &out_touchscreen_device);
    SET_DICT(has_stylus_garage_switch, touchscreen_device,
             &out_touchscreen_device);

    base::Value::Dict out_input_device;
    SET_DICT(name, touchscreen_device->input_device, &out_input_device);
    SET_DICT(connection_type, touchscreen_device->input_device,
             &out_input_device);
    SET_DICT(physical_location, touchscreen_device->input_device,
             &out_input_device);
    SET_DICT(is_enabled, touchscreen_device->input_device, &out_input_device);
    out_touchscreen_device.Set("input_device", std::move(out_input_device));

    out_touchscreen_devices.Append(std::move(out_touchscreen_device));
  }
  output.Set("touchscreen_devices", std::move(out_touchscreen_devices));

  OutputJson(output);
}

void DisplayAudioHardwareInfo(const mojom::AudioHardwareResultPtr& result) {
  if (result->is_error()) {
    DisplayError(result->get_error());
    return;
  }

  base::Value::Dict output;
  const auto& info = result->get_audio_hardware_info();
  CHECK(!info.is_null());

  const auto& audio_cards = info->audio_cards;
  base::Value::List out_audio_cards;
  for (const auto& audio_card : audio_cards) {
    base::Value::Dict out_audio_card;
    SET_DICT(alsa_id, audio_card, &out_audio_card);

    if (audio_card->bus_device) {
      out_audio_card.Set("bus_device",
                         GetBusDeviceJson(audio_card->bus_device));
    }

    const auto& hd_audio_codecs = audio_card->hd_audio_codecs;
    base::Value::List out_hd_audio_codecs;
    for (const auto& hd_audio_codec : hd_audio_codecs) {
      base::Value::Dict out_hd_audio_codec;
      SET_DICT(name, hd_audio_codec, &out_hd_audio_codec);
      SET_DICT(address, hd_audio_codec, &out_hd_audio_codec);

      out_hd_audio_codecs.Append(std::move(out_hd_audio_codec));
    }
    out_audio_card.Set("hd_audio_codecs", std::move(out_hd_audio_codecs));

    out_audio_cards.Append(std::move(out_audio_card));
  }
  output.Set("audio_cards", std::move(out_audio_cards));

  OutputJson(output);
}

void DisplaySensorInfo(const mojom::SensorResultPtr& result) {
  if (result->is_error()) {
    DisplayError(result->get_error());
    return;
  }

  base::Value::Dict output;
  const auto& info = result->get_sensor_info();
  CHECK(!info.is_null());

  if (info->sensors.has_value()) {
    base::Value::List out_sensors;
    for (const auto& sensor : info->sensors.value()) {
      base::Value::Dict out_sensor;
      SET_DICT(name, sensor, &out_sensor);
      SET_DICT(device_id, sensor, &out_sensor);
      SET_DICT(type, sensor, &out_sensor);
      SET_DICT(location, sensor, &out_sensor);
      out_sensors.Append(std::move(out_sensor));
    }
    output.Set("sensors", std::move(out_sensors));
  }

  SET_DICT(lid_angle, info, &output);

  OutputJson(output);
}

// Displays the retrieved telemetry information to the console.
void DisplayTelemetryInfo(const mojom::TelemetryInfoPtr& info) {
  const auto& battery_result = info->battery_result;
  if (battery_result)
    DisplayBatteryInfo(battery_result);

  const auto& block_device_result = info->block_device_result;
  if (block_device_result)
    DisplayBlockDeviceInfo(block_device_result);

  const auto& cpu_result = info->cpu_result;
  if (cpu_result)
    DisplayCpuInfo(cpu_result);

  const auto& timezone_result = info->timezone_result;
  if (timezone_result)
    DisplayTimezoneInfo(timezone_result);

  const auto& memory_result = info->memory_result;
  if (memory_result)
    DisplayMemoryInfo(memory_result);

  const auto& backlight_result = info->backlight_result;
  if (backlight_result)
    DisplayBacklightInfo(backlight_result);

  const auto& fan_result = info->fan_result;
  if (fan_result)
    DisplayFanInfo(fan_result);

  const auto& stateful_partition_result = info->stateful_partition_result;
  if (stateful_partition_result)
    DisplayStatefulPartitionInfo(stateful_partition_result);

  const auto& bluetooth_result = info->bluetooth_result;
  if (bluetooth_result)
    DisplayBluetoothInfo(bluetooth_result);

  const auto& network_result = info->network_result;
  if (network_result)
    DisplayNetworkInfo(network_result);

  const auto& audio_result = info->audio_result;
  if (audio_result)
    DisplayAudioInfo(audio_result);

  const auto& boot_performance_result = info->boot_performance_result;
  if (boot_performance_result)
    DisplayBootPerformanceInfo(boot_performance_result);

  const auto& network_interface_result = info->network_interface_result;
  if (network_interface_result)
    DisplayNetworkInterfaceInfo(network_interface_result);

  const auto& bus_result = info->bus_result;
  if (bus_result)
    DisplayBusDevices(bus_result);

  const auto& tpm_result = info->tpm_result;
  if (tpm_result)
    DisplayTpmInfo(tpm_result);

  const auto& system_result = info->system_result;
  if (system_result)
    DisplaySystemInfo(system_result);

  const auto& graphics_result = info->graphics_result;
  if (graphics_result)
    DisplayGraphicsInfo(graphics_result);

  const auto& display_result = info->display_result;
  if (display_result)
    DisplayDisplayInfo(display_result);

  const auto& input_result = info->input_result;
  if (input_result)
    DisplayInputInfo(input_result);

  const auto& audio_hardware_result = info->audio_hardware_result;
  if (audio_hardware_result)
    DisplayAudioHardwareInfo(audio_hardware_result);

  const auto& sensor_result = info->sensor_result;
  if (sensor_result)
    DisplaySensorInfo(sensor_result);
}

// Create a stringified list of the category names for use in help.
std::string GetCategoryHelp() {
  std::stringstream ss;
  ss << "Category or categories to probe, as comma-separated list: [";
  const char* sep = "";
  for (auto pair : kCategorySwitches) {
    ss << sep << pair.first;
    sep = ", ";
  }
  ss << "]";
  return ss.str();
}

}  // namespace

// 'telem' sub-command for cros-health-tool:
//
// Test driver for cros_healthd's telemetry collection. Supports requesting a
// comma-separate list of categories and/or a single process, multiple/ all
// processes at a time.
int telem_main(int argc, char** argv) {
  std::string category_help = GetCategoryHelp();
  DEFINE_string(category, "", category_help.c_str());
  DEFINE_string(process, "", "Process IDs to probe.");
  DEFINE_bool(ignore, false, "Set to true to ignore single process errors.");
  brillo::FlagHelper::Init(argc, argv, "telem - Device telemetry tool.");

  std::map<std::string, mojom::ProbeCategoryEnum> switch_to_category(
      std::begin(kCategorySwitches), std::end(kCategorySwitches));

  mojo::Remote<mojom::CrosHealthdProbeService> remote;
  RequestMojoServiceWithDisconnectHandler(
      chromeos::mojo_services::kCrosHealthdProbe, remote);

  // Probe single or multiple processes, if requested.
  if (FLAGS_process != "") {
    // Probe all processes if "all" is specified.
    if (FLAGS_process == "all") {
      MojoResponseWaiter<mojom::MultipleProcessResultPtr> waiter;
      remote->ProbeMultipleProcessInfo(std::nullopt, FLAGS_ignore,
                                       waiter.CreateCallback());
      DisplayMultipleProcessInfo(waiter.WaitForResponse());
      return EXIT_SUCCESS;
    }

    std::vector<uint32_t> process_ids;
    for (const auto& process_id_string :
         base::SplitString(FLAGS_process, ",", base::TRIM_WHITESPACE,
                           base::SPLIT_WANT_NONEMPTY)) {
      uint32_t process_id;
      if (!base::StringToUint(process_id_string, &process_id)) {
        LOG(ERROR) << "One of the provided process ids is invalid: "
                   << process_id_string;
        return EXIT_FAILURE;
      }
      process_ids.push_back(process_id);
    }
    if (process_ids.size() == 1) {
      // Use original ProcessFetcher for single process telemetry.
      MojoResponseWaiter<mojom::ProcessResultPtr> waiter;
      remote->ProbeProcessInfo(process_ids[0], waiter.CreateCallback());
      DisplayProcessInfo(waiter.WaitForResponse());
    } else {
      MojoResponseWaiter<mojom::MultipleProcessResultPtr> waiter;
      remote->ProbeMultipleProcessInfo(process_ids, FLAGS_ignore,
                                       waiter.CreateCallback());
      DisplayMultipleProcessInfo(waiter.WaitForResponse());
    }
    return EXIT_SUCCESS;
  }

  // Probe category info, if requested.
  if (FLAGS_category != "") {
    // Validate the category flag.
    std::vector<mojom::ProbeCategoryEnum> categories_to_probe;
    std::vector<std::string> input_categories = base::SplitString(
        FLAGS_category, ",", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);
    for (const auto& category : input_categories) {
      auto iterator = switch_to_category.find(category);
      if (iterator == switch_to_category.end()) {
        LOG(ERROR) << "Invalid category: " << category;
        return EXIT_FAILURE;
      }
      categories_to_probe.push_back(iterator->second);
    }

    // Probe and display the category or categories.
    MojoResponseWaiter<mojom::TelemetryInfoPtr> waiter;
    remote->ProbeTelemetryInfo(categories_to_probe, waiter.CreateCallback());
    DisplayTelemetryInfo(waiter.WaitForResponse());
    return EXIT_SUCCESS;
  }

  LOG(ERROR) << "Specify at least one of --category or --process.";
  return EXIT_FAILURE;
}

}  // namespace diagnostics
