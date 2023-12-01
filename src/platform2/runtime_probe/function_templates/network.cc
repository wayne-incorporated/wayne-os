// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "runtime_probe/function_templates/network.h"

#include <map>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

#include <base/containers/contains.h>
#include <base/files/file_path.h>
#include <base/logging.h>
#include <base/values.h>
#include <brillo/dbus/dbus_connection.h>
#include <brillo/variant_dictionary.h>
#include <chromeos/dbus/service_constants.h>
#include <chromeos/dbus/shill/dbus-constants.h>
#include <shill/dbus-proxies.h>

#include "runtime_probe/system/context.h"
#include "runtime_probe/utils/bus_utils.h"
#include "runtime_probe/utils/file_utils.h"

namespace runtime_probe {
namespace {

constexpr const char* kValidNetworkTypes[] = {
    "",  // The default value which means all the type are accepted.
    shill::kTypeWifi,
    shill::kTypeCellular,
    shill::kTypeEthernet,
};

std::map<std::string, std::string> GetDevicesType() {
  std::map<std::string, std::string> result;

  auto shill_proxy = Context::Get()->shill_manager_proxy();
  brillo::VariantDictionary props;
  if (!shill_proxy->GetProperties(&props, nullptr)) {
    LOG(ERROR) << "Unable to get manager properties.";
    return {};
  }
  const auto it = props.find(shill::kDevicesProperty);
  if (it == props.end()) {
    LOG(ERROR) << "Manager properties is missing devices.";
    return {};
  }

  for (const auto& path : it->second.TryGet<std::vector<dbus::ObjectPath>>()) {
    auto device = Context::Get()->CreateShillDeviceProxy(path);
    brillo::VariantDictionary device_props;
    if (!device->GetProperties(&device_props, nullptr)) {
      VLOG(2) << "Unable to get device properties of " << path.value()
              << ". Skipped.";
      continue;
    }
    std::string interface =
        device_props.at(shill::kInterfaceProperty).TryGet<std::string>();
    std::string type =
        device_props.at(shill::kTypeProperty).TryGet<std::string>();
    result[interface] = type;
  }

  return result;
}

}  // namespace

bool NetworkFunction::PostParseArguments() {
  if (!base::Contains(kValidNetworkTypes, device_type_)) {
    LOG(ERROR) << "function " << GetFunctionName()
               << " got an unexpected network type " << device_type_;
    return false;
  }
  return true;
}

NetworkFunction::DataType NetworkFunction::EvalImpl() const {
  DataType results;
  base::FilePath net_dev_pattern =
      Context::Get()->root_dir().Append("sys/class/net/*");
  for (const auto& net_dev_path : Glob(net_dev_pattern)) {
    auto node_res = GetDeviceBusDataFromSysfsNode(net_dev_path);
    if (node_res) {
      results.Append(std::move(*node_res));
    }
  }

  return results;
}

void NetworkFunction::PostHelperEvalImpl(DataType* results) const {
  const std::optional<std::string> target_type = GetNetworkType();
  const auto devices_type = GetDevicesType();
  auto helper_results = std::move(*results);
  *results = DataType();

  for (auto& helper_result : helper_results) {
    auto& dict = helper_result.GetDict();
    auto* path = dict.FindString("path");
    CHECK(path);
    const std::string interface = base::FilePath{*path}.BaseName().value();
    auto it = devices_type.find(interface);
    if (it == devices_type.end()) {
      LOG(ERROR) << "Cannot get type of interface " << interface;
      continue;
    }
    if (target_type && target_type.value() != it->second) {
      VLOG(3) << "Interface " << interface << " doesn't match the target type "
              << target_type.value();
      continue;
    }
    CHECK(!dict.FindString("type"));
    dict.Set("type", it->second);
    results->Append(std::move(helper_result));
  }
}

std::optional<std::string> NetworkFunction::GetNetworkType() const {
  if (device_type_.empty()) {
    return std::nullopt;
  }
  return device_type_;
}

}  // namespace runtime_probe
