// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "runtime_probe/functions/input_device.h"

#include <pcrecpp.h>

#include <map>
#include <string>
#include <utility>
#include <vector>

#include <base/check_op.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/notreached.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>

#include "runtime_probe/proto_bindings/runtime_probe.pb.h"
#include "runtime_probe/system/context.h"
#include "runtime_probe/utils/file_utils.h"
#include "runtime_probe/utils/input_device.h"

namespace runtime_probe {

namespace {
constexpr auto kInputDevicesPath = "proc/bus/input/devices";

using FieldType = std::pair<std::string, std::string>;

const std::vector<FieldType> kTouchscreenI2cFields = {
    {"name", "name"}, {"product", "hw_version"}, {"fw_version", "fw_version"}};
const std::map<std::string, std::string> kTouchscreenI2cDriverToVid = {
    {"elants_i2c", "04f3"}, {"raydium_ts", "27a3"}, {"atmel_ext_ts", "03eb"}};

std::string DeviceTypeEnumToString(InputDevice::Type device_type) {
  switch (device_type) {
    case InputDevice::TYPE_STYLUS:
      return "stylus";
    case InputDevice::TYPE_TOUCHPAD:
      return "touchpad";
    case InputDevice::TYPE_TOUCHSCREEN:
      return "touchscreen";
    case InputDevice::TYPE_UNKNOWN:
      return "unknown";
    default:
      NOTREACHED() << "Invalid device_type: " << device_type;
      return "unknown";
  }
}

std::string GetDriverName(const base::FilePath& node_path) {
  const auto driver_path = node_path.Append("driver");
  const auto real_driver_path = base::MakeAbsoluteFilePath(driver_path);
  if (real_driver_path.value().length() == 0)
    return "";
  const auto driver_name = real_driver_path.BaseName().value();
  return driver_name;
}

void FixTouchscreenI2cDevice(base::Value* device) {
  auto& device_dict = device->GetDict();
  const auto* path = device_dict.FindString("path");
  if (!path)
    return;

  const auto* vid_old = device_dict.FindString("vendor");
  if (vid_old && *vid_old != "0000")
    return;

  const auto node_path = base::FilePath{*path}.Append("device");
  const auto driver_name = GetDriverName(node_path);
  const auto entry = kTouchscreenI2cDriverToVid.find(driver_name);
  if (entry == kTouchscreenI2cDriverToVid.end())
    return;

  // Refer to http://crrev.com/c/1825942.
  auto dict_value = MapFilesToDict(node_path, kTouchscreenI2cFields);
  if (!dict_value) {
    DVLOG(1) << "touchscreen_i2c-specific fields do not exist on node \""
             << node_path << "\"";
    return;
  }

  device_dict.Set("vendor", entry->second);
  device_dict.Merge(std::move(dict_value->GetDict()));
  return;
}

void AppendInputDevice(InputDeviceFunction::DataType* list_value,
                       std::unique_ptr<InputDeviceImpl> input_device,
                       const std::string& device_type_filter) {
  const auto device_type = DeviceTypeEnumToString(input_device->type());
  if (!device_type_filter.empty() && device_type_filter != device_type)
    return;

  auto path = Context::Get()->root_dir().Append(
      base::StringPrintf("sys%s", input_device->sysfs.c_str()));

  base::Value value(base::Value::Type::DICT);
  auto& dict = value.GetDict();
  dict.Set("bus", input_device->bus);
  dict.Set("event", input_device->event);
  dict.Set("name", input_device->name);
  dict.Set("product", input_device->product);
  dict.Set("vendor", input_device->vendor);
  dict.Set("version", input_device->version);
  dict.Set("path", path.value());
  dict.Set("device_type", InputDevice::Type_Name(input_device->type()));
  FixTouchscreenI2cDevice(&value);
  list_value->Append(std::move(value));
}

}  // namespace

InputDeviceFunction::DataType InputDeviceFunction::EvalImpl() const {
  InputDeviceFunction::DataType results{};
  std::string input_devices_str;

  const base::FilePath procfs_path(
      Context::Get()->root_dir().Append(kInputDevicesPath));

  if (!base::ReadFileToString(procfs_path, &input_devices_str)) {
    LOG(ERROR) << "Failed to read " << procfs_path.value() << ".";
    return {};
  }

  auto lines = base::SplitString(input_devices_str, "\n", base::TRIM_WHITESPACE,
                                 base::SPLIT_WANT_ALL);
  auto begin_iter = lines.cbegin();
  while (true) {
    auto end_iter = begin_iter;
    while (end_iter != lines.cend() && !end_iter->empty())
      ++end_iter;
    if (begin_iter != end_iter) {
      AppendInputDevice(
          &results,
          InputDeviceImpl::From(std::vector<std::string>(begin_iter, end_iter)),
          device_type_);
    }
    if (end_iter == lines.cend())
      break;
    begin_iter = std::next(end_iter);
  }
  return results;
}

}  // namespace runtime_probe
