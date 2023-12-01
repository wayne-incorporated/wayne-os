// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstdint>
#include <optional>
#include <string>

#include <base/base64.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/values.h>
#include <brillo/process/process.h>

#include "libsegmentation/device_info.pb.h"
#include "libsegmentation/feature_management_impl.h"
#include "libsegmentation/feature_management_interface.h"
#include "libsegmentation/feature_management_util.h"

namespace segmentation {

namespace {

// The path for the "gsctool" binary.
constexpr char kGscToolBinaryPath[] = "/usr/sbin/gsctool";

// The output of |kGscToolBinaryPath| will contain a "chassis_x_branded:" line.
constexpr char kChassisXBrandedKey[] = "chassis_x_branded:";

// The output of |kGscToolBinaryPath| will contain a "hw_compliance_version:"
// line.
constexpr char kHwXComplianceVersion[] = "hw_x_compliance_version:";

// The output from the "gsctool" binary. Some or all of these fields may not be
// present in the output.
struct GscToolOutput {
  bool chassis_x_branded;
  int32_t hw_compliance_version;
};

// Parses output from running |kGscToolBinaryPath| into GscToolOutput.
std::optional<GscToolOutput> ParseGscToolOutput(
    const std::string& gsc_tool_output) {
  GscToolOutput output;
  std::istringstream iss(gsc_tool_output);
  std::string line;

  // Flags to indicate we've found the required fields.
  bool found_chassis = false;
  bool found_compliance_version = false;

  // Keep going till there are lines in the output or we've found both the
  // fields.
  while (std::getline(iss, line) &&
         (!found_chassis || !found_compliance_version)) {
    std::istringstream line_stream(line);
    std::string key;
    line_stream >> key;

    if (key == kChassisXBrandedKey) {
      bool value;
      line_stream >> std::boolalpha >> value;
      output.chassis_x_branded = value;
      found_chassis = true;
    } else if (key == kHwXComplianceVersion) {
      int32_t value;
      line_stream >> value;
      output.hw_compliance_version = value;
      found_compliance_version = true;
    }
  }

  if (found_chassis && found_compliance_version) {
    return output;
  }
  return std::nullopt;
}

libsegmentation::DeviceInfo_FeatureLevel HwComplianceVersionToFeatureLevel(
    int32_t hw_compliance_version) {
  switch (hw_compliance_version) {
    case 0:
      return libsegmentation::DeviceInfo_FeatureLevel::
          DeviceInfo_FeatureLevel_FEATURE_LEVEL_0;
    case 1:
      return libsegmentation::DeviceInfo_FeatureLevel::
          DeviceInfo_FeatureLevel_FEATURE_LEVEL_1;
    default:
      return libsegmentation::DeviceInfo_FeatureLevel::
          DeviceInfo_FeatureLevel_FEATURE_LEVEL_UNKNOWN;
  }
}

libsegmentation::DeviceInfo_ScopeLevel HwComplianceVersionToScopeLevel(
    bool is_chassis_x_branded) {
  if (is_chassis_x_branded)
    return libsegmentation::DeviceInfo_ScopeLevel::
        DeviceInfo_ScopeLevel_SCOPE_LEVEL_1;

  return libsegmentation::DeviceInfo_ScopeLevel::
      DeviceInfo_ScopeLevel_SCOPE_LEVEL_0;
}

// Returns the device information parsed from the output of the GSC tool binary
// on the device.
std::optional<libsegmentation::DeviceInfo> GetDeviceInfoFromGSC() {
  if (!base::PathExists(base::FilePath(kGscToolBinaryPath))) {
    LOG(ERROR) << "Can't find gsctool binary";
    return std::nullopt;
  }

  libsegmentation::DeviceInfo device_info;
  base::FilePath output_path;
  if (!base::CreateTemporaryFile(&output_path)) {
    LOG(ERROR) << "Failed to open output file";
    return std::nullopt;
  }

  brillo::ProcessImpl process;
  process.AddArg(kGscToolBinaryPath);
  std::vector<std::string> args = {"--factory_config", "--any"};
  for (const auto& arg : args) {
    process.AddArg(arg);
  }
  process.RedirectOutput(output_path.value().c_str());

  if (!process.Start()) {
    LOG(ERROR) << "Failed to start gsctool process";
    return std::nullopt;
  }

  if (process.Wait() < 0) {
    LOG(ERROR) << "Failed to wait for the gsctool process";
    return std::nullopt;
  }

  std::string output;
  if (!base::ReadFileToString(output_path, &output)) {
    LOG(ERROR) << "Failed to read output from the gsctool";
    return std::nullopt;
  }

  std::optional<GscToolOutput> gsc_tool_output = ParseGscToolOutput(output);
  if (!gsc_tool_output) {
    LOG(ERROR) << "Failed to parse output from the gsctool";
    return std::nullopt;
  }

  bool is_chassis_x_branded = gsc_tool_output.value().chassis_x_branded;
  int32_t hw_compliance_version = gsc_tool_output.value().hw_compliance_version;

  if (is_chassis_x_branded || hw_compliance_version > 0) {
    if (is_chassis_x_branded) {
      device_info.set_feature_level(
          HwComplianceVersionToFeatureLevel(hw_compliance_version));
      device_info.set_scope_level(
          HwComplianceVersionToScopeLevel(is_chassis_x_branded));
    } else {
      // TODO(abhishekbh): Read from PRODUCT_ALLOWLIST to determine the feature
      // level.
      device_info.set_feature_level(
          libsegmentation::DeviceInfo_FeatureLevel::
              DeviceInfo_FeatureLevel_FEATURE_LEVEL_0);
      device_info.set_scope_level(HwComplianceVersionToScopeLevel(false));
    }
  } else {
    // TODO(abhishekbh): Read from PRODUCT_COMPONENT_ALLOWLIST to determine the
    // feature level.
    device_info.set_feature_level(libsegmentation::DeviceInfo_FeatureLevel::
                                      DeviceInfo_FeatureLevel_FEATURE_LEVEL_0);
    device_info.set_scope_level(HwComplianceVersionToScopeLevel(false));
  }
  return device_info;
}

// Write |device_info| as base64 to the "vpd" binary by spawning a new process.
bool WriteToVpd(const libsegmentation::DeviceInfo& device_info) {
  std::string serialized = device_info.SerializeAsString();
  std::string base64_encoded;
  base::Base64Encode(serialized, &base64_encoded);

  brillo::ProcessImpl process;
  process.AddArg("/usr/sbin/vpd");
  process.AddArg("-i");
  process.AddArg("RW_VPD");
  process.AddArg("-s");
  process.AddArg("feature_device_info=" + base64_encoded);

  if (!process.Start()) {
    LOG(ERROR) << "Failed to start VPD process";
    return false;
  }

  int return_code = process.Wait();
  if (return_code != 0) {
    LOG(ERROR) << "VPD process exited with return code: " << return_code;
    return false;
  }
  return true;
}

}  // namespace

FeatureManagementInterface::FeatureLevel
FeatureManagementImpl::GetFeatureLevel() {
  if (cached_device_info_) {
    return FeatureManagementUtil::ConvertProtoFeatureLevel(
        cached_device_info_->feature_level());
  }

  if (!CacheDeviceInfo()) {
    return FeatureLevel::FEATURE_LEVEL_UNKNOWN;
  }

  return FeatureManagementUtil::ConvertProtoFeatureLevel(
      cached_device_info_->feature_level());
}

FeatureManagementInterface::ScopeLevel FeatureManagementImpl::GetScopeLevel() {
  if (cached_device_info_) {
    return FeatureManagementUtil::ConvertProtoScopeLevel(
        cached_device_info_->scope_level());
  }

  if (!CacheDeviceInfo()) {
    return ScopeLevel::SCOPE_LEVEL_UNKNOWN;
  }

  return FeatureManagementUtil::ConvertProtoScopeLevel(
      cached_device_info_->scope_level());
}

bool FeatureManagementImpl::CacheDeviceInfo() {
  base::FilePath device_info_file = base::FilePath(device_info_file_path_);
  // If the device info isn't cached, try to read it from the stateful partition
  // file that contains the information. If it's not present in the stateful
  // partition file then read it form the hardware id and write it to the
  // stateful partition for subsequent boots.
  std::optional<libsegmentation::DeviceInfo> device_info_result =
      FeatureManagementUtil::ReadDeviceInfoFromFile(device_info_file);
  if (!device_info_result ||
      device_info_result->cached_version_hash() != current_version_hash_) {
    device_info_result = GetDeviceInfoFromGSC();
    if (!device_info_result) {
      LOG(ERROR) << "Failed to get device info from the hardware id";
      return false;
    }

    // Persist the device info read from "gsctool" via "vpd" or to a regular
    // file for testing. If we fail to write it then don't cache it.
    device_info_result->set_cached_version_hash(current_version_hash_);
    if (persist_via_vpd_) {
      if (!WriteToVpd(device_info_result.value())) {
        LOG(ERROR) << "Failed to persist device info via vpd";
        return false;
      }
    } else {
      if (!FeatureManagementUtil::WriteDeviceInfoToFile(
              device_info_result.value(), device_info_file)) {
        LOG(ERROR) << "Failed to persist device info";
        return false;
      }
    }
  }

  // At this point device information is present on stateful. We can cache it.
  cached_device_info_ = device_info_result.value();
  return true;
}

}  // namespace segmentation
