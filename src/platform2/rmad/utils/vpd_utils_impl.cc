// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rmad/utils/vpd_utils_impl.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/strings/string_number_conversions.h>
#include <base/logging.h>

#include "rmad/utils/cmd_utils_impl.h"

namespace {

const char kVpdCmdPath[] = "/usr/sbin/vpd";

constexpr char kVpdKeySerialNumber[] = "serial_number";
constexpr char kVpdKeyCustomLabelTag[] = "custom_label_tag";
// Legacy name of custom_label_tag (see go/coil). We still need it for backward
// compatibility.
constexpr char kVpdKeyWhitelabelTag[] = "whitelabel_tag";
constexpr char kVpdKeyRegion[] = "region";
constexpr char kVpdKeyUbindAttribute[] = "ubind_attribute";
constexpr char kVpdKeyGbindAttribute[] = "gbind_attribute";
constexpr char kVpdKeyStableDeviceSecret[] =
    "stable_device_secret_DO_NOT_SHARE";

}  // namespace

namespace rmad {

VpdUtilsImpl::VpdUtilsImpl() : VpdUtils() {
  cmd_utils_ = std::make_unique<CmdUtilsImpl>();
}

VpdUtilsImpl::VpdUtilsImpl(std::unique_ptr<CmdUtils> cmd_utils)
    : VpdUtils(), cmd_utils_(std::move(cmd_utils)) {}

// We flush all caches into real VPD.
VpdUtilsImpl::~VpdUtilsImpl() {
  FlushOutRoVpdCache();
  FlushOutRwVpdCache();
}

bool VpdUtilsImpl::GetSerialNumber(std::string* serial_number) const {
  CHECK(serial_number);

  return GetRoVpd(kVpdKeySerialNumber, serial_number);
}

bool VpdUtilsImpl::GetCustomLabelTag(std::string* custom_label_tag,
                                     bool use_legacy) const {
  CHECK(custom_label_tag);

  if (use_legacy) {
    return GetRoVpd(kVpdKeyWhitelabelTag, custom_label_tag);
  }
  return GetRoVpd(kVpdKeyCustomLabelTag, custom_label_tag);
}

bool VpdUtilsImpl::GetRegion(std::string* region) const {
  CHECK(region);

  return GetRoVpd(kVpdKeyRegion, region);
}

bool VpdUtilsImpl::GetCalibbias(const std::vector<std::string>& entries,
                                std::vector<int>* calibbias) const {
  CHECK(calibbias);

  std::vector<int> values;
  for (const std::string& entry : entries) {
    std::string str;
    int val;
    if (!GetRoVpd(entry, &str) || !base::StringToInt(str, &val)) {
      LOG(ERROR) << "Failed to get int value of " << entry << " from vpd.";
      return false;
    }
    values.push_back(val);
  }

  *calibbias = values;
  return true;
}

bool VpdUtilsImpl::GetRegistrationCode(std::string* ubind,
                                       std::string* gbind) const {
  CHECK(ubind);
  CHECK(gbind);

  std::string temp_ubind, temp_gbind;
  if (!GetRwVpd(kVpdKeyUbindAttribute, &temp_ubind) ||
      !GetRwVpd(kVpdKeyGbindAttribute, &temp_gbind)) {
    return false;
  }

  *ubind = temp_ubind;
  *gbind = temp_gbind;
  return true;
}

bool VpdUtilsImpl::GetStableDeviceSecret(
    std::string* stable_device_secret) const {
  CHECK(stable_device_secret);

  return GetRoVpd(kVpdKeyStableDeviceSecret, stable_device_secret);
}

bool VpdUtilsImpl::SetSerialNumber(const std::string& serial_number) {
  cache_ro_[kVpdKeySerialNumber] = serial_number;
  return true;
}

bool VpdUtilsImpl::SetCustomLabelTag(const std::string& custom_label_tag,
                                     bool use_legacy) {
  if (use_legacy) {
    cache_ro_[kVpdKeyWhitelabelTag] = custom_label_tag;
  } else {
    cache_ro_[kVpdKeyCustomLabelTag] = custom_label_tag;
  }
  return true;
}

bool VpdUtilsImpl::SetRegion(const std::string& region) {
  cache_ro_[kVpdKeyRegion] = region;
  return true;
}

bool VpdUtilsImpl::SetCalibbias(const std::map<std::string, int>& calibbias) {
  for (const auto& [key, value] : calibbias) {
    cache_ro_[key] = base::NumberToString(value);
  }

  return true;
}

bool VpdUtilsImpl::SetRegistrationCode(const std::string& ubind,
                                       const std::string& gbind) {
  cache_rw_[kVpdKeyUbindAttribute] = ubind;
  cache_rw_[kVpdKeyGbindAttribute] = gbind;
  return true;
}

bool VpdUtilsImpl::SetStableDeviceSecret(
    const std::string& stable_device_secret) {
  cache_ro_[kVpdKeyStableDeviceSecret] = stable_device_secret;
  return true;
}

bool VpdUtilsImpl::RemoveCustomLabelTag() {
  cache_ro_.erase(kVpdKeyCustomLabelTag);
  return DelRoVpd(kVpdKeyCustomLabelTag);
}

bool VpdUtilsImpl::FlushOutRoVpdCache() {
  if (cache_ro_.size() && !SetRoVpd(cache_ro_)) {
    return false;
  }

  cache_ro_.clear();
  return true;
}

bool VpdUtilsImpl::FlushOutRwVpdCache() {
  if (cache_rw_.size() && !SetRwVpd(cache_rw_)) {
    return false;
  }

  cache_rw_.clear();
  return true;
}

bool VpdUtilsImpl::SetRoVpd(
    const std::map<std::string, std::string>& key_value_map) {
  std::string log_msg;
  std::vector<std::string> argv{kVpdCmdPath, "-i", "RO_VPD"};
  for (const auto& [key, value] : key_value_map) {
    argv.push_back("-s");
    std::string key_value_pair = key + "=" + value;
    argv.push_back(key_value_pair);
    log_msg += key_value_pair + " ";
  }

  static std::string unused_output;
  if (!cmd_utils_->GetOutput(argv, &unused_output)) {
    LOG(ERROR) << "Failed to flush " << log_msg << "into RO_PVD.";
    return false;
  }
  return true;
}

bool VpdUtilsImpl::GetRoVpd(const std::string& key, std::string* value) const {
  CHECK(value);
  if (auto it = cache_ro_.find(key); it != cache_ro_.end()) {
    *value = it->second;
    return true;
  }

  std::vector<std::string> argv{kVpdCmdPath, "-i", "RO_VPD", "-g", key};
  return cmd_utils_->GetOutput(argv, value);
}

bool VpdUtilsImpl::DelRoVpd(const std::string& key) {
  std::vector<std::string> argv{kVpdCmdPath, "-i", "RO_VPD", "-d", key};
  std::string unused;
  return cmd_utils_->GetOutput(argv, &unused);
}

bool VpdUtilsImpl::SetRwVpd(
    const std::map<std::string, std::string>& key_value_map) {
  std::string log_msg;
  std::vector<std::string> argv{kVpdCmdPath, "-i", "RW_VPD"};
  for (const auto& [key, value] : key_value_map) {
    argv.push_back("-s");
    std::string key_value_pair = key + "=" + value;
    argv.push_back(key_value_pair);
    log_msg += key_value_pair + " ";
  }

  static std::string unused_output;
  if (!cmd_utils_->GetOutput(argv, &unused_output)) {
    LOG(ERROR) << "Failed to flush " << log_msg << "into RW_PVD.";
    return false;
  }
  return true;
}

bool VpdUtilsImpl::GetRwVpd(const std::string& key, std::string* value) const {
  CHECK(value);
  if (auto it = cache_rw_.find(key); it != cache_rw_.end()) {
    *value = it->second;
    return true;
  }

  std::vector<std::string> argv{kVpdCmdPath, "-i", "RW_VPD", "-g", key};
  return cmd_utils_->GetOutput(argv, value);
}

bool VpdUtilsImpl::DelRwVpd(const std::string& key) {
  std::vector<std::string> argv{kVpdCmdPath, "-i", "RW_VPD", "-d", key};
  std::string unused;
  return cmd_utils_->GetOutput(argv, &unused);
}

void VpdUtilsImpl::ClearRoVpdCache() {
  cache_ro_.clear();
}

void VpdUtilsImpl::ClearRwVpdCache() {
  cache_rw_.clear();
}

}  // namespace rmad
