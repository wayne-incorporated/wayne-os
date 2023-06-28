// Copyright 2014 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "login_manager/server_backed_state_key_generator.h"

#include <base/bind.h>
#include <base/callback_helpers.h>
#include <base/stl_util.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <crypto/hmac.h>
#include <crypto/sha2.h>

#include "login_manager/login_metrics.h"
#include "login_manager/system_utils.h"

namespace login_manager {

namespace {

// Characters to trim from values.
const char kTrimChars[] = "\" ";

// Keys in the tool-provided key-value pairs.
const char kGroupCodeKey[] = "gbind_attribute";
const char kSerialNumberKey[] = "serial_number";
const char kDiskSerialNumberKey[] = "root_disk_serial_number";
const char kStableDeviceSecretKey[] = "stable_device_secret_DO_NOT_SHARE";

// These are the machine serial number keys that we check in order until we find
// a non-empty serial number.
//
// On older Samsung devices the VPD contains two serial numbers: "Product_S/N"
// and "serial_number" which are based on the same value except that the latter
// has a letter appended that serves as a check digit. Unfortunately, the
// sticker on the device packaging didn't include that check digit (the sticker
// on the device did though!). The former sticker was the source of the serial
// number used by device management service, so we preferred "Product_S/N" over
// "serial_number" to match the server. As an unintended consequence, older
// Samsung devices display and report a serial number that doesn't match the
// sticker on the device (the check digit is missing).
//
// "Product_S/N" is known to be used on celes, lumpy, pi, pit, snow, winky and
// some kevin devices and thus needs to be supported until AUE of these
// devices. It's known *not* to be present on caroline.
// TODO(tnagel): Remove "Product_S/N" after all devices that have it are AUE.
const char* const kMachineInfoSerialNumberKeys[] = {
    "Product_S/N",     // Samsung legacy
    kSerialNumberKey,  // VPD v2+ devices
};

// String constant identifying the device secret usage context.
const char kDeviceSecretUsageContext[] = "server_backed_state_keys";

std::string GetMapValue(const std::map<std::string, std::string>& map,
                        const std::string& key) {
  std::map<std::string, std::string>::const_iterator entry = map.find(key);
  return entry == map.end() ? std::string() : entry->second;
}

}  // namespace

const int ServerBackedStateKeyGenerator::kDeviceStateKeyTimeQuantumPower;
const int ServerBackedStateKeyGenerator::kDeviceStateKeyFutureQuanta;

ServerBackedStateKeyGenerator::ServerBackedStateKeyGenerator(
    SystemUtils* system_utils, LoginMetrics* metrics)
    : system_utils_(system_utils), metrics_(metrics) {}

ServerBackedStateKeyGenerator::~ServerBackedStateKeyGenerator() {}

// static
bool ServerBackedStateKeyGenerator::ParseMachineInfo(
    const std::string& data, std::map<std::string, std::string>* params) {
  params->clear();

  // Parse the name-value pairs list. The return value of
  // SplitStringIntoKeyValuePairs is deliberately ignored in order to handle
  // comment lines (those start with a #) emitted by dump_vpd_log.
  base::StringPairs pairs;
  base::SplitStringIntoKeyValuePairs(data, '=', '\n', &pairs);

  for (base::StringPairs::const_iterator pair(pairs.begin());
       pair != pairs.end(); ++pair) {
    std::string name;
    base::TrimString(pair->first, kTrimChars, &name);
    if (name.empty())
      continue;

    // Use the first pair present in the input. This is so values originating
    // from read-only VPD are given precedence over values from read-write VPD.
    // dump_vpd_log always dumps the former first.
    if (params->find(name) != params->end())
      continue;

    std::string value;
    base::TrimString(pair->second, kTrimChars, &value);
    (*params)[name] = value;
  }

  return !params->empty();
}

bool ServerBackedStateKeyGenerator::InitMachineInfo(
    const std::map<std::string, std::string>& params) {
  machine_info_available_ = true;

  for (size_t i = 0; i < base::size(kMachineInfoSerialNumberKeys); i++) {
    std::string candidate =
        GetMapValue(params, kMachineInfoSerialNumberKeys[i]);
    if (!candidate.empty()) {
      machine_serial_number_ = candidate;
      break;
    }
  }
  group_code_key_ = GetMapValue(params, kGroupCodeKey);
  disk_serial_number_ = GetMapValue(params, kDiskSerialNumberKey);
  stable_device_secret_ = GetMapValue(params, kStableDeviceSecretKey);

  LOG_IF(WARNING, machine_serial_number_.empty())
      << "Machine serial number missing!";
  LOG_IF(WARNING, disk_serial_number_.empty()) << "Disk serial number missing!";
  LOG_IF(INFO, stable_device_secret_.empty())
      << "Stable device secret missing!";

  // Fire all pending callbacks.
  std::vector<std::vector<uint8_t>> state_keys;
  ComputeKeys(&state_keys);
  std::vector<StateKeyCallback> callbacks;
  callbacks.swap(pending_callbacks_);
  for (std::vector<StateKeyCallback>::const_iterator callback(
           callbacks.begin());
       callback != callbacks.end(); ++callback) {
    callback->Run(state_keys);
  }

  return !stable_device_secret_.empty() ||
         (!machine_serial_number_.empty() && !disk_serial_number_.empty());
}

void ServerBackedStateKeyGenerator::RequestStateKeys(
    const StateKeyCallback& callback) {
  if (!machine_info_available_) {
    pending_callbacks_.push_back(callback);
    return;
  }

  std::vector<std::vector<uint8_t>> state_keys;
  ComputeKeys(&state_keys);
  callback.Run(state_keys);
}

void ServerBackedStateKeyGenerator::ComputeKeys(
    std::vector<std::vector<uint8_t>>* state_keys) {
  state_keys->clear();

  // Get the current time in quantized form.
  const int64_t quantum_size = 1 << kDeviceStateKeyTimeQuantumPower;
  int64_t quantized_time = system_utils_->time(nullptr) & ~(quantum_size - 1);

  // Compute the state keys.
  if (!stable_device_secret_.empty()) {
    crypto::HMAC hmac(crypto::HMAC::SHA256);
    std::vector<uint8_t> secret_bytes;
    if (!base::HexStringToBytes(stable_device_secret_, &secret_bytes) ||
        secret_bytes.size() < 32) {
      metrics_->SendStateKeyGenerationStatus(
          LoginMetrics::STATE_KEY_STATUS_BAD_DEVICE_SECRET);
      LOG(ERROR) << "Malformed device secret, no state keys generated.";
      return;
    }
    if (!hmac.Init(secret_bytes.data(), secret_bytes.size())) {
      metrics_->SendStateKeyGenerationStatus(
          LoginMetrics::STATE_KEY_STATUS_HMAC_INIT_FAILURE);
      LOG(ERROR) << "Failed to init HMAC, no state keys generated.";
      return;
    }

    for (int i = 0; i < kDeviceStateKeyFutureQuanta; ++i) {
      state_keys->push_back(std::vector<uint8_t>(hmac.DigestLength()));
      std::string data_to_sign;
      data_to_sign.append(kDeviceSecretUsageContext);
      data_to_sign.append(1, '\0');
      data_to_sign.append(reinterpret_cast<char*>(&quantized_time),
                          sizeof(quantized_time));
      if (!hmac.Sign(data_to_sign, state_keys->back().data(),
                     state_keys->back().size())) {
        metrics_->SendStateKeyGenerationStatus(
            LoginMetrics::STATE_KEY_STATUS_HMAC_SIGN_FAILURE);
        LOG(ERROR) << "Failed to compute HMAC, no state keys generated.";
        state_keys->clear();
        return;
      }
      quantized_time += quantum_size;
    }
    metrics_->SendStateKeyGenerationStatus(
        LoginMetrics::STATE_KEY_STATUS_GENERATION_METHOD_HMAC_DEVICE_SECRET);
  } else if (!machine_serial_number_.empty() && !disk_serial_number_.empty()) {
    for (int i = 0; i < kDeviceStateKeyFutureQuanta; ++i) {
      state_keys->push_back(std::vector<uint8_t>(crypto::kSHA256Length));
      crypto::SHA256HashString(
          crypto::SHA256HashString(group_code_key_) +
              crypto::SHA256HashString(disk_serial_number_) +
              crypto::SHA256HashString(machine_serial_number_) +
              crypto::SHA256HashString(base::NumberToString(quantized_time)),
          state_keys->back().data(), state_keys->back().size());
      quantized_time += quantum_size;
    }
    metrics_->SendStateKeyGenerationStatus(
        LoginMetrics::STATE_KEY_STATUS_GENERATION_METHOD_IDENTIFIER_HASH);
  } else {
    // Can't compute keys, signaled by empty |state_keys| vector.
    LOG(WARNING) << "No device identifiers available, no state keys generated";
    metrics_->SendStateKeyGenerationStatus(
        LoginMetrics::STATE_KEY_STATUS_MISSING_IDENTIFIERS);
  }
}

}  // namespace login_manager
