// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
#include "cecservice/cec_manager.h"

#include <algorithm>
#include <string>
#include <utility>
#include <vector>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/strings/string_util.h>

namespace cecservice {

namespace {
std::string PowerStatusToString(TvPowerStatus status) {
  switch (status) {
    case kTvPowerStatusError:
      return "error";
    case kTvPowerStatusAdapterNotConfigured:
      return "adapter not configured";
    case kTvPowerStatusNoTv:
      return "no TV";
    case kTvPowerStatusOn:
      return "on";
    case kTvPowerStatusStandBy:
      return "standby";
    case kTvPowerStatusToOn:
      return "to on";
    case kTvPowerStatusToStandBy:
      return "to standby";
    case kTvPowerStatusUnknown:
      return "unknown";
  }
}

std::string PowerStatusVectorToString(
    const std::vector<TvPowerStatus>& vector) {
  std::vector<std::string> strings;
  std::transform(vector.begin(), vector.end(), std::back_inserter(strings),
                 PowerStatusToString);
  return "[" + base::JoinString(strings, ", ") + "]";
}
}  // namespace

struct CecManager::TvPowerStatusResult {
  // Set to true if the response has been received from the device.
  bool received = false;

  // The actual power status received.
  TvPowerStatus power_status = kTvPowerStatusUnknown;
};

struct CecManager::TvsPowerStatusQuery {
  // Callback to invoke when all responses have been received.
  GetTvsPowerStatusCallback callback;
  // Device nodes the request has been sent to.
  std::map<base::FilePath, TvPowerStatusResult> responses;
};

CecManager::CecManager(const UdevFactory& udev_factory,
                       const CecDeviceFactory& cec_factory)
    : cec_factory_(cec_factory) {
  udev_ = udev_factory.Create(base::BindRepeating(&CecManager::OnDeviceAdded,
                                                  weak_factory_.GetWeakPtr()),
                              base::BindRepeating(&CecManager::OnDeviceRemoved,
                                                  weak_factory_.GetWeakPtr()));
  LOG_IF(FATAL, !udev_) << "Failed to create udev";

  EnumerateAndAddExistingDevices();
}

CecManager::~CecManager() = default;

void CecManager::GetTvsPowerStatus(GetTvsPowerStatusCallback callback) {
  VLOG(1) << "Received get TVs power status request";
  if (devices_.empty()) {
    std::move(callback).Run({});
    return;
  }

  TvsPowerStatusQuery query{std::move(callback)};

  for (auto& kv : devices_) {
    query.responses.insert(std::make_pair(kv.first, TvPowerStatusResult()));
  }

  QueryId id = next_query_id_++;
  tv_power_status_queries_.insert(std::make_pair(id, std::move(query)));

  for (auto& kv : devices_) {
    kv.second->GetTvPowerStatus(base::BindOnce(&CecManager::OnTvPowerResponse,
                                               weak_factory_.GetWeakPtr(), id,
                                               kv.first));
  }
}

void CecManager::SetWakeUp() {
  VLOG(1) << "Received wake up request";
  for (auto& kv : devices_) {
    kv.second->SetWakeUp();
  }
}

void CecManager::SetStandBy() {
  VLOG(1) << "Received standby request";
  for (auto& kv : devices_) {
    kv.second->SetStandBy();
  }
}

void CecManager::OnTvPowerResponse(QueryId id,
                                   base::FilePath device_path,
                                   TvPowerStatus result) {
  auto iterator = tv_power_status_queries_.find(id);
  CHECK(iterator != tv_power_status_queries_.end());

  TvsPowerStatusQuery& query = iterator->second;
  query.responses[device_path] = {true, result};

  if (MaybeRespondToTvsPowerStatusQuery(query)) {
    tv_power_status_queries_.erase(iterator);
  }
}

bool CecManager::MaybeRespondToTvsPowerStatusQuery(TvsPowerStatusQuery& query) {
  std::vector<TvPowerStatus> result;
  for (auto& response : query.responses) {
    const TvPowerStatusResult& status = response.second;
    if (!status.received) {
      return false;
    }

    result.push_back(status.power_status);
  }

  VLOG(1) << "Responding to power status request with: "
          << PowerStatusVectorToString(result);

  std::move(query.callback).Run(result);

  return true;
}

void CecManager::OnDeviceAdded(const base::FilePath& device_path) {
  LOG(INFO) << "New device: " << device_path.value();
  AddNewDevice(device_path);
}

void CecManager::OnDeviceRemoved(const base::FilePath& device_path) {
  LOG(INFO) << "Removing device: " << device_path.value();
  devices_.erase(device_path);

  auto iterator = tv_power_status_queries_.begin();
  while (iterator != tv_power_status_queries_.end()) {
    TvsPowerStatusQuery& query = iterator->second;
    query.responses.erase(device_path);

    if (MaybeRespondToTvsPowerStatusQuery(query)) {
      iterator = tv_power_status_queries_.erase(iterator);
    } else {
      ++iterator;
    }
  }
}

void CecManager::EnumerateAndAddExistingDevices() {
  std::vector<base::FilePath> paths;
  if (!udev_->EnumerateDevices(&paths)) {
    LOG(FATAL) << "Failed to enumerate devices.";
  }
  for (const auto& path : paths) {
    AddNewDevice(path);
  }
}

void CecManager::AddNewDevice(const base::FilePath& path) {
  std::unique_ptr<CecDevice> device = cec_factory_.Create(path);
  if (device) {
    LOG(INFO) << "Added new device: " << path.value();
    devices_[path] = std::move(device);
  } else {
    LOG(WARNING) << "Failed to add device: " << path.value();
  }
}

}  // namespace cecservice
