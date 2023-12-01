// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "lorgnette/sane_client_fake.h"

#include <algorithm>
#include <map>
#include <optional>
#include <utility>

#include <chromeos/dbus/service_constants.h>

#include "lorgnette/dbus_adaptors/org.chromium.lorgnette.Manager.h"

static const char* kDbusDomain = brillo::errors::dbus::kDomain;

namespace lorgnette {

std::unique_ptr<SaneDevice> SaneClientFake::ConnectToDeviceInternal(
    brillo::ErrorPtr* error,
    SANE_Status* sane_status,
    const std::string& device_name) {
  if (devices_.count(device_name) > 0) {
    auto ptr = std::move(devices_[device_name]);
    devices_.erase(device_name);
    return ptr;
  }

  brillo::Error::AddTo(error, FROM_HERE, kDbusDomain, kManagerServiceError,
                       "No device");
  return nullptr;
}

void SaneClientFake::SetListDevicesResult(bool value) {
  list_devices_result_ = value;
}

void SaneClientFake::AddDevice(const std::string& name,
                               const std::string& manufacturer,
                               const std::string& model,
                               const std::string& type) {
  ScannerInfo info;
  info.set_name(name);
  info.set_manufacturer(manufacturer);
  info.set_model(model);
  info.set_type(type);
  scanners_.push_back(info);
}

void SaneClientFake::RemoveDevice(const std::string& name) {
  auto it = scanners_.begin();
  while (it != scanners_.end()) {
    if (it->name() == name) {
      it = scanners_.erase(it);
    } else {
      ++it;
    }
  }
}

void SaneClientFake::SetDeviceForName(const std::string& device_name,
                                      std::unique_ptr<SaneDeviceFake> device) {
  devices_.emplace(device_name, std::move(device));
}

void SaneClientFake::SetIppUsbSocketDir(base::FilePath path) {
  ippusb_socket_dir_ = std::move(path);
}

base::FilePath SaneClientFake::IppUsbSocketDir() const {
  return ippusb_socket_dir_ ? *ippusb_socket_dir_
                            : SaneClient::IppUsbSocketDir();
}

SaneDeviceFake::SaneDeviceFake()
    : resolution_(100),
      source_name_("Fake source name"),
      color_mode_(MODE_COLOR),
      start_scan_result_(SANE_STATUS_GOOD),
      read_scan_data_result_(SANE_STATUS_GOOD),
      scan_running_(false),
      cancelled_(false) {}

SaneDeviceFake::~SaneDeviceFake() {}

std::optional<ValidOptionValues> SaneDeviceFake::GetValidOptionValues(
    brillo::ErrorPtr* error) {
  if (!values_.has_value()) {
    brillo::Error::AddTo(error, FROM_HERE, kDbusDomain, kManagerServiceError,
                         "No option values");
  }

  return values_;
}

bool SaneDeviceFake::SetScanResolution(brillo::ErrorPtr*, int resolution) {
  resolution_ = resolution;
  return true;
}

bool SaneDeviceFake::SetDocumentSource(brillo::ErrorPtr*,
                                       const std::string& source_name) {
  source_name_ = source_name;
  return true;
}

bool SaneDeviceFake::SetColorMode(brillo::ErrorPtr*, ColorMode color_mode) {
  color_mode_ = color_mode;
  return true;
}

bool SaneDeviceFake::SetScanRegion(brillo::ErrorPtr* error, const ScanRegion&) {
  return true;
}

SANE_Status SaneDeviceFake::StartScan(brillo::ErrorPtr* error) {
  // Don't allow starting the next page of the scan if we haven't completed the
  // previous one.
  if (scan_running_ && current_page_ < scan_data_.size() &&
      scan_data_offset_ < scan_data_[current_page_].size()) {
    brillo::Error::AddTo(error, FROM_HERE, kDbusDomain, kManagerServiceError,
                         "Scan is already running");
    return SANE_STATUS_DEVICE_BUSY;
  }

  if (cancelled_) {
    return SANE_STATUS_CANCELLED;
  }

  if (start_scan_result_ != SANE_STATUS_GOOD) {
    return start_scan_result_;
  }

  if (scan_running_ && current_page_ + 1 == scan_data_.size()) {
    // No more scan data left.
    return SANE_STATUS_NO_DOCS;
  } else if (scan_running_) {
    current_page_++;
    scan_data_offset_ = 0;
  } else {
    scan_running_ = true;
    current_page_ = 0;
    cancelled_ = false;
    scan_data_offset_ = 0;
  }

  return SANE_STATUS_GOOD;
}

std::optional<ScanParameters> SaneDeviceFake::GetScanParameters(
    brillo::ErrorPtr* error) {
  if (!params_.has_value()) {
    brillo::Error::AddTo(error, FROM_HERE, kDbusDomain, kManagerServiceError,
                         "No parameters");
  }

  return params_;
}

SANE_Status SaneDeviceFake::ReadScanData(brillo::ErrorPtr* error,
                                         uint8_t* buf,
                                         size_t count,
                                         size_t* read_out) {
  if (!scan_running_) {
    brillo::Error::AddTo(error, FROM_HERE, kDbusDomain, kManagerServiceError,
                         "Scan not running");
    return SANE_STATUS_INVAL;
  }

  if (cancelled_) {
    scan_running_ = false;
    return SANE_STATUS_CANCELLED;
  }

  if (read_scan_data_result_ != SANE_STATUS_GOOD) {
    brillo::Error::AddTo(error, FROM_HERE, kDbusDomain, kManagerServiceError,
                         "Reading data failed");
    return read_scan_data_result_;
  }

  if (current_page_ >= scan_data_.size()) {
    scan_running_ = false;
    return SANE_STATUS_NO_DOCS;
  }

  const std::vector<uint8_t>& page = scan_data_[current_page_];
  if (scan_data_offset_ >= page.size()) {
    *read_out = 0;
    return SANE_STATUS_EOF;
  }

  size_t to_copy = std::min(count, page.size() - scan_data_offset_);
  memcpy(buf, page.data() + scan_data_offset_, to_copy);
  *read_out = to_copy;

  scan_data_offset_ += to_copy;
  return SANE_STATUS_GOOD;
}

bool SaneDeviceFake::CancelScan(brillo::ErrorPtr* error) {
  if (!scan_running_) {
    brillo::Error::AddTo(error, FROM_HERE, kDbusDomain, kManagerServiceError,
                         "Scan not running");
    return false;
  }

  cancelled_ = true;
  return true;
}

void SaneDeviceFake::SetValidOptionValues(
    const std::optional<ValidOptionValues>& values) {
  values_ = values;
}

void SaneDeviceFake::SetStartScanResult(SANE_Status status) {
  start_scan_result_ = status;
}

void SaneDeviceFake::SetScanParameters(
    const std::optional<ScanParameters>& params) {
  params_ = params;
}

void SaneDeviceFake::SetReadScanDataResult(SANE_Status result) {
  read_scan_data_result_ = result;
}

void SaneDeviceFake::SetScanData(
    const std::vector<std::vector<uint8_t>>& scan_data) {
  scan_data_ = scan_data;
}

}  // namespace lorgnette
