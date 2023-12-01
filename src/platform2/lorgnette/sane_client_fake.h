// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LORGNETTE_SANE_CLIENT_FAKE_H_
#define LORGNETTE_SANE_CLIENT_FAKE_H_

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <sane/sane.h>

#include "lorgnette/sane_client.h"

namespace lorgnette {

class SaneDeviceFake;

class SaneClientFake : public SaneClient {
 public:
  std::optional<std::vector<ScannerInfo>> ListDevices(
      brillo::ErrorPtr* error) override {
    return (list_devices_result_ ? std::make_optional(scanners_)
                                 : std::nullopt);
  }

  void SetListDevicesResult(bool value);
  void AddDevice(const std::string& name,
                 const std::string& manufacturer,
                 const std::string& model,
                 const std::string& type);
  void RemoveDevice(const std::string& name);

  void SetDeviceForName(const std::string& device_name,
                        std::unique_ptr<SaneDeviceFake> device);
  void SetIppUsbSocketDir(base::FilePath path);

 protected:
  std::unique_ptr<SaneDevice> ConnectToDeviceInternal(
      brillo::ErrorPtr* error,
      SANE_Status* sane_status,
      const std::string& device_name) override;
  base::FilePath IppUsbSocketDir() const override;

 private:
  std::map<std::string, std::unique_ptr<SaneDeviceFake>> devices_;
  bool list_devices_result_;
  std::vector<ScannerInfo> scanners_;
  std::optional<base::FilePath> ippusb_socket_dir_;
};

class SaneDeviceFake : public SaneDevice {
 public:
  SaneDeviceFake();
  ~SaneDeviceFake();

  std::optional<ValidOptionValues> GetValidOptionValues(
      brillo::ErrorPtr* error) override;

  std::optional<int> GetScanResolution(brillo::ErrorPtr* error) override {
    return resolution_;
  }

  bool SetScanResolution(brillo::ErrorPtr* error, int resolution) override;
  std::optional<std::string> GetDocumentSource(
      brillo::ErrorPtr* error) override {
    return source_name_;
  }
  bool SetDocumentSource(brillo::ErrorPtr* error,
                         const std::string& source_name) override;
  std::optional<ColorMode> GetColorMode(brillo::ErrorPtr* error) override {
    return color_mode_;
  }
  bool SetColorMode(brillo::ErrorPtr* error, ColorMode color_mode) override;
  bool SetScanRegion(brillo::ErrorPtr* error,
                     const ScanRegion& region) override;
  SANE_Status StartScan(brillo::ErrorPtr* error) override;
  std::optional<ScanParameters> GetScanParameters(
      brillo::ErrorPtr* error) override;
  SANE_Status ReadScanData(brillo::ErrorPtr* error,
                           uint8_t* buf,
                           size_t count,
                           size_t* read_out) override;
  bool CancelScan(brillo::ErrorPtr* error) override;

  void SetValidOptionValues(const std::optional<ValidOptionValues>& values);
  void SetStartScanResult(SANE_Status status);
  void SetScanParameters(const std::optional<ScanParameters>& params);
  void SetReadScanDataResult(SANE_Status result);
  void SetScanData(const std::vector<std::vector<uint8_t>>& scan_data);

 private:
  int resolution_;
  std::string source_name_;
  ColorMode color_mode_;
  std::optional<ValidOptionValues> values_;
  SANE_Status start_scan_result_;
  SANE_Status read_scan_data_result_;
  bool scan_running_;
  bool cancelled_;
  std::optional<ScanParameters> params_;
  std::vector<std::vector<uint8_t>> scan_data_;
  size_t current_page_;
  size_t scan_data_offset_;
};

}  // namespace lorgnette

#endif  // LORGNETTE_SANE_CLIENT_FAKE_H_
