// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_UDEV_UDEV_UTILS_H_
#define RMAD_UDEV_UDEV_UTILS_H_

#include <memory>
#include <string>
#include <vector>

namespace brillo {
class Udev;
}  // namespace brillo

namespace rmad {

class UdevDevice;

class UdevUtils {
 public:
  UdevUtils() = default;
  virtual ~UdevUtils() = default;

  virtual std::vector<std::unique_ptr<UdevDevice>> EnumerateBlockDevices() = 0;
  virtual bool GetBlockDeviceFromDevicePath(
      const std::string& device_path, std::unique_ptr<UdevDevice>* dev) = 0;
};

class UdevUtilsImpl : public UdevUtils {
 public:
  UdevUtilsImpl();
  // Used to inject mocked |udev| for testing.
  explicit UdevUtilsImpl(std::unique_ptr<brillo::Udev> udev);
  ~UdevUtilsImpl() override;

  std::vector<std::unique_ptr<UdevDevice>> EnumerateBlockDevices() override;
  bool GetBlockDeviceFromDevicePath(const std::string& device_path,
                                    std::unique_ptr<UdevDevice>* dev) override;

 private:
  std::unique_ptr<brillo::Udev> udev_;
};

}  // namespace rmad

#endif  // RMAD_UDEV_UDEV_UTILS_H_
