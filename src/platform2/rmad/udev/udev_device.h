// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_UDEV_UDEV_DEVICE_H_
#define RMAD_UDEV_UDEV_DEVICE_H_

#include <blkid/blkid.h>

#include <memory>
#include <string>

namespace brillo {
class UdevDevice;
}  // namespace brillo

namespace rmad {

class UdevDevice {
 public:
  UdevDevice() = default;
  virtual ~UdevDevice() = default;

  virtual bool IsRemovable() const = 0;
  virtual std::string GetSysPath() const = 0;
  virtual std::string GetDeviceNode() const = 0;
  // Not a const method because the implementation updates |blkid_cache_|.
  virtual std::string GetFileSystemType() = 0;
};

class UdevDeviceImpl : public UdevDevice {
 public:
  explicit UdevDeviceImpl(std::unique_ptr<brillo::UdevDevice> dev);
  virtual ~UdevDeviceImpl();

  bool IsRemovable() const override;
  std::string GetSysPath() const override;
  std::string GetDeviceNode() const override;
  std::string GetFileSystemType() override;

 private:
  std::unique_ptr<brillo::UdevDevice> dev_;
  blkid_cache blkid_cache_;
};

}  // namespace rmad

#endif  // RMAD_UDEV_UDEV_DEVICE_H_
