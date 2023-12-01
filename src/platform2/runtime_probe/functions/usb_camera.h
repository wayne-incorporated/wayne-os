// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RUNTIME_PROBE_FUNCTIONS_USB_CAMERA_H_
#define RUNTIME_PROBE_FUNCTIONS_USB_CAMERA_H_

#include <linux/videodev2.h>

#include <optional>

#include <base/files/file_path.h>

#include "runtime_probe/probe_function.h"

namespace runtime_probe {

class UsbCameraFunction : public PrivilegedProbeFunction {
  using PrivilegedProbeFunction::PrivilegedProbeFunction;

 public:
  NAME_PROBE_FUNCTION("usb_camera");

 private:
  DataType EvalImpl() const override;

  // For mocking.
  // Query the V4L2 capability of file descriptor |fd| via ioctl.
  //
  // @return: V4L2 capability if the query is successful, otherwise
  // std::nullopt.
  virtual std::optional<v4l2_capability> QueryV4l2Cap(int32_t fd) const;

  // Check if the device at |path| is a capture device
  bool IsCaptureDevice(const base::FilePath& path) const;

  // If |path| represents an usb camera, probe its information from sysfs and
  // store it in |res|.
  //
  // @return: |true| if the device is an usb camera.
  bool ExploreAsUsbCamera(const base::FilePath& path, base::Value* res) const;
};

}  // namespace runtime_probe

#endif  // RUNTIME_PROBE_FUNCTIONS_USB_CAMERA_H_
