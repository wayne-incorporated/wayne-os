// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_BRILLO_UDEV_UDEV_H_
#define LIBBRILLO_BRILLO_UDEV_UDEV_H_

#include <sys/types.h>

#include <memory>

#include <brillo/brillo_export.h>

struct udev;
struct udev_device;

namespace brillo {

class UdevDevice;
class UdevEnumerate;
class UdevMonitor;

// A udev library context, which wraps a udev C struct from libudev and related
// library functions into a C++ object.
class BRILLO_EXPORT Udev {
 public:
  // Creates and initializes a Udev object. Returns nullptr on failure.
  static std::unique_ptr<Udev> Create();
  virtual ~Udev();

  // Wraps udev_device_new_from_syspath().
  virtual std::unique_ptr<UdevDevice> CreateDeviceFromSysPath(
      const char* sys_path);

  // Wraps udev_device_new_from_devnum().
  virtual std::unique_ptr<UdevDevice> CreateDeviceFromDeviceNumber(
      char type, dev_t device_number);

  // Wraps udev_device_new_from_subsystem_sysname().
  virtual std::unique_ptr<UdevDevice> CreateDeviceFromSubsystemSysName(
      const char* subsystem, const char* sys_name);

  // Wraps udev_enumerate_new().
  virtual std::unique_ptr<UdevEnumerate> CreateEnumerate();

  // Wraps udev_monitor_new_from_netlink().
  virtual std::unique_ptr<UdevMonitor> CreateMonitorFromNetlink(
      const char* name);

 private:
  friend class MockUdev;

  // Creates a Udev by taking ownership of the |udev|.
  explicit Udev(struct udev* udev);
  Udev(const Udev&) = delete;
  Udev& operator=(const Udev&) = delete;

  // Creates a UdevDevice object that wraps a given udev_device struct pointed
  // by |device|. The ownership of |device| is transferred to returned
  // UdevDevice object.
  static std::unique_ptr<UdevDevice> CreateDevice(udev_device* device);

  struct udev* udev_;
};

}  // namespace brillo

#endif  // LIBBRILLO_BRILLO_UDEV_UDEV_H_
