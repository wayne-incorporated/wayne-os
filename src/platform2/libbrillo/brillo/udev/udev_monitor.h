// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_BRILLO_UDEV_UDEV_MONITOR_H_
#define LIBBRILLO_BRILLO_UDEV_UDEV_MONITOR_H_

#include <memory>

#include <brillo/brillo_export.h>

struct udev_monitor;

namespace brillo {

class UdevDevice;

// A udev monitor, which wraps a udev_monitor C struct from libudev and related
// library functions into a C++ object.
class BRILLO_EXPORT UdevMonitor {
 public:
  static const int kInvalidFileDescriptor = -1;

  // Constructs a UdevMonitor object by taking a raw pointer to a udev_monitor
  // struct as |monitor|. The ownership of |monitor| is not transferred, but its
  // reference count is increased by one during the lifetime of this object.
  explicit UdevMonitor(udev_monitor* monitor);

  // Destructs this UdevMonitor object and decreases the reference count of the
  // underlying udev_monitor struct by one.
  virtual ~UdevMonitor();

  // Wraps udev_monitor_enable_receiving(). Returns true on success.
  virtual bool EnableReceiving();

  // Wraps udev_monitor_get_fd().
  virtual int GetFileDescriptor() const;

  // Wraps udev_monitor_receive_device().
  virtual std::unique_ptr<UdevDevice> ReceiveDevice();

  // Wraps udev_monitor_filter_add_match_subsystem_devtype(). Returns true on
  // success.
  virtual bool FilterAddMatchSubsystemDeviceType(const char* subsystem,
                                                 const char* device_type);

  // Wraps udev_monitor_filter_add_match_tag(). Returns true on success.
  virtual bool FilterAddMatchTag(const char* tag);

  // Wraps udev_monitor_filter_update(). Returns true on success.
  virtual bool FilterUpdate();

  // Wraps udev_monitor_filter_remove(). Returns true on success.
  virtual bool FilterRemove();

 private:
  // Allows MockUdevMonitor to invoke the private default constructor below.
  friend class MockUdevMonitor;

  // Constructs a UdevMonitor object without referencing a udev_monitor struct,
  // which is only allowed to be called by MockUdevMonitor.
  UdevMonitor();
  UdevMonitor(const UdevMonitor&) = delete;
  UdevMonitor& operator=(const UdevMonitor&) = delete;

  udev_monitor* monitor_;
};

}  // namespace brillo

#endif  // LIBBRILLO_BRILLO_UDEV_UDEV_MONITOR_H_
