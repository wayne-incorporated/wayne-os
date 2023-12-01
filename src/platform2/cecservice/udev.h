// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CECSERVICE_UDEV_H_
#define CECSERVICE_UDEV_H_

#include <libudev.h>

#include <memory>
#include <vector>

#include <base/files/file_descriptor_watcher_posix.h>
#include <base/files/file_path.h>
#include <base/functional/callback.h>
#include <base/memory/weak_ptr.h>

namespace cecservice {

// Simple wrapper around libudev.
class Udev {
 public:
  using DeviceCallback = base::RepeatingCallback<void(const base::FilePath&)>;

  virtual ~Udev() = default;

  // Enumerates /dev/cec* nodes, returns false if the enumeration failed.
  virtual bool EnumerateDevices(
      std::vector<base::FilePath>* devices_out) const = 0;
};

// Actual implementation of udev wrapper.
class UdevImpl : public Udev {
 public:
  UdevImpl();
  UdevImpl(const UdevImpl&) = delete;
  UdevImpl& operator=(const UdevImpl&) = delete;

  ~UdevImpl() override;

  // Initializes the object, configuring provided callbacks. False return value
  // indicates that the object's initialization failed and the object is
  // unusable.
  bool Init(const DeviceCallback& device_added_callback,
            const DeviceCallback& device_removed_callback);

  // Udev:
  bool EnumerateDevices(
      std::vector<base::FilePath>* devices_out) const override;

 private:
  struct UdevDeleter {
    void operator()(udev* udev) const;
  };

  struct UdevMonitorDeleter {
    void operator()(udev_monitor*) const;
  };

  // Callback receiving events from udev.
  void OnDeviceAction();

  DeviceCallback device_added_callback_;
  DeviceCallback device_removed_callback_;

  std::unique_ptr<udev, UdevDeleter> udev_;
  std::unique_ptr<udev_monitor, UdevMonitorDeleter> monitor_;

  std::unique_ptr<base::FileDescriptorWatcher::Controller> watcher_;

  base::WeakPtrFactory<UdevImpl> weak_factory_{this};
};

// Factory for udev object.
class UdevFactory {
 public:
  virtual ~UdevFactory();

  // Creates an Udev object. Provided callbacks are invoked whenever a CEC
  // device is added/removed.
  virtual std::unique_ptr<Udev> Create(
      const Udev::DeviceCallback& device_added_callback,
      const Udev::DeviceCallback& device_removed_callback) const = 0;
};

// Factory for udev object.
class UdevFactoryImpl : public UdevFactory {
 public:
  UdevFactoryImpl();
  UdevFactoryImpl(const UdevFactoryImpl&) = delete;
  UdevFactoryImpl& operator=(const UdevFactoryImpl&) = delete;

  ~UdevFactoryImpl() override;

  // Udev:
  std::unique_ptr<Udev> Create(
      const Udev::DeviceCallback& device_added_callback,
      const Udev::DeviceCallback& device_removed_callback) const override;
};

}  // namespace cecservice

#endif  // CECSERVICE_UDEV_H_
