/*
 * Copyright 2018 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_INCLUDE_CROS_CAMERA_UDEV_WATCHER_H_
#define CAMERA_INCLUDE_CROS_CAMERA_UDEV_WATCHER_H_

#include <memory>
#include <string>

#include <libudev.h>

#include <base/files/file_descriptor_watcher_posix.h>
#include <base/threading/thread.h>

#include "cros-camera/common.h"
#include "cros-camera/export.h"
#include "cros-camera/scoped_udev.h"

namespace cros {

// ref: http://www.signal11.us/oss/udev/
// > It's important to note that when using monitoring and enumeration together,
// > that monitoring should be enabled before enumeration. This way, any events
// > (for example devices being attached to the system) which happen during
// > enumeration will not be lost. If enumeration is done before monitoring is
// > enabled, any device attached between the time the enumeration happens and
// > when monitoring starts will be missed. The algorithm should be:
// >   1. Set up monitoring.
// >   2. Enumerate devices (optionally opening desired devices).
// >   3. Begin checking the monitoring interface for events.
//
// TODO(shik): There are some other packages in CrOS use libudev in the wrong
// way.  We should fix them as well.

class CROS_CAMERA_EXPORT UdevWatcher {
 public:
  class Observer {
   public:
    virtual ~Observer();
    virtual void OnDeviceAdded(ScopedUdevDevicePtr device);
    virtual void OnDeviceRemoved(ScopedUdevDevicePtr device);
  };

  // The observer must outlive this watcher.
  UdevWatcher(Observer* observer, std::string subsystem);
  ~UdevWatcher();

  // Disallow copy constructor and assign operator.
  UdevWatcher(const UdevWatcher&) = delete;
  UdevWatcher& operator=(const UdevWatcher&) = delete;

  // Start monitoring. This should be called before EnumerateExistingDevices().
  // All callbacks will be run on |task_runner|.
  bool Start(scoped_refptr<base::SingleThreadTaskRunner> task_runner);

  // Synchronously enumerates the all devices known to udev, and calling
  // |observer_->OnDeviceAdded()| for each device.
  bool EnumerateExistingDevices();

 private:
  void OnReadable();

  void StartOnThread(int fd, base::OnceCallback<void(bool)> callback);
  void StopOnThread();

  Observer* observer_;
  std::string subsystem_;
  base::Thread thread_;
  std::unique_ptr<base::FileDescriptorWatcher::Controller> watcher_;

  ScopedUdevPtr udev_;
  ScopedUdevMonitorPtr mon_;
  scoped_refptr<base::SingleThreadTaskRunner> callback_task_runner_;
};

}  // namespace cros

#endif  // CAMERA_INCLUDE_CROS_CAMERA_UDEV_WATCHER_H_
