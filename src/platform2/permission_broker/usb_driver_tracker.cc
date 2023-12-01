// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "permission_broker/usb_driver_tracker.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/usbdevice_fs.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <string>
#include <utility>

#include <base/containers/contains.h>
#include <base/containers/cxx20_erase_vector.h>
#include <base/files/file_descriptor_watcher_posix.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/posix/eintr_wrapper.h>
#include <base/strings/string_number_conversions.h>
#include <base/unguessable_token.h>

#include "permission_broker/udev_scopers.h"

namespace permission_broker {

UsbDriverTracker::UsbDriverTracker() = default;

UsbDriverTracker::~UsbDriverTracker() {
  CleanUpTracking();
}

void UsbDriverTracker::HandleClosedFd(std::string client_id) {
  auto iter = dev_fds_.find(client_id);
  if (iter != dev_fds_.end()) {
    auto& entry = iter->second;
    // Reattaching the kernel driver to the USB interface.
    while (!entry.interfaces.empty()) {
      uint8_t iface_num = *entry.interfaces.begin();
      // This might remove elements in entry.interfaces.
      if (!ReattachInterface(client_id, iface_num)) {
        LOG(ERROR) << "Failed to reattach interface "
                   << static_cast<int>(iface_num) << " for client "
                   << client_id;
        // Remove the interface from the tracking record even if reattaching
        // fails (ex: ioctl() failure) to avoid orphan tracking record as this
        // client is being closed.
        ClearDetachedInterfaceRecord(client_id, entry.path, iface_num);
      }
    }
    // We are done with the client_id.
    dev_fds_.erase(iter);
  } else {
    LOG(WARNING) << "Untracked USB client " << client_id;
  }
}

bool UsbDriverTracker::DetachPathFromKernel(int fd,
                                            const std::string* client_id,
                                            const base::FilePath& path) {
  // Use the USB device node major/minor to find the udev entry.
  struct stat st;
  if (fstat(fd, &st) || !S_ISCHR(st.st_mode)) {
    LOG(WARNING) << "Cannot stat " << path << " device id";
    return false;
  }

  ScopedUdevPtr udev(udev_new());
  ScopedUdevDevicePtr device(
      udev_device_new_from_devnum(udev.get(), 'c', st.st_rdev));
  if (!device.get()) {
    return false;
  }

  ScopedUdevEnumeratePtr enumerate(udev_enumerate_new(udev.get()));
  udev_enumerate_add_match_parent(enumerate.get(), device.get());
  udev_enumerate_scan_devices(enumerate.get());

  // Try to find our USB interface nodes, by iterating through all devices
  // and extracting our children devices.
  bool detached = false;
  struct udev_list_entry* entry;
  udev_list_entry_foreach(entry,
                          udev_enumerate_get_list_entry(enumerate.get())) {
    const char* entry_path = udev_list_entry_get_name(entry);
    ScopedUdevDevicePtr child(
        udev_device_new_from_syspath(udev.get(), entry_path));

    const char* child_type = udev_device_get_devtype(child.get());
    if (!child_type || strcmp(child_type, "usb_interface") != 0) {
      continue;
    }

    const char* driver = udev_device_get_driver(child.get());
    if (driver) {
      // A kernel driver is using this interface, try to detach it.
      const char* iface =
          udev_device_get_sysattr_value(child.get(), "bInterfaceNumber");
      unsigned iface_num;
      if (!iface || !base::StringToUint(iface, &iface_num)) {
        detached = false;
        continue;
      }

      detached = true;
      if (client_id) {
        if (!DetachInterface(*client_id, iface_num)) {
          LOG(ERROR) << "Fail to detach interface "
                     << static_cast<int>(iface_num) << " for client "
                     << client_id;
          detached = false;
        }
      } else {
        // This is the case in Permission Broker OpenPath() which doesn't use
        // any client tracking.
        if (!DisconnectInterface(fd, iface_num)) {
          LOG(ERROR) << "Failed to detach interface "
                     << static_cast<int>(iface_num) << " with fd " << fd;
          detached = false;
        }
      }
    }
  }

  return detached;
}

std::unique_ptr<base::FileDescriptorWatcher::Controller>
UsbDriverTracker::WatchLifelineFd(const std::string& client_id,
                                  int lifeline_fd) {
  return base::FileDescriptorWatcher::WatchReadable(
      lifeline_fd,
      base::BindRepeating(&UsbDriverTracker::HandleClosedFd,
                          weak_ptr_factory_.GetWeakPtr(), client_id));
}

std::optional<std::string> UsbDriverTracker::RegisterClient(
    int lifeline_fd, const base::FilePath& path) {
  // |dup_lifeline_fd| is the duplicated file descriptor of the client's
  // lifeline pipe read end. The ownership needs to be transferred to the
  // internal tracking structure to keep readable callback registered.
  base::ScopedFD fd(HANDLE_EINTR(open(path.value().c_str(), O_RDWR)));
  if (!fd.is_valid()) {
    PLOG(ERROR) << "Failed to open path " << path;
    return std::nullopt;
  }
  base::ScopedFD dup_lifeline_fd(HANDLE_EINTR(dup(lifeline_fd)));
  if (!dup_lifeline_fd.is_valid()) {
    PLOG(ERROR) << "Failed to dup lifeline_fd " << lifeline_fd;
    return std::nullopt;
  }

  std::string client_id;
  do {
    client_id = base::UnguessableToken::Create().ToString();
  } while (base::Contains(dev_fds_, client_id));

  auto controller = WatchLifelineFd(client_id, dup_lifeline_fd.get());
  if (!controller) {
    LOG(ERROR) << "Unable to watch lifeline_fd " << dup_lifeline_fd.get()
               << " for client " << client_id;
    return std::nullopt;
  }

  dev_fds_.emplace(client_id,
                   UsbInterfaces{.path = path,
                                 .controller = std::move(controller),
                                 .interfaces = {},
                                 .fd = std::move(fd),
                                 .lifeline_fd = std::move(dup_lifeline_fd)});

  return client_id;
}

bool UsbDriverTracker::DisconnectInterface(int fd, uint8_t iface_num) {
  struct usbdevfs_ioctl dio;
  dio.ifno = iface_num;
  dio.ioctl_code = USBDEVFS_DISCONNECT;
  dio.data = nullptr;
  int rc = ioctl(fd, USBDEVFS_IOCTL, &dio);
  // ENODATA is a benign error code which is when the interface isn't
  // associated with any driver.
  if (rc < 0 && errno != ENODATA) {
    PLOG(ERROR) << "Failed to disconnect interface "
                << static_cast<int>(iface_num) << " with fd " << fd;
    return false;
  }

  return true;
}

bool UsbDriverTracker::ConnectInterface(int fd, uint8_t iface_num) {
  struct usbdevfs_ioctl dio;
  dio.ifno = iface_num;
  dio.ioctl_code = USBDEVFS_CONNECT;
  dio.data = nullptr;
  int rc = ioctl(fd, USBDEVFS_IOCTL, &dio);
  if (rc < 0) {
    PLOG(ERROR) << "Failed to connect interface " << static_cast<int>(iface_num)
                << " with fd " << fd;
    return false;
  }

  return true;
}

void UsbDriverTracker::RecordInterfaceDetached(const std::string& client_id,
                                               const base::FilePath& path,
                                               uint8_t iface_num) {
  auto client_it = dev_fds_.find(client_id);
  if (client_it == dev_fds_.end()) {
    LOG(DFATAL) << "Can't find client " << client_id
                << " in the tracking record";
    return;
  }
  if (base::Contains(client_it->second.interfaces, iface_num)) {
    LOG(DFATAL) << "Detached interface " << static_cast<int>(iface_num)
                << " on path " << path
                << " has already been recorded by client " << client_id;
    return;
  }

  client_it->second.interfaces.push_back(iface_num);
  dev_ifaces_[path][iface_num] = client_id;
}

void UsbDriverTracker::ClearDetachedInterfaceRecord(
    const std::string& client_id,
    const base::FilePath& path,
    uint8_t iface_num) {
  auto client_it = dev_fds_.find(client_id);
  auto path_it = dev_ifaces_.find(path);
  if (client_it == dev_fds_.end()) {
    LOG(DFATAL) << "Can't find client " << client_id
                << " in the tracking record";
    return;
  }
  if (path_it == dev_ifaces_.end()) {
    LOG(DFATAL) << "Can't find path " << path << " in the tracking record";
    return;
  }

  auto num_erased = base::Erase(client_it->second.interfaces, iface_num);
  if (num_erased != 1) {
    LOG(DFATAL) << "Unexpected number of erased records " << num_erased
                << " for interface " << static_cast<int>(iface_num)
                << " on path " << path << " for client " << client_id;
  }
  path_it->second.erase(iface_num);
  if (path_it->second.empty()) {
    dev_ifaces_.erase(path_it);
  }
}

bool UsbDriverTracker::IsClientIdTracked(const std::string& client_id) {
  return base::Contains(dev_fds_, client_id);
}

void UsbDriverTracker::CleanUpTracking() {
  // Reattach all delegated USB interfaces.
  while (!dev_fds_.empty()) {
    // This might remove the element.
    HandleClosedFd(dev_fds_.begin()->first);
  }
}

bool UsbDriverTracker::DetachInterface(const std::string& client_id,
                                       uint8_t iface_num) {
  if (!IsClientIdTracked(client_id)) {
    LOG(WARNING) << "DetachInterface: Untracked client " << client_id;
    return false;
  }

  const auto& path = dev_fds_[client_id].path;
  const auto& fd = dev_fds_[client_id].fd;
  auto path_it = dev_ifaces_.find(path);
  if (path_it != dev_ifaces_.end()) {
    auto iface_it = path_it->second.find(iface_num);
    if (iface_it != path_it->second.end()) {
      if (iface_it->second != client_id) {
        LOG(WARNING) << "The interface " << static_cast<int>(iface_num)
                     << " at path " << path << " can't be detached by client "
                     << client_id << " as it has been detached by other client "
                     << iface_it->second;
        return false;
      }
      // No-op if the interface has been detached by the requested client.
      return true;
    }
  }

  if (!DisconnectInterface(fd.get(), iface_num)) {
    LOG(ERROR) << "Kernel USB driver disconnection for " << path
               << " on interface " << static_cast<int>(iface_num)
               << " by client " << client_id << " failed";
    return false;
  }

  RecordInterfaceDetached(client_id, path, iface_num);
  return true;
}

bool UsbDriverTracker::ReattachInterface(const std::string& client_id,
                                         uint8_t iface_num) {
  if (!IsClientIdTracked(client_id)) {
    LOG(WARNING) << "ReattachInterface: Untracked client " << client_id;
    return false;
  }

  const auto& path = dev_fds_[client_id].path;
  const auto& fd = dev_fds_[client_id].fd;
  auto path_it = dev_ifaces_.find(path);
  if (path_it == dev_ifaces_.end()) {
    // No-op if the path hasn't been detached by any clients.
    return true;
  }
  auto iface_it = path_it->second.find(iface_num);
  if (iface_it == path_it->second.end()) {
    // No-op if the interface hasn't been detached by any clients.
    return true;
  }
  if (iface_it->second != client_id) {
    LOG(WARNING) << "The interface " << static_cast<int>(iface_num)
                 << " at path " << path << " can't be attached by client "
                 << client_id << " as it was detached by other client "
                 << iface_it->second;
    return false;
  }

  if (!ConnectInterface(fd.get(), iface_num)) {
    LOG(ERROR) << "Kernel USB driver connection for " << path
               << " on interface " << static_cast<int>(iface_num)
               << " by client " << client_id << " failed";
    return false;
  }

  ClearDetachedInterfaceRecord(client_id, path, iface_num);
  return true;
}

}  // namespace permission_broker
