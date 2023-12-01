// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "brillo/usb/usb_manager.h"

#include <libusb.h>
#include <poll.h>

#include <memory>
#include <utility>

#include <base/check.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/memory/free_deleter.h>
#include <base/memory/ptr_util.h>
#include <brillo/streams/stream_utils.h>
#include <base/strings/stringprintf.h>
#include <brillo/usb/usb_device.h>
#include <brillo/usb/usb_device_descriptor.h>

namespace brillo {

namespace {

brillo::Stream::AccessMode ConvertEventFlagsToWatchMode(
    short events) {  // NOLINT
  if ((events & POLLIN) && (events & POLLOUT))
    return brillo::Stream::AccessMode::READ_WRITE;

  if (events & POLLIN)
    return brillo::Stream::AccessMode::READ;

  if (events & POLLOUT)
    return brillo::Stream::AccessMode::WRITE;

  return brillo::Stream::AccessMode::READ_WRITE;
}

}  // namespace

std::unique_ptr<UsbManager> UsbManager::Create() {
  // Using new to access non-public constructor. See
  // https://abseil.io/tips/134.
  std::unique_ptr<UsbManager> usb_manager = base::WrapUnique(new UsbManager());
  if (!usb_manager->Initialize()) {
    return nullptr;
  }

  return usb_manager;
}

UsbManager::UsbManager() : context_(nullptr) {}

UsbManager::~UsbManager() {
  if (context_) {
    libusb_exit(context_);
    context_ = nullptr;
  }
}

bool UsbManager::Initialize() {
  CHECK(!context_);

  int result = libusb_init(&context_);
  if (!error_.SetFromLibUsbError(static_cast<libusb_error>(result))) {
    LOG(ERROR) << "Could not initialize libusb: " << error_;
    return false;
  }

  if (!StartWatchingPollFileDescriptors()) {
    error_.set_type(UsbError::kErrorNotSupported);
    return false;
  }

  return true;
}

void UsbManager::SetDebugLevel(int level) {
  CHECK(context_);

  libusb_set_option(context_, LIBUSB_OPTION_LOG_LEVEL, level);
}

std::unique_ptr<UsbDevice> UsbManager::GetDevice(uint8_t bus_number,
                                                 uint8_t device_address,
                                                 uint16_t vendor_id,
                                                 uint16_t product_id) {
  std::vector<std::unique_ptr<UsbDevice>> devices;
  if (!GetDevices(&devices))
    return nullptr;

  for (auto& device : devices) {
    if (device->GetBusNumber() != bus_number ||
        device->GetDeviceAddress() != device_address)
      continue;

    std::unique_ptr<UsbDeviceDescriptor> device_descriptor =
        device->GetDeviceDescriptor();
    VLOG(2) << *device_descriptor;
    if (device_descriptor->GetVendorId() == vendor_id &&
        device_descriptor->GetProductId() == product_id) {
      return std::move(device);
    }
  }

  error_.set_type(UsbError::kErrorNotFound);
  return nullptr;
}

bool UsbManager::GetDevices(std::vector<std::unique_ptr<UsbDevice>>* devices) {
  CHECK(context_);
  CHECK(devices);

  devices->clear();

  libusb_device** device_list = nullptr;
  ssize_t result = libusb_get_device_list(context_, &device_list);
  if (result < 0)
    return error_.SetFromLibUsbError(static_cast<libusb_error>(result));

  for (ssize_t i = 0; i < result; ++i) {
    devices->push_back(std::make_unique<UsbDevice>(device_list[i]));
  }

  // UsbDevice holds a reference count of a libusb_device struct. Thus,
  // decrement the reference count of the libusb_device struct in the list by
  // one when freeing the list.
  libusb_free_device_list(device_list, 1);
  return true;
}

void UsbManager::OnPollFileDescriptorAdded(int file_descriptor,
                                           short events,  // NOLINT
                                           void* user_data) {
  CHECK(user_data);

  VLOG(2) << base::StringPrintf(
      "Poll file descriptor %d on events 0x%016x added.", file_descriptor,
      events);
  auto* manager = reinterpret_cast<UsbManager*>(user_data);
  manager->StartWatchingFileDescriptor(
      file_descriptor, ConvertEventFlagsToWatchMode(events),
      base::BindRepeating(&UsbManager::HandleEventsNonBlocking,
                          manager->weak_factory_.GetWeakPtr()));
}

void UsbManager::OnPollFileDescriptorRemoved(int file_descriptor,
                                             void* user_data) {
  CHECK(user_data);

  VLOG(2) << base::StringPrintf("Poll file descriptor %d removed.",
                                file_descriptor);
  auto* manager = reinterpret_cast<UsbManager*>(user_data);
  manager->StopWatchingFileDescriptor(file_descriptor);
}

bool UsbManager::StartWatchingPollFileDescriptors() {
  CHECK(context_);

  libusb_set_pollfd_notifiers(context_, &OnPollFileDescriptorAdded,
                              &OnPollFileDescriptorRemoved, this);

  std::unique_ptr<const libusb_pollfd*, base::FreeDeleter> pollfd_list(
      libusb_get_pollfds(context_));
  if (!pollfd_list) {
    LOG(ERROR) << "Could not get file descriptors for monitoring USB events.";
    return false;
  }

  for (const libusb_pollfd** fd_ptr = pollfd_list.get(); *fd_ptr; ++fd_ptr) {
    const libusb_pollfd& pollfd = *(*fd_ptr);
    VLOG(2) << base::StringPrintf(
        "Poll file descriptor %d for events 0x%016x added.", pollfd.fd,
        pollfd.events);
    if (!StartWatchingFileDescriptor(
            pollfd.fd, ConvertEventFlagsToWatchMode(pollfd.events),
            base::BindRepeating(&UsbManager::HandleEventsNonBlocking,
                                weak_factory_.GetWeakPtr()))) {
      return false;
    }
  }
  return true;
}

void UsbManager::HandleEventsNonBlocking() {
  CHECK(context_);

  timeval zero_tv = {0};
  int result =
      libusb_handle_events_timeout_completed(context_, &zero_tv, nullptr);
  UsbError error(static_cast<libusb_error>(result));
  LOG_IF(ERROR, !error.IsSuccess()) << "Could not handle USB events: " << error;
}

bool UsbManager::StartWatchingFileDescriptor(
    int file_descriptor,
    brillo::Stream::AccessMode mode,
    const base::RepeatingClosure& callback) {
  CHECK_GE(file_descriptor, 0);

  Watcher& watcher = file_descriptor_watchers_[file_descriptor];
  // Reset once if it is already being watched.
  watcher.read_watcher = nullptr;
  watcher.write_watcher = nullptr;

  bool success = true;
  if (brillo::stream_utils::IsReadAccessMode(mode)) {
    watcher.read_watcher =
        base::FileDescriptorWatcher::WatchReadable(file_descriptor, callback);
    success = watcher.read_watcher.get();
  }
  if (brillo::stream_utils::IsWriteAccessMode(mode)) {
    watcher.write_watcher =
        base::FileDescriptorWatcher::WatchWritable(file_descriptor, callback);
    success = success && watcher.write_watcher.get();
  }

  if (!success) {
    LOG(ERROR) << "Could not watch file descriptor: " << file_descriptor;
    file_descriptor_watchers_.erase(file_descriptor);
    return false;
  }

  VLOG(2) << "Started watching file descriptor: " << file_descriptor;
  return true;
}

bool UsbManager::StopWatchingFileDescriptor(int file_descriptor) {
  CHECK_GE(file_descriptor, 0);

  auto it = file_descriptor_watchers_.find(file_descriptor);
  if (it == file_descriptor_watchers_.end()) {
    LOG(ERROR) << "File descriptor " << file_descriptor
               << " is not being watched.";
    return false;
  }

  file_descriptor_watchers_.erase(it);
  VLOG(2) << "Stopped watching file descriptor: " << file_descriptor;
  return true;
}

void UsbManager::StopWatchingAllFileDescriptors() {
  file_descriptor_watchers_.clear();
}

}  // namespace brillo
