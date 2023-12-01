// Copyright 2011 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cros-disks/cros_disks_server.h"

#include <utility>

#include <base/check.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/strings/strcat.h>
#include <chromeos/dbus/service_constants.h>

#include "cros-disks/device_event.h"
#include "cros-disks/disk.h"
#include "cros-disks/disk_monitor.h"
#include "cros-disks/format_manager.h"
#include "cros-disks/mount_point.h"
#include "cros-disks/partition_manager.h"
#include "cros-disks/platform.h"
#include "cros-disks/quote.h"
#include "cros-disks/rename_manager.h"

namespace cros_disks {

CrosDisksServer::CrosDisksServer(scoped_refptr<dbus::Bus> bus,
                                 Platform* platform,
                                 DiskMonitor* disk_monitor,
                                 FormatManager* format_manager,
                                 PartitionManager* partition_manager,
                                 RenameManager* rename_manager)
    : org::chromium::CrosDisksAdaptor(this),
      dbus_object_(nullptr, bus, dbus::ObjectPath(kCrosDisksServicePath)),
      platform_(platform),
      disk_monitor_(disk_monitor),
      format_manager_(format_manager),
      partition_manager_(partition_manager),
      rename_manager_(rename_manager) {
  DCHECK(platform_);
  DCHECK(disk_monitor_);
  DCHECK(format_manager_);
  DCHECK(partition_manager_);
  DCHECK(rename_manager_);

  format_manager_->set_observer(this);
  rename_manager_->set_observer(this);
}

void CrosDisksServer::RegisterAsync(
    brillo::dbus_utils::AsyncEventSequencer::CompletionAction cb) {
  RegisterWithDBusObject(&dbus_object_);
  dbus_object_.RegisterAsync(std::move(cb));
}

void CrosDisksServer::RegisterMountManager(MountManager* mount_manager) {
  CHECK(mount_manager) << "Invalid mount manager object";
  mount_managers_.push_back(mount_manager);
}

void CrosDisksServer::Format(const std::string& path,
                             const std::string& filesystem_type,
                             const std::vector<std::string>& options) {
  FormatError error = FormatError::kSuccess;
  Disk disk;
  if (!disk_monitor_->GetDiskByDevicePath(base::FilePath(path), &disk)) {
    error = FormatError::kInvalidDevicePath;
  } else {
    error = format_manager_->StartFormatting(path, disk.device_file,
                                             filesystem_type, options);
  }

  if (error != FormatError::kSuccess) {
    LOG(ERROR) << "Cannot format device " << quote(path) << " as filesystem "
               << quote(filesystem_type) << ": " << error;
    SendFormatCompletedSignal(static_cast<uint32_t>(error), path);
  }
}

void CrosDisksServer::SinglePartitionFormat(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<uint32_t>> response,
    const std::string& path) {
  Disk disk;

  if (!disk_monitor_->GetDiskByDevicePath(base::FilePath(path), &disk)) {
    LOG(ERROR) << "Invalid device path " << quote(path) << ": "
               << PartitionError::kInvalidDevicePath;
    response->Return(static_cast<uint32_t>(PartitionError::kInvalidDevicePath));
  } else if (disk.is_on_boot_device || !disk.is_drive || disk.is_read_only) {
    LOG(ERROR) << "Device not allowed " << quote(path) << ": "
               << PartitionError::kDeviceNotAllowed;
    response->Return(static_cast<uint32_t>(PartitionError::kDeviceNotAllowed));
  } else {
    partition_manager_->StartSinglePartitionFormat(
        base::FilePath(disk.device_file),
        base::BindOnce(&CrosDisksServer::OnPartitionCompleted,
                       base::Unretained(this), std::move(response)));
  }
}

void CrosDisksServer::Rename(const std::string& path,
                             const std::string& volume_name) {
  RenameError error = RenameError::kSuccess;
  Disk disk;
  if (!disk_monitor_->GetDiskByDevicePath(base::FilePath(path), &disk)) {
    error = RenameError::kInvalidDevicePath;
  } else {
    error = rename_manager_->StartRenaming(path, disk.device_file, volume_name,
                                           disk.filesystem_type);
  }

  if (error != RenameError::kSuccess) {
    LOG(ERROR) << "Cannot rename device " << quote(path) << " as "
               << redact(volume_name) << ": " << error;
    SendRenameCompletedSignal(static_cast<uint32_t>(error), path);
  }
}

MountManager* CrosDisksServer::FindMounter(
    const std::string& source_path) const {
  for (const auto& manager : mount_managers_) {
    if (manager->CanMount(source_path)) {
      return manager;
    }
  }
  return nullptr;
}

void CrosDisksServer::OnMountProgress(const MountPoint* const mount_point) {
  DCHECK(mount_point);
  LOG(INFO) << "Progress for " << quote(mount_point->path()) << ": "
            << mount_point->progress_percent() << "%";
  SendMountProgressSignal(mount_point->progress_percent(),
                          mount_point->source(), mount_point->source_type(),
                          mount_point->path().value(),
                          mount_point->is_read_only());
}

void CrosDisksServer::OnMountCompleted(const std::string& source,
                                       MountSourceType source_type,
                                       const std::string& filesystem_type,
                                       const std::string& mount_path,
                                       MountError error,
                                       bool read_only) {
  if (error != MountError::kSuccess) {
    LOG(ERROR) << "Cannot mount " << filesystem_type << " " << redact(source)
               << ": " << error;
  } else {
    LOG(INFO) << "Mounted " << redact(source) << " as " << filesystem_type
              << " " << redact(mount_path);
  }

  SendMountCompletedSignal(static_cast<uint32_t>(error), source, source_type,
                           mount_path, read_only);
}

void CrosDisksServer::Mount(const std::string& source,
                            const std::string& filesystem_type,
                            const std::vector<std::string>& options) {
  MountManager* const mounter = FindMounter(source);
  if (!mounter) {
    LOG(ERROR) << "Cannot find mounter for " << filesystem_type << " "
               << redact(source);
    SendMountCompletedSignal(static_cast<uint32_t>(MountError::kInvalidPath),
                             source, MOUNT_SOURCE_INVALID, "", false);
    return;
  }

  const MountSourceType source_type = mounter->GetMountSourceType();
  VLOG(1) << "Mounting " << filesystem_type << " " << redact(source)
          << " using mounter " << source_type;

  MountManager::MountCallback mount_callback =
      base::BindOnce(&CrosDisksServer::OnMountCompleted, base::Unretained(this),
                     source, source_type);

  MountManager::ProgressCallback progress_callback = base::BindRepeating(
      &CrosDisksServer::OnMountProgress, base::Unretained(this));

  mounter->Mount(source, filesystem_type, options, std::move(mount_callback),
                 std::move(progress_callback));
}

uint32_t CrosDisksServer::Unmount(const std::string& path,
                                  const std::vector<std::string>& options) {
  if (path.empty()) {
    LOG(ERROR) << "Cannot unmount an empty path";
    return static_cast<uint32_t>(MountError::kInvalidArgument);
  }

  LOG(INFO) << "Unmounting " << redact(path) << "...";
  LOG_IF(WARNING, !options.empty())
      << "Ignored unmount options " << quote(options) << " for "
      << redact(path);

  MountError error = MountError::kPathNotMounted;
  for (const auto& manager : mount_managers_) {
    error = manager->Unmount(path);
    if (error != MountError::kPathNotMounted)
      break;
  }

  LOG_IF(ERROR, error != MountError::kSuccess)
      << "Cannot unmount " << redact(path) << ": " << error;

  return static_cast<uint32_t>(error);
}

void CrosDisksServer::UnmountAll() {
  for (const auto& manager : mount_managers_) {
    manager->UnmountAll();
  }
}

std::vector<std::string> CrosDisksServer::EnumerateDevices() {
  std::vector<Disk> disks = disk_monitor_->EnumerateDisks();
  std::vector<std::string> devices;
  devices.reserve(disks.size());
  for (const auto& disk : disks) {
    devices.push_back(disk.native_path);
  }
  return devices;
}

CrosDisksServer::MountEntries CrosDisksServer::EnumerateMountEntries() {
  MountEntries entries;
  for (const MountManager* const manager : mount_managers_) {
    DCHECK(manager);
    for (const MountPoint* const mount_point : manager->GetMountPoints()) {
      DCHECK(mount_point);

      // Skip the in-progress mount points.
      if (mount_point->error() == MountError::kInProgress)
        continue;

      entries.emplace_back(static_cast<uint32_t>(mount_point->error()),
                           mount_point->source(), mount_point->source_type(),
                           mount_point->path().value(),
                           mount_point->is_read_only());
    }
  }

  return entries;
}

bool CrosDisksServer::GetDeviceProperties(
    brillo::ErrorPtr* error,
    const std::string& device_path,
    brillo::VariantDictionary* properties) {
  Disk disk;
  if (!disk_monitor_->GetDiskByDevicePath(base::FilePath(device_path), &disk)) {
    LOG(ERROR) << "Cannot get properties of " << quote(device_path);
    brillo::Error::AddTo(
        error, FROM_HERE, brillo::errors::dbus::kDomain, kCrosDisksServiceError,
        base::StrCat({"Cannot get properties of '", device_path, "'"}));
    return false;
  }

  brillo::VariantDictionary temp_properties;
  temp_properties[kIsAutoMountable] = disk.is_auto_mountable;
  temp_properties[kDeviceIsDrive] = disk.is_drive;
  temp_properties[kDevicePresentationHide] = disk.is_hidden;
  temp_properties[kDeviceIsMounted] = disk.IsMounted();
  temp_properties[kDeviceIsMediaAvailable] = disk.is_media_available;
  temp_properties[kDeviceIsOnBootDevice] = disk.is_on_boot_device;
  temp_properties[kDeviceIsOnRemovableDevice] = disk.is_on_removable_device;
  temp_properties[kDeviceIsVirtual] = disk.is_virtual;
  temp_properties[kStorageDevicePath] = disk.storage_device_path;
  temp_properties[kDeviceFile] = disk.device_file;
  temp_properties[kIdUuid] = disk.uuid;
  temp_properties[kIdLabel] = disk.label;
  temp_properties[kVendorId] = disk.vendor_id;
  temp_properties[kVendorName] = disk.vendor_name;
  temp_properties[kProductId] = disk.product_id;
  temp_properties[kProductName] = disk.product_name;
  temp_properties[kDriveModel] = disk.drive_model;
  temp_properties[kDeviceMediaType] = static_cast<uint32_t>(disk.media_type);
  temp_properties[kBusNumber] = disk.bus_number;
  temp_properties[kDeviceNumber] = disk.device_number;
  temp_properties[kDeviceSize] = disk.device_capacity;
  temp_properties[kDeviceIsReadOnly] = disk.is_read_only;
  temp_properties[kFileSystemType] = disk.filesystem_type;
  temp_properties[kDeviceMountPaths] = disk.mount_paths;
  *properties = std::move(temp_properties);
  return true;
}

void CrosDisksServer::AddDeviceToAllowlist(const std::string& device_path) {
  disk_monitor_->AddDeviceToAllowlist(base::FilePath(device_path));
}

void CrosDisksServer::RemoveDeviceFromAllowlist(
    const std::string& device_path) {
  disk_monitor_->RemoveDeviceFromAllowlist(base::FilePath(device_path));
}

void CrosDisksServer::OnFormatCompleted(const std::string& device_path,
                                        FormatError error) {
  SendFormatCompletedSignal(static_cast<uint32_t>(error), device_path);
}

void CrosDisksServer::OnPartitionCompleted(
    std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<uint32_t>> response,
    const base::FilePath& device_path,
    PartitionError error) {
  if (error == PartitionError::kSuccess) {
    LOG(INFO) << "Partitioned device " << quote(device_path);
  } else {
    LOG(ERROR) << "Cannot partition device " << quote(device_path) << ": "
               << error;
  }
  response->Return(static_cast<uint32_t>(error));
}

void CrosDisksServer::OnRenameCompleted(const std::string& device_path,
                                        RenameError error) {
  SendRenameCompletedSignal(static_cast<uint32_t>(error), device_path);
}

void CrosDisksServer::OnScreenIsLocked() {}

void CrosDisksServer::OnScreenIsUnlocked() {}

void CrosDisksServer::OnSessionStarted() {
  LOG(INFO) << "Starting session...";
  for (const auto& manager : mount_managers_) {
    manager->StartSession();
  }
}

void CrosDisksServer::OnSessionStopped() {
  LOG(INFO) << "Stopping session...";
  for (const auto& manager : mount_managers_) {
    manager->StopSession();
  }
}

void CrosDisksServer::DispatchDeviceEvent(const DeviceEvent& event) {
  LOG(INFO) << "Dispatching device event " << event;
  switch (event.event_type) {
    case DeviceEvent::kIgnored:
      break;
    case DeviceEvent::kDeviceAdded:
      SendDeviceAddedSignal(event.device_path);
      break;
    case DeviceEvent::kDeviceScanned:
      SendDeviceScannedSignal(event.device_path);
      break;
    case DeviceEvent::kDeviceRemoved:
      SendDeviceRemovedSignal(event.device_path);
      break;
    case DeviceEvent::kDiskAdded:
      SendDiskAddedSignal(event.device_path);
      break;
    case DeviceEvent::kDiskChanged:
      SendDiskChangedSignal(event.device_path);
      break;
    case DeviceEvent::kDiskRemoved:
      SendDiskRemovedSignal(event.device_path);
      break;
  }
}

}  // namespace cros_disks
