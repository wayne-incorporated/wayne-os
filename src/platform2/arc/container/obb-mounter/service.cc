// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/container/obb-mounter/service.h"

#include <string>
#include <utility>
#include <vector>

#include <base/files/file_path.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/strings/string_util.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/bus.h>
#include <dbus/message.h>

#include "arc/container/obb-mounter/mount.h"

namespace arc {
namespace obb_mounter {

namespace {

bool IsValidObbMountPath(const base::FilePath& path) {
  // OBB mount path should look like /var/run/arc/obb/obb:1.
  std::vector<std::string> components = path.GetComponents();
  return components.size() == 6 && components[0] == "/" &&
         components[1] == "var" && components[2] == "run" &&
         components[3] == "arc" && components[4] == "obb" &&
         base::StartsWith(components[5], "obb:");
}

}  // namespace

Service::Service() : weak_ptr_factory_(this) {}

Service::~Service() {
  if (bus_) {
    bus_->ShutdownAndBlock();
  }
}

bool Service::Initialize(scoped_refptr<dbus::Bus> bus) {
  bus_ = bus;
  // Export methods.
  exported_object_ =
      bus->GetExportedObject(dbus::ObjectPath(kArcObbMounterServicePath));
  if (!exported_object_->ExportMethodAndBlock(
          kArcObbMounterInterface, kMountObbMethod,
          base::BindRepeating(&Service::MountObb,
                              weak_ptr_factory_.GetWeakPtr()))) {
    LOG(ERROR) << "Failed to export MountObb method.";
    return false;
  }
  if (!exported_object_->ExportMethodAndBlock(
          kArcObbMounterInterface, kUnmountObbMethod,
          base::BindRepeating(&Service::UnmountObb,
                              weak_ptr_factory_.GetWeakPtr()))) {
    LOG(ERROR) << "Failed to export UnmountObb method.";
    return false;
  }
  // Request the ownership of the service name.
  if (!bus->RequestOwnershipAndBlock(kArcObbMounterServiceName,
                                     dbus::Bus::REQUIRE_PRIMARY)) {
    LOG(ERROR) << "Failed to own the service name";
    return false;
  }
  return true;
}

void Service::MountObb(dbus::MethodCall* method_call,
                       dbus::ExportedObject::ResponseSender response_sender) {
  dbus::MessageReader reader(method_call);
  std::string obb_file, mount_path;
  int32_t owner_gid = 0;
  if (!reader.PopString(&obb_file) || !reader.PopString(&mount_path) ||
      !reader.PopInt32(&owner_gid) || reader.HasMoreData()) {
    std::move(response_sender)
        .Run(dbus::ErrorResponse::FromMethodCall(
            method_call, DBUS_ERROR_INVALID_ARGS, std::string()));
    return;
  }
  if (!IsValidObbMountPath(base::FilePath(mount_path))) {
    std::move(response_sender)
        .Run(dbus::ErrorResponse::FromMethodCall(
            method_call, DBUS_ERROR_INVALID_ARGS, std::string()));
    return;
  }
  if (!obb_mounter::MountObb(obb_file, mount_path, owner_gid)) {
    std::move(response_sender)
        .Run(dbus::ErrorResponse::FromMethodCall(method_call, DBUS_ERROR_FAILED,
                                                 std::string()));
    return;
  }
  std::move(response_sender).Run(dbus::Response::FromMethodCall(method_call));
}

void Service::UnmountObb(dbus::MethodCall* method_call,
                         dbus::ExportedObject::ResponseSender response_sender) {
  dbus::MessageReader reader(method_call);
  std::string mount_path;
  if (!reader.PopString(&mount_path) || reader.HasMoreData()) {
    std::move(response_sender)
        .Run(dbus::ErrorResponse::FromMethodCall(
            method_call, DBUS_ERROR_INVALID_ARGS, std::string()));
    return;
  }
  if (!IsValidObbMountPath(base::FilePath(mount_path))) {
    std::move(response_sender)
        .Run(dbus::ErrorResponse::FromMethodCall(
            method_call, DBUS_ERROR_INVALID_ARGS, std::string()));
    return;
  }
  if (!obb_mounter::UnmountObb(mount_path)) {
    std::move(response_sender)
        .Run(dbus::ErrorResponse::FromMethodCall(method_call, DBUS_ERROR_FAILED,
                                                 std::string()));
    return;
  }
  std::move(response_sender).Run(dbus::Response::FromMethodCall(method_call));
}

}  // namespace obb_mounter
}  // namespace arc
