// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "virtual_file_provider/service.h"

#include <fcntl.h>
#include <unistd.h>
#include <memory>
#include <string>
#include <utility>

#include <base/check.h>
#include <base/check_op.h>
#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <base/logging.h>
#include <base/posix/eintr_wrapper.h>
#include <base/uuid.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/bus.h>
#include <dbus/message.h>
#include <dbus/object_proxy.h>

namespace virtual_file_provider {

Service::Service(const base::FilePath& fuse_mount_path, SizeMap* size_map)
    : fuse_mount_path_(fuse_mount_path),
      size_map_(size_map),
      weak_ptr_factory_(this) {
  thread_checker_.DetachFromThread();
}

Service::~Service() {
  DCHECK(thread_checker_.CalledOnValidThread());
  if (bus_)
    bus_->ShutdownAndBlock();
}

bool Service::Initialize() {
  DCHECK(thread_checker_.CalledOnValidThread());
  // Connect the bus.
  dbus::Bus::Options options;
  options.bus_type = dbus::Bus::SYSTEM;
  bus_ = new dbus::Bus(options);
  if (!bus_->Connect()) {
    LOG(ERROR) << "Failed to initialize D-Bus connection.";
    return false;
  }
  request_handler_proxy_ = bus_->GetObjectProxy(
      chromeos::kVirtualFileRequestServiceName,
      dbus::ObjectPath(chromeos::kVirtualFileRequestServicePath));
  // Export methods.
  exported_object_ = bus_->GetExportedObject(
      dbus::ObjectPath(kVirtualFileProviderServicePath));
  if (!exported_object_->ExportMethodAndBlock(
          kVirtualFileProviderInterface, kGenerateVirtualFileIdMethod,
          base::BindRepeating(&Service::GenerateVirtualFileId,
                              weak_ptr_factory_.GetWeakPtr()))) {
    LOG(ERROR) << "Failed to export GenerateVirtualFileId method.";
    return false;
  }
  if (!exported_object_->ExportMethodAndBlock(
          kVirtualFileProviderInterface, kOpenFileByIdMethod,
          base::BindRepeating(&Service::OpenFileById,
                              weak_ptr_factory_.GetWeakPtr()))) {
    LOG(ERROR) << "Failed to export OpenFileById method.";
    return false;
  }
  // Request the ownership of the service name.
  if (!bus_->RequestOwnershipAndBlock(kVirtualFileProviderServiceName,
                                      dbus::Bus::REQUIRE_PRIMARY)) {
    LOG(ERROR) << "Failed to own the service name";
    return false;
  }
  return true;
}

void Service::SendReadRequest(const std::string& id,
                              int64_t offset,
                              int64_t size,
                              base::ScopedFD fd) {
  DCHECK(thread_checker_.CalledOnValidThread());
  dbus::MethodCall method_call(
      chromeos::kVirtualFileRequestServiceInterface,
      chromeos::kVirtualFileRequestServiceHandleReadRequestMethod);

  dbus::MessageWriter writer(&method_call);
  writer.AppendString(id);
  writer.AppendInt64(offset);
  writer.AppendInt64(size);
  writer.AppendFileDescriptor(fd.get());
  request_handler_proxy_->CallMethod(
      &method_call, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT, base::DoNothing());
}

void Service::SendIdReleased(const std::string& id) {
  DCHECK(thread_checker_.CalledOnValidThread());
  dbus::MethodCall method_call(
      chromeos::kVirtualFileRequestServiceInterface,
      chromeos::kVirtualFileRequestServiceHandleIdReleasedMethod);

  dbus::MessageWriter writer(&method_call);
  writer.AppendString(id);
  request_handler_proxy_->CallMethod(
      &method_call, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT, base::DoNothing());
}

// static
bool Service::IsValidVirtualFileId(const std::string& id) {
  return base::Uuid::ParseCaseInsensitive(id).is_valid();
}

void Service::GenerateVirtualFileId(
    dbus::MethodCall* method_call,
    dbus::ExportedObject::ResponseSender response_sender) {
  DCHECK(thread_checker_.CalledOnValidThread());

  dbus::MessageReader reader(method_call);
  int64_t size = 0;
  if (!reader.PopInt64(&size)) {
    std::move(response_sender)
        .Run(dbus::ErrorResponse::FromMethodCall(
            method_call, DBUS_ERROR_INVALID_ARGS, "Size must be provided."));
    return;
  }
  // Generate a new ID.
  std::string id = base::Uuid::GenerateRandomV4().AsLowercaseString();

  // Set the size of the ID.
  // NOTE: Currently, updating the size value is not supported. If the virtual
  // file gets modified later, the size map's value can contradict with the real
  // value and it can result in read errors.
  CHECK_EQ(-1, size_map_->GetSize(id));
  size_map_->SetSize(id, size);

  // Send response.
  std::unique_ptr<dbus::Response> response =
      dbus::Response::FromMethodCall(method_call);
  dbus::MessageWriter writer(response.get());
  writer.AppendString(std::move(id));
  std::move(response_sender).Run(std::move(response));
}

void Service::OpenFileById(
    dbus::MethodCall* method_call,
    dbus::ExportedObject::ResponseSender response_sender) {
  DCHECK(thread_checker_.CalledOnValidThread());

  dbus::MessageReader reader(method_call);
  std::string id;
  if (!reader.PopString(&id) || !IsValidVirtualFileId(id)) {
    LOG(ERROR) << "No valid ID was provided. id = " << id;
    std::move(response_sender)
        .Run(dbus::ErrorResponse::FromMethodCall(method_call,
                                                 DBUS_ERROR_INVALID_ARGS,
                                                 "Valid ID must be provided."));
    return;
  }

  // An ID corresponds to a file name in the FUSE file system.
  base::FilePath path = fuse_mount_path_.AppendASCII(std::move(id));

  // Create a new FD associated with the ID.
  base::ScopedFD fd(
      HANDLE_EINTR(open(path.value().c_str(), O_RDONLY | O_CLOEXEC)));
  if (!fd.is_valid()) {
    std::move(response_sender)
        .Run(dbus::ErrorResponse::FromMethodCall(
            method_call, DBUS_ERROR_INVALID_ARGS, "Invalid Id."));
    return;
  }

  // Send response.
  std::unique_ptr<dbus::Response> response =
      dbus::Response::FromMethodCall(method_call);
  dbus::MessageWriter writer(response.get());
  writer.AppendFileDescriptor(fd.get());
  std::move(response_sender).Run(std::move(response));
}

}  // namespace virtual_file_provider
