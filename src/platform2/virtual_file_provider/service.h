// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VIRTUAL_FILE_PROVIDER_SERVICE_H_
#define VIRTUAL_FILE_PROVIDER_SERVICE_H_

#include <string>

#include <base/files/file_path.h>
#include <base/files/scoped_file.h>
#include <base/memory/weak_ptr.h>
#include <base/threading/thread_checker.h>
#include <dbus/exported_object.h>

#include "virtual_file_provider/size_map.h"

namespace dbus {
class Bus;
class MethodCall;
class ObjectProxy;
}  // namespace dbus

namespace virtual_file_provider {

// This class handles incoming D-Bus method calls.
class Service {
 public:
  Service(const base::FilePath& fuse_mount_path, SizeMap* size_map);
  Service(const Service&) = delete;
  Service& operator=(const Service&) = delete;

  ~Service();

  // Exports D-Bus methods via the system bus and requests the ownership of the
  // service name.
  bool Initialize();

  // Sends read request with the given parameters.
  // Chrome is responsible for feeding the data to the FD.
  void SendReadRequest(const std::string& id,
                       int64_t offset,
                       int64_t size,
                       base::ScopedFD fd);

  // Sends a released ID. Chrome is responsible for releasing resources
  // associated with the ID.
  void SendIdReleased(const std::string& id);

  // Returns true if the given string is a valid virtual file ID.
  static bool IsValidVirtualFileId(const std::string& id);

 private:
  // Handles GenerateVirtualFileId D-Bus method call.
  // Generates and returns an ID, to be used for FD creation on the FUSE file
  // system at a later stage. This ID is registered in the |size_map_|.
  void GenerateVirtualFileId(
      dbus::MethodCall* method_call,
      dbus::ExportedObject::ResponseSender response_sender);

  // Handles OpenFileById D-Bus method call.
  // Given an ID, creates and returns a seekable FD backed by the FUSE file
  // system.
  void OpenFileById(dbus::MethodCall* method_call,
                    dbus::ExportedObject::ResponseSender response_sender);

  const base::FilePath fuse_mount_path_;
  SizeMap* const size_map_;
  scoped_refptr<dbus::Bus> bus_;
  dbus::ExportedObject* exported_object_ = nullptr;
  dbus::ObjectProxy* request_handler_proxy_ = nullptr;

  base::ThreadChecker thread_checker_;

  base::WeakPtrFactory<Service> weak_ptr_factory_;
};

}  // namespace virtual_file_provider

#endif  // VIRTUAL_FILE_PROVIDER_SERVICE_H_
