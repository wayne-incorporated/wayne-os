// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_GARCON_FILE_CHOOSER_DBUS_SERVICE_H_
#define VM_TOOLS_GARCON_FILE_CHOOSER_DBUS_SERVICE_H_

#include <memory>
#include <string>

#include <dbus/bus.h>
#include <dbus/exported_object.h>
#include <dbus/message.h>

#include "vm_tools/garcon/host_notifier.h"

namespace vm_tools {
namespace garcon {

class FileChooserDBusService {
 public:
  ~FileChooserDBusService() = default;

  static std::unique_ptr<FileChooserDBusService> Create(
      vm_tools::garcon::HostNotifier* host_notifier);

 private:
  explicit FileChooserDBusService(
      vm_tools::garcon::HostNotifier* host_notifier);
  FileChooserDBusService(const FileChooserDBusService&) = delete;
  FileChooserDBusService& operator=(const FileChooserDBusService&) = delete;

  bool Init();
  bool RegisterMethods();

  std::unique_ptr<dbus::Response> OpenFile(dbus::MethodCall* method_call);
  std::unique_ptr<dbus::Response> SaveFile(dbus::MethodCall* method_call);
  std::unique_ptr<dbus::Response> SaveFiles(dbus::MethodCall* method_call);
  std::unique_ptr<dbus::Response> SelectFile(dbus::MethodCall* method_call,
                                             const std::string& type);

  scoped_refptr<dbus::Bus> bus_;
  dbus::ExportedObject* exported_object_ = nullptr;  // Owned by |bus_|.
  vm_tools::garcon::HostNotifier* host_notifier_ = nullptr;
};

}  // namespace garcon
}  // namespace vm_tools

#endif  // VM_TOOLS_GARCON_FILE_CHOOSER_DBUS_SERVICE_H_
