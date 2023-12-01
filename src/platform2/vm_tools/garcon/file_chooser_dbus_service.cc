// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/garcon/file_chooser_dbus_service.h"

#include <map>
#include <string>
#include <utility>
#include <vector>

#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/memory/ptr_util.h>
#include "vm_tools/garcon/host_notifier.h"

namespace {

const char kPortalServiceName[] = "org.freedesktop.impl.portal.desktop.cros";
const char kPortalInterfaceName[] = "org.freedesktop.impl.portal.FileChooser";
const char kPortalServicePath[] = "/org/freedesktop/portal/desktop";

void HandleSynchronousDBusMethodCall(
    base::RepeatingCallback<std::unique_ptr<dbus::Response>(dbus::MethodCall*)>
        handler,
    dbus::MethodCall* method_call,
    dbus::ExportedObject::ResponseSender response_sender) {
  auto response = handler.Run(method_call);
  if (!response)
    response = dbus::Response::FromMethodCall(method_call);

  std::move(response_sender).Run(std::move(response));
}

}  // namespace

namespace vm_tools {
namespace garcon {

FileChooserDBusService::FileChooserDBusService(
    vm_tools::garcon::HostNotifier* host_notifier)
    : host_notifier_(host_notifier) {}

// static
std::unique_ptr<FileChooserDBusService> FileChooserDBusService::Create(
    vm_tools::garcon::HostNotifier* host_notifier) {
  auto service = base::WrapUnique(new FileChooserDBusService(host_notifier));

  if (!service->Init())
    return nullptr;

  return service;
}

bool FileChooserDBusService::Init() {
  dbus::Bus::Options options;
  bus_ = new dbus::Bus(options);

  if (!bus_->Connect()) {
    LOG(ERROR) << "Failed to connect to session bus";
    return false;
  }

  exported_object_ =
      bus_->GetExportedObject(dbus::ObjectPath(kPortalServicePath));
  if (!exported_object_) {
    LOG(ERROR) << "Failed to export " << kPortalServicePath << " object";
    return false;
  }

  if (!RegisterMethods()) {
    LOG(ERROR) << "Failed to export methods";
    return false;
  }

  if (!bus_->RequestOwnershipAndBlock(kPortalServiceName,
                                      dbus::Bus::REQUIRE_PRIMARY)) {
    LOG(ERROR) << "Unable to take ownership of " << kPortalServiceName;
    return false;
  }

  return true;
}

bool FileChooserDBusService::RegisterMethods() {
  using ServiceMethod = std::unique_ptr<dbus::Response> (
      FileChooserDBusService::*)(dbus::MethodCall*);
  const std::map<const char*, ServiceMethod> kServiceMethods = {
      {"OpenFile", &FileChooserDBusService::OpenFile},
      {"SaveFile", &FileChooserDBusService::SaveFile},
      {"SaveFiles", &FileChooserDBusService::SaveFiles},
  };

  for (const auto& iter : kServiceMethods) {
    const bool ret = exported_object_->ExportMethodAndBlock(
        kPortalInterfaceName, iter.first,
        base::BindRepeating(
            &HandleSynchronousDBusMethodCall,
            base::BindRepeating(iter.second, base::Unretained(this))));
    if (!ret) {
      LOG(ERROR) << "Failed to export method " << iter.first;
      return false;
    }
  }

  return true;
}

std::unique_ptr<dbus::Response> FileChooserDBusService::OpenFile(
    dbus::MethodCall* method_call) {
  return SelectFile(method_call, "open-file");
}

std::unique_ptr<dbus::Response> FileChooserDBusService::SaveFile(
    dbus::MethodCall* method_call) {
  return SelectFile(method_call, "saveas-file");
}

std::unique_ptr<dbus::Response> FileChooserDBusService::SaveFiles(
    dbus::MethodCall* method_call) {
  return SelectFile(method_call, "saveas-file");
}

std::unique_ptr<dbus::Response> FileChooserDBusService::SelectFile(
    dbus::MethodCall* method_call, const std::string& type) {
  dbus::MessageReader reader(method_call);
  std::string app_id;
  reader.PopString(&app_id);
  std::string reason;
  reader.PopString(&reason);
  std::string parent_window;
  reader.PopString(&parent_window);
  std::string title;
  reader.PopString(&title);

  std::string default_path;
  std::string allowed_extensions;
  std::vector<std::string> files;

  std::unique_ptr<dbus::Response> dbus_response(
      dbus::Response::FromMethodCall(method_call));
  dbus::MessageWriter writer(dbus_response.get());

  if (!host_notifier_->SelectFile(type, title, default_path, allowed_extensions,
                                  &files)) {
    writer.AppendUint32(1);  // error
    return dbus_response;
  }

  writer.AppendUint32(0);  // success

  dbus::MessageWriter array_writer(nullptr);
  dbus::MessageWriter dict_entry_writer(nullptr);
  dbus::MessageWriter array_of_strings_writer(nullptr);

  writer.OpenArray("{sv}", &array_writer);

  array_writer.OpenDictEntry(&dict_entry_writer);
  dict_entry_writer.AppendString("uris");
  dict_entry_writer.OpenVariant("as", &array_of_strings_writer);
  array_of_strings_writer.AppendArrayOfStrings(files);
  dict_entry_writer.CloseContainer(&array_of_strings_writer);
  array_writer.CloseContainer(&dict_entry_writer);

  array_writer.OpenDictEntry(&dict_entry_writer);
  dict_entry_writer.AppendString("writable");
  dict_entry_writer.AppendVariantOfBool(true);
  array_writer.CloseContainer(&dict_entry_writer);

  writer.CloseContainer(&array_writer);
  return dbus_response;
}

}  // namespace garcon
}  // namespace vm_tools
