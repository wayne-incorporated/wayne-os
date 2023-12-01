// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "mtpd/mtpd_server_impl.h"

#include <utility>

#include <base/containers/contains.h>
#include <base/location.h>
#include <base/logging.h>
#include <base/rand_util.h>
#include <base/strings/string_number_conversions.h>
#include <chromeos/dbus/service_constants.h>

namespace mtpd {

namespace {

// Maximum number of bytes to read from the device at one time. This is set low
// enough such that a reasonable device can read this much data before D-Bus
// times out.
const uint32_t kMaxReadCount = 1024 * 1024;

void AddError(brillo::ErrorPtr* error,
              const base::Location& location,
              const std::string& message) {
  brillo::Error::AddTo(error, location, brillo::errors::dbus::kDomain,
                       kMtpdServiceError, message);
}

void AddInvalidHandleError(brillo::ErrorPtr* error,
                           const base::Location& location,
                           const std::string& handle) {
  brillo::Error::AddToPrintf(error, location, brillo::errors::dbus::kDomain,
                             kMtpdServiceError, "Invalid handle %s",
                             handle.c_str());
}

}  // namespace

MtpdServer::MtpdServer(scoped_refptr<dbus::Bus> bus)
    : org::chromium::MtpdAdaptor(this),
      dbus_object_(nullptr, bus, dbus::ObjectPath(kMtpdServicePath)),
      device_manager_(this) {}

MtpdServer::~MtpdServer() {}

std::vector<std::string> MtpdServer::EnumerateStorages() {
  return device_manager_.EnumerateStorages();
}

std::vector<uint8_t> MtpdServer::GetStorageInfo(
    const std::string& storage_name) {
  const StorageInfo* info = device_manager_.GetStorageInfo(storage_name);
  return info ? info->ToDBusFormat() : StorageInfo().ToDBusFormat();
}

std::vector<uint8_t> MtpdServer::GetStorageInfoFromDevice(
    const std::string& storage_name) {
  const StorageInfo* info =
      device_manager_.GetStorageInfoFromDevice(storage_name);
  return info ? info->ToDBusFormat() : StorageInfo().ToDBusFormat();
}

bool MtpdServer::OpenStorage(brillo::ErrorPtr* error,
                             const std::string& storage_name,
                             const std::string& mode,
                             std::string* id) {
  if (!(mode == kReadOnlyMode || mode == kReadWriteMode)) {
    brillo::Error::AddToPrintf(error, FROM_HERE, brillo::errors::dbus::kDomain,
                               kMtpdServiceError, "Cannot open %s in mode: %s",
                               storage_name.c_str(), mode.c_str());
    return false;
  }

  if (!device_manager_.HasStorage(storage_name)) {
    brillo::Error::AddToPrintf(
        error, FROM_HERE, brillo::errors::dbus::kDomain, kMtpdServiceError,
        "Cannot open unknown storage %s", storage_name.c_str());
    return false;
  }

  std::string new_id;
  uint32_t random_data[4];
  do {
    base::RandBytes(random_data, sizeof(random_data));
    new_id = base::HexEncode(random_data, sizeof(random_data));
  } while (base::Contains(handle_map_, new_id));

  handle_map_.insert(
      std::make_pair(new_id, std::make_pair(storage_name, mode)));
  *id = new_id;
  return true;
}

bool MtpdServer::CloseStorage(brillo::ErrorPtr* error,
                              const std::string& handle) {
  if (handle_map_.erase(handle) == 0) {
    AddInvalidHandleError(error, FROM_HERE, handle);
    return false;
  }

  return true;
}

bool MtpdServer::ReadDirectoryEntryIds(
    brillo::ErrorPtr* error,
    const std::string& handle,
    uint32_t file_id,
    std::vector<uint32_t>* directory_listing) {
  std::string storage_name = LookupHandle(handle);
  if (storage_name.empty()) {
    AddInvalidHandleError(error, FROM_HERE, handle);
    return false;
  }

  if (!device_manager_.ReadDirectoryEntryIds(storage_name, file_id,
                                             directory_listing)) {
    AddError(error, FROM_HERE, "ReadDirectoryEntryIds failed");
    return false;
  }

  return true;
}

bool MtpdServer::GetFileInfo(brillo::ErrorPtr* error,
                             const std::string& handle,
                             const std::vector<uint32_t>& file_ids,
                             std::vector<uint8_t>* serialized_file_entries) {
  if (file_ids.empty()) {
    AddError(error, FROM_HERE, "GetFileInfo called with no file ids");
    return false;
  }

  std::string storage_name = LookupHandle(handle);
  if (storage_name.empty()) {
    AddInvalidHandleError(error, FROM_HERE, handle);
    return false;
  }

  std::vector<FileEntry> file_info;
  if (!device_manager_.GetFileInfo(storage_name, file_ids, &file_info)) {
    AddError(error, FROM_HERE, "GetFileInfo failed");
    return false;
  }

  *serialized_file_entries = FileEntry::FileEntriesToDBusFormat(file_info);
  return true;
}

bool MtpdServer::ReadFileChunk(brillo::ErrorPtr* error,
                               const std::string& handle,
                               uint32_t file_id,
                               uint32_t offset,
                               uint32_t count,
                               std::vector<uint8_t>* file_contents) {
  if (count > kMaxReadCount || count == 0) {
    AddError(error, FROM_HERE, "Invalid count for ReadFileChunk");
    return false;
  }
  std::string storage_name = LookupHandle(handle);
  if (storage_name.empty()) {
    AddInvalidHandleError(error, FROM_HERE, handle);
    return false;
  }

  if (!device_manager_.ReadFileChunk(storage_name, file_id, offset, count,
                                     file_contents)) {
    AddError(error, FROM_HERE, "ReadFileChunk failed");
    return false;
  }

  return true;
}

bool MtpdServer::CopyFileFromLocal(brillo::ErrorPtr* error,
                                   const std::string& handle,
                                   const base::ScopedFD& file_descriptor,
                                   uint32_t parent_id,
                                   const std::string& file_name) {
  const std::string storage_name = LookupHandle(handle);
  if (storage_name.empty() || !IsOpenedWithWrite(handle)) {
    AddInvalidHandleError(error, FROM_HERE, handle);
    return false;
  }

  if (!device_manager_.CopyFileFromLocal(storage_name, file_descriptor.get(),
                                         parent_id, file_name)) {
    AddError(error, FROM_HERE, "CopyFileFromLocal failed");
    return false;
  }

  return true;
}

bool MtpdServer::DeleteObject(brillo::ErrorPtr* error,
                              const std::string& handle,
                              uint32_t object_id) {
  const std::string storage_name = LookupHandle(handle);
  if (storage_name.empty() || !IsOpenedWithWrite(handle)) {
    AddInvalidHandleError(error, FROM_HERE, handle);
    return false;
  }

  if (!device_manager_.DeleteObject(storage_name, object_id)) {
    AddError(error, FROM_HERE, "DeleteObject failed");
    return false;
  }

  return true;
}

bool MtpdServer::RenameObject(brillo::ErrorPtr* error,
                              const std::string& handle,
                              uint32_t object_id,
                              const std::string& new_name) {
  const std::string storage_name = LookupHandle(handle);
  if (storage_name.empty() || !IsOpenedWithWrite(handle)) {
    AddInvalidHandleError(error, FROM_HERE, handle);
    return false;
  }

  if (!device_manager_.RenameObject(storage_name, object_id, new_name)) {
    AddError(error, FROM_HERE, "RenameObject failed");
    return false;
  }

  return true;
}

bool MtpdServer::CreateDirectory(brillo::ErrorPtr* error,
                                 const std::string& handle,
                                 uint32_t parent_id,
                                 const std::string& directory_name) {
  const std::string storage_name = LookupHandle(handle);
  if (storage_name.empty() || !IsOpenedWithWrite(handle)) {
    AddInvalidHandleError(error, FROM_HERE, handle);
    return false;
  }

  if (!device_manager_.CreateDirectory(storage_name, parent_id,
                                       directory_name)) {
    AddError(error, FROM_HERE, "CreateDirectory failed.");
    return false;
  }

  return true;
}

bool MtpdServer::IsAlive() {
  return true;
}

void MtpdServer::StorageAttached(const std::string& storage_name) {
  // Fire DBus signal.
  SendMTPStorageAttachedSignal(storage_name);
}

void MtpdServer::StorageDetached(const std::string& storage_name) {
  // Fire DBus signal.
  SendMTPStorageDetachedSignal(storage_name);
}

int MtpdServer::GetDeviceEventDescriptor() const {
  return device_manager_.GetDeviceEventDescriptor();
}

void MtpdServer::ProcessDeviceEvents() {
  device_manager_.ProcessDeviceEvents();
}

std::string MtpdServer::LookupHandle(const std::string& handle) {
  HandleMap::const_iterator it = handle_map_.find(handle);
  return (it == handle_map_.end()) ? std::string() : it->second.first;
}

bool MtpdServer::IsOpenedWithWrite(const std::string& handle) {
  HandleMap::const_iterator it = handle_map_.find(handle);
  return (it == handle_map_.end()) ? false
                                   : it->second.second == kReadWriteMode;
}

void MtpdServer::RegisterAsync(
    brillo::dbus_utils::AsyncEventSequencer::CompletionAction cb) {
  RegisterWithDBusObject(&dbus_object_);
  dbus_object_.RegisterAsync(std::move(cb));
}

}  // namespace mtpd
