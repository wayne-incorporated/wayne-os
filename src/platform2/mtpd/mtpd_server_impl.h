// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MTPD_MTPD_SERVER_IMPL_H_
#define MTPD_MTPD_SERVER_IMPL_H_

#include <map>
#include <string>
#include <utility>
#include <vector>

#include <base/compiler_specific.h>
#include <brillo/dbus/async_event_sequencer.h>
#include <brillo/dbus/dbus_object.h>
#include <brillo/errors/error.h>
#include <dbus/bus.h>

#include "mtpd/dbus_adaptors/org.chromium.Mtpd.h"
#include "mtpd/device_event_delegate.h"
#include "mtpd/device_manager.h"
#include "mtpd/file_entry.h"

namespace mtpd {

class DeviceManager;

// The D-bus server for the mtpd daemon.
class MtpdServer : public org::chromium::MtpdInterface,
                   public org::chromium::MtpdAdaptor,
                   public DeviceEventDelegate {
 public:
  explicit MtpdServer(scoped_refptr<dbus::Bus> bus);
  MtpdServer(const MtpdServer&) = delete;
  MtpdServer& operator=(const MtpdServer&) = delete;

  virtual ~MtpdServer();

  // org::chromium::MtpdAdaptor implementation.
  std::vector<std::string> EnumerateStorages() override;
  std::vector<uint8_t> GetStorageInfo(const std::string& storage_name) override;
  std::vector<uint8_t> GetStorageInfoFromDevice(
      const std::string& storage_name) override;
  bool OpenStorage(brillo::ErrorPtr* error,
                   const std::string& storage_name,
                   const std::string& mode,
                   std::string* id) override;
  bool CloseStorage(brillo::ErrorPtr* error,
                    const std::string& handle) override;
  bool ReadDirectoryEntryIds(brillo::ErrorPtr* error,
                             const std::string& handle,
                             uint32_t file_id,
                             std::vector<uint32_t>* directory_listing) override;
  bool GetFileInfo(brillo::ErrorPtr* error,
                   const std::string& handle,
                   const std::vector<uint32_t>& file_ids,
                   std::vector<uint8_t>* serialized_file_entries) override;
  bool ReadFileChunk(brillo::ErrorPtr* error,
                     const std::string& handle,
                     uint32_t file_id,
                     uint32_t offset,
                     uint32_t count,
                     std::vector<uint8_t>* file_contents) override;
  bool CopyFileFromLocal(brillo::ErrorPtr* error,
                         const std::string& handle,
                         const base::ScopedFD& file_descriptor,
                         uint32_t parent_id,
                         const std::string& file_name) override;
  bool DeleteObject(brillo::ErrorPtr* error,
                    const std::string& handle,
                    uint32_t object_id) override;
  bool RenameObject(brillo::ErrorPtr* error,
                    const std::string& handle,
                    uint32_t object_id,
                    const std::string& new_name) override;
  bool CreateDirectory(brillo::ErrorPtr* error,
                       const std::string& handle,
                       uint32_t parent_id,
                       const std::string& directory_name) override;
  bool IsAlive() override;

  // DeviceEventDelegate implementation.
  void StorageAttached(const std::string& storage_name) override;
  void StorageDetached(const std::string& storage_name) override;

  // Returns a file descriptor for monitoring device events.
  int GetDeviceEventDescriptor() const;

  // Processes the available device events.
  void ProcessDeviceEvents();

  // Register D-Bus object.
  void RegisterAsync(
      brillo::dbus_utils::AsyncEventSequencer::CompletionAction cb);

 private:
  // StorageHandleInfo is a pair of StorageName and Mode.
  using StorageHandleInfo = std::pair<std::string, std::string>;

  // Handle to StorageHandleInfo map.
  using HandleMap = std::map<std::string, StorageHandleInfo>;

  // Returns the StorageName for a handle, or an empty string on failure.
  std::string LookupHandle(const std::string& handle);

  // Returns true if the storage is opened with write access.
  bool IsOpenedWithWrite(const std::string& handle);

  HandleMap handle_map_;

  // Exported D-Bus object.
  brillo::dbus_utils::DBusObject dbus_object_;

  // Device manager needs to be last, so it is the first to be destroyed.
  DeviceManager device_manager_;
};

}  // namespace mtpd

#endif  // MTPD_MTPD_SERVER_IMPL_H_
