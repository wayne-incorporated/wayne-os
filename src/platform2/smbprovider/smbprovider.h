// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SMBPROVIDER_SMBPROVIDER_H_
#define SMBPROVIDER_SMBPROVIDER_H_

#include <memory>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/memory/weak_ptr.h>
#include <dbus_adaptors/org.chromium.SmbProvider.h>

#include "smbprovider/copy_progress_interface.h"
#include "smbprovider/id_map.h"
#include "smbprovider/iterator/caching_iterator.h"
#include "smbprovider/iterator/share_iterator.h"
#include "smbprovider/kerberos_artifact_synchronizer.h"
#include "smbprovider/mount_config.h"
#include "smbprovider/proto.h"
#include "smbprovider/proto_bindings/directory_entry.pb.h"
#include "smbprovider/read_dir_progress.h"
#include "smbprovider/smb_credential.h"
#include "smbprovider/smbprovider_helper.h"

using brillo::dbus_utils::AsyncEventSequencer;

namespace smbprovider {

class DirectoryEntryListProto;
class MountManager;
class PostDepthFirstIterator;
class SambaInterface;

// Helper method that reads shares on a host using a Share Iterator and outputs
// them to |out_entries|. Returns true on success and sets |error_code| on
// failure. |options| is used for logging purposes.
bool GetShareEntries(const GetSharesOptionsProto& options,
                     ShareIterator iterator,
                     int32_t* error_code,
                     ProtoBlob* out_entries);

// Implementation of smbprovider's DBus interface. Mostly routes stuff between
// DBus and samba_interface.
class SmbProvider : public org::chromium::SmbProviderAdaptor,
                    public org::chromium::SmbProviderInterface {
 public:
  using SetupKerberosCallback =
      std::unique_ptr<brillo::dbus_utils::DBusMethodResponse<bool>>;

  SmbProvider(std::unique_ptr<brillo::dbus_utils::DBusObject> dbus_object,
              std::unique_ptr<MountManager> mount_manager,
              std::unique_ptr<KerberosArtifactSynchronizer>
                  kerberos_artifact_synchronizer,
              const base::FilePath& daemon_store_directory);
  SmbProvider(const SmbProvider&) = delete;
  SmbProvider& operator=(const SmbProvider&) = delete;

  void GetShares(const ProtoBlob& options_blob,
                 int32_t* error_code,
                 ProtoBlob* shares) override;

  void SetupKerberos(SetupKerberosCallback callback,
                     const std::string& account_identifier) override;

  ProtoBlob ParseNetBiosPacket(const std::vector<uint8_t>& packet,
                               uint16_t transaction_id) override;

  // Register DBus object and interfaces.
  void RegisterAsync(AsyncEventSequencer::CompletionAction completion_callback);

 private:
  // Returns a pointer to the SambaInterface corresponding to |mount_id|.
  SambaInterface* GetSambaInterface(int32_t mount_id) const;

  // Uses |options| to create the full path based on the mount id and entry path
  // supplied in |options|. |full_path| will be unmodified on failure.
  template <typename Proto>
  bool GetFullPath(const Proto* options, std::string* full_path) const;

  // Parses the raw contents of |blob| into |options| and validates that
  // the required fields are all correctly set.
  // |full_path| will contain the full path, including the mount root, based
  // on the mount id and entry path supplied in |options|.
  // On failure |error_code| will be populated and |options| and |full_path|
  // are undefined.
  template <typename Proto>
  bool ParseOptionsAndPath(const ProtoBlob& blob,
                           Proto* options,
                           std::string* full_path,
                           int32_t* error_code);

  // Reads the shares on a host and outputs the shares in |out_entries|.
  // |options_blob| is used as input for the ShareIterator. |error_code| is set
  // on failure.
  void ReadShareEntries(const ProtoBlob& options_blob,
                        int32_t* error_code,
                        ProtoBlob* out_entries);

  // Callback handler for SetupKerberos.
  void HandleSetupKerberosResponse(SetupKerberosCallback callback, bool result);

  // Creates a HostnamesProto from a list of |hostnames|.
  HostnamesProto BuildHostnamesProto(
      const std::vector<std::string>& hostnames) const;

  std::unique_ptr<brillo::dbus_utils::DBusObject> dbus_object_;
  std::unique_ptr<MountManager> mount_manager_;
  std::unique_ptr<KerberosArtifactSynchronizer> kerberos_artifact_synchronizer_;
};

}  // namespace smbprovider

#endif  // SMBPROVIDER_SMBPROVIDER_H_
