// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SMBPROVIDER_MOUNT_TRACKER_H_
#define SMBPROVIDER_MOUNT_TRACKER_H_

#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>

#include <base/functional/callback.h>
#include <base/time/tick_clock.h>
#include <libpasswordprovider/password.h>

#include "smbprovider/constants.h"
#include "smbprovider/id_map.h"
#include "smbprovider/metadata_cache.h"
#include "smbprovider/samba_interface.h"
#include "smbprovider/smb_credential.h"
#include "smbprovider/smbprovider_helper.h"

namespace smbprovider {

class MountTracker {
 public:
  MountTracker(std::unique_ptr<base::TickClock> tick_clock,
               bool metadata_cache_enabled);
  MountTracker(const MountTracker&) = delete;
  MountTracker& operator=(const MountTracker&) = delete;

  ~MountTracker();

  // Returns true if |mount_id| is already mounted.
  bool IsAlreadyMounted(int32_t mount_id) const;

  // Return true if |samba_interface_id| is already mounted.
  bool IsAlreadyMounted(
      const SambaInterface::SambaInterfaceId samba_interface_id) const;

  // Adds |mount_root| to the |mounts_| map and adds SambaInterfaceId to
  // |samba_interface_map_|.  Ids are >=0 and are not re-used within the
  // lifetime of this class.
  // TODO(zentaro): Review if this should have a maximum number of mounts,
  // even if it is relatively large. It may already be enforced at a higher
  // level.
  void AddMount(const std::string& mount_root,
                SmbCredential credential,
                std::unique_ptr<SambaInterface> samba_interface,
                int32_t* mount_id);

  // Returns true if |mount_id| was mounted and removes the mount. Returns false
  // if |mount_id| does not exist in |mounts_|.
  bool RemoveMount(int32_t mount_id);

  // Uses the mount root associated with |mount_id| and appends |entry_path|
  // to form |full_path|. Returns true if |full_path| has been properly appended
  // with the full path. Returns false if |mount_id| does not exist in
  // |mounts_|.
  bool GetFullPath(int32_t mount_id,
                   const std::string& entry_path,
                   std::string* full_path) const;

  // Gets the mount root of the mount associated with |mount_id|. Returns false
  // if |mount_id| does not exist in |mounts_|.
  bool GetMountRootPath(int32_t mount_id, std::string* mount_root) const;

  // Uses the mount root associated with |mount_id| to remove the root path
  // from |full_path| to yield a relative path.
  std::string GetRelativePath(int32_t mount_id,
                              const std::string& full_path) const;

  // Returns the number of mounts.
  size_t MountCount() const { return mounts_.Count(); }

  // Returns the SmbCredential for |samba_interface_id|. A SambaInterfaceId must
  // exist for this function.
  // TODO(jimmyxgong): Change this function to return a bool and have an out
  // parameter for an SmbCredential.
  const SmbCredential& GetCredential(
      SambaInterface::SambaInterfaceId samba_interface_id) const;

  // Gives a pointer to the SambaInterface corresponding to |mount_id|.
  // Returns true if |samba_interface| points to an existing SambaInterface
  // pointer. Returns false if |mount_id| does not exist in |mounts_|.
  bool GetSambaInterface(int32_t mount_id,
                         SambaInterface** samba_interface) const;

  // Gets a pointer to the metadata cache for |mount_id|. Returns true if
  // getting metadata cache succeeds. Returns false if |mount_id| does not
  // exist in |mounts_|.
  bool GetMetadataCache(int32_t mount_id, MetadataCache** cache) const;

  // Updates the SmbCredential within MountInfo. Returns true if updating mount
  // credentials succeeds. Returns false if |mount_id| does not exist in
  // |mounts_|.
  bool UpdateCredential(int32_t mount_id, SmbCredential credential);

  // Updates the share_path of a mount. Returns true if updating a mount's share
  // path succeeds. Returns false if |mount_id| does not exist in |mounts_|.
  bool UpdateSharePath(int32_t mount_id, const std::string& share_path);

 private:
  // Maintains the state of a single mount. Contains the mount root path and
  // the metadata cache.
  struct MountInfo {
    MountInfo() = default;
    MountInfo(MountInfo&& other) = default;
    MountInfo(const std::string& mount_root,
              base::TickClock* tick_clock,
              SmbCredential credential,
              std::unique_ptr<SambaInterface> samba_interface,
              bool metadata_cache_enabled)
        : mount_root(mount_root),
          credential(std::move(credential)),
          samba_interface(std::move(samba_interface)) {
      auto cache_mode = metadata_cache_enabled ? MetadataCache::Mode::kStandard
                                               : MetadataCache::Mode::kDisabled;
      cache = std::make_unique<MetadataCache>(
          tick_clock, base::Microseconds(kMetadataCacheLifetimeMicroseconds),
          cache_mode);
    }
    MountInfo(const MountInfo&) = delete;
    MountInfo& operator=(const MountInfo&) = delete;

    MountInfo& operator=(MountInfo&& other) = default;

    std::string mount_root;
    SmbCredential credential;
    std::unique_ptr<SambaInterface> samba_interface;
    std::unique_ptr<MetadataCache> cache;
  };

  // Returns true if |mount_id| exists as a value in |samba_interface_map_|.
  // This method is only used for DCHECK to ensure that |mounts_| is in sync
  // |samba_interface_map_|
  bool ExistsInSambaInterfaceMap(const int32_t mount_id) const;

  // Returns a new MountInfo.
  MountInfo CreateMountInfo(const std::string& mount_root,
                            SmbCredential credential,
                            std::unique_ptr<SambaInterface> samba_interface);

  // Adds |samba_interface_id| to |mount_id| mapping to |samba_interface_map_|.
  void AddSambaInterfaceIdToSambaInterfaceMap(int32_t mount_id);

  // Returns the SambaInterfaceId corresponding to the |mount_id|.
  SambaInterface::SambaInterfaceId GetSambaInterfaceIdForMountId(
      int32_t mount_id) const;

  // Removes |samba_interface_id| from |samba_interface_map_|.
  void DeleteSambaInterfaceIdFromSambaInterfaceMap(int32_t mount_id);

  // Maps MountId to MountInfo.
  IdMap<MountInfo> mounts_;

  // Maps SambaInterfaceId to MountId.
  std::unordered_map<SambaInterface::SambaInterfaceId, int32_t>
      samba_interface_map_;

  std::unique_ptr<base::TickClock> tick_clock_;
  bool metadata_cache_enabled_;
};

}  // namespace smbprovider

#endif  // SMBPROVIDER_MOUNT_TRACKER_H_
