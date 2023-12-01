// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SMBPROVIDER_SAMBA_INTERFACE_IMPL_H_
#define SMBPROVIDER_SAMBA_INTERFACE_IMPL_H_

#include <memory>
#include <string>

#include <base/functional/callback.h>
#include <base/memory/weak_ptr.h>
#include <dbus/smbprovider/dbus-constants.h>

#include "smbprovider/id_map.h"
#include "smbprovider/mount_config.h"
#include "smbprovider/samba_interface.h"

namespace smbprovider {

// Implements SambaInterface and calls libsmbclient's smbc_* methods 1:1.
class SambaInterfaceImpl : public SambaInterface {
 public:
  // SMB authentication callback.
  using AuthCallback =
      base::RepeatingCallback<void(SambaInterfaceId samba_interface_id,
                                   const std::string& share_path,
                                   char* workgroup,
                                   int32_t workgroup_length,
                                   char* username,
                                   int32_t username_length,
                                   char* password,
                                   int32_t password_length)>;
  ~SambaInterfaceImpl() override;

  // Creates a SambaInterfaceImpl.
  static std::unique_ptr<SambaInterface> Create(
      AuthCallback auth_callback, const MountConfig& mount_config);

  int32_t OpenFile(const std::string& file_path,
                   int32_t flags,
                   int32_t* file_id) override;

  int32_t CloseFile(int32_t file_id) override;

  int32_t OpenDirectory(const std::string& directory_path,
                        int32_t* dir_id) override;

  int32_t CloseDirectory(int32_t dir_id) override;

  int32_t GetDirectoryEntry(int32_t dir_id,
                            const struct smbc_dirent** dirent) override;

  int32_t GetDirectoryEntryWithMetadata(
      int32_t dir_id, const struct libsmb_file_info** file_info) override;

  int32_t GetEntryStatus(const std::string& full_path,
                         struct stat* stat) override;

  SambaInterfaceId GetSambaInterfaceId() override;

  WeakPtr AsWeakPtr() override;

  int32_t ReadFile(int32_t file_id,
                   uint8_t* buffer,
                   size_t buffer_size,
                   size_t* bytes_read) override;

  int32_t Seek(int32_t file_id, int64_t offset) override;

  int32_t Unlink(const std::string& file_path) override;

  int32_t RemoveDirectory(const std::string& dir_path) override;

  int32_t CreateFile(const std::string& file_path, int32_t* file_id) override;

  int32_t Truncate(int32_t file_id, size_t size) override;

  int32_t WriteFile(int32_t file_id,
                    const uint8_t* buffer,
                    size_t buffer_size) override;

  int32_t CreateDirectory(const std::string& directory_path) override;

  int32_t MoveEntry(const std::string& source_path,
                    const std::string& target_path) override;

  int32_t CopyFile(const std::string& source_path,
                   const std::string& target_path) override;

  int32_t SpliceFile(int32_t source_fd,
                     int32_t target_fd,
                     off_t length,
                     off_t* bytes_written) override;

 private:
  using CopyProgressCallback = int (*)(off_t upto, void* callback_context);

  // Copies a file from |source_path| to |target_path| using a server side
  // copy. If there is already an entry at |target_path|, this will return an
  // error. The parent directory of the destination must exist. Returns 0 on
  // success and errno on failure. The progress callback is currently not
  // exposed outside this class, but could in future to support progress and
  // cancellation.
  [[nodiscard]] int32_t CopyFile(const std::string& source_path,
                                 const std::string& target_path,
                                 CopyProgressCallback progress_callback,
                                 void* callback_context);
  int32_t OpenCopySource(const std::string& file_path, int32_t* source_fd);
  int32_t OpenCopyTarget(const std::string& file_path, int32_t* target_fd);
  void CloseCopySourceAndTarget(int32_t source_fd, int32_t target_fd);

  // Inserts the |file| pointer into the map and returns a new FD.
  int32_t NewFd(SMBCFILE* file);

  // Releases a file descriptor back to the pool.
  void ReleaseFd(int32_t fd);

  // Returns the SMBCFILE pointer for |fd| or nullptr if it doesn't exist.
  SMBCFILE* GetFile(int32_t fd);

  // Returns the SMBCFILE pointer for |fd| and DCHECKS if it doesn't exist.
  SMBCFILE* MustGetFile(int32_t fd);

  // Close all file descriptors in |fds_|.
  void CloseOutstandingFileDescriptors();

  explicit SambaInterfaceImpl(SMBCCTX* context);
  SambaInterfaceImpl(const SambaInterfaceImpl&) = delete;
  SambaInterfaceImpl& operator=(const SambaInterfaceImpl&) = delete;

  SMBCCTX* context_ = nullptr;
  smbc_close_fn smbc_close_ctx_ = nullptr;
  smbc_closedir_fn smbc_closedir_ctx_ = nullptr;
  smbc_ftruncate_fn smbc_ftruncate_ctx_ = nullptr;
  smbc_lseek_fn smbc_lseek_ctx_ = nullptr;
  smbc_mkdir_fn smbc_mkdir_ctx_ = nullptr;
  smbc_open_fn smbc_open_ctx_ = nullptr;
  smbc_opendir_fn smbc_opendir_ctx_ = nullptr;
  smbc_read_fn smbc_read_ctx_ = nullptr;
  smbc_readdir_fn smbc_readdir_ctx_ = nullptr;
  smbc_readdirplus_fn smbc_readdirplus_ctx_ = nullptr;
  smbc_rename_fn smbc_rename_ctx_ = nullptr;
  smbc_rmdir_fn smbc_rmdir_ctx_ = nullptr;
  smbc_splice_fn smbc_splice_ctx_ = nullptr;
  smbc_stat_fn smbc_stat_ctx_ = nullptr;
  smbc_unlink_fn smbc_unlink_ctx_ = nullptr;
  smbc_write_fn smbc_write_ctx_ = nullptr;
  IdMap<SMBCFILE*> fds_;

  // Weak pointer factory. Should be the last member.
  base::WeakPtrFactory<SambaInterfaceImpl> weak_factory_{this};
};

}  // namespace smbprovider

#endif  // SMBPROVIDER_SAMBA_INTERFACE_IMPL_H_
