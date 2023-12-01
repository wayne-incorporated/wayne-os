// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SMBFS_SAMBA_INTERFACE_IMPL_H_
#define SMBFS_SAMBA_INTERFACE_IMPL_H_

#include <libsmbclient.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <memory>
#include <string>

#include <base/memory/weak_ptr.h>
#include <base/synchronization/lock.h>
#include <gtest/gtest_prod.h>

#include "smbfs/samba_interface.h"
#include "smbfs/smb_credential.h"

namespace smbfs {

class SambaInterfaceImpl : public SambaInterface {
 public:
  SambaInterfaceImpl(std::unique_ptr<SmbCredential> credentials,
                     bool allow_ntlm);
  ~SambaInterfaceImpl() override;

  SambaInterfaceImpl(const SambaInterfaceImpl&) = delete;
  SambaInterfaceImpl& operator=(const SambaInterfaceImpl&) = delete;

  // SambaInterface overrides.
  WeakPtr AsWeakPtr() override;

  void UpdateCredentials(std::unique_ptr<SmbCredential> credentials) override;

  int StatVfs(const std::string& path, struct statvfs* out_statvfs) override;

  int OpenFile(const std::string& file_path,
               int flags,
               mode_t mode,
               SMBCFILE** out_file) override;
  int CloseFile(SMBCFILE* file) override;
  int SeekFile(SMBCFILE* file, off_t offset, int whence) override;
  int ReadFile(SMBCFILE* file,
               void* buf,
               size_t count,
               size_t* out_bytes_read) override;
  int WriteFile(SMBCFILE* file,
                const void* buf,
                size_t count,
                size_t* out_bytes_written) override;
  int TruncateFile(SMBCFILE* file, off_t size) override;
  int Stat(const std::string& path, struct stat* out_stat) override;
  int SetUtimes(const std::string& path,
                const struct timespec& atime,
                const struct timespec& mtime) override;
  int Rename(const std::string& old_path, const std::string& new_path) override;
  int UnlinkFile(const std::string& file_path) override;

  int CreateDirectory(const std::string& dir_path, mode_t mode) override;
  int OpenDirectory(const std::string& dir_path, SMBCFILE** out_dir) override;
  int CloseDirectory(SMBCFILE* dir) override;
  int SeekDirectory(SMBCFILE* dir, off_t offset) override;
  int TellDirectory(SMBCFILE* dir, off_t* out_offset) override;
  int ReadDirectory(SMBCFILE* dir,
                    const struct libsmb_file_info** out_file_info,
                    struct stat* out_stat) override;
  int RemoveDirectory(const std::string& dir_path) override;

 protected:
  // Protected constructor for unit test subclasses.
  SambaInterfaceImpl();

 private:
  FRIEND_TEST(SambaInterfaceImplTest, MakeStatModeBitsFromDOSAttributes);
  FRIEND_TEST(SambaInterfaceImplTest, UpdateCredentials);

  // Callback function for obtaining authentication credentials. Set by calling
  // smbc_setFunctionAuthDataWithContext() and called from libsmbclient.
  static void GetUserAuth(SMBCCTX* context,
                          const char* server,
                          const char* share,
                          char* workgroup,
                          int workgroup_len,
                          char* username,
                          int username_len,
                          char* password,
                          int password_len);

  // Constructs mode (type and permission) bits for stat from DOS attributes.
  mode_t MakeStatModeBitsFromDOSAttributes(uint16_t attrs) const;

  mutable base::Lock lock_;
  std::unique_ptr<SmbCredential> credentials_;

  SMBCCTX* context_ = nullptr;

  smbc_close_fn smbc_close_ctx_ = nullptr;
  smbc_closedir_fn smbc_closedir_ctx_ = nullptr;
  smbc_ftruncate_fn smbc_ftruncate_ctx_ = nullptr;
  smbc_lseek_fn smbc_lseek_ctx_ = nullptr;
  smbc_lseekdir_fn smbc_lseekdir_ctx_ = nullptr;
  smbc_mkdir_fn smbc_mkdir_ctx_ = nullptr;
  smbc_open_fn smbc_open_ctx_ = nullptr;
  smbc_opendir_fn smbc_opendir_ctx_ = nullptr;
  smbc_read_fn smbc_read_ctx_ = nullptr;
  // TODO(crbug.com/1054711): This should be swapped out for
  // smbc_readdirplus2_fn when Samba is updated to 4.12.
  smbc_readdirplus_fn smbc_readdirplus_ctx_ = nullptr;
  smbc_rename_fn smbc_rename_ctx_ = nullptr;
  smbc_rmdir_fn smbc_rmdir_ctx_ = nullptr;
  smbc_stat_fn smbc_stat_ctx_ = nullptr;
  smbc_statvfs_fn smbc_statvfs_ctx_ = nullptr;
  smbc_telldir_fn smbc_telldir_ctx_ = nullptr;
  smbc_unlink_fn smbc_unlink_ctx_ = nullptr;
  smbc_utimes_fn smbc_utimes_ctx_ = nullptr;
  smbc_write_fn smbc_write_ctx_ = nullptr;

  // Should be the last member.
  base::WeakPtrFactory<SambaInterfaceImpl> weak_factory_{this};
};

}  // namespace smbfs

#endif  // SMBFS_SAMBA_INTERFACE_IMPL_H_
