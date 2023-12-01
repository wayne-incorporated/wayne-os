// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "smbfs/samba_interface_impl.h"

#include <sys/stat.h>

#include <memory>
#include <utility>

#include <base/check.h>
#include <base/check_op.h>
#include <base/logging.h>
#include <base/memory/ptr_util.h>
#include <base/strings/string_util.h>

namespace smbfs {

namespace {

// Default that is consistent with common filesystems (ie. ext3, ext4, NFTS).
constexpr int kMaxShareFilenameLength = 255;

void SambaLog(void* private_ptr, int level, const char* msg) {
  VLOG(level) << "libsmbclient: " << msg;
}

void CopyCredential(const std::string& cred, char* out, int out_len) {
  DCHECK_GT(out_len, 0);
  if (cred.size() > out_len - 1) {
    LOG(ERROR) << "Credential string longer than buffer provided";
  }
  base::strlcpy(out, cred.c_str(), out_len);
}

void CopyPassword(const password_provider::Password& password,
                  char* out,
                  int out_len) {
  DCHECK_GT(out_len, 0);
  if (password.size() > out_len - 1) {
    LOG(ERROR) << "Password string longer than buffer provided";
  }
  base::strlcpy(out, password.GetRaw(), out_len);
}

}  // namespace

SambaInterfaceImpl::SambaInterfaceImpl(
    std::unique_ptr<SmbCredential> credentials, bool allow_ntlm)
    : credentials_(std::move(credentials)) {
  context_ = smbc_new_context();
  CHECK(context_);
  CHECK(smbc_init_context(context_));

  smbc_setLogCallback(context_, nullptr, &SambaLog);
  int vlog_level = logging::GetVlogVerbosity();
  if (vlog_level > 0) {
    smbc_setDebug(context_, vlog_level);
  }

  smbc_setOptionUserData(context_, this);
  smbc_setOptionUseKerberos(context_, 1);
  // Allow fallback to NTLMv2 authentication if Kerberos fails. This does not
  // prevent fallback to anonymous auth if authentication fails.
  smbc_setOptionFallbackAfterKerberos(context_, allow_ntlm);
  LOG_IF(WARNING, !allow_ntlm) << "NTLM protocol is disabled";
  smbc_setFunctionAuthDataWithContext(context_,
                                      &SambaInterfaceImpl::GetUserAuth);

  smbc_close_ctx_ = smbc_getFunctionClose(context_);
  smbc_closedir_ctx_ = smbc_getFunctionClosedir(context_);
  smbc_ftruncate_ctx_ = smbc_getFunctionFtruncate(context_);
  smbc_lseek_ctx_ = smbc_getFunctionLseek(context_);
  smbc_lseekdir_ctx_ = smbc_getFunctionLseekdir(context_);
  smbc_mkdir_ctx_ = smbc_getFunctionMkdir(context_);
  smbc_open_ctx_ = smbc_getFunctionOpen(context_);
  smbc_opendir_ctx_ = smbc_getFunctionOpendir(context_);
  smbc_read_ctx_ = smbc_getFunctionRead(context_);
  smbc_readdirplus_ctx_ = smbc_getFunctionReaddirPlus(context_);
  smbc_rename_ctx_ = smbc_getFunctionRename(context_);
  smbc_rmdir_ctx_ = smbc_getFunctionRmdir(context_);
  smbc_stat_ctx_ = smbc_getFunctionStat(context_);
  smbc_statvfs_ctx_ = smbc_getFunctionStatVFS(context_);
  smbc_telldir_ctx_ = smbc_getFunctionTelldir(context_);
  smbc_unlink_ctx_ = smbc_getFunctionUnlink(context_);
  smbc_utimes_ctx_ = smbc_getFunctionUtimes(context_);
  smbc_write_ctx_ = smbc_getFunctionWrite(context_);
}

SambaInterfaceImpl::SambaInterfaceImpl() = default;

SambaInterfaceImpl::~SambaInterfaceImpl() {
  if (context_) {
    smbc_free_context(context_, 1 /* shutdown_ctx */);
  }
}

void SambaInterfaceImpl::UpdateCredentials(
    std::unique_ptr<SmbCredential> credentials) {
  base::AutoLock l(lock_);
  credentials_ = std::move(credentials);
}

SambaInterface::WeakPtr SambaInterfaceImpl::AsWeakPtr() {
  return weak_factory_.GetWeakPtr();
}

// static
void SambaInterfaceImpl::GetUserAuth(SMBCCTX* context,
                                     const char* server,
                                     const char* share,
                                     char* workgroup,
                                     int workgroup_len,
                                     char* username,
                                     int username_len,
                                     char* password,
                                     int password_len) {
  SambaInterfaceImpl* samba_impl =
      static_cast<SambaInterfaceImpl*>(smbc_getOptionUserData(context));
  DCHECK(samba_impl);

  base::AutoLock l(samba_impl->lock_);
  // Credentials can be omitted during mounts manually initiated from the
  // command line.
  if (!samba_impl->credentials_) {
    return;
  }

  CopyCredential(samba_impl->credentials_->workgroup, workgroup, workgroup_len);
  CopyCredential(samba_impl->credentials_->username, username, username_len);
  password[0] = 0;
  if (samba_impl->credentials_->password) {
    CopyPassword(*samba_impl->credentials_->password, password, password_len);
  }
}

int SambaInterfaceImpl::StatVfs(const std::string& path,
                                struct statvfs* out_statvfs) {
  DCHECK(out_statvfs);

  // libsmbclient's statvfs() takes a non-const char* as path, hence the
  // address-of-first-element pattern/hack.
  std::string stat_path = path;
  if (smbc_statvfs_ctx_(context_, &stat_path[0], out_statvfs) < 0) {
    return errno;
  }

  if ((out_statvfs->f_flag & SMBC_VFS_FEATURE_NO_UNIXCIFS) &&
      out_statvfs->f_frsize) {
    // If the server does not support the UNIX CIFS extensions, libsmbclient
    // incorrectly fills out the value of f_frsize. Instead of providing the
    // size in bytes, it provides it as a multiple of f_bsize. See the
    // implementation of SMBC_fstatvfs_ctx() in the Samba source tree for
    // details.
    out_statvfs->f_frsize *= out_statvfs->f_bsize;
  }

  // libsmbclient can return 0 for this but some clients require it to be set.
  if (!out_statvfs->f_namemax) {
    out_statvfs->f_namemax = kMaxShareFilenameLength;
  }

  return 0;
}

int SambaInterfaceImpl::OpenFile(const std::string& file_path,
                                 int flags,
                                 mode_t mode,
                                 SMBCFILE** out_file) {
  DCHECK(out_file);

  *out_file = smbc_open_ctx_(context_, file_path.c_str(), flags, mode);
  if (!*out_file) {
    return errno;
  }

  return 0;
}

int SambaInterfaceImpl::CloseFile(SMBCFILE* file) {
  DCHECK(file);

  if (smbc_close_ctx_(context_, file) < 0) {
    return errno;
  }

  return 0;
}

int SambaInterfaceImpl::SeekFile(SMBCFILE* file, off_t offset, int whence) {
  DCHECK(file);

  off_t actual_offset = smbc_lseek_ctx_(context_, file, offset, whence);
  if (actual_offset < 0) {
    return errno;
  }

  return 0;
}

int SambaInterfaceImpl::ReadFile(SMBCFILE* file,
                                 void* buf,
                                 size_t count,
                                 size_t* out_bytes_read) {
  DCHECK(file);
  DCHECK(buf);
  DCHECK(out_bytes_read);

  ssize_t bytes_read = smbc_read_ctx_(context_, file, buf, count);
  if (bytes_read < 0) {
    return errno;
  }
  *out_bytes_read = static_cast<size_t>(bytes_read);

  return 0;
}

int SambaInterfaceImpl::WriteFile(SMBCFILE* file,
                                  const void* buf,
                                  size_t count,
                                  size_t* out_bytes_written) {
  DCHECK(file);
  DCHECK(buf);
  DCHECK(out_bytes_written);

  ssize_t bytes_written = smbc_write_ctx_(context_, file, buf, count);
  if (bytes_written < 0) {
    return errno;
  }
  *out_bytes_written = static_cast<size_t>(bytes_written);

  return 0;
}

int SambaInterfaceImpl::TruncateFile(SMBCFILE* file, off_t size) {
  DCHECK(file);

  if (smbc_ftruncate_ctx_(context_, file, size) < 0) {
    return errno;
  }

  return 0;
}

int SambaInterfaceImpl::Stat(const std::string& path, struct stat* out_stat) {
  DCHECK(out_stat);

  if (smbc_stat_ctx_(context_, path.c_str(), out_stat) < 0) {
    return errno;
  }

  return 0;
}

int SambaInterfaceImpl::SetUtimes(const std::string& path,
                                  const struct timespec& atime,
                                  const struct timespec& mtime) {
  struct timeval packed_times[2];

  packed_times[0].tv_sec = atime.tv_sec;
  packed_times[0].tv_usec = 0;  // per libsmbclient, tv_usec is ignored
  packed_times[1].tv_sec = mtime.tv_sec;
  packed_times[1].tv_usec = 0;  // per libsmbclient, tv_usec is ignored

  if (smbc_utimes_ctx_(context_, path.c_str(), packed_times) < 0) {
    return errno;
  }

  return 0;
}

int SambaInterfaceImpl::Rename(const std::string& old_path,
                               const std::string& new_path) {
  if (smbc_rename_ctx_(context_, old_path.c_str(), context_, new_path.c_str()) <
      0) {
    return errno;
  }

  return 0;
}

int SambaInterfaceImpl::UnlinkFile(const std::string& file_path) {
  if (smbc_unlink_ctx_(context_, file_path.c_str()) < 0) {
    return errno;
  }

  return 0;
}

int SambaInterfaceImpl::CreateDirectory(const std::string& dir_path,
                                        mode_t mode) {
  if (smbc_mkdir_ctx_(context_, dir_path.c_str(), mode) < 0) {
    return errno;
  }

  return 0;
}

int SambaInterfaceImpl::OpenDirectory(const std::string& dir_path,
                                      SMBCFILE** out_dir) {
  DCHECK(out_dir);

  *out_dir = smbc_opendir_ctx_(context_, dir_path.c_str());
  if (!*out_dir) {
    return errno;
  }

  return 0;
}

int SambaInterfaceImpl::CloseDirectory(SMBCFILE* dir) {
  DCHECK(dir);

  if (smbc_closedir_ctx_(context_, dir) < 0) {
    return errno;
  }

  return 0;
}

int SambaInterfaceImpl::SeekDirectory(SMBCFILE* dir, off_t offset) {
  DCHECK(dir);

  if (smbc_lseekdir_ctx_(context_, dir, offset) < 0) {
    return errno;
  }

  return 0;
}

int SambaInterfaceImpl::TellDirectory(SMBCFILE* dir, off_t* out_offset) {
  DCHECK(dir);
  DCHECK(out_offset);

  // Explicitly set |errno| to 0 to detect error cases. On 32-bit platforms,
  // smbc_telldir_ctx_() can return <0 in normal cases since internally,
  // libsmbclient does a signed cast of a pointer to off_t.
  errno = 0;

  *out_offset = smbc_telldir_ctx_(context_, dir);
  if (*out_offset < 0 && errno) {
    return errno;
  }

  return 0;
}

int SambaInterfaceImpl::ReadDirectory(
    SMBCFILE* dir,
    const struct libsmb_file_info** out_file_info,
    struct stat* out_stat) {
  DCHECK(dir);
  DCHECK(out_file_info);
  DCHECK(out_stat);

  *out_stat = {0};
  *out_file_info = nullptr;

  // Explicitly set |errno| to 0 to detect EOF vs. error cases.
  errno = 0;

  *out_file_info = smbc_readdirplus_ctx_(context_, dir);
  if (!*out_file_info) {
    // Differentiate between error and no more files to read.
    if (errno) {
      return errno;
    }

    // EOF.
    return 0;
  }

  // TODO(crbug.com/1054711): The mapping of DOS attributes to a mode_t can
  // be removed when struct stat is available from smbc_readdirplus2.
  out_stat->st_mode =
      MakeStatModeBitsFromDOSAttributes((*out_file_info)->attrs);

  // TODO(crbug.com/1054711): structure synthesis can be removed once
  // smbc_readdirplus2 is available.
  out_stat->st_atim = (*out_file_info)->atime_ts;
  out_stat->st_ctim = (*out_file_info)->ctime_ts;
  out_stat->st_mtim = (*out_file_info)->mtime_ts;
  out_stat->st_size = (*out_file_info)->size;

  // TODO(crbug.com/1075758): rounding of modification time can be removed once
  // libsmbclient is up-revved to include nanosecond precision in SMBC_stat_ctx
  if (out_stat->st_mtim.tv_nsec > 500000000) {
    out_stat->st_mtim.tv_sec += 1;
  }
  out_stat->st_mtim.tv_nsec = 0;

  return 0;
}

int SambaInterfaceImpl::RemoveDirectory(const std::string& dir_path) {
  if (smbc_rmdir_ctx_(context_, dir_path.c_str()) < 0) {
    return errno;
  }

  return 0;
}

mode_t SambaInterfaceImpl::MakeStatModeBitsFromDOSAttributes(
    uint16_t attrs) const {
  mode_t mode = 0;

  if (attrs & SMBC_DOS_MODE_DIRECTORY) {
    mode = S_IFDIR;
  } else {
    mode = S_IFREG;
  }

  // All files and directories are read / write unless read only.
  if (attrs & SMBC_DOS_MODE_READONLY) {
    mode |= S_IRUSR;
  } else {
    mode |= S_IRUSR | S_IWUSR;
  }

  return mode;
}

}  // namespace smbfs
