// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SMBFS_SAMBA_INTERFACE_H_
#define SMBFS_SAMBA_INTERFACE_H_

#include <libsmbclient.h>
#include <sys/types.h>

#include <memory>
#include <string>

#include <base/memory/weak_ptr.h>

namespace smbfs {

struct SmbCredential;

// Lightweight wrapper to make libsmbclient functions available without having
// to define and retrieve their function pointers in multiple places.
//
// Methods map 1:1 onto libsmbclient functions but unlike libsmbclient provide
// a consistent interface where the return value is 0 on success or errno on
// failure. Methods that natively return other data (ie. OpenFile()) do so via
// pointer-based output parameters.
//
// All methods must be called from the same thread, unless noted.
class SambaInterface {
 public:
  SambaInterface() = default;
  virtual ~SambaInterface() = default;

  SambaInterface(const SambaInterface&) = delete;
  SambaInterface& operator=(const SambaInterface&) = delete;

  // Weak pointer type.
  using WeakPtr = ::base::WeakPtr<SambaInterface>;

  // Gets a weak pointer to this object. Should only be called from, and
  // the resultant pointer dereferenced from, the constructor thread.
  virtual WeakPtr AsWeakPtr() = 0;

  // Sets the password to be used for libsmbclient auth callbacks (if
  // implemented). Can be called from any thread.
  virtual void UpdateCredentials(
      std::unique_ptr<SmbCredential> credentials) = 0;

  // Retrieve stat information for the filesystem that backs |path| into
  // |out_statvfs|.
  // Returns 0 on success and errno on failure.
  [[nodiscard]] virtual int StatVfs(const std::string& path,
                                    struct statvfs* out_statvfs) = 0;

  // Opens a file at a given |file_path| with |flags| (O_RDONLY, O_WRONLY etc),
  // returning a handle to it in |out_file|, which will be nullptr on failure.
  // |mode| is used when using OpenFile() to create a new file.
  // Returns 0 on success and errno on failure.
  [[nodiscard]] virtual int OpenFile(const std::string& file_path,
                                     int flags,
                                     mode_t mode,
                                     SMBCFILE** out_file) = 0;

  // Closes |file|, which is from OpenFile().
  // Returns 0 on success and errno on failure.
  [[nodiscard]] virtual int CloseFile(SMBCFILE* file) = 0;

  // Seeks to |offset| in |file| from position |whence|.
  // Returns 0 on success and errno on failure.
  [[nodiscard]] virtual int SeekFile(SMBCFILE* file,
                                     off_t offset,
                                     int whence) = 0;

  // Reads |count| bytes from |file| into |buf|. On success, |out_bytes_read|
  // contains the number of bytes read.
  // Returns 0 on success and errno on failure.
  [[nodiscard]] virtual int ReadFile(SMBCFILE* file,
                                     void* buf,
                                     size_t count,
                                     size_t* out_bytes_read) = 0;

  // Writes |count| bytes from |buf| into |file|. On success,
  // |out_bytes_written| contains the number of bytes written. Returns 0 on
  // success and errno on failure.
  [[nodiscard]] virtual int WriteFile(SMBCFILE* file,
                                      const void* buf,
                                      size_t count,
                                      size_t* out_bytes_written) = 0;

  // Truncates |file| to |size| bytes.
  // Returns 0 on success and errno on failure.
  [[nodiscard]] virtual int TruncateFile(SMBCFILE* file, off_t size) = 0;

  // Retrieves a stat structure for the file or directory at |path| into
  // |out_stat|. Returns 0 on success and errno on failure.
  [[nodiscard]] virtual int Stat(const std::string& path,
                                 struct stat* out_stat) = 0;

  // Sets the access and modification times for the file or directory at |path|.
  // Returns 0 on success and errno on failure.
  virtual int SetUtimes(const std::string& path,
                        const struct timespec& atime,
                        const struct timespec& mtime) = 0;

  // Renames |old_path| to |new_path|.
  // Returns 0 on success and errno on failure.
  [[nodiscard]] virtual int Rename(const std::string& old_path,
                                   const std::string& new_path) = 0;

  // Removes the file at |file_path|. Use RmDir() to remove a directory.
  // Returns 0 on success and errno on failure.
  [[nodiscard]] virtual int UnlinkFile(const std::string& file_path) = 0;

  // Creates directory at |dir_path| with mode |mode|.
  // Returns 0 on success and errno on failure.
  [[nodiscard]] virtual int CreateDirectory(const std::string& dir_path,
                                            mode_t mode) = 0;

  // Opens directory at |dir_path|, returning a handle to it in |out_dir|,
  // which will be nullptr on failure.
  // Returns 0 on success and errno on failure.
  [[nodiscard]] virtual int OpenDirectory(const std::string& dir_path,
                                          SMBCFILE** out_dir) = 0;

  // Closes |dir|, which is from OpenDirectory().
  // Returns 0 on success and errno on failure.
  [[nodiscard]] virtual int CloseDirectory(SMBCFILE* dir) = 0;

  // Seeks |offset| entries into |directory|. |offset| should be 0 to seek to
  // the beginning of the directory, or a value returned by TellDirectory().
  // Returns 0 on success and errno on failure.
  [[nodiscard]] virtual int SeekDirectory(SMBCFILE* dir, off_t offset) = 0;

  // Retrieve the current offset in |dir| into |out_offset|. The value returned
  // in |out_offset| is opaque and should not be interpreted. It should only be
  // passed into SeekDirectory().
  // Returns 0 on success and errno on failure.
  [[nodiscard]] virtual int TellDirectory(SMBCFILE* dir, off_t* out_offset) = 0;

  // Reads a directory entry from |dir|, returning metadata into
  // |out_file_info| and an associated stat structure into |out_stat|. Is used
  // in conjunction with SeekDirectory() to set the read offset. If no more
  // directory entries are available it will return 0 and set |out_file_info|
  // to a nullptr and |out_stat| to an empty struct.
  // Returns 0 on success and errno on failure.
  [[nodiscard]] virtual int ReadDirectory(
      SMBCFILE* dir,
      const struct libsmb_file_info** out_file_info,
      struct stat* out_stat) = 0;

  // Removes the directory at |dir_path|.
  // Returns 0 on success and errno on failure.
  [[nodiscard]] virtual int RemoveDirectory(const std::string& dir_path) = 0;
};

}  // namespace smbfs

#endif  // SMBFS_SAMBA_INTERFACE_H_
