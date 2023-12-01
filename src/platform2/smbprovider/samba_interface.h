// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SMBPROVIDER_SAMBA_INTERFACE_H_
#define SMBPROVIDER_SAMBA_INTERFACE_H_

#include <string>

#include <base/memory/weak_ptr.h>
#include <libsmbclient.h>

namespace smbprovider {

// Interface for interacting with Samba. The actual implementation calls smbc_*
// methods 1:1, while the fake implementation deals with fake directories and
// fake entries. All paths that are passed to the methods in this interface are
// smb:// urls. The methods will return errno on failure.
class SambaInterface {
 public:
  using SambaInterfaceId = uintptr_t;

  SambaInterface() = default;
  SambaInterface(const SambaInterface&) = delete;
  SambaInterface& operator=(const SambaInterface&) = delete;

  virtual ~SambaInterface() = default;

  // Opens a file at a given |file_path|.
  // |file_id| is the file id of the opened file. This will be -1 on failure.
  // Flags should be either O_RDONLY or O_RDWR.
  // Returns 0 on success, and errno on failure.
  [[nodiscard]] virtual int32_t OpenFile(const std::string& file_path,
                                         int32_t flags,
                                         int32_t* file_id) = 0;

  // Closes file from a given |file_id|, which is from OpenFile().
  // Returns 0 on success, and errno on failure.
  [[nodiscard]] virtual int32_t CloseFile(int32_t file_id) = 0;

  // Opens directory in a given |directory_path|.
  // |dir_id| is the directory id of the opened directory. This will be
  // -1 on failure.
  // Returns 0 on success, and errno on failure.
  [[nodiscard]] virtual int32_t OpenDirectory(const std::string& directory_path,
                                              int32_t* dir_id) = 0;

  // Closes directory from a given |dir_id|, which is from OpenDirectory().
  // Returns 0 on success, and errno on failure.
  [[nodiscard]] virtual int32_t CloseDirectory(int32_t dir_id) = 0;

  [[nodiscard]] virtual int32_t GetDirectoryEntry(
      int32_t dir_id, const struct smbc_dirent** dirent) = 0;

  // Gets the next directory entry with all metadata attached for |dir_id|.
  // |file_info| will be nullptr on failure or to indicate that there are
  // no more entries.
  //
  // When there are no more entries the return value will be 0 and on failure
  // it will be errno.
  // |dir_id| is the directory_id from OpenDirectory().
  // |file_info| is assigned a const pointer to info about the file. It is
  // invalidated on the next operation on the directory handle.
  [[nodiscard]] virtual int32_t GetDirectoryEntryWithMetadata(
      int32_t dir_id, const struct libsmb_file_info** file_info) = 0;

  // Gets information about a file or directory.
  // Returns 0 on success, and errno on failure.
  // |full_path| is the smb url to get information for.
  // |stat| is the pointer to a buffer that will be filled with standard Unix
  // struct stat information.
  [[nodiscard]] virtual int32_t GetEntryStatus(const std::string& full_path,
                                               struct stat* stat) = 0;

  // Reads the contents of the file corresponding to the file handle |file_id|.
  // Returns 0 on success, and errno on failure.
  // |buffer| is the pointer to a buffer that will receive the file contents.
  // |buffer_size| is the size of |buffer| in bytes.
  // |bytes_read| is the number of bytes read, this will undefined on failure.
  [[nodiscard]] virtual int32_t ReadFile(int32_t file_id,
                                         uint8_t* buffer,
                                         size_t buffer_size,
                                         size_t* bytes_read) = 0;

  // Seeks to a specific location in a file with the file handle |file_id|.
  // |offset| is where the file is seeked to from the beginning of the file.
  // Returns 0 on success and errno on failure.
  [[nodiscard]] virtual int32_t Seek(int32_t file_id, int64_t offset) = 0;

  // Unlinks (deletes) a file with the smb url |file_path|.
  // Returns 0 on success and errno on failure.
  [[nodiscard]] virtual int32_t Unlink(const std::string& file_path) = 0;

  // Removes the directory with the smb url |dir_path|.
  // Directory must be empty.
  // Returns 0 on success and errno on failure.
  [[nodiscard]] virtual int32_t RemoveDirectory(
      const std::string& dir_path) = 0;

  // Creates a file in a given |file_path|. |file_id| will be the file handle of
  // the created file and will be -1 on failure. The file that is created will
  // have 755 as permissions and will be opened as write only. If a file with
  // the same path exists, this will return an error. Returns 0 on success and
  // errno on failure.
  [[nodiscard]] virtual int32_t CreateFile(const std::string& file_path,
                                           int32_t* file_id) = 0;

  // Truncates a file corresponding to the file handle |file_id| to the
  // specified |size|. If the file was previously larger than |size|, the extra
  // data is lost. If the file was shorter, it is extended and the extended part
  // reads as null bytes. The file offset is not changed. Returns 0 on success
  // and errno on failure.
  [[nodiscard]] virtual int32_t Truncate(int32_t file_id, size_t size) = 0;

  // Writes the contents of |buffer| into the file with |file_id|. |buffer_size|
  // is the size of the data being written. Returns 0 on success and errno on
  // failure.
  [[nodiscard]] virtual int32_t WriteFile(int32_t file_id,
                                          const uint8_t* buffer,
                                          size_t buffer_size) = 0;

  // Creates the directory at |directory_path|. The directory that is created
  // will have 755 as permissions. If a directory with the same path exists,
  // this will return an error. If the parent directory of the directory doesn't
  // exist, this will return an error. Returns 0 on success and errno on
  // failure.
  [[nodiscard]] virtual int32_t CreateDirectory(
      const std::string& directory_path) = 0;

  // Moves the entry at |souce_path| to |target_path|. If there is already an
  // entry at |target_path|, this will return an error. The parent directory of
  // the destination must exist. Returns 0 on success and errno on failure.
  [[nodiscard]] virtual int32_t MoveEntry(const std::string& source_path,
                                          const std::string& target_path) = 0;

  // Copies a file from |source_path| to |target_path| using a server side
  // copy. If there is already an entry at |target_path|, this will return an
  // error. The parent directory of the destination must exist. Returns 0 on
  // success and errno on failure.
  [[nodiscard]] virtual int32_t CopyFile(const std::string& source_path,
                                         const std::string& target_path) = 0;

  // Splices |length| bytes from |source| to |target| using a server side
  // splice. Returns 0 on success and errno on failure.
  [[nodiscard]] virtual int32_t SpliceFile(int32_t source_fd,
                                           int32_t target_fd,
                                           off_t length,
                                           off_t* bytes_written) = 0;

  // Returns the SambaInterfaceId of this interface.
  virtual SambaInterfaceId GetSambaInterfaceId() = 0;

  // Weak pointer type.
  using WeakPtr = ::base::WeakPtr<SambaInterface>;

  // Gets a weak pointer to this object.
  virtual WeakPtr AsWeakPtr() = 0;

 private:
  static_assert(std::is_same<int, int32_t>::value,
                "Ensure that int32_t is same as int, due to casting of int to "
                "int32_t in samba interface");
};

}  // namespace smbprovider

#endif  // SMBPROVIDER_SAMBA_INTERFACE_H_
