// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SMBPROVIDER_ITERATOR_DIRECTORY_ITERATOR_H_
#define SMBPROVIDER_ITERATOR_DIRECTORY_ITERATOR_H_

#include <string>
#include <vector>

#include "smbprovider/constants.h"
#include "smbprovider/proto.h"
#include "smbprovider/samba_interface.h"
#include "smbprovider/smbprovider_helper.h"

namespace smbprovider {

// BaseDirectoryIterator is a class that handles iterating over the DirEnts of
// an SMB directory. It must be subclassed and ShouldIncludeEntryType() have to
// be defined by the derived classes.
//
// Example:
//    DirectoryIterator it("smb://testShare/test/dogs",
//    SambaInterface.get()); result = it.Init(); while (result == 0)  {
//      if it.IsDone: return 0
//      // Do something with it.Get();
//      result = it.Next();
//    }
//    return result;
class BaseDirectoryIterator {
 public:
  BaseDirectoryIterator(const std::string& dir_path,
                        SambaInterface* samba_interface,
                        size_t batch_size,
                        bool include_metadata);

  BaseDirectoryIterator(const std::string& dir_path,
                        SambaInterface* samba_interface,
                        size_t batch_size);

  BaseDirectoryIterator(const std::string& dir_path,
                        SambaInterface* samba_interface);

  BaseDirectoryIterator(BaseDirectoryIterator&& other);
  BaseDirectoryIterator(const BaseDirectoryIterator&) = delete;
  BaseDirectoryIterator& operator=(const BaseDirectoryIterator&) = delete;

  // Initializes the iterator, setting the first value of current. Returns 0 on
  // success, error on failure. Must be called before any other operation.
  [[nodiscard]] int32_t Init();

  // Advances current to the next entry. Returns 0 on success,
  // error on failure.
  [[nodiscard]] int32_t Next();

  // Returns the current DirectoryEntry.
  const DirectoryEntry& Get();

  // Returns true if there is nothing left to iterate over.
  [[nodiscard]] bool IsDone();

  virtual ~BaseDirectoryIterator();

 protected:
  // Returns true on the entry types that should be included.
  virtual bool ShouldIncludeEntryType(uint32_t smbc_type) const = 0;

 private:
  // Fetches the next chunk of DirEntries into entries_ and resets
  // |current_entry_index|. Sets |is_done_| if there are no more entries to
  // fetch. Returns 0 on success.
  int32_t FillBuffer();

  // Reads entries without metadata into |dir_buf_| then converts the raw
  // buffer into the |entries_| vector.
  int32_t ReadEntriesToVector();

  // Reads entries that include metadata in the |entries_| vector.
  int32_t ReadEntriesWithMetadataToVector();

  // Clears the |entries_| vector and resets |current_entry_index_| to 0.
  void ClearVector();

  // Opens the directory at |dir_path_|, setting |dir_id|. Returns 0 on success
  // and errno on failure.
  int32_t OpenDirectory();

  // Attempts to Close the directory with |dir_id_|. Logs on failure.
  void CloseDirectory();

  // Helper method to transform and add |dirent| to the |entries_| vector as
  // a DirectoryEntry.
  void AddEntryIfValid(const smbc_dirent& dirent);

  // Helper method to transform and add |file_info| to the |entries_| vector as
  // a DirectoryEntry.
  void AddEntryIfValid(const struct libsmb_file_info& file_info);

  const std::string dir_path_;
  std::vector<DirectoryEntry> entries_;
  uint32_t current_entry_index_ = 0;
  // |batch_size_| is the number of entries to populate at one time.
  size_t batch_size_ = 0;
  // |dir_id_| represents the fd for the open directory at |dir_path_|.
  int32_t dir_id_ = -1;
  // |is_done_| is set to true when no entries left to read.
  bool is_done_ = false;
  // |is_initialized_| is set to true once Init() executes successfully.
  bool is_initialized_ = false;
  // |include_metadata| uses readdirplus to populate metadata while reading
  // the directory.
  bool include_metadata_ = false;

  SambaInterface::WeakPtr samba_interface_;
};

// DirectoryIterator is an implementation of BaseDirectoryIterator that only
// iterates through files and directories.
class DirectoryIterator : public BaseDirectoryIterator {
  using BaseDirectoryIterator::BaseDirectoryIterator;

 public:
  DirectoryIterator(const std::string& full_path,
                    SambaInterface* samba_interface)
      : DirectoryIterator(full_path,
                          samba_interface,
                          kDefaultMetadataBatchSize,
                          true /* include_metadata */) {}
  DirectoryIterator(DirectoryIterator&& other) = default;
  DirectoryIterator(const DirectoryIterator&) = delete;
  DirectoryIterator& operator=(const DirectoryIterator&) = delete;

 protected:
  bool ShouldIncludeEntryType(uint32_t smbc_type) const override {
    return IsFileOrDir(smbc_type);
  }
};

}  // namespace smbprovider

#endif  // SMBPROVIDER_ITERATOR_DIRECTORY_ITERATOR_H_
