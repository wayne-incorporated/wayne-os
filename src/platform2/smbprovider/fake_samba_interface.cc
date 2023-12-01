// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "smbprovider/fake_samba_interface.h"

#include <errno.h>

#include <algorithm>
#include <iomanip>

#include <base/bits.h>
#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file_path.h>
#include <base/logging.h>
#include <base/notreached.h>
#include <brillo/any.h>

#include "smbprovider/constants.h"
#include "smbprovider/smbprovider.h"
#include "smbprovider/smbprovider_helper.h"

namespace smbprovider {
namespace {

constexpr mode_t kFileMode = 33188;  // File entry
constexpr mode_t kDirMode = 16877;   // Dir entry

// Returns if |flag| is set in |flags|.
bool IsFlagSet(int32_t flags, int32_t flag) {
  return (flags & flag) == flag;
}

// Returns true if |target| is inside of |source|.
bool IsTargetInsideSource(const std::string& target,
                          const std::string& source) {
  base::FilePath target_path(target);
  base::FilePath source_path(source);

  return source_path.IsParent(target_path);
}

size_t CalculateEntrySize(const std::string& entry_name) {
  return base::bits::AlignUp(sizeof(smbc_dirent) + entry_name.size(),
                             alignof(smbc_dirent));
}

bool WriteEntry(const std::string& entry_name,
                int32_t entry_type,
                size_t buffer_size,
                smbc_dirent* dirp) {
  DCHECK(dirp);
  size_t entry_size = CalculateEntrySize(entry_name);
  if (entry_size > buffer_size) {
    return false;
  }
  dirp->smbc_type = entry_type;
  dirp->dirlen = entry_size;
  memcpy(dirp->name, entry_name.c_str(), entry_name.size() + 1);
  return true;
}

}  // namespace

FakeSambaInterface::FakeSambaInterface() {
  // Initialize the |file_info_| struct.
  memset(&file_info_, 0, sizeof(file_info_));
}

int32_t FakeSambaInterface::OpenDirectory(const std::string& directory_path,
                                          int32_t* dir_id) {
  DCHECK(dir_id);
  *dir_id = -1;

  int32_t error;
  if (!GetDirectory(RemoveURLScheme(directory_path), &error)) {
    return error;
  }

  *dir_id = AddOpenDirectory(directory_path);
  return 0;
}

int32_t FakeSambaInterface::CloseDirectory(int32_t dir_id) {
  if (!IsDirectoryFDOpen(dir_id)) {
    LOG(ERROR) << "Cannot close directory [" << dir_id
               << "]: Bad file descriptor";
    return EBADF;
  }

  auto open_info_iter = FindOpenFD(dir_id);
  LOG(INFO) << "Closed directory [" << dir_id << "] "
            << std::quoted(open_info_iter->second.full_path);
  open_fds.erase(open_info_iter);
  return 0;
}

int32_t FakeSambaInterface::GetDirectoryEntry(int32_t dir_id,
                                              const smbc_dirent** dirent) {
  DCHECK(dirent);
  *dirent = nullptr;
  if (!IsDirectoryFDOpen(dir_id)) {
    return EBADF;
  }

  OpenInfo& open_info = FindOpenFD(dir_id)->second;
  FakeDirectory* directory = GetDirectory(RemoveURLScheme(open_info.full_path));
  DCHECK(directory);

  if (open_info.current_index >= directory->entries.size()) {
    // Reached the end of directory.
    return 0;
  }

  FakeEntry* entry = directory->entries[open_info.current_index].get();
  *dirent = PopulateDirEnt(*entry);
  open_info.current_index++;
  return 0;
}

int32_t FakeSambaInterface::GetDirectoryEntryWithMetadata(
    int32_t dir_id, const libsmb_file_info** file_info) {
  DCHECK(file_info);
  *file_info = nullptr;
  if (!IsDirectoryFDOpen(dir_id)) {
    return EBADF;
  }

  OpenInfo& open_info = FindOpenFD(dir_id)->second;
  FakeDirectory* directory = GetDirectory(RemoveURLScheme(open_info.full_path));
  DCHECK(directory);

  if (open_info.current_index >= directory->entries.size()) {
    // Reached the end of directory.
    return 0;
  }

  FakeEntry* entry = directory->entries[open_info.current_index].get();
  *file_info = PopulateFileInfo(*entry);
  open_info.current_index++;
  return 0;
}

int32_t FakeSambaInterface::GetEntryStatus(const std::string& entry_path,
                                           struct stat* stat) {
  DCHECK(stat);

  FakeEntry* entry = GetEntry(entry_path);
  if (!entry || !entry->IsValidEntryType()) {
    return ENOENT;
  }

  if (entry->locked) {
    return EACCES;
  }

  stat->st_size = entry->size;
  stat->st_mode = entry->IsFile() ? kFileMode : kDirMode;
  stat->st_mtime = entry->date;
  return 0;
}

int32_t FakeSambaInterface::OpenFile(const std::string& file_path,
                                     int32_t flags,
                                     int32_t* file_id) {
  DCHECK(file_id);
  *file_id = -1;

  FakeFile* file = GetFile(file_path);
  if (!file) {
    return ENOENT;
  }

  if (file->locked) {
    return EACCES;
  }

  DCHECK(IsValidOpenFileFlags(flags));
  bool readable = IsFlagSet(flags, O_RDONLY) || IsFlagSet(flags, O_RDWR);
  bool writeable = IsFlagSet(flags, O_WRONLY) || IsFlagSet(flags, O_RDWR);
  DCHECK(readable || writeable);

  *file_id = AddOpenFile(file_path, readable, writeable);
  return 0;
}

int32_t FakeSambaInterface::CloseFile(int32_t file_id) {
  if (close_file_error_ != 0) {
    LOG(ERROR) << "Cannot close file [" << file_id << "]: Error "
               << close_file_error_;
    return close_file_error_;
  }

  DCHECK_GT(file_id, 0);
  if (!IsFileFDOpen(file_id)) {
    LOG(ERROR) << "Cannot close file [" << file_id << "]: Bad file descriptor";
    return EBADF;
  }

  auto open_info_iter = FindOpenFD(file_id);
  LOG(INFO) << "Closed file [" << file_id << "] "
            << std::quoted(open_info_iter->second.full_path);
  open_fds.erase(open_info_iter);
  return 0;
}

int32_t FakeSambaInterface::ReadFile(int32_t file_id,
                                     uint8_t* buffer,
                                     size_t buffer_size,
                                     size_t* bytes_read) {
  DCHECK(buffer);
  DCHECK(bytes_read);
  if (!IsFileFDOpen(file_id)) {
    return EBADF;
  }

  OpenInfo& open_info = FindOpenFD(file_id)->second;
  FakeFile* file = GetFile(open_info.full_path);
  DCHECK(file);
  DCHECK(file->has_data);
  DCHECK(file->size == file->data.size());
  DCHECK(open_info.current_index <= file->data.size());

  // Only read up to the end of the file.
  *bytes_read =
      std::min(buffer_size, file->data.size() - open_info.current_index);
  if (*bytes_read == 0) {
    // No need for copy or seek when bytes_read is zero.
    return 0;
  }

  // Copy the buffer and update the offset.
  memcpy(buffer, file->data.data() + open_info.current_index, *bytes_read);
  open_info.current_index += *bytes_read;
  DCHECK(open_info.current_index <= file->data.size());

  return 0;
}

int32_t FakeSambaInterface::Seek(int32_t file_id, int64_t offset) {
  if (!IsFileFDOpen(file_id)) {
    return EBADF;
  }

  OpenInfo& open_info = FindOpenFD(file_id)->second;
  if (offset > GetFile(open_info.full_path)->data.size()) {
    // Returning an error when offset is outside the bounds of the file.
    return EINVAL;
  }

  open_info.current_index = offset;
  return 0;
}

int32_t FakeSambaInterface::Unlink(const std::string& file_path) {
  FakeFile* file = GetFile(file_path);
  if (!file) {
    return ENOENT;
  }

  if (file->locked) {
    return EACCES;
  }

  RemoveEntryAndResetIndicies(file_path);
  return 0;
}

int32_t FakeSambaInterface::RemoveDirectory(const std::string& dir_path) {
  int32_t error;
  FakeDirectory* directory = GetDirectory(RemoveURLScheme(dir_path), &error);
  if (!directory) {
    return error;
  }
  if (!directory->entries.empty()) {
    return ENOTEMPTY;
  }

  RemoveEntryAndResetIndicies(dir_path);
  return 0;
}

int32_t FakeSambaInterface::CreateFile(const std::string& file_path,
                                       int32_t* file_id) {
  if (EntryExists(file_path)) {
    return EEXIST;
  }

  int32_t error;
  FakeDirectory* parent = GetDirectory(GetDirPath(file_path), &error);
  if (!parent) {
    return error;
  }

  AddFile(file_path);
  *file_id = AddOpenFile(file_path, false /* readable */, true /* writeable */);
  return 0;
}

int32_t FakeSambaInterface::Truncate(int32_t file_id, size_t size) {
  if (truncate_error_ != 0) {
    return truncate_error_;
  }

  if (!IsFileFDOpen(file_id)) {
    return EBADFD;
  }
  OpenInfo& open_info = FindOpenFD(file_id)->second;
  FakeFile* file = GetFile(open_info.full_path);
  DCHECK(file);
  file->size = size;
  if (file->has_data) {
    file->data.resize(size, 0);
  }
  // Adjust offset to end of file if the previous offset was larger than size.
  open_info.current_index = std::min(open_info.current_index, size);
  return 0;
}

int32_t FakeSambaInterface::WriteFile(int32_t file_id,
                                      const uint8_t* buffer,
                                      size_t buffer_size) {
  DCHECK(buffer);
  OpenInfo& open_info = FindOpenFD(file_id)->second;
  DCHECK(open_info.smbc_type == SMBC_DIR || open_info.smbc_type == SMBC_FILE);
  if (open_info.smbc_type != SMBC_FILE) {
    return EISDIR;
  }

  if (!open_info.writeable) {
    return EINVAL;
  }

  FakeFile* file = GetFile(open_info.full_path);
  DCHECK(file);

  // Write the data into the file.
  file->WriteData(open_info.current_index, buffer, buffer_size);

  // Adjust to the new offset.
  open_info.current_index += buffer_size;

  return 0;
}

int32_t FakeSambaInterface::CreateDirectory(const std::string& directory_path) {
  if (EntryExists(directory_path)) {
    return EEXIST;
  }

  FakeDirectory* parent = GetDirectory(GetDirPath(directory_path));
  if (!parent) {
    return ENOENT;
  }

  AddDirectory(directory_path);
  return 0;
}

int32_t FakeSambaInterface::MoveEntry(const std::string& source_path,
                                      const std::string& target_path) {
  if (IsTargetInsideSource(target_path, source_path)) {
    // MoveEntry fails if |target_path| is a child of source_path.
    return EINVAL;
  }

  if (!EntryExists(source_path)) {
    // MoveEntry fails if |source_path| does not exist.
    return ENOENT;
  }

  FakeEntry* src_entry = GetEntry(source_path);
  if (EntryExists(target_path)) {
    // If |target_path| exists, check that we can continue with the move.
    FakeEntry* target_entry = GetEntry(target_path);
    int32_t result = CheckEntriesValidForMove(src_entry, target_entry);
    if (result != 0) {
      return result;
    }
  }

  if (src_entry->IsDir() && src_entry->locked) {
    // MoveEntry fails to move a locked directory.
    return EACCES;
  }

  return MoveEntryFromSourceToTarget(source_path, target_path);
}

int32_t FakeSambaInterface::SpliceFile(int32_t source_fd,
                                       int32_t target_fd,
                                       off_t length,
                                       off_t* bytes_written) {
  DCHECK(bytes_written);

  if (!IsFDOpen(source_fd) || !IsFDOpen(target_fd)) {
    return EBADF;
  }

  // Verify the source is a readable file.
  OpenInfo& source_info = FindOpenFD(source_fd)->second;
  if (source_info.smbc_type != SMBC_FILE) {
    return EISDIR;
  }
  if (!source_info.readable) {
    return EINVAL;
  }

  // Verify the target is a writable file.
  OpenInfo& target_info = FindOpenFD(target_fd)->second;
  if (target_info.smbc_type != SMBC_FILE) {
    return EISDIR;
  }
  if (!target_info.writeable) {
    return EINVAL;
  }

  // Get the file structs.
  FakeFile* source_file = GetFile(source_info.full_path);
  DCHECK(source_file);
  FakeFile* target_file = GetFile(target_info.full_path);
  DCHECK(target_file);

  // Verify there is at least |length| bytes remaining in source_info.
  DCHECK_GE(source_file->data.size(), source_info.current_index);
  int32_t max_bytes_remaining =
      source_file->data.size() - source_info.current_index;
  DCHECK_GE(max_bytes_remaining, length);

  auto begin = source_file->data.begin() + source_info.current_index;
  auto end = source_file->data.begin() + source_info.current_index + length;
  std::vector<uint8_t> buffer(begin, end);

  // Write the data into the file.
  target_file->WriteData(target_info.current_index, buffer.data(),
                         buffer.size());

  // Adjust to the new offsets of the files.
  source_info.current_index += length;
  target_info.current_index += length;

  *bytes_written = length;
  return 0;
}

int32_t FakeSambaInterface::CopyFile(const std::string& source_path,
                                     const std::string& target_path) {
  if (!EntryExists(source_path)) {
    // CopyFile fails if |source_path| does not exist.
    return ENOENT;
  }

  // CopyFile should only be called on files. A higher layer should have
  // already translated a copy of a directory to a series of file copies and
  // directory creations.
  FakeFile* source_entry = GetFile(source_path);
  if (!source_entry) {
    return EISDIR;
  }

  if (EntryExists(target_path)) {
    // |target_path| is the full path to the intended target file and must
    // not exist. |target_path| also cannot be a directory.
    return EEXIST;
  }

  // The parent of |target_path| must exist.
  int32_t error;
  FakeDirectory* target_parent = GetDirectory(GetDirPath(target_path), &error);
  if (!target_parent) {
    return error;
  }

  std::unique_ptr<FakeFile> new_target_file;
  if (source_entry->has_data) {
    new_target_file = std::make_unique<FakeFile>(
        GetFileName(target_path), source_entry->date, source_entry->data);

  } else {
    new_target_file =
        std::make_unique<FakeFile>(GetFileName(target_path), source_entry->size,
                                   source_entry->date, false /*locked */);
  }

  target_parent->entries.push_back(std::move(new_target_file));

  return 0;
}

int32_t FakeSambaInterface::CheckEntriesValidForMove(
    FakeEntry* src_entry, FakeEntry* target_entry) const {
  DCHECK(src_entry);
  DCHECK(target_entry);

  if (target_entry->IsFile()) {
    if (src_entry->IsDir()) {
      return ENOTDIR;
    }
    return EEXIST;
  } else {
    if (src_entry->IsFile()) {
      return EISDIR;
    }
    DCHECK(target_entry->IsDir());
    FakeDirectory* target_dir = static_cast<FakeDirectory*>(target_entry);
    if (!target_dir->IsEmpty()) {
      return EEXIST;
    }
    return 0;
  }
}

int32_t FakeSambaInterface::MoveEntryFromSourceToTarget(
    const std::string& source_path, const std::string& target_path) {
  FakeDirectory* source_dir;
  FakeDirectory* target_dir;
  int32_t result = GetSourceAndTargetParentDirectories(
      source_path, target_path, &source_dir, &target_dir);
  if (result != 0) {
    return result;
  }

  FakeSambaInterface::FakeDirectory::EntriesIterator source_it =
      source_dir->GetEntryIt(GetFileName(source_path));
  (*source_it)->name = GetFileName(target_path);

  if (source_dir != target_dir) {
    // Must perform move in addition to rename.
    target_dir->entries.push_back(std::move(*source_it));
    source_dir->entries.erase(source_it);
  }

  return 0;
}

int32_t FakeSambaInterface::GetSourceAndTargetParentDirectories(
    const std::string& source_path,
    const std::string& target_path,
    FakeDirectory** source_parent,
    FakeDirectory** target_parent) const {
  DCHECK(source_parent);
  DCHECK(target_parent);

  int32_t error;
  *source_parent = GetDirectory(GetDirPath(source_path), &error);
  if (!(*source_parent)) {
    return error;
  }

  *target_parent = GetDirectory(GetDirPath(target_path), &error);
  if (!(*target_parent)) {
    return error;
  }

  // FakeSambaInterface does not support moving open entries/parents.
  DCHECK(!IsOpen(GetDirPath(source_path)));
  DCHECK(!IsOpen(GetDirPath(target_path)));
  DCHECK(!IsOpen(source_path));
  DCHECK(!IsOpen(target_path));

  return 0;
}

bool FakeSambaInterface::FakeDirectory::IsEmpty() const {
  return entries.empty();
}

FakeSambaInterface::FakeEntry* FakeSambaInterface::FakeDirectory::FindEntry(
    const std::string& name) {
  for (auto&& entry : entries) {
    if (entry->name == name) {
      return entry.get();
    }
  }
  return nullptr;
}

FakeSambaInterface::FakeDirectory::EntriesIterator
FakeSambaInterface::FakeDirectory::GetEntryIt(const std::string& name) {
  return std::find_if(
      entries.begin(), entries.end(),
      [&name](const std::unique_ptr<FakeEntry>& p) { return p->name == name; });
}

int32_t FakeSambaInterface::FakeDirectory::RemoveEntry(
    const std::string& name) {
  const EntriesIterator it = GetEntryIt(name);
  if (it == entries.end()) {
    return -1;
  }

  DCHECK((*it)->IsFileOrEmptyDir());

  const size_t i = it - entries.begin();
  entries.erase(it);
  return i;
}

void FakeSambaInterface::FakeFile::WriteData(size_t offset,
                                             const uint8_t* buffer,
                                             size_t buffer_size) {
  // Ensure that the current size of the file greater than or equal to the
  // offset.
  DCHECK(this->data.size() >= offset);

  // Resize the data to the new length if necessary.
  const size_t new_length = std::max(offset + buffer_size, this->data.size());
  this->data.resize(new_length, 0);
  this->size = new_length;

  // Copy the data from buffer into the vector starting from the offset.
  memcpy(this->data.data() + offset, buffer, buffer_size);

  this->has_data = true;
}

FakeSambaInterface::FakeEntry::FakeEntry(const std::string& name,
                                         uint32_t smbc_type,
                                         size_t size,
                                         time_t date,
                                         bool locked)
    : name(name),
      smbc_type(smbc_type),
      size(size),
      date(date),
      locked(locked) {}

void FakeSambaInterface::AddDirectory(const std::string& path) {
  AddDirectory(path, false /* locked */, SMBC_DIR);
}

void FakeSambaInterface::AddServer(const std::string& server_url) {
  AddDirectory(server_url, false /* locked */, SMBC_SERVER);
}

void FakeSambaInterface::AddShare(const std::string& path) {
  AddDirectory(path, false /* locked */, SMBC_FILE_SHARE);
}

void FakeSambaInterface::AddDirectory(const std::string& path,
                                      bool locked,
                                      uint32_t smbc_type) {
  AddDirectory(path, locked, smbc_type, 0 /* date */);
}

void FakeSambaInterface::AddDirectory(const std::string& path,
                                      bool locked,
                                      uint32_t smbc_type,
                                      time_t date) {
  // Make sure that no entry exists in that path.
  DCHECK(!EntryExists(path));
  DCHECK(!IsOpen(path));
  FakeDirectory* directory = GetDirectory(GetDirPath(path));
  DCHECK(directory);
  directory->entries.emplace_back(std::make_unique<FakeDirectory>(
      GetFileName(path), locked, smbc_type, date));
}

void FakeSambaInterface::AddLockedDirectory(const std::string& path) {
  AddDirectory(path, true, SMBC_DIR);
}

void FakeSambaInterface::AddFile(const std::string& path) {
  AddFile(path, 0 /* size */);
}

void FakeSambaInterface::AddFile(const std::string& path, size_t size) {
  AddFile(path, size, 0 /* date */);
}

void FakeSambaInterface::AddFile(const std::string& path,
                                 size_t size,
                                 time_t date) {
  AddFile(path, size, date, false /* locked */);
}

void FakeSambaInterface::AddFile(const std::string& path,
                                 size_t size,
                                 time_t date,
                                 bool locked) {
  // Make sure that no entry exists in that path.
  DCHECK(!EntryExists(path));
  DCHECK(!IsOpen(path));
  FakeDirectory* directory = GetDirectory(GetDirPath(path));
  DCHECK(directory);
  directory->entries.emplace_back(
      std::make_unique<FakeFile>(GetFileName(path), size, date, locked));
}

void FakeSambaInterface::AddFile(const std::string& path,
                                 time_t date,
                                 std::vector<uint8_t> file_data) {
  // Make sure that no entry exists in that path.
  DCHECK(!EntryExists(path));
  DCHECK(!IsOpen(path));
  FakeDirectory* directory = GetDirectory(GetDirPath(path));
  DCHECK(directory);
  directory->entries.emplace_back(std::make_unique<FakeFile>(
      GetFileName(path), date, std::move(file_data)));
}

void FakeSambaInterface::AddFile(const std::string& dir_path,
                                 const std::string& name) {
  FakeDirectory* directory = GetDirectory(RemoveURLScheme(dir_path));
  DCHECK(directory);
  directory->entries.emplace_back(std::make_unique<FakeFile>(
      name, 0 /* size */, 0 /* date */, false /* locked */));
}

void FakeSambaInterface::AddLockedFile(const std::string& path) {
  AddFile(path, 0 /* size */, 0 /* date */, true /* locked */);
}

void FakeSambaInterface::AddEntry(const std::string& path, uint32_t smbc_type) {
  // Make sure that no entry exists in that path.
  DCHECK(!EntryExists(path));
  DCHECK(!IsOpen(path));
  FakeDirectory* directory = GetDirectory(GetDirPath(path));
  DCHECK(directory);
  directory->entries.emplace_back(
      std::make_unique<FakeEntry>(GetFileName(path), smbc_type, 0 /* size */,
                                  0 /* date */, false /* locked */));
}

FakeSambaInterface::FakeDirectory* FakeSambaInterface::GetDirectory(
    const std::string& full_path) const {
  int32_t error;
  return GetDirectory(full_path, &error);
}

FakeSambaInterface::FakeDirectory* FakeSambaInterface::GetDirectory(
    const std::string& full_path, int32_t* error) const {
  if (get_directory_error_ != 0) {
    *error = get_directory_error_;
    return nullptr;
  }

  PathParts split_path = SplitPath(full_path);
  FakeDirectory* current = &root;

  // i = 0 represents the root directory which we already have.
  DCHECK_EQ("/", split_path[0]);
  for (int i = 1; i < split_path.size(); ++i) {
    FakeEntry* entry = current->FindEntry(split_path[i]);
    if (!entry) {
      *error = ENOENT;
      return nullptr;
    }
    if (!entry->IsDir()) {
      *error = ENOTDIR;
      return nullptr;
    }
    if (entry->locked) {
      *error = EACCES;
      return nullptr;
    }
    current = static_cast<FakeDirectory*>(entry);
  }
  return current;
}

FakeSambaInterface::FakeFile* FakeSambaInterface::GetFile(
    const std::string& file_path) const {
  FakeEntry* entry = GetEntry(file_path);
  if (!entry || !entry->IsFile()) {
    return nullptr;
  }
  return static_cast<FakeFile*>(entry);
}

FakeSambaInterface::FakeEntry* FakeSambaInterface::GetEntry(
    const std::string& entry_path) const {
  FakeDirectory* directory = GetDirectory(GetDirPath(entry_path));
  if (!directory) {
    return nullptr;
  }
  return directory->FindEntry(GetFileName(entry_path));
}

int32_t FakeSambaInterface::AddOpenDirectory(const std::string& path) {
  DCHECK(!IsFDOpen(next_fd));
  open_fds.emplace(next_fd, OpenInfo(path, SMBC_DIR));
  LOG(INFO) << "Opened directory [" << next_fd << "] " << std::quoted(path);
  return next_fd++;
}

int32_t FakeSambaInterface::AddOpenFile(const std::string& path,
                                        bool readable,
                                        bool writeable) {
  DCHECK(!IsFDOpen(next_fd));
  open_fds.emplace(next_fd, OpenInfo(path, SMBC_FILE, readable, writeable));
  LOG(INFO) << "Opened file [" << next_fd << "] " << std::quoted(path);
  return next_fd++;
}

bool FakeSambaInterface::IsOpen(const std::string& full_path) const {
  for (auto const& open_it : open_fds) {
    if (open_it.second.full_path == full_path) {
      return true;
    }
  }
  return false;
}

bool FakeSambaInterface::HasOpenEntries() const {
  return !open_fds.empty();
}

bool FakeSambaInterface::IsFileFDOpen(uint32_t fd) const {
  auto open_iter = open_fds.find(fd);
  return open_iter != open_fds.end() &&
         open_iter->second.smbc_type == SMBC_FILE;
}

bool FakeSambaInterface::IsDirectoryFDOpen(uint32_t fd) const {
  auto open_iter = open_fds.find(fd);
  return open_iter != open_fds.end() && open_iter->second.smbc_type == SMBC_DIR;
}

bool FakeSambaInterface::IsFDOpen(uint32_t fd) const {
  return open_fds.count(fd) != 0;
}

size_t FakeSambaInterface::GetFileOffset(int32_t fd) const {
  const OpenInfo& open_info = FindOpenFD(fd)->second;
  DCHECK_EQ(open_info.smbc_type, SMBC_FILE);
  return open_info.current_index;
}

size_t FakeSambaInterface::GetFileSize(const std::string& path) const {
  FakeFile* file = GetFile(path);
  DCHECK(file);
  return file->size;
}

FakeSambaInterface::OpenEntriesIterator FakeSambaInterface::FindOpenFD(
    uint32_t fd) {
  return open_fds.find(fd);
}

FakeSambaInterface::OpenEntriesConstIterator FakeSambaInterface::FindOpenFD(
    uint32_t fd) const {
  return open_fds.find(fd);
}

bool FakeSambaInterface::FakeEntry::IsValidEntryType() const {
  return IsFile() || IsDir();
}

bool FakeSambaInterface::FakeEntry::IsFile() const {
  return smbc_type == SMBC_FILE;
}

bool FakeSambaInterface::FakeEntry::IsDir() const {
  return smbc_type == SMBC_DIR || smbc_type == SMBC_SERVER ||
         smbc_type == SMBC_FILE_SHARE;
}

bool FakeSambaInterface::FakeEntry::IsFileOrEmptyDir() const {
  DCHECK(IsValidEntryType());
  return IsFile() || static_cast<const FakeDirectory*>(this)->IsEmpty();
}

bool FakeSambaInterface::HasReadSet(int32_t fd) const {
  DCHECK(IsFDOpen(fd));
  return open_fds.at(fd).readable;
}

bool FakeSambaInterface::HasWriteSet(int32_t fd) const {
  DCHECK(IsFDOpen(fd));
  return open_fds.at(fd).writeable;
}

bool FakeSambaInterface::EntryExists(const std::string& path) const {
  return GetEntry(path);
}

void FakeSambaInterface::SetCloseFileError(int32_t error) {
  close_file_error_ = error;
}

void FakeSambaInterface::SetTruncateError(int32_t error) {
  truncate_error_ = error;
}

void FakeSambaInterface::SetGetDirectoryError(int32_t error) {
  get_directory_error_ = error;
}

void FakeSambaInterface::SetCurrentEntry(int32_t dir_id, size_t index) {
  DCHECK(IsFDOpen(dir_id));
  OpenInfo& info = FindOpenFD(dir_id)->second;

  FakeDirectory* directory = GetDirectory(RemoveURLScheme(info.full_path));
  DCHECK(directory);

  DCHECK_LE(index, directory->entries.size());
  info.current_index = index;
}

std::string FakeSambaInterface::GetCurrentEntry(int32_t dir_id) {
  DCHECK(IsFDOpen(dir_id));
  OpenInfo& info = FindOpenFD(dir_id)->second;
  const size_t index = info.current_index;

  FakeDirectory* directory = GetDirectory(RemoveURLScheme(info.full_path));
  DCHECK(directory);

  if (index == directory->entries.size()) {
    return "";
  }

  return directory->entries[index]->name;
}

bool FakeSambaInterface::IsFileDataEqual(
    const std::string& path, const std::vector<uint8_t>& expected) const {
  FakeFile* file = GetFile(path);
  if (!file || !file->has_data) {
    return false;
  }

  if (file->size != expected.size()) {
    return false;
  }

  return expected == file->data;
}

void FakeSambaInterface::RewindOpenInfoIndicesIfNeccessary(
    const std::string& dir_path, size_t deleted_index) {
  for (auto& it : open_fds) {
    OpenInfo& info = it.second;
    if (info.IsForDir(dir_path)) {
      if (deleted_index < info.current_index) {
        // By removing an entry from the directory that has already been read,
        // current_index will have been inadvertantly advanced.
        --info.current_index;
      }
    }
  }
}

bool FakeSambaInterface::OpenInfo::IsForDir(const std::string& dir_path) {
  return RemoveURLScheme(full_path) == dir_path;
}

void FakeSambaInterface::RemoveEntryAndResetIndicies(
    const std::string& full_path) {
  FakeDirectory* parent = GetDirectory(GetDirPath(full_path));
  const int32_t deleted_index = parent->RemoveEntry(GetFileName(full_path));
  DCHECK_GE(deleted_index, 0);
  RewindOpenInfoIndicesIfNeccessary(GetDirPath(full_path), deleted_index);
}

const libsmb_file_info* FakeSambaInterface::PopulateFileInfo(
    const FakeEntry& entry) {
  file_info_.size = entry.size;
  file_info_.mtime_ts.tv_sec = entry.date;
  file_info_.attrs =
      (entry.smbc_type == SMBC_FILE) ? 0 : kFileAttributeDirectory;

  // The libsmb_file_info struct has a non-const char* so even through only
  // a const pointer is ever returned, the member variable backing it is
  // not const.
  file_info_.name = const_cast<char*>(entry.name.c_str());

  return &file_info_;
}

const smbc_dirent* FakeSambaInterface::PopulateDirEnt(const FakeEntry& entry) {
  smbc_dirent* const dirent = reinterpret_cast<smbc_dirent*>(&dirent_buf_);
  const bool result =
      WriteEntry(entry.name, entry.smbc_type, kDirEntBufSize, dirent);
  DCHECK(result);

  return dirent;
}

SambaInterface::SambaInterfaceId FakeSambaInterface::GetSambaInterfaceId() {
  // GetSambaInterfaceId() should never be called directly on
  // FakeSambaInterface. All tests should call FakeSambaProxy which provides a
  // unique SambaInterfaceId for each instance.
  NOTREACHED();
  return 0;
}

SambaInterface::WeakPtr FakeSambaInterface::AsWeakPtr() {
  return weak_factory_.GetWeakPtr();
}

}  // namespace smbprovider
