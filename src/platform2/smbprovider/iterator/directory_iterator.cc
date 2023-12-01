// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "smbprovider/iterator/directory_iterator.h"

#include <utility>

#include <base/check.h>
#include <base/check_op.h>
#include <base/containers/contains.h>
#include <base/logging.h>

#include "smbprovider/constants.h"
#include "smbprovider/smbprovider_helper.h"

namespace smbprovider {
namespace {

constexpr int32_t kNoMoreEntriesError = -1;

}  // namespace

BaseDirectoryIterator::BaseDirectoryIterator(const std::string& dir_path,
                                             SambaInterface* samba_interface)
    : BaseDirectoryIterator(dir_path,
                            samba_interface,
                            kDefaultMetadataBatchSize,
                            false /* include_metadata */) {}

BaseDirectoryIterator::BaseDirectoryIterator(const std::string& dir_path,
                                             SambaInterface* samba_interface,
                                             size_t batch_size)
    : BaseDirectoryIterator(
          dir_path, samba_interface, batch_size, false /* include_metadata */) {
}

BaseDirectoryIterator::BaseDirectoryIterator(const std::string& dir_path,
                                             SambaInterface* samba_interface,
                                             size_t batch_size,
                                             bool include_metadata)
    : dir_path_(dir_path),
      batch_size_(batch_size),
      include_metadata_(include_metadata),
      samba_interface_(samba_interface->AsWeakPtr()) {}

BaseDirectoryIterator::BaseDirectoryIterator(BaseDirectoryIterator&& other)
    : dir_path_(std::move(other.dir_path_)),
      entries_(std::move(other.entries_)),
      current_entry_index_(other.current_entry_index_),
      batch_size_(other.batch_size_),
      dir_id_(other.dir_id_),
      is_done_(other.is_done_),
      is_initialized_(other.is_initialized_),
      include_metadata_(other.include_metadata_),
      samba_interface_(std::move(other.samba_interface_)) {
  other.dir_id_ = -1;
  other.is_initialized_ = false;
  other.samba_interface_ = nullptr;
}

BaseDirectoryIterator::~BaseDirectoryIterator() {
  if (dir_id_ != -1) {
    CloseDirectory();
  }
}

int32_t BaseDirectoryIterator::Init() {
  DCHECK(!is_initialized_);

  int32_t open_dir_error = OpenDirectory();
  if (open_dir_error != 0) {
    return open_dir_error;
  }
  is_initialized_ = true;
  return Next();
}

int32_t BaseDirectoryIterator::Next() {
  DCHECK(is_initialized_);
  DCHECK(!is_done_);

  ++current_entry_index_;
  if (current_entry_index_ >= entries_.size()) {
    int32_t result = FillBuffer();
    if (result != 0 && result != kNoMoreEntriesError) {
      return result;
    }
  }
  return 0;
}

const DirectoryEntry& BaseDirectoryIterator::Get() {
  DCHECK(is_initialized_);
  DCHECK(!is_done_);
  DCHECK_LT(current_entry_index_, entries_.size());

  return entries_[current_entry_index_];
}

bool BaseDirectoryIterator::IsDone() {
  DCHECK(is_initialized_);
  return is_done_;
}

int32_t BaseDirectoryIterator::OpenDirectory() {
  DCHECK_EQ(-1, dir_id_);
  return samba_interface_->OpenDirectory(dir_path_, &dir_id_);
}

void BaseDirectoryIterator::CloseDirectory() {
  const int32_t dir_id = std::exchange(dir_id_, -1);
  DCHECK_NE(-1, dir_id);

  if (!samba_interface_) {
    LOG(ERROR) << "Cannot close directory [" << dir_id
               << "]: Samba implementation already deleted";
    return;
  }

  const int32_t error = samba_interface_->CloseDirectory(dir_id);
  if (error != 0) {
    LOG(ERROR) << "Cannot close directory [" << dir_id
               << "]: " << GetErrorFromErrno(error);
  }
}

int32_t BaseDirectoryIterator::FillBuffer() {
  int32_t fetch_error = include_metadata_ ? ReadEntriesWithMetadataToVector()
                                          : ReadEntriesToVector();

  if (fetch_error != 0) {
    return fetch_error;
  }

  if (entries_.empty()) {
    // Succeeded but nothing valid left to read.
    is_done_ = true;
    return kNoMoreEntriesError;
  }

  return 0;
}

int32_t BaseDirectoryIterator::ReadEntriesToVector() {
  DCHECK(!include_metadata_);
  DCHECK_GT(batch_size_, 0);

  ClearVector();

  for (size_t i = 0; i < batch_size_; i++) {
    const struct smbc_dirent* dirent = nullptr;
    int fetch_error = samba_interface_->GetDirectoryEntry(dir_id_, &dirent);
    if (fetch_error) {
      return fetch_error;
    }

    if (!dirent) {
      // There are no more files, but this is not an error. The next call to
      // refill the buffer will hit this case on the first iteration of the
      // loop and will return an empty vector which will cause FillBuffer()
      // to set |done_| and return |kNoMoreEntriesError|.
      return 0;
    }

    AddEntryIfValid(*dirent);
  }

  // Completed the batch successfully.
  return 0;
}

int32_t BaseDirectoryIterator::ReadEntriesWithMetadataToVector() {
  DCHECK(include_metadata_);
  DCHECK_GT(batch_size_, 0);

  ClearVector();

  for (size_t i = 0; i < batch_size_; i++) {
    const struct libsmb_file_info* file_info = nullptr;
    int fetch_error =
        samba_interface_->GetDirectoryEntryWithMetadata(dir_id_, &file_info);
    if (fetch_error) {
      return fetch_error;
    }

    if (!file_info) {
      // There are no more files, but this is not an error. The next call to
      // refill the buffer will hit this case on the first iteration of the
      // loop and will return an empty vector which will cause FillBuffer()
      // to set |done_| and return |kNoMoreEntriesError|.
      return 0;
    }

    AddEntryIfValid(*file_info);
  }

  // Completed the batch successfully.
  return 0;
}

void BaseDirectoryIterator::ClearVector() {
  entries_.clear();
  current_entry_index_ = 0;
}

void BaseDirectoryIterator::AddEntryIfValid(const smbc_dirent& dirent) {
  const std::string name(dirent.name);
  // Ignore "." and ".." entries.
  // TODO(allenvic): Handle SMBC_LINK
  if (IsSelfOrParentDir(name) || !ShouldIncludeEntryType(dirent.smbc_type) ||
      base::Contains(name, '/') || base::Contains(name, '\\')) {
    return;
  }

  bool is_directory =
      dirent.smbc_type == SMBC_DIR || dirent.smbc_type == SMBC_FILE_SHARE;
  entries_.emplace_back(is_directory, name, AppendPath(dir_path_, name));
}

void BaseDirectoryIterator::AddEntryIfValid(
    const struct libsmb_file_info& file_info) {
  const std::string name(file_info.name);
  const uint16_t attrs(file_info.attrs);
  // Ignore "." and ".." entries as well as symlinks.
  // TODO(zentaro): Investigate how this API deals with directories that are
  // file shares.
  if (IsSelfOrParentDir(name) || IsSymlink(file_info.attrs) ||
      base::Contains(name, '/') || base::Contains(name, '\\')) {
    return;
  }

  bool is_directory = attrs & kFileAttributeDirectory;
  entries_.emplace_back(is_directory, name, AppendPath(dir_path_, name),
                        file_info.size, file_info.mtime_ts.tv_sec);
}

}  // namespace smbprovider
