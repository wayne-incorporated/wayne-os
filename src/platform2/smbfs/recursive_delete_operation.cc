// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "smbfs/recursive_delete_operation.h"

#include <list>
#include <string>
#include <utility>

#include <base/check.h>
#include <base/check_op.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/posix/safe_strerror.h>

#include "smbfs/samba_interface.h"
#include "smbfs/smb_filesystem.h"

namespace smbfs {

RecursiveDeleteOperation::RecursiveDeleteOperation(
    SambaInterface* samba_impl,
    const std::string& base_share_path,
    const base::FilePath& root_path,
    CompletionCallback completion_callback)
    : samba_impl_(samba_impl),
      base_share_path_(base_share_path),
      root_path_(root_path),
      completion_callback_(std::move(completion_callback)) {
  CHECK_NE('/', base_share_path.back());
}

void RecursiveDeleteOperation::SetSambaInterface(SambaInterface* samba_impl) {
  samba_impl_ = samba_impl;
}

void RecursiveDeleteOperation::Start() {
  std::string share_path = MakeSharePath(root_path_);
  struct stat entry_stat = {0};
  int error = samba_impl_->Stat(share_path, &entry_stat);
  if (error) {
    VLOG(1) << "Stat path: " << share_path
            << " failed: " << base::safe_strerror(error);
    std::move(completion_callback_)
        .Run(mojom::DeleteRecursivelyError::kPathNotFound);
    return;
  }

  if (S_ISREG(entry_stat.st_mode)) {
    bool deleted = DeleteFile(root_path_);
    std::move(completion_callback_)
        .Run(deleted ? mojom::DeleteRecursivelyError::kOk
                     : mojom::DeleteRecursivelyError::kFailedToDeleteNode);
    return;
  }

  DeleteRecursively(root_path_,
                    base::BindOnce(&RecursiveDeleteOperation::Finished,
                                   base::Unretained(this)));
}

void RecursiveDeleteOperation::Finished(bool success) {
  LOG_IF(WARNING, success && last_error_ != mojom::DeleteRecursivelyError::kOk)
      << "Operation completed successfully but reported error: " << last_error_;
  std::move(completion_callback_).Run(last_error_);
}

void RecursiveDeleteOperation::DeleteRecursively(
    const base::FilePath& dir_path,
    ContinuationCallback path_removed_callback) {
  VLOG(1) << "Recursively deleting directory: " << dir_path;

  std::list<Entry> entries;
  if (!GetDirectoryListing(dir_path, &entries)) {
    last_error_ = mojom::DeleteRecursivelyError::kFailedToListDirectory;
    std::move(path_removed_callback).Run(false);
    return;
  }

  // Spread SMB calls (directory listing or directory / file removal) over
  // multiple tasks to enable fair access to synchronous libsmbclient APIs.
  main_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(
          &RecursiveDeleteOperation::ProcessDirectoryEntries,
          weak_factory_.GetWeakPtr(), std::move(entries),
          // Schedule removal of the entry itself once all children are removed.
          base::BindOnce(
              &RecursiveDeleteOperation::OnProcessDirectoryEntriesDone,
              weak_factory_.GetWeakPtr(), std::move(dir_path),
              std::move(path_removed_callback)),
          true /* previous_entry_succeeded */));
}

void RecursiveDeleteOperation::ProcessDirectoryEntries(
    std::list<Entry> entries,
    ContinuationCallback processing_complete_callback,
    bool previous_entry_succeeded) {
  VLOG(1) << "Processing directory entries, " << entries.size()
          << " remaining at this level";

  if (!previous_entry_succeeded) {
    LOG(WARNING) << "Aborting entry processing as previous entry failed";
    std::move(processing_complete_callback).Run(false);
    return;
  }

  // Handle the case where an empty |root_path_| is processed.
  if (entries.empty()) {
    std::move(processing_complete_callback).Run(true);
    return;
  }

  Entry entry = std::move(entries.front());
  entries.pop_front();
  if (entries.empty()) {
    // This is the last entry, delete the containing directory once done.
    ProcessSingleDirectoryEntry(entry, std::move(processing_complete_callback));
    return;
  }

  ProcessSingleDirectoryEntry(
      entry,
      // Continue to process the remaining siblings (here: entries) of this
      // entry once it (and all of its descendants, if it's a directory) have
      // been removed.
      base::BindOnce(&RecursiveDeleteOperation::ProcessDirectoryEntries,
                     weak_factory_.GetWeakPtr(), std::move(entries),
                     std::move(processing_complete_callback)));
}

void RecursiveDeleteOperation::OnProcessDirectoryEntriesDone(
    const base::FilePath& dir_path,
    ContinuationCallback path_removed_callback,
    bool all_descendants_removed) {
  bool directory_removed = false;

  if (all_descendants_removed) {
    // All descendants were successfully removed, remove myself.
    VLOG(1) << "Finished processing all descendants of " << dir_path
            << ", deleting myself";
    directory_removed = DeleteDirectory(dir_path);
  } else {
    LOG(WARNING) << "Failed to process all descendants of " << dir_path
                 << ", will abort operation";
  }

  // The callback may be |root_path_removed_callback_| or a follow-up call to
  // ProcessDirectoryEntries() to continue processing the list of siblings
  // of an entry that was itself a directory.
  std::move(path_removed_callback).Run(directory_removed);
}

void RecursiveDeleteOperation::ProcessSingleDirectoryEntry(
    const Entry& entry, ContinuationCallback entry_removed_callback) {
  if (entry.is_directory) {
    DeleteRecursively(entry.path, std::move(entry_removed_callback));
  } else {
    bool file_removed = DeleteFile(entry.path);
    std::move(entry_removed_callback).Run(file_removed);
  }
}

bool RecursiveDeleteOperation::DeleteDirectory(const base::FilePath& dir_path) {
  std::string share_dir_path = MakeSharePath(dir_path);
  int error = samba_impl_->RemoveDirectory(share_dir_path);
  if (error) {
    VLOG(1) << "RemoveDirectory path: " << share_dir_path
            << " failed: " << base::safe_strerror(error);
    last_error_ = mojom::DeleteRecursivelyError::kFailedToDeleteNode;
    return false;
  }

  return true;
}

bool RecursiveDeleteOperation::DeleteFile(const base::FilePath& file_path) {
  std::string share_file_path = MakeSharePath(file_path);
  int error = samba_impl_->UnlinkFile(share_file_path);
  if (error) {
    VLOG(1) << "UnlinkFile path: " << share_file_path
            << " failed: " << base::safe_strerror(error);
    last_error_ = mojom::DeleteRecursivelyError::kFailedToDeleteNode;
    return false;
  }

  return true;
}

bool RecursiveDeleteOperation::GetDirectoryListing(
    const base::FilePath& dir_path, std::list<Entry>* const entries) {
  DCHECK(entries);
  std::string share_path = MakeSharePath(dir_path);

  // Open a directory handle
  SMBCFILE* dir;
  int error = samba_impl_->OpenDirectory(share_path, &dir);
  if (error) {
    VLOG(1) << "OpenDirectory path: " << dir_path
            << " failed: " << base::safe_strerror(error);
    return false;
  }

  while (true) {
    // Explicitly set |errno| to 0 to detect EOF vs. error cases.
    errno = 0;
    const struct libsmb_file_info* dirent_info = nullptr;
    struct stat inode_stat = {0};

    error = samba_impl_->ReadDirectory(dir, &dirent_info, &inode_stat);
    if (error) {
      VLOG(1) << "ReadDirectory path: " << dir_path
              << " failed: " << base::safe_strerror(error);
      CloseDirectory(dir);
      return false;
    }
    if (!dirent_info) {
      // EOF.
      break;
    }

    base::StringPiece filename(dirent_info->name);
    if (filename == "." || filename == "..") {
      // Ignore . and .. since FUSE already takes care of these.
      continue;
    }
    CHECK(!filename.empty());
    CHECK_EQ(filename.find("/"), base::StringPiece::npos);

    Entry entry;
    entry.is_directory = S_ISDIR(inode_stat.st_mode);
    entry.path = dir_path.Append(filename);

    entries->push_back(std::move(entry));
  }

  return CloseDirectory(dir);
}

bool RecursiveDeleteOperation::CloseDirectory(SMBCFILE* dir) {
  int error = samba_impl_->CloseDirectory(dir);
  if (error) {
    LOG(WARNING) << "Failed to close directory: " << base::safe_strerror(error);
    return false;
  }

  return true;
}

std::string RecursiveDeleteOperation::MakeSharePath(
    const base::FilePath& path) {
  DCHECK(path.IsAbsolute());
  DCHECK(!path.EndsWithSeparator());
  return base_share_path_ + path.value();
}

}  // namespace smbfs
