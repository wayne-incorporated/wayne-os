// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SMBFS_RECURSIVE_DELETE_OPERATION_H_
#define SMBFS_RECURSIVE_DELETE_OPERATION_H_

#include <libsmbclient.h>

#include <list>
#include <string>

#include <base/files/file_path.h>
#include <base/functional/callback.h>
#include <base/memory/weak_ptr.h>
#include <base/task/single_thread_task_runner.h>
#include <gtest/gtest_prod.h>

#include "smbfs/mojom/smbfs.mojom.h"
#include "smbfs/samba_interface.h"

namespace smbfs {

class SmbFilesystem;

// Recursively deletes all nodes (files and sub-directories) under a given
// |root_path| by doing a post-order DFT of the directory tree and spreading
// I/O calls out over multiple tasks. |completion_callback| is called once the
// operation succeeds or fails.
//
// This class must be created, used and destroyed on the same thread.
class RecursiveDeleteOperation {
 public:
  using CompletionCallback =
      base::OnceCallback<void(mojom::DeleteRecursivelyError)>;

  // |base_share_path| is a fully-qualified SMB share path *without* the
  // trailing slash (ie. smb://server/share) and |root_path| should be the
  // absolute path, within that share, to the directory being deleted (ie.
  // /delete/this/dir).
  RecursiveDeleteOperation(SambaInterface* samba_impl,
                           const std::string& base_share_path,
                           const base::FilePath& root_path,
                           CompletionCallback completion_callback);

  RecursiveDeleteOperation(const RecursiveDeleteOperation&) = delete;
  RecursiveDeleteOperation& operator=(const RecursiveDeleteOperation&) = delete;

  // Start deletion from |root_path_|, which may be a file or directory.
  void Start();

 protected:
  // Helper for unit tests.
  void SetSambaInterface(SambaInterface* samba_impl);

 private:
  // Multiple methods can serve as ContinuationCallbacks (ie. Finished(),
  // ProcessDirectoryEntries()). The overall operation is aborted whenever the
  // parameter to this callback is false.
  using ContinuationCallback = base::OnceCallback<void(bool)>;

  FRIEND_TEST(RecursiveDeleteOperationTest, DeleteFile);
  FRIEND_TEST(RecursiveDeleteOperationTest, DeleteDirectory);
  FRIEND_TEST(RecursiveDeleteOperationTest, CloseDirectory);
  FRIEND_TEST(RecursiveDeleteOperationTest, GetDirectoryListing);

  struct Entry {
    base::FilePath path;
    bool is_directory;
  };

  // The top-level ContinuationCallback that is called when the recursive
  // deletion completes due to success or failure. It marshalls |last_error_|
  // back to the |completion_callback_|.
  void Finished(bool success);

  // Delete the directory |dir_path| recursively. |path_removed_callback| is
  // called once |dir_path| is fully removed and may be Finished() (for the
  // top-level directory) or ProcessDirectoryEntries() if continuing to process
  // the siblings of a |dir_path| that is a descendant of |root_path_|.
  void DeleteRecursively(const base::FilePath& dir_path,
                         ContinuationCallback path_removed_callback);

  // Process (traverse directories, delete files) all |entries| from the
  // directory currently being deleted by DeleteRecursively(). For any given
  // directory this method will be called multiple times, working its way
  // through |entries| one-at-a-time. Each time it is called the previous entry
  // is guaranteed to be completely removed unless |previous_entry_succeeded| is
  // false (which aborts the entire process).
  void ProcessDirectoryEntries(
      std::list<Entry> entries,
      ContinuationCallback processing_complete_callback,
      bool previous_entry_succeeded);

  // Called once all entries from a directory have been processed. If they
  // were all successfully removed (|all_descendants_removed| is true) it will
  // proceed to remove the directory itself. The callback may be Finished() or a
  // follow-up call to ProcessDirectoryEntries() to continue processing the list
  // of siblings of an entry that was itself a directory.
  void OnProcessDirectoryEntriesDone(const base::FilePath& dir_path,
                                     ContinuationCallback path_removed_callback,
                                     bool all_descendants_removed);

  // Descends into directories or removes a file.
  void ProcessSingleDirectoryEntry(const Entry& entry,
                                   ContinuationCallback entry_removed_callback);

  // Build a list of Entry's to describe the contents of directory |dir_path|.
  bool GetDirectoryListing(const base::FilePath& dir_path,
                           std::list<Entry>* const entries);

  bool DeleteDirectory(const base::FilePath& dir_path);
  bool DeleteFile(const base::FilePath& file_path);
  bool CloseDirectory(SMBCFILE* dir);
  std::string MakeSharePath(const base::FilePath& path);

  // Origin/constructor thread task runner.
  scoped_refptr<base::SingleThreadTaskRunner> main_task_runner_ =
      base::SingleThreadTaskRunner::GetCurrentDefault();
  SambaInterface* samba_impl_;
  const std::string base_share_path_;
  const base::FilePath root_path_;
  CompletionCallback completion_callback_;

  // If progress is aborted at any time, the reason is stored in |last_error_|
  // and marshalled back to |completion_callback_| via Finished().
  mojom::DeleteRecursivelyError last_error_ =
      mojom::DeleteRecursivelyError::kOk;

  base::WeakPtrFactory<RecursiveDeleteOperation> weak_factory_{this};
};

}  // namespace smbfs

#endif  // SMBFS_RECURSIVE_DELETE_OPERATION_H_
