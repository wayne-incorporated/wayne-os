// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DLP_DLP_DATABASE_H_
#define DLP_DLP_DATABASE_H_

#include <stdint.h>

#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>
#include "dlp/dlp_metrics.h"

#include <base/files/file_path.h>
#include <base/functional/callback.h>
#include <base/task/single_thread_task_runner.h>
#include <base/threading/thread.h>

namespace dlp {

// Database for storing information about DLP-protected files.

// |FileEntry| objects stored in |file_entries| table.
// A file entry represents a DLP-protected file. |inode| identifies the file on
// the user filesystem, |source_url| and |referrer_url| (possibly empty)
// tell where from the file was originated.
struct FileEntry {
  int64_t inode;
  std::string source_url;
  std::string referrer_url;
};

class DlpDatabaseDelegate {
 public:
  // Called when an error occurres.
  virtual void OnDatabaseError(DatabaseError error) = 0;

 protected:
  virtual ~DlpDatabaseDelegate() = default;
};

// Provides API to access database and base functions.
// Access to the database is done on a separate thread.
class DlpDatabase : public DlpDatabaseDelegate {
 public:
  class Delegate {
   public:
    // Called when an error occurres.
    virtual void OnDatabaseError(DatabaseError error) = 0;
  };
  // Creates an instance to talk to the database file at |db_path|. Init() must
  // be called to establish connection.
  DlpDatabase(const base::FilePath& db_path, Delegate* delegate);

  // Not copyable or movable.
  DlpDatabase(const DlpDatabase&) = delete;
  DlpDatabase& operator=(const DlpDatabase&) = delete;

  ~DlpDatabase();

  // Initializes database connection. Must be called before any other queries.
  // Returns |SQLITE_OK| to the |callback| if no error occurred.
  void Init(base::OnceCallback<void(int)> callback);

  // Inserts file_entry into database. Returns true to the |callback| if no
  // error occurred.
  void InsertFileEntry(const FileEntry& file_entry,
                       base::OnceCallback<void(bool)> callback);

  // Inserts file_entries into database. Returns true to the |callback| if no
  // error occurred.
  void InsertFileEntries(const std::vector<FileEntry>& file_entries,
                         base::OnceCallback<void(bool)> callback);

  // Gets the file entries by inodes. Returns a map of only found entries to
  // the |callback|.
  void GetFileEntriesByInodes(
      std::vector<ino64_t> inodes,
      base::OnceCallback<void(std::map<ino64_t, FileEntry>)> callback) const;

  // Deletes file entry with |inode| from database. Returns true to the
  // |callback| if no error occurred.
  void DeleteFileEntryByInode(int64_t inode,
                              base::OnceCallback<void(bool)> callback);

  // Filters the file entries table to contain only entries with
  // |inodes_to_keep| inode values. Returns true to the |callback| if no error
  // occurred.
  void DeleteFileEntriesWithInodesNotInSet(
      std::set<ino64_t> inodes_to_keep,
      base::OnceCallback<void(bool)> callback);

 private:
  // DlpDatabaseDelegate overrides:
  void OnDatabaseError(DatabaseError error) override;

  // Class impelmenting the core functionality.
  class Core;

  std::unique_ptr<Core> core_;

  base::Thread database_thread_;
  scoped_refptr<base::SingleThreadTaskRunner> task_runner_;

  Delegate* delegate_;
};

}  // namespace dlp

#endif  // DLP_DLP_DATABASE_H_
