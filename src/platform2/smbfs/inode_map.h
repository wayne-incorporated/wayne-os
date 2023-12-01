// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SMBFS_INODE_MAP_H_
#define SMBFS_INODE_MAP_H_

#include <stdint.h>
#include <sys/types.h>

#include <memory>
#include <string>
#include <unordered_map>

#include <base/files/file_path.h>

namespace smbfs {

// Class that synthesizes inode numbers for file paths, and keeps a reference
// count for each inode. Inode numbers are never re-used by new paths.
class InodeMap {
 public:
  explicit InodeMap(ino_t root_inode);

  InodeMap() = delete;
  InodeMap(const InodeMap&) = delete;
  InodeMap& operator=(const InodeMap&) = delete;

  ~InodeMap();

  // Return an inode for |path| without incrementing the refcount. If |path|
  // does not have a corresponding inode, create a weak inode with a refcount of
  // 0. The weak inode will not exist for the purpose of any other function
  // except GetWeakInode() and IncInodeRef(). Namely, GetPath(inode) will return
  // the empty path, and PathExists(path) will return false.  Future calls to
  // GetWeakInode() or IncInodeRef() will return the same inode until the inode
  // is forgotten by calling Forget(). |path| must be an absolute path, and not
  // contain any relative components (i.e. '.' and '..').
  ino_t GetWeakInode(const base::FilePath& path);

  // Increment the inode refcount for |path| by 1 and return the inode number.
  // If the inode for |path| is weak (see above), return the same inode and set
  // its refcount to 1. If |path| does not have a corresponding inode, create a
  // new one with a refcount of 1. |path| must be an absolute path, and not
  // contain any relative components (i.e. '.' and '..').
  ino_t IncInodeRef(const base::FilePath& path);

  // Return the path corresponding to the file |inode|. If the inode does not
  // exist, return the empty path.
  base::FilePath GetPath(ino_t inode) const;

  // Return whether or not an inode exists for |path|.
  bool PathExists(const base::FilePath& path) const;

  // Update the path corresponding to the file |inode|. The inode must exist and
  // must not be |root_inode|, and |new_path| must be an absolute path and not
  // contain any relative components (i.e. '.' and '..').
  void UpdatePath(ino_t inode, const base::FilePath& new_path);

  // Forget |forget_count| reference to |inode|. If the refcount falls to 0,
  // remove the inode. |forget_count| cannot be greater than the current
  // refcount of |inode|. Returns true if the inode was removed.
  bool Forget(ino_t inode, uint64_t forget_count);

 private:
  struct Entry;

  // Returns the Entry for |path|. If no existing entry exists, a new one is
  // created with a refcount of 0.
  Entry* GetEntryByPath(const base::FilePath& path);

  const ino_t root_inode_;
  ino_t seq_num_;
  std::unordered_map<ino_t, std::unique_ptr<Entry>> inodes_;
  std::unordered_map<std::string, Entry*> files_;
};

}  // namespace smbfs

#endif  // SMBFS_INODE_MAP_H_
