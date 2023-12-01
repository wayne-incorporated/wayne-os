// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "smbfs/inode_map.h"

#include <utility>

#include <base/check.h>
#include <base/check_op.h>
#include <base/containers/contains.h>
#include <base/logging.h>

namespace smbfs {

struct InodeMap::Entry {
  Entry(ino_t inode, const base::FilePath& path) : inode(inode), path(path) {}

  Entry() = delete;
  Entry(const Entry&) = delete;
  Entry& operator=(const Entry&) = delete;

  ~Entry() = default;

  uint64_t refcount = 0;

  const ino_t inode;
  base::FilePath path;
};

InodeMap::InodeMap(ino_t root_inode)
    : root_inode_(root_inode), seq_num_(root_inode + 1) {
  DCHECK(root_inode_);

  // Insert an entry for the root inode.
  std::unique_ptr<Entry> entry =
      std::make_unique<Entry>(root_inode, base::FilePath("/"));
  entry->refcount = 1;
  files_.emplace("/", entry.get());
  inodes_.emplace(root_inode, std::move(entry));
}

InodeMap::~InodeMap() = default;

InodeMap::Entry* InodeMap::GetEntryByPath(const base::FilePath& path) {
  CHECK(!path.empty());
  CHECK(path.IsAbsolute());
  CHECK(!path.ReferencesParent());

  const auto it = files_.find(path.value());
  if (it != files_.end()) {
    return it->second;
  }

  DCHECK(!base::Contains(inodes_, seq_num_));

  ino_t inode = seq_num_++;
  CHECK(inode) << "Inode wrap around";
  std::unique_ptr<Entry> entry = std::make_unique<Entry>(inode, path);
  Entry* raw_entry = entry.get();
  files_.emplace(path.value(), raw_entry);
  inodes_.emplace(inode, std::move(entry));
  return raw_entry;
}

ino_t InodeMap::GetWeakInode(const base::FilePath& path) {
  Entry* entry = GetEntryByPath(path);
  return entry->inode;
}

ino_t InodeMap::IncInodeRef(const base::FilePath& path) {
  Entry* entry = GetEntryByPath(path);
  entry->refcount++;
  CHECK(entry->refcount) << "Refcount wrap around";
  return entry->inode;
}

base::FilePath InodeMap::GetPath(ino_t inode) const {
  const auto it = inodes_.find(inode);
  if (it == inodes_.end() || it->second->refcount == 0) {
    return {};
  }
  return it->second->path;
}

bool InodeMap::PathExists(const base::FilePath& path) const {
  auto it = files_.find(path.value());
  return it != files_.end() && it->second->refcount > 0;
}

void InodeMap::UpdatePath(ino_t inode, const base::FilePath& new_path) {
  CHECK_NE(inode, root_inode_);
  CHECK(!new_path.empty());
  CHECK(new_path.IsAbsolute());
  CHECK(!new_path.ReferencesParent());
  DCHECK(!PathExists(new_path));

  const auto it = inodes_.find(inode);
  CHECK(it != inodes_.end());
  CHECK_GT(it->second->refcount, 0);

  const base::FilePath old_path = it->second->path;
  it->second->path = new_path;

  files_.erase(old_path.value());
  files_.emplace(new_path.value(), it->second.get());
}

bool InodeMap::Forget(ino_t inode, uint64_t forget_count) {
  if (inode == root_inode_) {
    // Ignore the root inode.
    return false;
  }

  const auto it = inodes_.find(inode);
  CHECK(it != inodes_.end());

  Entry* entry = it->second.get();
  CHECK_GE(entry->refcount, forget_count);
  entry->refcount -= forget_count;
  if (entry->refcount > 0) {
    return false;
  }
  size_t removed = files_.erase(entry->path.value());
  DCHECK_EQ(removed, 1);
  inodes_.erase(it);
  return true;
}

}  // namespace smbfs
