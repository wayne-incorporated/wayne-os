// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SMBPROVIDER_ITERATOR_DEPTH_FIRST_ITERATOR_H_
#define SMBPROVIDER_ITERATOR_DEPTH_FIRST_ITERATOR_H_

#include <stack>
#include <string>

#include "smbprovider/iterator/directory_iterator.h"
#include "smbprovider/proto.h"
#include "smbprovider/samba_interface.h"

namespace smbprovider {

// DepthFirstIterator is an abstract class that implements the logic for a Depth
// First Traversal of an SMB filesystem. Two variants, PreDepthFirstIterator and
// PostDepthFirstIterator are concrete classes that extend DepthFirstIterator in
// order to provide a preorder and postorder traversal, respectively.
class DepthFirstIterator {
 public:
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

  DepthFirstIterator(DepthFirstIterator&& other);

 protected:
  DepthFirstIterator(const std::string& dir_path,
                     SambaInterface* samba_interface);
  DepthFirstIterator(const DepthFirstIterator&) = delete;
  DepthFirstIterator& operator=(const DepthFirstIterator&) = delete;

  virtual ~DepthFirstIterator() = default;

  // Either OnPop() or OnPush() should be overridden to set |current_| to
  // |entry| in order to achieve a Postorder or Preorder traversal. Without an
  // override, DepthFirstIterator performs an Inorder traversal of files only.
  virtual int32_t OnPop(const DirectoryEntry& entry);
  virtual int32_t OnPush(const DirectoryEntry& entry);

  // Sets |current_| to |entry|.
  void SetCurrent(const DirectoryEntry& entry);

 private:
  // Creates an entry on |open_directories_| for the directory |entry| and
  // calls OnPush() with it.
  int32_t PushDir(const DirectoryEntry& entry);

  // Pops the top entry from |open_directories_| and calls OnPop() with the
  // DirectoryEntry that was popped.
  int32_t PopDir();

  // Helper method that returns the current DirectoryEntry for the
  // DirectoryIterator at the top of the |open_directories_| stack.
  const DirectoryEntry& TopEntry();

  // Helper method that returns the DirectoryIterator on the top of the
  // |open_directories_| stack.
  DirectoryIterator& TopDirectoryIterator();

  // Helper method that constructs a DirectoryIterator for the directory with
  // full path |full_path| on the top of the |open_directories| stack.
  void AddDirectoryToStack(const std::string& full_path);

  bool is_done_ = false;
  bool is_initialized_ = false;
  // |dir_entry_| is a DirectoryEntry for the root of the DepthFirstIterator.
  const DirectoryEntry dir_entry_;
  // |open_directories_| is a stack representing the directories currently open
  // in the file system, with the root-most directory on the bottom of the
  // stack and the leaf-most on the top.
  std::stack<DirectoryIterator> open_directories_;
  DirectoryEntry current_;

  SambaInterface* samba_interface_;  // not owned.
};

}  // namespace smbprovider

#endif  // SMBPROVIDER_ITERATOR_DEPTH_FIRST_ITERATOR_H_
