// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "smbprovider/iterator/depth_first_iterator.h"

#include <utility>

#include "smbprovider/smbprovider_helper.h"

#include <base/check.h>

namespace smbprovider {

DepthFirstIterator::DepthFirstIterator(const std::string& dir_path,
                                       SambaInterface* samba_interface)
    : dir_entry_(true /* is_directory */, GetFileName(dir_path), dir_path),
      samba_interface_(samba_interface) {}

DepthFirstIterator::DepthFirstIterator(DepthFirstIterator&& other)
    : is_done_(other.is_done_),
      is_initialized_(other.is_initialized_),
      dir_entry_(std::move(other.dir_entry_)),
      open_directories_(std::move(other.open_directories_)),
      current_(std::move(other.current_)),
      samba_interface_(other.samba_interface_) {
  other.is_done_ = false;
  other.is_initialized_ = false;
  other.samba_interface_ = nullptr;
}

int32_t DepthFirstIterator::Init() {
  DCHECK(!is_initialized_);
  is_initialized_ = true;

  int32_t result = PushDir(dir_entry_);
  if (result != 0) {
    is_initialized_ = false;
  }
  return result;
}

int32_t DepthFirstIterator::Next() {
  DCHECK(is_initialized_);
  DCHECK(!is_done_);

  if (open_directories_.empty()) {
    is_done_ = true;
    return 0;
  }

  if (TopDirectoryIterator().IsDone()) {
    return PopDir();
  }

  if (TopEntry().is_directory) {
    return PushDir(TopEntry());
  }

  SetCurrent(TopEntry());

  return TopDirectoryIterator().Next();
}

int32_t DepthFirstIterator::OnPop(const DirectoryEntry& entry) {
  return Next();
}

int32_t DepthFirstIterator::OnPush(const DirectoryEntry& entry) {
  return Next();
}

void DepthFirstIterator::SetCurrent(const DirectoryEntry& entry) {
  current_ = entry;
}

int32_t DepthFirstIterator::PushDir(const DirectoryEntry& entry) {
  AddDirectoryToStack(entry.full_path);
  int32_t result = TopDirectoryIterator().Init();
  if (result != 0) {
    return result;
  }
  return OnPush(entry);
}

int32_t DepthFirstIterator::PopDir() {
  open_directories_.pop();
  DirectoryEntry entry = open_directories_.empty() ? dir_entry_ : TopEntry();

  if (!open_directories_.empty()) {
    int32_t result = TopDirectoryIterator().Next();
    if (result != 0) {
      return result;
    }
  }
  return OnPop(entry);
}

const DirectoryEntry& DepthFirstIterator::Get() {
  DCHECK(is_initialized_);
  DCHECK(!is_done_);

  return current_;
}

bool DepthFirstIterator::IsDone() {
  DCHECK(is_initialized_);

  return is_done_;
}

DirectoryIterator& DepthFirstIterator::TopDirectoryIterator() {
  return open_directories_.top();
}

const DirectoryEntry& DepthFirstIterator::TopEntry() {
  return TopDirectoryIterator().Get();
}

void DepthFirstIterator::AddDirectoryToStack(const std::string& full_path) {
  open_directories_.emplace(full_path, samba_interface_);
}

}  // namespace smbprovider
