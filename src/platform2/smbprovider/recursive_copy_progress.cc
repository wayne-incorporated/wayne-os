// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include "smbprovider/recursive_copy_progress.h"

#include <base/check.h>
#include <base/logging.h>
#include <base/strings/string_util.h>

namespace smbprovider {

RecursiveCopyProgress::RecursiveCopyProgress(SambaInterface* samba_interface)
    : samba_interface_(samba_interface) {}

RecursiveCopyProgress::~RecursiveCopyProgress() = default;

bool RecursiveCopyProgress::StartCopy(const std::string& source,
                                      const std::string& target,
                                      int32_t* error) {
  DCHECK(!is_started_);
  DCHECK(!is_done_);

  source_root_ = source;
  target_root_ = target;
  is_started_ = true;

  // Create an iterator for |source|.
  CreateCopySourceIterator();
  const int32_t it_result = copy_iterator_->Init();
  if (it_result != 0 || copy_iterator_->IsDone()) {
    // There was an error initializing the iterator.
    *error = it_result;
    FinishCopy();
    return false;
  }

  return ContinueCopy(error);
}

bool RecursiveCopyProgress::ContinueCopy(int32_t* error) {
  DCHECK(is_started_);
  DCHECK(!is_done_);
  DCHECK(!copy_iterator_->IsDone());

  if (file_progress_) {
    // Continue copying an in-progress file.
    *error = ContinueFileCopy();
    if (*error != 0) {
      FinishCopy();
      return false;
    }
    return true;
  }

  const DirectoryEntry& current = copy_iterator_->Get();
  if (current.is_directory) {
    *error = CreateDirectory(current);
  } else {
    *error = StartFileCopy(current);
  }

  if (*error != 0) {
    FinishCopy();
    return false;
  }

  const int32_t it_result = copy_iterator_->Next();
  if (it_result != 0 || copy_iterator_->IsDone()) {
    *error = it_result;
    FinishCopy();
    return false;
  }

  // Return true to indicate that ContinueCopy should be called again.
  return true;
}

void RecursiveCopyProgress::FinishCopy() {
  DCHECK(!is_done_);
  is_done_ = true;
}

int32_t RecursiveCopyProgress::CreateDirectory(const DirectoryEntry& entry) {
  return samba_interface_->CreateDirectory(
      ConvertToTargetPath(entry.full_path));
}

int32_t RecursiveCopyProgress::StartFileCopy(const DirectoryEntry& entry) {
  DCHECK(!file_progress_);

  file_progress_ = std::make_unique<FileCopyProgress>(samba_interface_);
  int32_t error;
  const bool should_continue_copy = file_progress_->StartCopy(
      entry.full_path, ConvertToTargetPath(entry.full_path), &error);
  if (!should_continue_copy) {
    file_progress_.reset();
  }
  return error;
}

int32_t RecursiveCopyProgress::ContinueFileCopy() {
  DCHECK(file_progress_);

  int32_t error;
  const bool should_continue_copy = file_progress_->ContinueCopy(&error);
  if (!should_continue_copy) {
    // There is no more work to be done. Either the file copy completed
    // successfully or encountered an error and failed.
    file_progress_.reset();
  }
  return error;
}

std::string RecursiveCopyProgress::ConvertToTargetPath(
    const std::string& full_source_path) const {
  DCHECK(base::StartsWith(full_source_path, source_root_,
                          base::CompareCase::INSENSITIVE_ASCII));

  return target_root_ + full_source_path.substr(source_root_.size());
}

void RecursiveCopyProgress::CreateCopySourceIterator() {
  copy_iterator_ =
      std::make_unique<PreDepthFirstIterator>(source_root_, samba_interface_);
}

}  // namespace smbprovider
