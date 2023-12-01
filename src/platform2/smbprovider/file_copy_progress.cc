// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "smbprovider/file_copy_progress.h"

#include <algorithm>

#include <base/check.h>
#include <base/check_op.h>
#include <base/logging.h>

namespace smbprovider {
namespace {

const off_t kDefaultIterationChunkSize = 4 * 1024 * 1024;

}  // namespace

FileCopyProgress::FileCopyProgress(SambaInterface* samba_interface,
                                   off_t iteration_chunk_size)
    : samba_interface_(samba_interface),
      iteration_chunk_size_(iteration_chunk_size) {}

FileCopyProgress::FileCopyProgress(SambaInterface* samba_interface)
    : FileCopyProgress(samba_interface, kDefaultIterationChunkSize) {}

FileCopyProgress::~FileCopyProgress() = default;

bool FileCopyProgress::StartCopy(const std::string& source,
                                 const std::string& target,
                                 int32_t* error) {
  DCHECK(!is_started_);
  is_started_ = true;

  if (!OpenCopySource(source, error) || !OpenCopyTarget(target, error)) {
    FinishCopy();
    return false;
  }

  struct stat source_stat;
  const int32_t stat_result =
      samba_interface_->GetEntryStatus(source, &source_stat);
  if (stat_result != 0) {
    FinishCopy();

    *error = stat_result;
    return false;
  }

  if (source_stat.st_size == 0) {
    // Empty file.
    FinishCopy();

    *error = 0;
    return false;
  }

  bytes_remaining_ = source_stat.st_size;

  return ContinueCopy(error);
}

bool FileCopyProgress::ContinueCopy(int32_t* error) {
  DCHECK(is_started_);
  DCHECK(!is_done_);

  const off_t bytes_to_splice =
      std::min(bytes_remaining_, iteration_chunk_size_);

  DCHECK_GT(bytes_to_splice, 0);
  off_t bytes_spliced;
  int32_t result = samba_interface_->SpliceFile(
      source_fd_, target_fd_, bytes_to_splice, &bytes_spliced);

  if (result != 0) {
    // The copy failed.
    FinishCopy();

    *error = result;
    return false;
  }

  DCHECK_GE(bytes_remaining_, bytes_spliced);
  bytes_remaining_ -= bytes_spliced;

  if (bytes_remaining_ == 0) {
    // The copy is done.
    FinishCopy();

    *error = 0;
    return false;
  }

  // No error and there are |bytes_remaining_| so the copy should be continued.
  return true;
}

bool FileCopyProgress::OpenCopySource(const std::string& file_path,
                                      int32_t* error) {
  *error = samba_interface_->OpenFile(file_path, O_RDONLY, &source_fd_);
  if (*error != 0) {
    return false;
  }
  return true;
}

bool FileCopyProgress::OpenCopyTarget(const std::string& file_path,
                                      int32_t* error) {
  *error = samba_interface_->CreateFile(file_path, &target_fd_);
  if (*error != 0) {
    return false;
  }
  return true;
}

void FileCopyProgress::CloseCopySourceAndTarget() {
  if (source_fd_ >= 0) {
    (void)samba_interface_->CloseFile(source_fd_);
  }
  if (target_fd_ >= 0) {
    (void)samba_interface_->CloseFile(target_fd_);
  }
}

void FileCopyProgress::FinishCopy() {
  is_done_ = true;
  CloseCopySourceAndTarget();
}

}  // namespace smbprovider
