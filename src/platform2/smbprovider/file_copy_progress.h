// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SMBPROVIDER_FILE_COPY_PROGRESS_H_
#define SMBPROVIDER_FILE_COPY_PROGRESS_H_

#include <string>

#include "smbprovider/copy_progress_interface.h"
#include "smbprovider/samba_interface.h"

namespace smbprovider {

// Keeps track of the progress of a CopyFile operation.
class FileCopyProgress : public CopyProgressInterface {
 public:
  explicit FileCopyProgress(SambaInterface* samba_interface);

  // Allows setting of |iteration_chunk_size_| for testing.
  FileCopyProgress(SambaInterface* samba_interface, off_t iteration_chunk_size);
  FileCopyProgress(const FileCopyProgress&) = delete;
  FileCopyProgress& operator=(const FileCopyProgress&) = delete;

  ~FileCopyProgress() override;

  // CopyProgressInterface overrides.
  bool StartCopy(const std::string& source,
                 const std::string& target,
                 int32_t* error) override;
  bool ContinueCopy(int32_t* error) override;

 private:
  // Opens |file_path| to copy from, setting |source_fd_|. Returns 0 on success
  // and errno on failure.
  bool OpenCopySource(const std::string& file_path, int32_t* error);

  // Opens |file_path| to copy to, setting |target_fd_|. Returns 0 on success
  // and errno on failure.
  bool OpenCopyTarget(const std::string& file_path, int32_t* error);

  // Closes |source_fd_| and |target_fd_| if open.
  void CloseCopySourceAndTarget();

  // Closes any open files and sets |is_done_| to true.
  void FinishCopy();

  bool is_started_ = false;
  bool is_done_ = false;
  SambaInterface* samba_interface_;  // not owned.
  const off_t iteration_chunk_size_;
  int32_t source_fd_ = -1;
  int32_t target_fd_ = -1;
  off_t bytes_remaining_;
};

}  // namespace smbprovider

#endif  // SMBPROVIDER_FILE_COPY_PROGRESS_H_
