// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SMBPROVIDER_RECURSIVE_COPY_PROGRESS_H_
#define SMBPROVIDER_RECURSIVE_COPY_PROGRESS_H_

#include <memory>
#include <string>

#include "smbprovider/copy_progress_interface.h"
#include "smbprovider/file_copy_progress.h"
#include "smbprovider/iterator/pre_depth_first_iterator.h"
#include "smbprovider/samba_interface.h"

namespace smbprovider {

// Keeps track of the progress of a CopyDirectory operation.
// Each call to ContinueCopy performs one step of the recursive copy progress
// which is either copying a chunk of data in a file or creating a directory.
class RecursiveCopyProgress : public CopyProgressInterface {
 public:
  explicit RecursiveCopyProgress(SambaInterface* samba_interface);
  RecursiveCopyProgress(const RecursiveCopyProgress&) = delete;
  RecursiveCopyProgress& operator=(const RecursiveCopyProgress&) = delete;

  ~RecursiveCopyProgress() override;

  // CopyProgressInterface overrides.
  bool StartCopy(const std::string& source,
                 const std::string& target,
                 int32_t* error) override;
  bool ContinueCopy(int32_t* error) override;

 private:
  void FinishCopy();

  int32_t CreateDirectory(const DirectoryEntry& entry);

  int32_t StartFileCopy(const DirectoryEntry& entry);

  int32_t ContinueFileCopy();

  std::string ConvertToTargetPath(const std::string& full_path) const;

  // Creates a PreDepthFirstIterator for the source directory at |source_root_|
  // and assigns |copy_iterator_| to it.
  void CreateCopySourceIterator();

  std::unique_ptr<PreDepthFirstIterator> copy_iterator_;
  std::unique_ptr<FileCopyProgress> file_progress_;
  bool is_started_ = false;
  bool is_done_ = false;
  SambaInterface* samba_interface_;  // not owned.
  std::string source_root_;
  std::string target_root_;
};

}  // namespace smbprovider

#endif  // SMBPROVIDER_RECURSIVE_COPY_PROGRESS_H_
