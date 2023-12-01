// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SMBPROVIDER_READ_DIR_PROGRESS_H_
#define SMBPROVIDER_READ_DIR_PROGRESS_H_

#include <memory>
#include <string>
#include <utility>

#include "smbprovider/iterator/caching_iterator.h"
#include "smbprovider/proto.h"
#include "smbprovider/samba_interface.h"

namespace smbprovider {
class DirectoryEntryListProto;
class MetadataCache;

// Keeps track of the progress of a ReadDirectory operation.
//
// A ReadDirectory is started by constructing a ReadDirProgress and calling
// StartReadDir(). The ReadDirectory is continued by calling ContinueReadDir().
class ReadDirProgress {
 public:
  explicit ReadDirProgress(SambaInterface* samba_interface);

  // Allows setting |batch_size_| to a small number for testing.
  ReadDirProgress(SambaInterface* samba_interface, uint32_t initial_batch_size);
  ReadDirProgress(const ReadDirProgress&) = delete;
  ReadDirProgress& operator=(const ReadDirProgress&) = delete;

  ~ReadDirProgress();

  // Starts a ReadDirectory using |iterator|. The first batch of directory
  // entries are returned via |out_entries|. Returns true if ContinueReadDir
  // must be called again. Returns false if the ReadDirectory is complete or has
  // failed. |error| is 0 if the ReadDirectory completed successfully, and errno
  // otherwise.
  bool StartReadDir(const std::string& directory_path,
                    MetadataCache* cache,
                    int32_t* error,
                    DirectoryEntryListProto* out_entries);

  // Continues the ReadDirectory. The next batch of directory entries are
  // returned via |out_entries|. Returns true if ContinueReadDir must be called
  // again. Returns false if the ReadDirectory is complete or has failed.
  // |error| is 0 if the ReadDirectory completed successfully, and errno
  // otherwise.
  bool ContinueReadDir(int32_t* error, DirectoryEntryListProto* out_entries);

 private:
  // Increments |batch_size_|.
  void IncreaseBatchSize();

  SambaInterface* samba_interface_;  // Not owned.
  uint32_t batch_size_;
  std::unique_ptr<CachingIterator> iterator_;
  bool is_started_ = false;
};

}  // namespace smbprovider

#endif  // SMBPROVIDER_READ_DIR_PROGRESS_H_
