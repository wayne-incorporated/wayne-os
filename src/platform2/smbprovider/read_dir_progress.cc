// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "smbprovider/read_dir_progress.h"

#include <algorithm>

#include <base/check.h>
#include <base/logging.h>
#include <dbus/smbprovider/dbus-constants.h>

#include "smbprovider/constants.h"
#include "smbprovider/metadata_cache.h"

namespace smbprovider {

ReadDirProgress::ReadDirProgress(SambaInterface* samba_interface)
    : ReadDirProgress(samba_interface, kReadDirectoryInitialBatchSize) {}

ReadDirProgress::ReadDirProgress(SambaInterface* samba_interface,
                                 uint32_t initial_batch_size)
    : samba_interface_(samba_interface), batch_size_(initial_batch_size) {}

ReadDirProgress::~ReadDirProgress() = default;

bool ReadDirProgress::StartReadDir(const std::string& directory_path,
                                   MetadataCache* cache,
                                   int32_t* error,
                                   DirectoryEntryListProto* out_entries) {
  DCHECK(cache);
  DCHECK(error);
  DCHECK(out_entries);

  DCHECK(!is_started_);
  is_started_ = true;

  // Purge the cache of expired entries before reading next directory.
  cache->PurgeExpiredEntries();

  DCHECK(!iterator_);
  iterator_ = std::make_unique<CachingIterator>(directory_path,
                                                samba_interface_, cache);

  *error = iterator_->Init();
  if (*error != 0) {
    return false;
  }

  return ContinueReadDir(error, out_entries);
}

bool ReadDirProgress::ContinueReadDir(int32_t* error,
                                      DirectoryEntryListProto* out_entries) {
  DCHECK(error);
  DCHECK(out_entries);

  DCHECK(is_started_);

  out_entries->clear_entries();

  *error = 0;
  uint32_t num_read = 0;
  while (*error == 0 && num_read < batch_size_) {
    if (iterator_->IsDone()) {
      return false;
    }
    AddDirectoryEntry(iterator_->Get(), out_entries);
    ++num_read;
    *error = iterator_->Next();
  }

  // The while-loop is exited from if |batch_size_| has been met or there was an
  // error.

  if (*error != 0) {
    return false;
  }

  IncreaseBatchSize();
  return true;
}

void ReadDirProgress::IncreaseBatchSize() {
  batch_size_ = std::min(batch_size_ * 2, kReadDirectoryMaxBatchSize);
}

}  // namespace smbprovider
