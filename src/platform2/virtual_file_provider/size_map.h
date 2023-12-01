// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VIRTUAL_FILE_PROVIDER_SIZE_MAP_H_
#define VIRTUAL_FILE_PROVIDER_SIZE_MAP_H_

#include <map>
#include <stdint.h>
#include <string>

#include <base/synchronization/lock.h>

namespace virtual_file_provider {

// This class manages ID to size mapping.
// This class is thread-safe.
class SizeMap {
 public:
  SizeMap();
  SizeMap(const SizeMap&) = delete;
  SizeMap& operator=(const SizeMap&) = delete;

  ~SizeMap();

  // Sets the size of the specified entry.
  void SetSize(const std::string& id, int64_t size);

  // Returns the size of the specified entry.
  int64_t GetSize(const std::string& id);

  // Erases the size of the specified entry. Returns false if ID is not valid.
  bool Erase(const std::string& id);

 private:
  std::map<std::string, int64_t> id_to_size_;
  base::Lock id_to_size_lock_;
};

}  // namespace virtual_file_provider

#endif  // VIRTUAL_FILE_PROVIDER_SIZE_MAP_H_
