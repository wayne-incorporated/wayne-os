// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Wrapper around /etc/os-release and /etc/os-release.d.
// Standard fields can come from both places depending on how we set them. They
// should always be accessed through this interface.

#ifndef LIBBRILLO_BRILLO_OSRELEASE_READER_H_
#define LIBBRILLO_BRILLO_OSRELEASE_READER_H_

#include <string>
#include <vector>

#include <brillo/brillo_export.h>
#include <brillo/key_value_store.h>
#include <gtest/gtest_prod.h>

namespace brillo {

class BRILLO_EXPORT OsReleaseReader final {
 public:
  // Create an empty reader
  OsReleaseReader() = default;
  OsReleaseReader(const OsReleaseReader&) = delete;
  OsReleaseReader& operator=(const OsReleaseReader&) = delete;

  // Loads the key=value pairs from either /etc/os-release.d/<KEY> or
  // /etc/os-release.
  void Load();

  // Same as the private Load method.
  // This need to be public so that services can use it in testing mode (for
  // autotest tests for example).
  // This should not be used in production so suffix it with TestingOnly to
  // make it obvious.
  void LoadTestingOnly(const base::FilePath& root_dir);

  // Getter for the given key. Returns whether the key was found on the store.
  bool GetString(const std::string& key, std::string* value) const;

  // Getter for all the keys in /etc/os-release.
  std::vector<std::string> GetKeys() const;

 private:
  // The map storing all the key-value pairs.
  KeyValueStore store_;

  // os-release can be lazily loaded if need be.
  bool initialized_;

  // Load the data from a given root_dir.
  BRILLO_PRIVATE void Load(const base::FilePath& root_dir);
};

}  // namespace brillo

#endif  // LIBBRILLO_BRILLO_OSRELEASE_READER_H_
