// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LOGIN_MANAGER_LOGIN_SCREEN_STORAGE_H_
#define LOGIN_MANAGER_LOGIN_SCREEN_STORAGE_H_

#include <map>
#include <memory>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/files/scoped_file.h>
#include <brillo/errors/error.h>

#include "login_manager/proto_bindings/login_screen_storage.pb.h"

namespace login_manager {

class LoginScreenStorageIndex;

namespace secret_util {
class SharedMemoryUtil;
}

// Name of the file that keeps an index of the currently stored keys, relative
// to the |persistent_storage_path| passed to the |LoginScreenStorage|.
extern const char kLoginScreenStorageIndexFilename[];

// Provides an interface to store data from the login screen. It serves the two
// following use-cases:
// 1. Injecting user credentials from the login screen into the session. In this
// case, data is stored with a |clear_on_session_exit| flag set to 'true' and
// credentials are deleted on session exit.
// 2. Storing non-sensitive data for access across reboots and login screen
// relaunches. In this case, |clear_on_session_exit| flag is set to 'false' and
// data is stored on disk.
//
// Also, |LoginScreenStorage| only can store data while no user session is
// running (this restriction is enforced by |SessionManagerImpl|). This way we
// ensure that no corrupted user session can modify data that is used by the
// login screen and login screen can always trust the data it has saved using
// this class.
class LoginScreenStorage {
 public:
  explicit LoginScreenStorage(
      const base::FilePath& persistent_storage_path,
      std::unique_ptr<secret_util::SharedMemoryUtil> shared_memory_util);

  // Stores a given key/value pair to the login screen storage. If the given key
  // is already present in the storage (either on disk or in memory), its
  // previous value is deleted. If |metadata.clear_on_session_exit| flag is set
  // to 'true', data is saved to the in-memory storage. Otherwise, data is
  // stored on disk.
  //
  // |value_fd| should contain a value to associate with |key|, |value_size|
  // should contain the size of that value. Values stored in memory will
  // be deleted on SessionManager's exit. In case of failure, returns 'false'
  // and sets |error| accordingly.
  bool Store(brillo::ErrorPtr* error,
             const std::string& key,
             const LoginScreenStorageMetadata& metadata,
             uint64_t value_size,
             const base::ScopedFD& value_fd);

  // Retrieves a value previously stored using |Store()|.
  //
  // If the value is retrieved successfully, this function returns 'true',
  // |out_value_fd| contains the retrieved value and |out_value_size| contains
  // the size of that value in bytes.
  // In case of failure, returns 'false' and sets |error| accordingly.
  bool Retrieve(brillo::ErrorPtr* error,
                const std::string& key,
                uint64_t* out_value_size,
                base::ScopedFD* out_value_fd);

  // Lists all keys currently stored in login screen storage.
  std::vector<std::string> ListKeys();

  // Deletes a previously stored key from the storage.
  void Delete(const std::string& key);

 private:
  // Returns a file path inside of the persistent storage directory that
  // corresponds to a given key.
  base::FilePath GetPersistentStoragePathForKey(const std::string& key);

  // Removes a given key from both persistent and in-memory login screen
  // storages.
  void RemoveKeyFromLoginScreenStorage(LoginScreenStorageIndex* index,
                                       const std::string& key);

  // Reads the index file with all stored keys from disk.
  LoginScreenStorageIndex ReadIndexFromFile();

  // Saves the index of currently stored keys on disk.
  bool WriteIndexToFile(const LoginScreenStorageIndex& index);

  // Create a shared memory region that contains a given data and writes a file
  // descriptor that can be shared with another process to
  // |out_shared_memory_fd|. In case of failure fills |error| accordingly.
  bool CreateSharedMemoryWithData(brillo::ErrorPtr* error,
                                  const std::vector<uint8_t>& data,
                                  base::ScopedFD* out_shared_memory_fd);

  base::FilePath persistent_storage_path_;
  std::unique_ptr<secret_util::SharedMemoryUtil> shared_memory_util_;
  std::map<std::string, std::vector<uint8_t>> in_memory_storage_;
};

}  // namespace login_manager

#endif  // LOGIN_MANAGER_LOGIN_SCREEN_STORAGE_H_
