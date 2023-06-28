// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LOGIN_MANAGER_SECRET_UTIL_H_
#define LOGIN_MANAGER_SECRET_UTIL_H_

#include <string>
#include <vector>

#include <base/files/scoped_file.h>
#include <base/files/file_path.h>

#include "libpasswordprovider/password_provider.h"

namespace login_manager {
namespace secret_util {

// Maximum amount of data in bytes that can be sent through shared
// memory using |secret_util| methods.
extern const size_t kSharedMemorySecretSizeLimit;

// Provides methods for reading and writing shared memory. These functions are
// extracted into a class to be mockable from the tests.
class SharedMemoryUtil {
 public:
  virtual ~SharedMemoryUtil();

  // Creates a shared memory region that contains the given data. Returns a file
  // descriptor of that region that can be passed to another process. Returns
  // '-1'in case of failure.
  virtual base::ScopedFD WriteDataToSharedMemory(
      const std::vector<uint8_t>& data);

  // Reads data from the |in_data_fd| shared memory region. Writes the result
  // to |out_data|. Returns 'true' if the data was successfully read, 'false'
  // otherwise.
  // TODO(crbug.com/1124567): change D-Bus generator to generate
  // SessionManagerImpl::LoginScreenStorageStore so that base::ScopedFD instead
  // of const base::ScopedFD& would be used here.
  virtual bool ReadDataFromSharedMemory(const base::ScopedFD& in_data_fd,
                                        size_t data_size,
                                        std::vector<uint8_t>* out_data);
};

// Creates a file descriptor pointing to a pipe that contains the given data.
// The data size (of type |size_t|) will be inserted into the pipe first,
// followed by the actual data. |size_t| value representation follows the host
// byte order.
base::ScopedFD WriteSizeAndDataToPipe(const std::vector<uint8_t>& data);

// Saves secret written in |in_secret_fd| to |provider|. Secret must be
// preceded by |size_t| value representing its length. Returns 'true' if the
// data was successfully read, 'false' otherwise.
bool SaveSecretFromPipe(password_provider::PasswordProviderInterface* provider,
                        const base::ScopedFD& in_secret_fd);

// Gets a SHA256 hash of the given data and returns its hexadicimal
// representation. This is used to generate a unique string that is safe to use
// as a filename.
base::FilePath StringToSafeFilename(std::string data);

}  // namespace secret_util
}  // namespace login_manager

#endif  // LOGIN_MANAGER_SECRET_UTIL_H_
