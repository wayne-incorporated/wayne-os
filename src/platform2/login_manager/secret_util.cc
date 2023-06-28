// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "login_manager/secret_util.h"

#include <unistd.h>

#include <utility>

#include <base/check_op.h>
#include <base/file_descriptor_posix.h>
#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/memory/read_only_shared_memory_region.h>
#include <base/process/process_handle.h>
#include <base/strings/string_number_conversions.h>
#include <crypto/sha2.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace login_manager {
namespace secret_util {

namespace {

// Maximum amount of data that can be sent through the pipe using |secret_util|
// methods.
// 64k of data, minus 64 bits for a preceding size. This number was chosen to
// fit all the data in a single pipe buffer and avoid blocking on write.
// (http://man7.org/linux/man-pages/man7/pipe.7.html)
const size_t kPipeSecretSizeLimit = 1024 * 64 - sizeof(size_t);

// Reads |data_size| from the pipe. Returns 'false' if it couldn't read
// |data_size| or if |data_size| was incorrect.
bool GetSecretDataSizeFromPipe(int in_secret_fd, size_t* data_size_out) {
  if (!base::ReadFromFD(in_secret_fd, reinterpret_cast<char*>(data_size_out),
                        sizeof(size_t))) {
    PLOG(ERROR) << "Could not read secret size from file.";
    return false;
  }

  if (*data_size_out == 0 || *data_size_out > kPipeSecretSizeLimit) {
    LOG(ERROR) << "Invalid data size read from file descriptor. Size read: "
               << *data_size_out;
    return false;
  }

  return true;
}

}  // namespace

// Limiting data size to 10MB here because it covers the current use cases,
// it can be increased if needed up to an operating system limit (man 1 lsipc).
const size_t kSharedMemorySecretSizeLimit = 10 * 1024 * 1024;

SharedMemoryUtil::~SharedMemoryUtil() = default;

base::ScopedFD SharedMemoryUtil::WriteDataToSharedMemory(
    const std::vector<uint8_t>& data) {
  size_t data_size = data.size();
  CHECK_LE(data_size, kSharedMemorySecretSizeLimit);
  // Creates a new base::ReadOnlySharedMemoryRegion instance mapped to a
  // base::WritableSharedMemoryMapping, which is the only way to modify the
  // content of the newly created region.
  auto shmem = base::ReadOnlySharedMemoryRegion::Create(data.size());
  if (!shmem.IsValid())
    return base::ScopedFD();
  memcpy(shmem.mapping.GetMemoryAs<uint8_t>(), data.data(), data.size());
  base::subtle::PlatformSharedMemoryRegion platform_shm =
      base::ReadOnlySharedMemoryRegion::TakeHandleForSerialization(
          std::move(shmem.region));
  if (!platform_shm.IsValid())
    return base::ScopedFD();
  return base::ScopedFD(std::move(platform_shm.PassPlatformHandle().fd));
}

bool SharedMemoryUtil::ReadDataFromSharedMemory(
    const base::ScopedFD& in_data_fd,
    size_t data_size,
    std::vector<uint8_t>* out_data) {
  base::ScopedFD dup_in_data_fd(dup(in_data_fd.get()));
  base::ReadOnlySharedMemoryRegion shm_region =
      base::ReadOnlySharedMemoryRegion::Deserialize(
          base::subtle::PlatformSharedMemoryRegion::Take(
              std::move(dup_in_data_fd),
              base::subtle::PlatformSharedMemoryRegion::Mode::kReadOnly,
              data_size, base::UnguessableToken::Create()));
  if (!shm_region.IsValid())
    return false;
  base::ReadOnlySharedMemoryMapping shm_mapping = shm_region.Map();
  if (!shm_mapping.IsValid())
    return false;
  out_data->assign(shm_mapping.GetMemoryAs<uint8_t>(),
                   shm_mapping.GetMemoryAs<uint8_t>() + data_size);
  return true;
}

base::ScopedFD WriteSizeAndDataToPipe(const std::vector<uint8_t>& data) {
  size_t data_size = data.size();
  CHECK_LE(data_size, kPipeSecretSizeLimit);

  int fds[2];
  base::CreateLocalNonBlockingPipe(fds);
  base::ScopedFD read_dbus_fd(fds[0]);
  base::ScopedFD write_scoped_fd(fds[1]);

  base::WriteFileDescriptor(write_scoped_fd.get(),
                            base::as_bytes(base::make_span(&data_size, 1)));
  base::WriteFileDescriptor(write_scoped_fd.get(), data);
  return read_dbus_fd;
}

bool SaveSecretFromPipe(password_provider::PasswordProviderInterface* provider,
                        const base::ScopedFD& in_secret_fd) {
  size_t data_size = 0;
  if (!GetSecretDataSizeFromPipe(in_secret_fd.get(), &data_size))
    return false;

  auto secret = password_provider::Password::CreateFromFileDescriptor(
      in_secret_fd.get(), data_size);

  if (!secret) {
    LOG(ERROR) << "Could not create secret from file descriptor.";
    return false;
  }

  if (!provider->SavePassword(*secret)) {
    LOG(ERROR) << "Could not save secret.";
    return false;
  }

  return true;
}

base::FilePath StringToSafeFilename(std::string data) {
  std::string sha256hash = crypto::SHA256HashString(data);
  return base::FilePath(base::HexEncode(sha256hash.data(), sha256hash.size()));
}

}  // namespace secret_util
}  // namespace login_manager
