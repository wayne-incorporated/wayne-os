// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/wilco_dtc_supportd/utils/mojo_test_utils.h"

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>
#include <cstdint>
#include <cstring>
#include <utility>

#include <base/check.h>
#include <base/logging.h>
#include <base/posix/eintr_wrapper.h>
#include <diagnostics/wilco_dtc_supportd/utils/mojo_utils.h>

namespace diagnostics {
namespace wilco {

namespace {

// Creates an abstract socket with a unique address.
base::ScopedFD CreateAbstractSocket() {
  // Use autobind feature to avoid having to supply a unique socket address.
  const socklen_t kAddrlen = sizeof(sa_family_t);

  base::ScopedFD fd(
      HANDLE_EINTR(socket(AF_UNIX, SOCK_STREAM, 0 /* protocol */)));
  if (!fd.is_valid())
    return base::ScopedFD();

  sockaddr_un socket_address;
  memset(&socket_address, 0, sizeof(sockaddr_un));
  socket_address.sun_family = AF_UNIX;
  if (HANDLE_EINTR(bind(fd.get(),
                        reinterpret_cast<const sockaddr*>(&socket_address),
                        kAddrlen)) < 0) {
    return base::ScopedFD();
  }

  return fd;
}

// Returns the device ID and inode which the given file descriptor points to.
bool GetFdInfo(int fd, uint64_t* device_id, uint64_t* inode) {
  struct stat fd_stat;
  if (HANDLE_EINTR(fstat(fd, &fd_stat)) < 0) {
    PLOG(ERROR) << "fstat failed for file descriptor " << fd;
    return false;
  }
  *device_id = fd_stat.st_dev;
  *inode = fd_stat.st_ino;
  return true;
}

}  // namespace

FakeMojoFdGenerator::FakeMojoFdGenerator() : fd_(CreateAbstractSocket()) {
  CHECK(fd_.is_valid());
}

FakeMojoFdGenerator::~FakeMojoFdGenerator() = default;

base::ScopedFD FakeMojoFdGenerator::MakeFd() const {
  return base::ScopedFD(HANDLE_EINTR(dup(fd_.get())));
}

bool FakeMojoFdGenerator::IsDuplicateFd(int another_fd) const {
  uint64_t own_device_id = 0;
  uint64_t own_inode = 0;
  uint64_t another_device_id = 0;
  uint64_t another_inode = 0;
  if (!GetFdInfo(fd_.get(), &own_device_id, &own_inode) ||
      !GetFdInfo(another_fd, &another_device_id, &another_inode)) {
    return false;
  }
  return own_device_id == another_device_id && own_inode == another_inode;
}

std::string GetStringFromMojoHandle(mojo::ScopedHandle handle) {
  if (!handle.is_valid())
    return "";
  auto shm_mapping =
      GetReadOnlySharedMemoryMappingFromMojoHandle(std::move(handle));
  DCHECK(shm_mapping.IsValid());
  return std::string(shm_mapping.GetMemoryAs<const char>(),
                     shm_mapping.mapped_size());
}

}  // namespace wilco
}  // namespace diagnostics
