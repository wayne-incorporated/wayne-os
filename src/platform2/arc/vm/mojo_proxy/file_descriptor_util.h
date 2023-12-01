// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ARC_VM_MOJO_PROXY_FILE_DESCRIPTOR_UTIL_H_
#define ARC_VM_MOJO_PROXY_FILE_DESCRIPTOR_UTIL_H_

#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <base/files/scoped_file.h>

namespace base {
class FilePath;
}  // namespace base

namespace arc {

// Creates a pair of pipe file descriptors, and returns it.
// Returns nullopt if failed.
std::optional<std::pair<base::ScopedFD, base::ScopedFD>> CreatePipe();

// Creates a pair of socketpair file desciprotrs, and returns it.
// Returns nullopt if failed.
std::optional<std::pair<base::ScopedFD, base::ScopedFD>> CreateSocketPair(
    int type);

// Creates a socket at |path|, and starts listening.
base::ScopedFD CreateUnixDomainSocket(const base::FilePath& path);

// Accepts a connection request to |raw_fd|, and returns the connected file
// descriptor.
base::ScopedFD AcceptSocket(int raw_fd);

// Connects to a unix domain socket at |path|. Returns errno (which is 0 on
// success), and the connected fd if succeeded.
// Note: in C++17, the return type should be std::variant<int, base::ScopedFD>.
std::pair<int, base::ScopedFD> ConnectUnixDomainSocket(
    const base::FilePath& path);

// Returns the type of the socket.
int GetSocketType(int fd);

// Calls sendmsg and returns the number of bytes sent on success.
// On error, returns -1 and sets errno appropriately.
ssize_t Sendmsg(int fd,
                const void* buf,
                size_t length,
                const std::vector<base::ScopedFD>& fds);

// Calls recvmsg and returns the number of bytes received on success.
// On error, returns -1 and sets errno appropriately.
ssize_t Recvmsg(int fd,
                void* buf,
                size_t length,
                std::vector<base::ScopedFD>* fds);

}  // namespace arc

#endif  // ARC_VM_MOJO_PROXY_FILE_DESCRIPTOR_UTIL_H_
