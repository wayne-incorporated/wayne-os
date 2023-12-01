// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ARC_VM_BOOT_NOTIFICATION_SERVER_UTIL_H_
#define ARC_VM_BOOT_NOTIFICATION_SERVER_UTIL_H_

#include <sys/socket.h>

#include <optional>
#include <string>
#include <utility>

#include <base/files/scoped_file.h>

// Returns the length of the corresponding sockaddr_XX structure for the given
// socket family.
socklen_t GetSockLen(sa_family_t family);

// Creates a streaming socket bound to addr and starts listening on the
// socket. If successful, returns a socket in the listening state.
base::ScopedFD StartListening(sockaddr* addr);

// Waits for a client to connect to fd and returns the connected socket.
// client_addr will be populated with the address of the client.
base::ScopedFD WaitForClientConnect(int fd);

// Reads from fd until EOF (read() returns 0). If able to read successfully,
// returns read data as a string. Else, returns empty optional.
std::optional<std::string> ReadFD(int fd);

// Locates the CID key in the given string and returns the CID value if it
// exists, and the |props| string with the CID line removed. Else, returns empty
// optional. This function expects the CID line to be at the beginning of the
// string.
std::optional<std::pair<unsigned int, std::string>> ExtractCidValue(
    const std::string& props);

// Returns the CID of the peer that is connected to |fd|, which must be a
// connected VSOCK socket.
std::optional<unsigned int> GetPeerCid(int fd);

#endif  // ARC_VM_BOOT_NOTIFICATION_SERVER_UTIL_H_
