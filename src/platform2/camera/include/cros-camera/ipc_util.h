/*
 * Copyright 2016 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_INCLUDE_CROS_CAMERA_IPC_UTIL_H_
#define CAMERA_INCLUDE_CROS_CAMERA_IPC_UTIL_H_

#include <string>

#include <base/files/scoped_file.h>
#include <base/unguessable_token.h>
#include <mojo/public/c/system/types.h>
#include <mojo/public/cpp/system/message_pipe.h>

#include "cros-camera/export.h"

namespace base {
class FilePath;
}  // namespace base

namespace cros {

CROS_CAMERA_EXPORT bool CreateServerUnixDomainSocket(
    const base::FilePath& socket_path, int* server_listen_fd);

CROS_CAMERA_EXPORT bool ServerAcceptConnection(int server_listen_fd,
                                               int* server_socket);

CROS_CAMERA_EXPORT base::ScopedFD CreateClientUnixDomainSocket(
    const base::FilePath& socket_path);

CROS_CAMERA_EXPORT MojoResult CreateMojoChannelToParentByUnixDomainSocket(
    const base::FilePath& socket_path,
    mojo::ScopedMessagePipeHandle* child_pipe);

CROS_CAMERA_EXPORT MojoResult CreateMojoChannelToChildByUnixDomainSocket(
    const base::FilePath& socket_path,
    mojo::ScopedMessagePipeHandle* parent_pipe,
    const std::string& pipe_name);

CROS_CAMERA_EXPORT std::optional<base::UnguessableToken> TokenFromString(
    const std::string& token_string);

}  // namespace cros

#endif  // CAMERA_INCLUDE_CROS_CAMERA_IPC_UTIL_H_
