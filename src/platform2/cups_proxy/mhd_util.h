// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CUPS_PROXY_MHD_UTIL_H_
#define CUPS_PROXY_MHD_UTIL_H_

#include <memory>

#include <base/files/file_util.h>
#include <microhttpd.h>

#include "cups_proxy/mojo_handler.h"

namespace cups_proxy {

struct MHDResponseDeleter {
  void operator()(MHD_Response* response) { MHD_destroy_response(response); }
};

// Smart ptr wrapper for MHD_Response
using ScopedMHDResponse = std::unique_ptr<MHD_Response, MHDResponseDeleter>;

struct MHDDaemonDeleter {
  void operator()(MHD_Daemon* daemon) { MHD_stop_daemon(daemon); }
};

// Smart ptr wrapper for MHD_daemon
using ScopedMHDDaemon = std::unique_ptr<MHD_Daemon, MHDDaemonDeleter>;

ScopedMHDDaemon StartMHDDaemon(base::ScopedFD fd, MojoHandler* mojo_handler);

}  // namespace cups_proxy

#endif  // CUPS_PROXY_MHD_UTIL_H_
