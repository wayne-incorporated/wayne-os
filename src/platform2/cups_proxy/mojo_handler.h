// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CUPS_PROXY_MOJO_HANDLER_H_
#define CUPS_PROXY_MOJO_HANDLER_H_

#include <string>
#include <vector>

#include <base/files/file_util.h>
#include <base/memory/ref_counted.h>
#include <base/task/single_thread_task_runner.h>
#include <mojo/public/cpp/bindings/remote.h>
#include <mojo/public/cpp/system/invitation.h>

#include "cups_proxy/mhd_http_request.h"
#include "cups_proxy/mojom/proxy.mojom.h"

namespace cups_proxy {

using IppHeaders = std::vector<mojom::HttpHeaderPtr>;
using IppBody = std::vector<uint8_t>;

struct IppResponse {
  int http_status_code;
  IppHeaders headers;
  IppBody body;
};

// MojoHandler handles the mojo connection between the cups_proxy and Chrome.
class MojoHandler {
 public:
  MojoHandler();
  ~MojoHandler();

  // Creates the mojo task runner. Returns true iff the creation succeeds.
  bool CreateTaskRunner();

  // Setup the mojo pipe using the fd, and set error handler.
  void SetupMojoPipe(base::ScopedFD fd, base::OnceClosure error_handler);

  // Returns whether the mojo interface is bounded.
  bool IsInitialized();

  // Sends the request to the mojo pipe, and returns the response
  // synchronously.
  //
  // This calls method ProxyRequest@0 on the mojo interface. If called before
  // the mojo pipe is bound, the request would be queued and send after pipe is
  // bound.
  IppResponse ProxyRequestSync(const MHDHttpRequest& request);

 private:
  // Setup the mojo pipe. This is always called on the mojo thread.
  void SetupMojoPipeOnThread(base::OnceClosure error_handler,
                             mojo::IncomingInvitation invitation);

  // Sends the request to the mojo pipe. This is always called on the mojo
  // thread.
  void ProxyRequestOnThread(const std::string& method,
                            const std::string& url,
                            const std::string& version,
                            IppHeaders headers,
                            const IppBody& body,
                            mojom::CupsProxier::ProxyRequestCallback callback);

  scoped_refptr<base::SingleThreadTaskRunner> mojo_task_runner_;

  // The top-level interface. Empty until it is created & bound to a pipe by
  // BootstrapMojoConnection.
  mojo::Remote<mojom::CupsProxier> chrome_proxy_;

  // Queued requests that come before |chrome_proxy_| is ready.
  std::vector<base::OnceClosure> queued_requests_;
};
}  // namespace cups_proxy

#endif  // CUPS_PROXY_MOJO_HANDLER_H_
