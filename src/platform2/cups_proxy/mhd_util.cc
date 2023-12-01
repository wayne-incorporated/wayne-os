// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cups_proxy/mhd_util.h"

#include <microhttpd.h>

#include "cups_proxy/mhd_http_request.h"

#include <base/check.h>

namespace cups_proxy {

namespace {

#if MHD_VERSION >= 0x00097002
// libmicrohttpd 0.9.71 broke API
#define MHD_RESULT enum MHD_Result
#else
#define MHD_RESULT int
#endif

// Adds a HTTP header to the MHDHttpRequest.
//
// This is called for each header of the request.
// |cls| is the MHDHttpRequest argument passed from MHD_get_connection_values.
MHD_RESULT AddHeader(void* cls,
                     enum MHD_ValueKind kind,
                     const char* key,
                     const char* value) {
  DCHECK(kind == MHD_HEADER_KIND);
  auto* request = static_cast<MHDHttpRequest*>(cls);
  request->AddHeader(key, value);
  return MHD_YES;
}

// Handles incoming HTTP request.
//
// This function would be called multiple times by MHD with the same |con_cls|
// for a single HTTP request.
//
// For a POST request, the first call would have |con_cls| storing NULL, |url|,
// |method|, |version| from the HTTP header, and empty |upload_data|.
// Then POST data would be incrementally available by calling this function
// multiple times (with data in |upload_data| and a non-zero
// |*upload_data_size|).
// A final call with |*upload_data_size| zero indicates the end of the request.
// Marked as extern "C" because it is called inside a C library.
extern "C" MHD_RESULT AccessHandler(void* cls,
                                    struct MHD_Connection* connection,
                                    const char* url,
                                    const char* method,
                                    const char* version,
                                    const char* upload_data,
                                    size_t* upload_data_size,
                                    void** con_cls) {
  auto* request = static_cast<MHDHttpRequest*>(*con_cls);
  if (request == nullptr) {
    request = new MHDHttpRequest();
    request->SetStatusLine(method, url, version);
    MHD_get_connection_values(connection, MHD_HEADER_KIND, &AddHeader, request);
    *con_cls = request;
    return MHD_YES;
  }

  if (*upload_data_size != 0) {
    request->PushToBody(base::StringPiece(upload_data, *upload_data_size));
    *upload_data_size = 0;
    return MHD_YES;
  }

  request->Finalize();
  auto* mojo_handler = static_cast<MojoHandler*>(cls);
  IppResponse response = mojo_handler->ProxyRequestSync(*request);

  ScopedMHDResponse mhd_resp(MHD_create_response_from_buffer(
      response.body.size(), response.body.data(), MHD_RESPMEM_MUST_COPY));
  if (!mhd_resp) {
    return MHD_NO;
  }

  for (auto& header : response.headers) {
    if (header->key != "Content-Length") {
      MHD_RESULT ret = MHD_add_response_header(
          mhd_resp.get(), header->key.c_str(), header->value.c_str());
      if (ret != MHD_YES) {
        LOG(WARNING) << "Discarding header: " << header->key << "="
                     << header->value;
      }
    }
  }

  MHD_RESULT ret =
      MHD_queue_response(connection, response.http_status_code, mhd_resp.get());
  return ret;
}

// Cleanup the allocated MHDHttpRequest object.
//
// This function is called when the HTTP request is completed.
// Marked as extern "C" because it is called inside a C library.
extern "C" void CleanupRequest(void* cls,
                               struct MHD_Connection* connection,
                               void** con_cls,
                               enum MHD_RequestTerminationCode toe) {
  auto* request = static_cast<MHDHttpRequest*>(*con_cls);
  delete request;
}

}  // namespace

ScopedMHDDaemon StartMHDDaemon(base::ScopedFD fd, MojoHandler* mojo_handler) {
  const struct MHD_OptionItem kOps[] = {
      {MHD_OPTION_LISTEN_SOCKET, fd.release(), NULL},
      {MHD_OPTION_NOTIFY_COMPLETED, reinterpret_cast<intptr_t>(&CleanupRequest),
       NULL},
      {MHD_OPTION_END, 0, NULL}  // MUST stay last option
  };

  return ScopedMHDDaemon(
      MHD_start_daemon(MHD_USE_SELECT_INTERNALLY, 0, NULL, NULL, &AccessHandler,
                       mojo_handler, MHD_OPTION_ARRAY, kOps, MHD_OPTION_END));
}

}  // namespace cups_proxy
