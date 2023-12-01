// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cups_proxy/mojo_handler.h"

#include <map>
#include <utility>

#include <base/check.h>
#include <base/strings/string_util.h>
#include <base/synchronization/waitable_event.h>
#include <base/task/thread_pool.h>
#include <chromeos/dbus/service_constants.h>

namespace cups_proxy {

namespace {

// Minimum proxy.mojom CupsProxier interface version required.
const int kMinVersionRequired = 1;

std::string ShowHeaders(const IppHeaders& headers) {
  std::vector<std::string> ret;
  for (const auto& header : headers) {
    ret.push_back(base::JoinString({header->key, header->value}, " = "));
  }
  return base::JoinString(ret, ", ");
}

std::string ShowBody(const IppBody& body) {
  std::string s(body.begin(), body.end());
  std::replace_if(
      s.begin(), s.end(), [](char c) -> bool { return c == '\0'; }, '|');
  return s;
}

IppHeaders ConvertHeadersToMojom(
    const std::map<std::string, std::string>& headers) {
  IppHeaders ret;

  for (const auto& header : headers) {
    auto mojom_header = mojom::HttpHeader::New();
    mojom_header->key = header.first;
    mojom_header->value = header.second;
    ret.push_back(std::move(mojom_header));
  }

  return ret;
}

}  // namespace

MojoHandler::MojoHandler() = default;

MojoHandler::~MojoHandler() {
  // The message pipe is bound on the mojo task runner, and it has to be closed
  // on the same task runner which it is bound, so we close the message pipe by
  // calling .reset() on the mojo task runner.
  mojo_task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&mojo::Remote<mojom::CupsProxier>::reset,
                                base::Unretained(&chrome_proxy_)));
}

bool MojoHandler::CreateTaskRunner() {
  mojo_task_runner_ = base::ThreadPool::CreateSingleThreadTaskRunner({});
  return mojo_task_runner_ != nullptr;
}

void MojoHandler::SetupMojoPipe(base::ScopedFD fd,
                                base::OnceClosure error_handler) {
  mojo::IncomingInvitation invitation = mojo::IncomingInvitation::Accept(
      mojo::PlatformChannelEndpoint(mojo::PlatformHandle(std::move(fd))));

  mojo_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&MojoHandler::SetupMojoPipeOnThread,
                     base::Unretained(this), std::move(error_handler),
                     std::move(invitation)));
}

void MojoHandler::SetupMojoPipeOnThread(base::OnceClosure error_handler,
                                        mojo::IncomingInvitation invitation) {
  DCHECK(mojo_task_runner_->BelongsToCurrentThread());
  DCHECK(!chrome_proxy_);

  // Bind primordial message pipe to a CupsProxyService implementation.
  chrome_proxy_.Bind(mojo::PendingRemote<mojom::CupsProxier>(
      invitation.ExtractMessagePipe(
          printing::kBootstrapMojoConnectionChannelToken),
      0u /* version */));
  chrome_proxy_.set_disconnect_handler(std::move(error_handler));

  chrome_proxy_.RequireVersion(kMinVersionRequired);

  for (auto& callback : queued_requests_) {
    mojo_task_runner_->PostTask(FROM_HERE, std::move(callback));
  }
  queued_requests_.clear();
  LOG(INFO) << "Mojo connection bootstrapped.";
}

bool MojoHandler::IsInitialized() {
  return chrome_proxy_.is_bound();
}

void MojoHandler::ProxyRequestOnThread(
    const std::string& method,
    const std::string& url,
    const std::string& version,
    IppHeaders headers,
    const IppBody& body,
    mojom::CupsProxier::ProxyRequestCallback callback) {
  DCHECK(mojo_task_runner_->BelongsToCurrentThread());

  if (chrome_proxy_) {
    chrome_proxy_->ProxyRequest(method, url, version, std::move(headers), body,
                                std::move(callback));
  } else {
    LOG(INFO) << "Chrome Proxy is not up yet, queuing the request.";
    queued_requests_.push_back(base::BindOnce(
        &MojoHandler::ProxyRequestOnThread, base::Unretained(this), method, url,
        version, std::move(headers), body, std::move(callback)));
  }
}

IppResponse MojoHandler::ProxyRequestSync(const MHDHttpRequest& request) {
  DCHECK(!mojo_task_runner_->BelongsToCurrentThread());

  const std::string& url = request.url();
  const std::string& method = request.method();
  const std::string& version = request.version();
  IppHeaders headers = ConvertHeadersToMojom(request.headers());
  const IppBody& body = request.body();

  IppResponse response;

  base::WaitableEvent event(base::WaitableEvent::ResetPolicy::MANUAL,
                            base::WaitableEvent::InitialState::NOT_SIGNALED);

  auto callback = base::BindOnce(
      [](IppResponse* response, base::WaitableEvent* event, IppHeaders headers,
         const IppBody& ipp_message, int http_status_code) {
        response->headers = std::move(headers);
        response->body = ipp_message;
        response->http_status_code = http_status_code;
        event->Signal();
      },
      &response, &event);

  DVLOG(2) << "url = " << url << ", method = " << method
           << ", version = " << version;
  DVLOG(2) << "headers = " << ShowHeaders(headers);
  DVLOG(2) << "body = " << ShowBody(body);

  mojo_task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&MojoHandler::ProxyRequestOnThread,
                                base::Unretained(this), method, url, version,
                                std::move(headers), body, std::move(callback)));
  event.Wait();

  DVLOG(2) << "response code = " << response.http_status_code;
  DVLOG(2) << "response headers = " << ShowHeaders(response.headers);
  DVLOG(2) << "response body = " << ShowBody(response.body);

  return response;
}

}  // namespace cups_proxy
