// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "system-proxy/sandboxed_worker.h"

#include <inttypes.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/types.h>

#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <base/logging.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <brillo/http/http_transport.h>
#include <chromeos/patchpanel/net_util.h>
#include <google/protobuf/repeated_field.h>

#include "system-proxy/protobuf_util.h"
#include "system-proxy/system_proxy_adaptor.h"

namespace {
constexpr char kSystemProxyWorkerBin[] = "/usr/sbin/system_proxy_worker";
constexpr char kSeccompFilterPath[] =
    "/usr/share/policy/system-proxy-worker-seccomp.policy";
constexpr int kMaxWorkerMessageSize = 4096;
// Size of the buffer array used to read data from the worker's stderr.
constexpr int kWorkerBufferSize = 1024;
constexpr char kPrefixDirect[] = "direct://";
constexpr char kPrefixHttp[] = "http://";
}  // namespace

namespace system_proxy {

SandboxedWorker::SandboxedWorker(base::WeakPtr<SystemProxyAdaptor> adaptor)
    : jail_(minijail_new()), adaptor_(adaptor), pid_(0) {}

bool SandboxedWorker::Start() {
  DCHECK(!IsRunning()) << "Worker is already running.";

  if (!jail_)
    return false;

  minijail_namespace_pids(jail_.get());
  minijail_namespace_net(jail_.get());
  minijail_no_new_privs(jail_.get());
  minijail_use_seccomp_filter(jail_.get());
  minijail_parse_seccomp_filters(jail_.get(), kSeccompFilterPath);
  // Required to forward SIGTERM to the child process.
  minijail_forward_signals(jail_.get());
  // Resets the signal mask to ensure signals are not unintentionally blocked.
  minijail_reset_signal_mask(jail_.get());
  // Resets the signal handlers to the default behaviours. This is needed so
  // that the child process terminates when receiving the SIGTERM signal.
  minijail_reset_signal_handlers(jail_.get());

  int child_stdin = -1, child_stdout = -1, child_stderr = -1;

  std::vector<char*> args_ptr;

  args_ptr.push_back(const_cast<char*>(kSystemProxyWorkerBin));
  args_ptr.push_back(nullptr);

  // Execute the command.
  int res =
      minijail_run_pid_pipes(jail_.get(), args_ptr[0], args_ptr.data(), &pid_,
                             &child_stdin, &child_stdout, &child_stderr);

  if (res != 0) {
    LOG(ERROR) << "Failed to start sandboxed worker: " << strerror(-res);
    return false;
  }

  stdin_pipe_.reset(child_stdin);
  stdout_pipe_.reset(child_stdout);
  stderr_pipe_.reset(child_stderr);

  stdout_watcher_ = base::FileDescriptorWatcher::WatchReadable(
      stdout_pipe_.get(),
      base::BindRepeating(&SandboxedWorker::OnMessageReceived,
                          base::Unretained(this)));

  stderr_watcher_ = base::FileDescriptorWatcher::WatchReadable(
      stderr_pipe_.get(), base::BindRepeating(&SandboxedWorker::OnErrorReceived,
                                              base::Unretained(this)));
  return true;
}

void SandboxedWorker::SetCredentials(const worker::Credentials& credentials) {
  worker::WorkerConfigs configs;
  *configs.mutable_credentials() = credentials;
  if (!WriteProtobuf(stdin_pipe_.get(), configs)) {
    LOG(ERROR) << "Failed to set credentials for worker " << pid_;
  }
}

bool SandboxedWorker::SetListeningAddress(const net_base::IPv4Address& addr,
                                          int port) {
  worker::SocketAddress address;
  address.set_addr(addr.ToByteString());
  address.set_port(port);
  worker::WorkerConfigs configs;
  *configs.mutable_listening_address() = address;

  if (!WriteProtobuf(stdin_pipe_.get(), configs)) {
    LOG(ERROR) << "Failed to set local proxy address for worker " << pid_;
    return false;
  }
  local_proxy_host_and_port_ =
      base::StringPrintf("%s:%d", addr.ToString().c_str(), port);
  LOG(INFO) << "Set proxy address " << local_proxy_host_and_port_
            << " for worker " << pid_;
  return true;
}

bool SandboxedWorker::SetKerberosEnabled(bool enabled,
                                         const std::string& krb5_conf_path,
                                         const std::string& krb5_ccache_path) {
  worker::KerberosConfig kerberos_config;
  kerberos_config.set_enabled(enabled);
  kerberos_config.set_krb5cc_path(krb5_ccache_path);
  kerberos_config.set_krb5conf_path(krb5_conf_path);
  worker::WorkerConfigs configs;
  *configs.mutable_kerberos_config() = kerberos_config;

  if (!WriteProtobuf(stdin_pipe_.get(), configs)) {
    LOG(ERROR) << "Failed to set kerberos enabled for worker " << pid_;
    return false;
  }
  return true;
}

bool SandboxedWorker::ClearUserCredentials() {
  worker::ClearUserCredentials clear_user_credentials;
  worker::WorkerConfigs configs;
  *configs.mutable_clear_user_credentials() = clear_user_credentials;

  if (!WriteProtobuf(stdin_pipe_.get(), configs)) {
    LOG(ERROR) << "Failed to send request to clear user credentials for worker "
               << pid_;
    return false;
  }
  return true;
}

bool SandboxedWorker::Stop() {
  if (is_being_terminated_)
    return true;
  LOG(INFO) << "Killing " << pid_;
  is_being_terminated_ = true;

  if (kill(pid_, SIGTERM) < 0) {
    if (errno == ESRCH) {
      // No process or group found for pid, assume already terminated.
      return true;
    }
    PLOG(ERROR) << "Failed to terminate process " << pid_;
    return false;
  }
  return true;
}

bool SandboxedWorker::IsRunning() {
  return pid_ != 0 && !is_being_terminated_;
}

void SandboxedWorker::OnMessageReceived() {
  worker::WorkerRequest request;

  if (!ReadProtobuf(stdout_pipe_.get(), &request)) {
    LOG(ERROR) << "Failed to read request from worker " << pid_;
    // The message is corrupted or the pipe closed, either way stop listening.
    stdout_watcher_ = nullptr;
    return;
  }
  if (request.has_log_request()) {
    LOG(INFO) << "[worker: " << pid_ << "]" << request.log_request().message();
  }

  if (request.has_proxy_resolution_request()) {
    const worker::ProxyResolutionRequest& proxy_request =
        request.proxy_resolution_request();

    // This callback will always be called with at least one proxy entry. Even
    // if the dbus call itself fails, the proxy server list will contain the
    // direct proxy.
    adaptor_->GetChromeProxyServersAsync(
        proxy_request.target_url(),
        base::BindRepeating(&SandboxedWorker::OnProxyResolved,
                            weak_ptr_factory_.GetWeakPtr(),
                            proxy_request.target_url()));
  }
  if (request.has_auth_required_request()) {
    const worker::AuthRequiredRequest& auth_request =
        request.auth_required_request();
    adaptor_->RequestAuthenticationCredentials(
        auth_request.protection_space(), auth_request.bad_cached_credentials());
  }
}

void SandboxedWorker::SetNetNamespaceLifelineFd(
    base::ScopedFD net_namespace_lifeline_fd) {
  // Sanity check that only one network namespace is setup for the worker
  // process.
  DCHECK(!net_namespace_lifeline_fd_.is_valid());
  net_namespace_lifeline_fd_ = std::move(net_namespace_lifeline_fd);
}

void SandboxedWorker::OnErrorReceived() {
  std::vector<char> buf;
  buf.resize(kWorkerBufferSize);

  std::string message;
  std::string worker_msg = "[worker: " + std::to_string(pid_) + "] ";

  ssize_t count = kWorkerBufferSize;
  ssize_t total_count = 0;

  while (count == kWorkerBufferSize) {
    count = HANDLE_EINTR(read(stderr_pipe_.get(), buf.data(), buf.size()));

    if (count < 0) {
      PLOG(ERROR) << worker_msg << "Failed to read from stdio";
      return;
    }

    if (count == 0) {
      if (!message.empty())
        break;  // Full message was read at the first iteration.

      PLOG(INFO) << worker_msg << "Pipe closed";
      // Stop watching, otherwise the handler will fire forever.
      stderr_watcher_ = nullptr;
    }

    total_count += count;
    if (total_count > kMaxWorkerMessageSize) {
      LOG(ERROR) << "Failure to read message from woker: message size exceeds "
                    "maximum allowed";
      stderr_watcher_ = nullptr;
      return;
    }
    message.append(buf.begin(), buf.begin() + count);
  }

  LOG(ERROR) << worker_msg << message;
}

void SandboxedWorker::OnProxyResolved(
    const std::string& target_url,
    bool success,
    const std::vector<std::string>& proxy_servers) {
  worker::ProxyResolutionReply reply;
  reply.set_target_url(target_url);

  // Only http and direct proxies are supported at the moment.
  for (const auto& proxy : proxy_servers) {
    if (base::StartsWith(proxy, kPrefixHttp,
                         base::CompareCase::INSENSITIVE_ASCII) ||
        base::StartsWith(proxy, kPrefixDirect,
                         base::CompareCase::INSENSITIVE_ASCII)) {
      reply.add_proxy_servers(proxy);
    }
  }

  worker::WorkerConfigs configs;
  *configs.mutable_proxy_resolution_reply() = reply;

  if (!WriteProtobuf(stdin_pipe_.get(), configs)) {
    LOG(ERROR) << "Failed to send proxy resolution reply to worker" << pid_;
  }
}

}  // namespace system_proxy
