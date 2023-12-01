// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include "system-proxy/system_proxy_adaptor.h"

#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/check_op.h>
#include <base/location.h>
#include <base/logging.h>
#include <base/strings/stringprintf.h>
#include <base/time/time.h>
#include <brillo/dbus/dbus_object.h>
#include <brillo/message_loops/message_loop.h>
#include <chromeos/dbus/service_constants.h>
#include <chromeos/patchpanel/dbus/client.h>
#include <dbus/object_proxy.h>

#include "system-proxy/kerberos_client.h"
#include "system-proxy/sandboxed_worker.h"

namespace system_proxy {
namespace {

constexpr int kProxyPort = 3128;
constexpr char kFailedToStartWorkerError[] = "Failed to start worker process";
// Time delay for calling patchpanel::ConnectNamespace(). Patchpanel needs to
// enter the network namespace of the worker process to configure it and fails
// if it's soon after the process starts. See https://crbug.com/1095170 for
// details.
constexpr base::TimeDelta kConnectNamespaceDelay = base::Seconds(1);
constexpr int kNetworkNamespaceReconnectAttempts = 3;

// Serializes |proto| to a vector of bytes.
std::vector<uint8_t> SerializeProto(
    const google::protobuf::MessageLite& proto) {
  std::vector<uint8_t> proto_blob(proto.ByteSizeLong());
  bool result = proto.SerializeToArray(proto_blob.data(), proto_blob.size());
  DCHECK(result);
  return proto_blob;
}

// Parses a proto from an array of bytes |proto_blob|. Returns
// ERROR_PARSE_REQUEST_FAILED on error.
std::string DeserializeProto(const base::Location& from_here,
                             google::protobuf::MessageLite* proto,
                             const std::vector<uint8_t>& proto_blob) {
  if (!proto->ParseFromArray(proto_blob.data(), proto_blob.size())) {
    const std::string error_message = "Failed to parse proto message.";
    LOG(ERROR) << from_here.ToString() << error_message;
    return error_message;
  }
  return "";
}
}  // namespace

SystemProxyAdaptor::SystemProxyAdaptor(
    std::unique_ptr<brillo::dbus_utils::DBusObject> dbus_object)
    : org::chromium::SystemProxyAdaptor(this),
      netns_reconnect_attempts_available_(kNetworkNamespaceReconnectAttempts),
      dbus_object_(std::move(dbus_object)),
      weak_ptr_factory_(this) {
  kerberos_client_ = std::make_unique<KerberosClient>(dbus_object_->GetBus());
}

SystemProxyAdaptor::~SystemProxyAdaptor() = default;

void SystemProxyAdaptor::RegisterAsync(
    brillo::dbus_utils::AsyncEventSequencer::CompletionAction
        completion_callback) {
  RegisterWithDBusObject(dbus_object_.get());
  dbus_object_->RegisterAsync(std::move(completion_callback));
}

std::vector<uint8_t> SystemProxyAdaptor::SetAuthenticationDetails(
    const std::vector<uint8_t>& request_blob) {
  LOG(INFO) << "Received set authentication details request.";

  SetAuthenticationDetailsRequest request;
  std::string error_message =
      DeserializeProto(FROM_HERE, &request, request_blob);

  SetAuthenticationDetailsResponse response;
  if (!error_message.empty()) {
    response.set_error_message(error_message);
    return SerializeProto(response);
  }

  if (IncludesSystemTraffic(request.traffic_type())) {
    SetAuthenticationDetails(request, /*user_traffic=*/false, &error_message);
  }
  if (IncludesUserTraffic(request.traffic_type())) {
    SetAuthenticationDetails(request, /*user_traffic=*/true, &error_message);
  }
  if (!error_message.empty()) {
    response.set_error_message(error_message);
  }
  return SerializeProto(response);
}

void SystemProxyAdaptor::SetAuthenticationDetails(
    SetAuthenticationDetailsRequest auth_details,
    bool user_traffic,
    std::string* error_message) {
  SandboxedWorker* worker = CreateWorkerIfNeeded(user_traffic);
  if (!worker) {
    error_message->append(kFailedToStartWorkerError);
    return;
  }

  if (auth_details.has_credentials() || auth_details.has_protection_space()) {
    worker::Credentials credentials;
    if (auth_details.has_protection_space()) {
      worker::ProtectionSpace protection_space;
      protection_space.set_origin(auth_details.protection_space().origin());
      protection_space.set_scheme(auth_details.protection_space().scheme());
      protection_space.set_realm(auth_details.protection_space().realm());
      *credentials.mutable_protection_space() = protection_space;
    }

    if (auth_details.has_credentials()) {
      system_proxy::Credentials dbus_cred = auth_details.credentials();
      if (dbus_cred.has_username() && dbus_cred.has_password()) {
        credentials.set_username(dbus_cred.username());
        credentials.set_password(dbus_cred.password());
        credentials.mutable_policy_credentials_auth_schemes()->Swap(
            dbus_cred.mutable_policy_credentials_auth_schemes());
      }
    }

    brillo::MessageLoop::current()->PostTask(
        FROM_HERE,
        base::BindOnce(&SystemProxyAdaptor::SetCredentialsTask,
                       weak_ptr_factory_.GetWeakPtr(), worker, credentials));
  }
  if (auth_details.has_kerberos_enabled()) {
    std::string principal_name = auth_details.has_active_principal_name()
                                     ? auth_details.active_principal_name()
                                     : std::string();

    brillo::MessageLoop::current()->PostTask(
        FROM_HERE,
        base::BindOnce(&SystemProxyAdaptor::SetKerberosEnabledTask,
                       weak_ptr_factory_.GetWeakPtr(), worker,
                       auth_details.kerberos_enabled(), principal_name));
  }
}

std::vector<uint8_t> SystemProxyAdaptor::ClearUserCredentials(
    const std::vector<uint8_t>& request_blob) {
  LOG(INFO) << "Received request to clear user credentials.";
  std::string error_message;
  ClearUserCredentials(/*user_traffic=*/false, &error_message);
  ClearUserCredentials(/*user_traffic=*/true, &error_message);

  ClearUserCredentialsResponse response;
  if (!error_message.empty())
    response.set_error_message(error_message);
  return SerializeProto(response);
}

void SystemProxyAdaptor::ClearUserCredentials(bool user_traffic,
                                              std::string* error_message) {
  SandboxedWorker* worker = GetWorker(user_traffic);
  if (!worker) {
    return;
  }
  if (!worker->ClearUserCredentials()) {
    error_message->append(
        base::StringPrintf("Failure to clear user credentials for worker with "
                           "pid %s. Restarting worker.",
                           std::to_string(worker->pid()).c_str()));
    ResetWorker(user_traffic);
    CreateWorkerIfNeeded(user_traffic);
  }
}

std::vector<uint8_t> SystemProxyAdaptor::ShutDownProcess(
    const std::vector<uint8_t>& request_blob) {
  LOG(INFO) << "Received shutdown request.";
  ShutDownRequest request;
  std::string error_message =
      DeserializeProto(FROM_HERE, &request, request_blob);

  if (IncludesSystemTraffic(request.traffic_type()) &&
      !ResetWorker(/* user_traffic=*/false)) {
    error_message =
        "Failure to terminate worker process for system services traffic.";
  }

  if (IncludesUserTraffic(request.traffic_type()) &&
      !ResetWorker(/* user_traffic=*/true)) {
    error_message += "Failure to terminate worker process for arc traffic.";
  }

  ShutDownResponse response;
  if (!error_message.empty())
    response.set_error_message(error_message);

  if (request.traffic_type() == TrafficOrigin::ALL) {
    brillo::MessageLoop::current()->PostTask(
        FROM_HERE, base::BindOnce(&SystemProxyAdaptor::ShutDownTask,
                                  weak_ptr_factory_.GetWeakPtr()));
  }
  return SerializeProto(response);
}

void SystemProxyAdaptor::GetChromeProxyServersAsync(
    const std::string& target_url,
    brillo::http::GetChromeProxyServersCallback callback) {
  brillo::http::GetChromeProxyServersWithOverrideAsync(
      dbus_object_->GetBus(), target_url,
      brillo::http::SystemProxyOverride::kOptOut, std::move(callback));
}

std::unique_ptr<SandboxedWorker> SystemProxyAdaptor::CreateWorker() {
  return std::make_unique<SandboxedWorker>(weak_ptr_factory_.GetWeakPtr());
}

SandboxedWorker* SystemProxyAdaptor::CreateWorkerIfNeeded(bool user_traffic) {
  SandboxedWorker* worker = GetWorker(user_traffic);
  if (worker) {
    // A worker for traffic indicated by |user_traffic| already exists.
    return worker;
  }
  SetWorker(user_traffic, CreateWorker());
  worker = GetWorker(user_traffic);

  if (!worker->Start()) {
    ResetWorker(user_traffic);
    return nullptr;
  }
  // patchpanel_proxy is owned by |dbus_object_->bus_|.
  dbus::ObjectProxy* patchpanel_proxy = dbus_object_->GetBus()->GetObjectProxy(
      patchpanel::kPatchPanelServiceName,
      dbus::ObjectPath(patchpanel::kPatchPanelServicePath));
  patchpanel_proxy->WaitForServiceToBeAvailable(
      base::BindOnce(&SystemProxyAdaptor::OnPatchpanelServiceAvailable,
                     weak_ptr_factory_.GetWeakPtr(), user_traffic));
  return worker;
}

void SystemProxyAdaptor::SetCredentialsTask(
    SandboxedWorker* worker, const worker::Credentials& credentials) {
  DCHECK(worker);
  worker->SetCredentials(credentials);
}

void SystemProxyAdaptor::SetKerberosEnabledTask(
    SandboxedWorker* worker,
    bool kerberos_enabled,
    const std::string& principal_name) {
  DCHECK(worker);
  worker->SetKerberosEnabled(kerberos_enabled,
                             kerberos_client_->krb5_conf_path(),
                             kerberos_client_->krb5_ccache_path());
  kerberos_client_->SetKerberosEnabled(kerberos_enabled);
  if (kerberos_enabled) {
    kerberos_client_->SetPrincipalName(principal_name);
  }
}

void SystemProxyAdaptor::ShutDownTask() {
  brillo::MessageLoop::current()->BreakLoop();
}

void SystemProxyAdaptor::SetWorker(bool user_traffic,
                                   std::unique_ptr<SandboxedWorker> worker) {
  if (user_traffic) {
    arc_worker_ = std::move(worker);
  } else {
    system_services_worker_ = std::move(worker);
  }
}

bool SystemProxyAdaptor::ResetWorker(bool user_traffic) {
  SandboxedWorker* worker =
      user_traffic ? arc_worker_.get() : system_services_worker_.get();
  if (!worker) {
    return true;
  }
  if (!worker->Stop()) {
    return false;
  }
  if (user_traffic) {
    arc_worker_.reset();
  } else {
    system_services_worker_.reset();
  }
  return true;
}

SandboxedWorker* SystemProxyAdaptor::GetWorker(bool user_traffic) {
  return user_traffic ? arc_worker_.get() : system_services_worker_.get();
}

bool SystemProxyAdaptor::IncludesSystemTraffic(TrafficOrigin traffic_origin) {
  return traffic_origin != TrafficOrigin::USER;
}

bool SystemProxyAdaptor::IncludesUserTraffic(TrafficOrigin traffic_origin) {
  return traffic_origin != TrafficOrigin::SYSTEM;
}

void SystemProxyAdaptor::OnPatchpanelServiceAvailable(bool user_traffic,
                                                      bool is_available) {
  if (!is_available) {
    LOG(ERROR) << "Patchpanel service not available";
    return;
  }
  ConnectNamespace(user_traffic);
}

void SystemProxyAdaptor::ConnectNamespace(bool user_traffic) {
  DCHECK_GT(netns_reconnect_attempts_available_, 0);
  --netns_reconnect_attempts_available_;
  SandboxedWorker* worker = GetWorker(user_traffic);
  DCHECK(worker);
  // TODO(b/160736881, acostinas): Remove the delay after patchpanel
  // implements "ip netns" to create the veth pair across network namespaces.
  brillo::MessageLoop::current()->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&SystemProxyAdaptor::ConnectNamespaceTask,
                     weak_ptr_factory_.GetWeakPtr(), worker, user_traffic),
      kConnectNamespaceDelay);
}

void SystemProxyAdaptor::ConnectNamespaceTask(SandboxedWorker* worker,
                                              bool user_traffic) {
  std::unique_ptr<patchpanel::Client> patchpanel_client =
      patchpanel::Client::New();
  if (!patchpanel_client) {
    LOG(ERROR) << "Failed to open networking service client";
    return;
  }

  // TODO(acostinas): The source will need to be updated to accommodate Crostini
  // when proxy support is added.
  auto traffic_source = user_traffic
                            ? patchpanel::Client::TrafficSource::kArc
                            : patchpanel::Client::TrafficSource::kSystem;
  std::pair<base::ScopedFD, patchpanel::Client::ConnectedNamespace> result =
      patchpanel_client->ConnectNamespace(
          worker->pid(), "" /* outbound_ifname */, user_traffic,
          true /* route_on_vpn */, traffic_source);

  if (!result.first.is_valid()) {
    LOG(ERROR) << "Failed to setup network namespace on attempt "
               << kNetworkNamespaceReconnectAttempts -
                      netns_reconnect_attempts_available_;
    if (netns_reconnect_attempts_available_ > 0) {
      ConnectNamespace(user_traffic);
    }
    return;
  }

  worker->SetNetNamespaceLifelineFd(std::move(result.first));
  if (!worker->SetListeningAddress(result.second.peer_ipv4_address,
                                   kProxyPort)) {
    return;
  }
  OnNamespaceConnected(worker, user_traffic);
}

void SystemProxyAdaptor::OnNamespaceConnected(SandboxedWorker* worker,
                                              bool user_traffic) {
  WorkerActiveSignalDetails details;
  details.set_traffic_origin(user_traffic ? TrafficOrigin::USER
                                          : TrafficOrigin::SYSTEM);
  details.set_local_proxy_url(worker->local_proxy_host_and_port());
  SendWorkerActiveSignal(SerializeProto(details));
}

void SystemProxyAdaptor::RequestAuthenticationCredentials(
    const worker::ProtectionSpace& protection_space,
    bool bad_cached_credentials) {
  AuthenticationRequiredDetails details;
  ProtectionSpace proxy_protection_space;
  proxy_protection_space.set_origin(protection_space.origin());
  proxy_protection_space.set_realm(protection_space.realm());
  proxy_protection_space.set_scheme(protection_space.scheme());
  *details.mutable_proxy_protection_space() = proxy_protection_space;
  details.set_bad_cached_credentials(bad_cached_credentials);
  SendAuthenticationRequiredSignal(SerializeProto(details));
}

}  // namespace system_proxy
