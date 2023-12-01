// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#ifndef SYSTEM_PROXY_SYSTEM_PROXY_ADAPTOR_H_
#define SYSTEM_PROXY_SYSTEM_PROXY_ADAPTOR_H_

#include <memory>
#include <string>
#include <vector>

#include <base/memory/weak_ptr.h>
#include <brillo/dbus/async_event_sequencer.h>
#include <brillo/http/http_proxy.h>
#include <gtest/gtest_prod.h>  // for FRIEND_TEST

#include "bindings/worker_common.pb.h"
#include "system_proxy/org.chromium.SystemProxy.h"
#include "system_proxy/proto_bindings/system_proxy_service.pb.h"

namespace brillo {
namespace dbus_utils {
class DBusObject;
}

}  // namespace brillo

namespace system_proxy {

class KerberosClient;
class SandboxedWorker;

// Implementation of the SystemProxy D-Bus interface.
class SystemProxyAdaptor : public org::chromium::SystemProxyAdaptor,
                           public org::chromium::SystemProxyInterface {
 public:
  explicit SystemProxyAdaptor(
      std::unique_ptr<brillo::dbus_utils::DBusObject> dbus_object);
  SystemProxyAdaptor(const SystemProxyAdaptor&) = delete;
  SystemProxyAdaptor& operator=(const SystemProxyAdaptor&) = delete;
  virtual ~SystemProxyAdaptor();

  // Registers the D-Bus object and interfaces.
  void RegisterAsync(brillo::dbus_utils::AsyncEventSequencer::CompletionAction
                         completion_callback);

  // org::chromium::SystemProxyInterface: (see org.chromium.SystemProxy.xml).
  std::vector<uint8_t> SetAuthenticationDetails(
      const std::vector<uint8_t>& request_blob) override;
  std::vector<uint8_t> ClearUserCredentials(
      const std::vector<uint8_t>& request_blob) override;
  std::vector<uint8_t> ShutDownProcess(
      const std::vector<uint8_t>& request_blob) override;

  void GetChromeProxyServersAsync(
      const std::string& target_url,
      brillo::http::GetChromeProxyServersCallback callback);

  void RequestAuthenticationCredentials(
      const worker::ProtectionSpace& protection_space,
      bool bad_cached_credentials);

 protected:
  virtual std::unique_ptr<SandboxedWorker> CreateWorker();
  virtual void ConnectNamespace(bool user_traffic);
  // Triggers the |WorkerActive| signal.
  void OnNamespaceConnected(SandboxedWorker* worker, bool user_traffic);
  // Returns a pointer to the worker process associated with |user_traffic|. Can
  // return nullptr.
  SandboxedWorker* GetWorker(bool user_traffic);

 private:
  friend class SystemProxyAdaptorTest;
  FRIEND_TEST(SystemProxyAdaptorTest, SetAuthenticationDetails);
  FRIEND_TEST(SystemProxyAdaptorTest,
              SetAuthenticationDetailsOnlySystemTraffic);
  FRIEND_TEST(SystemProxyAdaptorTest, KerberosEnabled);
  FRIEND_TEST(SystemProxyAdaptorTest, ShutDownProcess);
  FRIEND_TEST(SystemProxyAdaptorTest, ShutDownArc);
  FRIEND_TEST(SystemProxyAdaptorTest, ConnectNamespace);
  FRIEND_TEST(SystemProxyAdaptorTest, ProxyResolutionFilter);
  FRIEND_TEST(SystemProxyAdaptorTest, ProtectionSpaceAuthenticationRequired);
  FRIEND_TEST(SystemProxyAdaptorTest, ProtectionSpaceNoCredentials);
  FRIEND_TEST(SystemProxyAdaptorTest, ClearUserCredentials);
  FRIEND_TEST(SystemProxyAdaptorTest, ClearUserCredentialsRestartService);

  void SetCredentialsTask(SandboxedWorker* worker,
                          const worker::Credentials& credentials);

  void SetKerberosEnabledTask(SandboxedWorker* worker,
                              bool kerberos_enabled,
                              const std::string& principal_name);

  void ShutDownTask();

  void ConnectNamespaceTask(SandboxedWorker* worker, bool user_traffic);

  // Terminates the worker process for traffic indicated by |user_traffic| and
  // frees the SandboxedWorker associated with it.
  bool ResetWorker(bool user_traffic);

  void SetWorker(bool user_traffic, std::unique_ptr<SandboxedWorker> worker);

  // Return true if |traffic_origin| represents the traffic originating from
  // system services or if it includes all traffic.
  bool IncludesSystemTraffic(TrafficOrigin traffic_origin);
  // Return true if |traffic_origin| represents the traffic originating from ARC
  // or if it includes all traffic.
  bool IncludesUserTraffic(TrafficOrigin traffic_origin);

  // Checks if a worker process exists and if not creates one and sends a
  // request to patchpanel to setup the network namespace for it. Returns true
  // if the worker exists or was created successfully, false otherwise.
  SandboxedWorker* CreateWorkerIfNeeded(bool user_traffic);

  // If setting the authentication details to |worker| fails, it  updates
  // |error_message| with an appropriate error message.
  void SetAuthenticationDetails(SetAuthenticationDetailsRequest auth_details,
                                bool user_traffic,
                                std::string* error_message);

  // Sends a request to the worker process associated with |user_traffic| to
  // clear the cached user credentials. If sending the request fails, the worker
  // will be restarted.
  void ClearUserCredentials(bool user_traffic, std::string* error_message);

  // Called when the patchpanel D-Bus service becomes available.
  void OnPatchpanelServiceAvailable(bool user_traffic, bool is_available);

  // The callback of |GetChromeProxyServersAsync|.
  void OnGetProxyServers(bool success, const std::vector<std::string>& servers);

  // The number of tries left for setting up the network namespace of the
  // System-proxy worker for system traffic. TODO(acostinas, b/160736881) Remove
  // when patchpaneld creates the veth pair directly across the host and worker
  // network namespaces.
  int netns_reconnect_attempts_available_;

  // Worker that authenticates and forwards to a remote web proxy traffic
  // coming form Chrome OS system services.
  std::unique_ptr<SandboxedWorker> system_services_worker_;
  // Worker that authenticates and forwards to a remote web proxy traffic
  // coming form ARC++ apps.
  std::unique_ptr<SandboxedWorker> arc_worker_;
  std::unique_ptr<KerberosClient> kerberos_client_;

  std::unique_ptr<brillo::dbus_utils::DBusObject> dbus_object_;
  base::WeakPtrFactory<SystemProxyAdaptor> weak_ptr_factory_;
};

}  // namespace system_proxy
#endif  // SYSTEM_PROXY_SYSTEM_PROXY_ADAPTOR_H_
