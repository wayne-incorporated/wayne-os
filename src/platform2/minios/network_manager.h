// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MINIOS_NETWORK_MANAGER_H_
#define MINIOS_NETWORK_MANAGER_H_

#include <memory>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include <base/memory/weak_ptr.h>
#include <base/time/time.h>
#include <dbus/shill/dbus-constants.h>
#include <gtest/gtest_prod.h>  // for FRIEND_TEST

#include "minios/network_manager_interface.h"
#include "minios/shill_proxy_interface.h"

namespace minios {

class NetworkManager : public NetworkManagerInterface {
 public:
  // The delay in milliseconds before retrying connection to network.
  static const int kConnectionRetryMsDelay = 500;
  // The delay in milliseconds before checking connection state.
  static const int kCheckConnectionRetryMsDelay = 1000;
  // The number of times to retry scans. We want to retry up to a max of
  // `kMaxNumScanRetries` * `kScanRetryMsDelay` seconds.
  static const int kMaxNumScanRetries = 10;
  // The delay in milliseconds before retrying scanning for networks.
  static constexpr base::TimeDelta kScanRetryMsDelay = base::Milliseconds(500);

  explicit NetworkManager(std::unique_ptr<ShillProxyInterface> shill_proxy);
  virtual ~NetworkManager() = default;

  NetworkManager(const NetworkManager&) = delete;
  NetworkManager& operator=(const NetworkManager&) = delete;

  // NetworkManagerInterface overrides.
  void Connect(const std::string& ssid, const std::string& passphrase) override;
  void GetNetworks() override;

 private:
  friend class NetworkManagerTest;
  FRIEND_TEST(NetworkManagerTest, Connect);
  FRIEND_TEST(NetworkManagerTest, Connect_RequestScanSuccess_NoPassphrase);
  FRIEND_TEST(NetworkManagerTest, Connect_RequestScanSuccess_Passphrase);
  FRIEND_TEST(NetworkManagerTest, Connect_GetServiceSuccess_GoodStrength);
  FRIEND_TEST(NetworkManagerTest, Connect_GetServiceSuccess_NoPassphrase);
  FRIEND_TEST(NetworkManagerTest, Connect_GetServiceSuccess_BadStrength);
  FRIEND_TEST(NetworkManagerTest, Connect_GetServiceSuccess_MissingStrength);
  FRIEND_TEST(NetworkManagerTest,
              Connect_ConnectToNetworkError_InProgressRetriesConnection);
  FRIEND_TEST(NetworkManagerTest,
              Connect_ConnectToNetworkError_AlreadyConnected);
  FRIEND_TEST(NetworkManagerTest,
              Connect_ConnectToNetworkError_OtherErrorResponsesFromShill);
  FRIEND_TEST(NetworkManagerTest,
              Connect_GetServiceCheckConnectionSuccess_FailureState);
  FRIEND_TEST(NetworkManagerTest,
              Connect_GetServiceCheckConnectionSuccess_OnlineState);
  FRIEND_TEST(NetworkManagerTest,
              Connect_GetServiceCheckConnectionSuccess_MissingState);
  FRIEND_TEST(NetworkManagerTest,
              Connect_GetServiceCheckConnectionSuccess_IntermediateState);
  FRIEND_TEST(NetworkManagerTest, GetNetworks);
  FRIEND_TEST(NetworkManagerTest, GetGlobalPropertiesSuccess_MultipleServices);
  FRIEND_TEST(NetworkManagerTest,
              GetGlobalPropertiesSuccess_EmptyServices_DoneRetries);
  FRIEND_TEST(NetworkManagerTest,
              GetGlobalPropertiesSuccess_EmptyServices_Retry);
  FRIEND_TEST(NetworkManagerTest,
              IterateOverServicePropertiesSuccess_EmptyServices);
  FRIEND_TEST(NetworkManagerTest,
              IterateOverServicePropertiesSuccess_OneService);
  FRIEND_TEST(NetworkManagerTest,
              IterateOverServicePropertiesSuccess_MoreServicesToIterate);
  FRIEND_TEST(NetworkManagerTest,
              IterateOverServicePropertiesError_MoreServicesToIterate);
  FRIEND_TEST(NetworkManagerTest,
              IterateOverServicePropertiesError_AlwaysReturnOnEnd);

  typedef struct {
    std::string passphrase;
    // The service path for the SSID.
    dbus::ObjectPath service_path;
  } ConnectField;
  // Mapping from SSID to `ConnectField`.
  using ConnectMapType = std::unordered_map<std::string, ConnectField>;
  using ConnectMapIter = ConnectMapType::iterator;

  typedef struct {
    // The scanned list of services to go over.
    std::vector<dbus::ObjectPath> service_paths;
    // The network names that is built up.
    std::vector<NetworkProperties> networks;
  } GetNetworksField;
  using GetNetworksListType = std::vector<GetNetworksField>;
  using GetNetworksListIter = GetNetworksListType::iterator;

  // Member function types for `*RequestScan()`s.
  using ConnectRequestScanSuccessType =
      void (NetworkManager::*)(ConnectMapIter);
  using ConnectRequestScanErrorType = void (NetworkManager::*)(ConnectMapIter,
                                                               brillo::Error*);
  using GetNetworksRequestScanSuccessType =
      void (NetworkManager::*)(GetNetworksListIter);
  using GetNetworksRequestScanErrorType =
      void (NetworkManager::*)(GetNetworksListIter, brillo::Error*);

  // `Connect()` sequence.
  // `ManagerRequestScan()` callbacks.
  void RequestScanSuccess(ConnectMapIter iter);
  void RequestScanError(ConnectMapIter iter, brillo::Error* error);
  // `ManagerFindMatchingService()` callbacks.
  void FindServiceSuccess(ConnectMapIter iter,
                          const dbus::ObjectPath& service_path);
  void FindServiceError(ConnectMapIter iter, brillo::Error* error);
  // `ServiceGetProperties()` callbacks.
  void GetServiceSuccess(ConnectMapIter iter,
                         const brillo::VariantDictionary& dict);
  void GetServiceError(ConnectMapIter iter, brillo::Error* error);
  // `ServiceSetProperties()` callbacks.
  void ConfigureNetworkSuccess(ConnectMapIter iter);
  void ConfigureNetworkError(ConnectMapIter iter, brillo::Error* error);
  void ServiceConnect(ConnectMapIter iter);
  // `ServiceConnect()` callbacks.
  void ConnectToNetworkSuccess(ConnectMapIter iter);
  void ConnectToNetworkError(ConnectMapIter iter, brillo::Error* error);
  // `ServiceGetProperties()` callbacks on connection sanity check.
  void GetServiceCheckConnectionSuccess(ConnectMapIter iter,
                                        const brillo::VariantDictionary& dict);
  void GetServiceCheckConnectionError(ConnectMapIter iter,
                                      brillo::Error* error);
  // Response helpers for `ConnectMapIter`.
  void Return(ConnectMapIter iter, brillo::Error* error = nullptr);

  // `GetNetworks()` sequence.
  // `ManagerRequestScan()` callbacks.
  void RequestScan(GetNetworksListIter iter);
  void RequestScanSuccess(GetNetworksListIter iter);
  void RequestScanError(GetNetworksListIter iter, brillo::Error* error);
  // `ManagerGetProperties()` callbacks.
  void GetGlobalPropertiesSuccess(GetNetworksListIter iter,
                                  const brillo::VariantDictionary& dict);
  void GetGlobalPropertiesError(GetNetworksListIter iter, brillo::Error* error);
  // `ServiceGetProperties()` callbacks.
  void IterateOverServicePropertiesSuccess(
      GetNetworksListIter iter, const brillo::VariantDictionary& dict);
  void IterateOverServicePropertiesError(GetNetworksListIter iter,
                                         brillo::Error* error);
  // Response helpers for `GetNetworksListIter`.
  void Return(GetNetworksListIter iter, brillo::Error* error = nullptr);

  int num_scan_retries_;
  ConnectMapType connect_map_;
  GetNetworksListType get_networks_list_;

  std::unique_ptr<ShillProxyInterface> shill_proxy_;

  base::WeakPtrFactory<NetworkManager> weak_ptr_factory_;
};

}  // namespace minios

#endif  // MINIOS_NETWORK_MANAGER_H__
