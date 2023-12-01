// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "minios/network_manager.h"

#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/strings/stringprintf.h>
#include <brillo/errors/error_codes.h>
#include <brillo/message_loops/message_loop.h>
#include <dbus/shill/dbus-constants.h>

namespace minios {

namespace {
std::string ToString(brillo::Error* error) {
  if (!error)
    return "";
  return base::StringPrintf("code=%s,message=%s", error->GetCode().c_str(),
                            error->GetMessage().c_str());
}
}  // namespace

NetworkManager::NetworkManager(std::unique_ptr<ShillProxyInterface> shill_proxy)
    : num_scan_retries_(0),
      shill_proxy_(std::move(shill_proxy)),
      weak_ptr_factory_(this) {}

void NetworkManager::Connect(const std::string& ssid,
                             const std::string& passphrase) {
  ConnectMapIter iter = connect_map_.find(ssid);
  // Bundle in with the already processing `Connect()`.
  if (iter != connect_map_.end()) {
    return;
  }
  connect_map_[ssid] = ConnectField{.passphrase = passphrase};
  iter = connect_map_.find(ssid);

  shill_proxy_->ManagerRequestScan(
      shill::kTypeWifi,
      base::BindRepeating(static_cast<void (NetworkManager::*)(ConnectMapIter)>(
                              &NetworkManager::RequestScanSuccess),
                          weak_ptr_factory_.GetWeakPtr(), iter),
      base::BindRepeating(
          static_cast<void (NetworkManager::*)(ConnectMapIter, brillo::Error*)>(
              &NetworkManager::RequestScanError),
          weak_ptr_factory_.GetWeakPtr(), iter));
}

void NetworkManager::RequestScanSuccess(ConnectMapIter iter) {
  LOG(INFO) << "RequestScan success for SSID=" << iter->first;

  // If there is no passphrase, default to no security.
  const std::string security = iter->second.passphrase.empty()
                                   ? shill::kSecurityClassNone
                                   : shill::kSecurityClassPsk;
  const brillo::VariantDictionary properties = {
      // Mode needs to be set from supported station type.
      {shill::kModeProperty, brillo::Any(std::string(shill::kModeManaged))},
      {shill::kNameProperty, brillo::Any(iter->first)},
      {shill::kSecurityClassProperty, brillo::Any(security)},
      {shill::kTypeProperty, brillo::Any(std::string(shill::kTypeWifi))},
  };
  shill_proxy_->ManagerFindMatchingService(
      properties,
      base::BindRepeating(&NetworkManager::FindServiceSuccess,
                          weak_ptr_factory_.GetWeakPtr(), iter),
      base::BindRepeating(&NetworkManager::FindServiceError,
                          weak_ptr_factory_.GetWeakPtr(), iter));
}

void NetworkManager::RequestScanError(ConnectMapIter iter,
                                      brillo::Error* error) {
  LOG(ERROR) << "RequestScan failed for SSID=" << iter->first << ": "
             << ToString(error);
  Return(iter, error);
}

void NetworkManager::FindServiceSuccess(ConnectMapIter iter,
                                        const dbus::ObjectPath& service_path) {
  LOG(INFO) << "FindService success for SSID=" << iter->first
            << ": found object path " << service_path.value();
  iter->second.service_path = service_path;
  shill_proxy_->ServiceGetProperties(
      service_path,
      base::BindRepeating(&NetworkManager::GetServiceSuccess,
                          weak_ptr_factory_.GetWeakPtr(), iter),
      base::BindRepeating(&NetworkManager::GetServiceError,
                          weak_ptr_factory_.GetWeakPtr(), iter));
}

void NetworkManager::FindServiceError(ConnectMapIter iter,
                                      brillo::Error* error) {
  LOG(ERROR) << "FindService failed for SSID=" << iter->first << ": "
             << ToString(error);
  Return(iter, error);
}

void NetworkManager::GetServiceSuccess(ConnectMapIter iter,
                                       const brillo::VariantDictionary& dict) {
  LOG(INFO) << "GetService success for SSID=" << iter->first;

  // Check the strength of the service before continuing to connect.
  for (const auto& pr : dict) {
    if (pr.first == shill::kSignalStrengthProperty) {
      const auto& strength =
          brillo::GetVariantValueOrDefault<uint8_t>(dict, pr.first);
      if (strength > 0) {
        brillo::VariantDictionary properties;
        properties.emplace(shill::kAutoConnectProperty, brillo::Any(true));
        // Don't set passphrase property if empty.
        if (!iter->second.passphrase.empty()) {
          properties.emplace(shill::kPassphraseProperty,
                             brillo::Any(iter->second.passphrase));
        }
        // Set the SSID passphrase and proceed with connecting.
        shill_proxy_->ServiceSetProperties(
            iter->second.service_path, properties,
            base::BindRepeating(&NetworkManager::ConfigureNetworkSuccess,
                                weak_ptr_factory_.GetWeakPtr(), iter),
            base::BindRepeating(&NetworkManager::ConfigureNetworkError,
                                weak_ptr_factory_.GetWeakPtr(), iter));
      } else {
        Return(iter,
               brillo::Error::Create(
                   FROM_HERE, brillo::errors::dbus::kDomain, DBUS_ERROR_FAILED,
                   "Strength is too weak to connect for SSID=" + iter->first)
                   .get());
      }
      return;
    }
  }
  Return(iter, brillo::Error::Create(
                   FROM_HERE, brillo::errors::dbus::kDomain, DBUS_ERROR_FAILED,
                   "Strength is missing for SSID=" + iter->first)
                   .get());
}

void NetworkManager::GetServiceError(ConnectMapIter iter,
                                     brillo::Error* error) {
  LOG(ERROR) << "GetService failed for SSID=" << iter->first << ": "
             << ToString(error);
  Return(iter, error);
}

void NetworkManager::ConfigureNetworkSuccess(ConnectMapIter iter) {
  LOG(INFO) << "ConfigureNetwork success for SSID=" << iter->first;
  ServiceConnect(iter);
}

void NetworkManager::ConfigureNetworkError(ConnectMapIter iter,
                                           brillo::Error* error) {
  LOG(ERROR) << "ConfigureNetwork failed for SSID=" << iter->first << ": "
             << ToString(error);
  Return(iter, error);
}

void NetworkManager::ServiceConnect(ConnectMapIter iter) {
  shill_proxy_->ServiceConnect(
      iter->second.service_path,
      base::BindRepeating(&NetworkManager::ConnectToNetworkSuccess,
                          weak_ptr_factory_.GetWeakPtr(), iter),
      base::BindRepeating(&NetworkManager::ConnectToNetworkError,
                          weak_ptr_factory_.GetWeakPtr(), iter));
}

void NetworkManager::ConnectToNetworkSuccess(ConnectMapIter iter) {
  LOG(INFO) << "ConnectToNetwork success for SSID=" << iter->first
            << " proceeding to verify connection.";
  shill_proxy_->ServiceGetProperties(
      iter->second.service_path,
      base::BindRepeating(&NetworkManager::GetServiceCheckConnectionSuccess,
                          weak_ptr_factory_.GetWeakPtr(), iter),
      base::BindRepeating(&NetworkManager::GetServiceCheckConnectionError,
                          weak_ptr_factory_.GetWeakPtr(), iter));
}

void NetworkManager::ConnectToNetworkError(ConnectMapIter iter,
                                           brillo::Error* error) {
  auto error_code = error->GetCode();
  if (error->GetCode() == shill::kErrorResultInProgress) {
    LOG(INFO) << "ConnectToNetwork failed, but connection is in progress for "
              << "SSID=" << iter->first;
    // Try connecting again until connection is not in progress or gets
    // connected.
    brillo::MessageLoop::current()->PostDelayedTask(
        FROM_HERE,
        base::BindOnce(&NetworkManager::ServiceConnect,
                       weak_ptr_factory_.GetWeakPtr(), iter),
        base::Milliseconds(kConnectionRetryMsDelay));
  } else if (error_code == shill::kErrorResultAlreadyConnected) {
    LOG(INFO) << "ConnectToNetwork failed, but already connected for SSID="
              << iter->first;
    Return(iter);
  } else {
    LOG(ERROR) << "ConnectToNetwork failed for SSID=" << iter->first << ": "
               << ToString(error);
    Return(iter, error);
  }
}

void NetworkManager::GetServiceCheckConnectionSuccess(
    ConnectMapIter iter, const brillo::VariantDictionary& dict) {
  for (const auto& [property, any] : dict) {
    if (property == shill::kStateProperty) {
      const auto& state = any.Get<std::string>();
      LOG(INFO) << "GetServiceCheckConnection state is " << state;
      if (state == shill::kStateOnline) {
        Return(iter);
      } else if (state == shill::kStateAssociation ||
                 state == shill::kStateConfiguration ||
                 state == shill::kStateReady) {
        brillo::MessageLoop::current()->PostDelayedTask(
            FROM_HERE,
            base::BindOnce(&NetworkManager::ConnectToNetworkSuccess,
                           weak_ptr_factory_.GetWeakPtr(), iter),
            base::Milliseconds(kCheckConnectionRetryMsDelay));
      } else {
        Return(iter,
               brillo::Error::Create(
                   FROM_HERE, brillo::errors::dbus::kDomain, DBUS_ERROR_FAILED,
                   "Connection failed for SSID=" + iter->first)
                   .get());
      }
      return;
    }
  }
  Return(iter, brillo::Error::Create(
                   FROM_HERE, brillo::errors::dbus::kDomain, DBUS_ERROR_FAILED,
                   "Connection property missing for SSID=" + iter->first)
                   .get());
}

void NetworkManager::GetServiceCheckConnectionError(ConnectMapIter iter,
                                                    brillo::Error* error) {
  LOG(ERROR) << "GetServiceCheckConnection failed for SSID=" << iter->first
             << ": " << ToString(error);
  Return(iter, error);
}

void NetworkManager::Return(ConnectMapIter iter, brillo::Error* error) {
  for (auto& observer : observers_)
    observer.OnConnect(iter->first, error);
  connect_map_.erase(iter);
}

void NetworkManager::GetNetworks() {
  // Bundle in with the already processing `GetNetworks()`.
  if (!get_networks_list_.empty())
    return;

  // `get_networks_list_`'s max size should never exceed a single node.
  GetNetworksListIter iter =
      get_networks_list_.insert(get_networks_list_.end(), GetNetworksField());

  // Reset retry counter before starting scan.
  num_scan_retries_ = kMaxNumScanRetries;
  RequestScan(iter);
}

void NetworkManager::RequestScan(GetNetworksListIter iter) {
  shill_proxy_->ManagerRequestScan(
      shill::kTypeWifi,
      base::BindRepeating(static_cast<GetNetworksRequestScanSuccessType>(
                              &NetworkManager::RequestScanSuccess),
                          weak_ptr_factory_.GetWeakPtr(), iter),
      base::BindRepeating(static_cast<GetNetworksRequestScanErrorType>(
                              &NetworkManager::RequestScanError),
                          weak_ptr_factory_.GetWeakPtr(), iter));
  --num_scan_retries_;
}

void NetworkManager::RequestScanSuccess(GetNetworksListIter iter) {
  LOG(INFO) << "RequestScan success.";
  shill_proxy_->ManagerGetProperties(
      base::BindRepeating(&NetworkManager::GetGlobalPropertiesSuccess,
                          weak_ptr_factory_.GetWeakPtr(), iter),
      base::BindRepeating(&NetworkManager::GetGlobalPropertiesError,
                          weak_ptr_factory_.GetWeakPtr(), iter));
}

void NetworkManager::RequestScanError(GetNetworksListIter iter,
                                      brillo::Error* error) {
  LOG(ERROR) << "RequestScan failed: " << ToString(error);
  Return(iter, error);
}

void NetworkManager::GetGlobalPropertiesSuccess(
    GetNetworksListIter iter, const brillo::VariantDictionary& dict) {
  LOG(INFO) << "GetGlobalProperties success.";
  for (const auto& pr : dict) {
    if (pr.first == shill::kServicesProperty) {
      auto services =
          brillo::GetVariantValueOrDefault<std::vector<dbus::ObjectPath>>(
              dict, pr.first);
      if (services.empty()) {
        break;
      }
      // Move the list of services to read from.
      iter->service_paths.assign(services.begin(), services.end());
      // Start the iterations over each service asynchronously.
      shill_proxy_->ServiceGetProperties(
          iter->service_paths.back(),
          base::BindRepeating(
              &NetworkManager::IterateOverServicePropertiesSuccess,
              weak_ptr_factory_.GetWeakPtr(), iter),
          base::BindRepeating(
              &NetworkManager::IterateOverServicePropertiesError,
              weak_ptr_factory_.GetWeakPtr(), iter));
      iter->service_paths.pop_back();
      return;
    }
  }
  // No services were found. Retry if we can else error out.
  if (num_scan_retries_ > 0) {
    LOG(WARNING) << "No services found - Retrying scan.";
    brillo::MessageLoop::current()->PostDelayedTask(
        FROM_HERE,
        base::BindOnce(&NetworkManager::RequestScan,
                       weak_ptr_factory_.GetWeakPtr(), iter),
        kScanRetryMsDelay);
    return;
  }
  LOG(ERROR) << "No services found.";
  Return(iter,
         brillo::Error::Create(FROM_HERE, brillo::errors::dbus::kDomain,
                               DBUS_ERROR_FAILED, "No network devices found.")
             .get());
}

void NetworkManager::GetGlobalPropertiesError(GetNetworksListIter iter,
                                              brillo::Error* error) {
  LOG(ERROR) << "GetGlobalProperties failed: " << ToString(error);
  Return(iter, error);
}

void NetworkManager::IterateOverServicePropertiesSuccess(
    GetNetworksListIter iter, const brillo::VariantDictionary& dict) {
  LOG(INFO) << "IterateOverServiceProperties success.";

  auto name =
      brillo::GetVariantValueOrDefault<std::string>(dict, shill::kNameProperty);

  // Get the network strength and save the network propertiess if SSID is not
  // empty.
  if (!name.empty()) {
    auto strength = brillo::GetVariantValueOrDefault<uint8_t>(
        dict, shill::kSignalStrengthProperty);
    auto security = brillo::GetVariantValueOrDefault<std::string>(
        dict, shill::kSecurityClassProperty);
    iter->networks.push_back(
        {.ssid = name, .strength = strength, .security = security});
  }

  // Iterated over all services.
  if (iter->service_paths.empty()) {
    Return(iter);
    return;
  }

  // Iterate over the next service.
  shill_proxy_->ServiceGetProperties(
      iter->service_paths.back(),
      base::BindRepeating(&NetworkManager::IterateOverServicePropertiesSuccess,
                          weak_ptr_factory_.GetWeakPtr(), iter),
      base::BindRepeating(&NetworkManager::IterateOverServicePropertiesError,
                          weak_ptr_factory_.GetWeakPtr(), iter));
  iter->service_paths.pop_back();
}

void NetworkManager::IterateOverServicePropertiesError(GetNetworksListIter iter,
                                                       brillo::Error* error) {
  LOG(ERROR) << "IterateOverServiceProperties failed: " << ToString(error);
  if (!iter->service_paths.empty()) {
    shill_proxy_->ServiceGetProperties(
        iter->service_paths.back(),
        base::BindRepeating(
            &NetworkManager::IterateOverServicePropertiesSuccess,
            weak_ptr_factory_.GetWeakPtr(), iter),
        base::BindRepeating(&NetworkManager::IterateOverServicePropertiesError,
                            weak_ptr_factory_.GetWeakPtr(), iter));
    iter->service_paths.pop_back();
    return;
  }
  Return(iter);
}

void NetworkManager::Return(GetNetworksListIter iter, brillo::Error* error) {
  for (auto& observer : observers_)
    observer.OnGetNetworks(iter->networks, error);
  get_networks_list_.clear();
}

}  // namespace minios
