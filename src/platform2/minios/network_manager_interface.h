// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MINIOS_NETWORK_MANAGER_INTERFACE_H_
#define MINIOS_NETWORK_MANAGER_INTERFACE_H_

#include <string>
#include <vector>

#include <base/functional/callback.h>
#include <base/observer_list.h>
#include <base/observer_list_types.h>
#include <brillo/errors/error.h>
#include <brillo/variant_dictionary.h>

namespace minios {

class NetworkManagerInterface {
 public:
  virtual ~NetworkManagerInterface() = default;

  // Network information returned `OnGetNetworks`.
  typedef struct {
    std::string ssid;
    uint8_t strength;
    std::string security;
  } NetworkProperties;

  class Observer : public base::CheckedObserver {
   public:
    ~Observer() override = default;

    // Called when a connection to an SSID has completed/failed.
    virtual void OnConnect(const std::string& ssid, brillo::Error* error) = 0;

    // Called when a network scan is complete with the list of networks names.
    virtual void OnGetNetworks(const std::vector<NetworkProperties>& networks,
                               brillo::Error* error) = 0;

   protected:
    Observer() = default;
  };

  virtual void AddObserver(Observer* observer) {
    observers_.AddObserver(observer);
  }
  virtual void RemoveObserver(Observer* observer) {
    observers_.RemoveObserver(observer);
  }

  // Connects to the given SSID.
  virtual void Connect(const std::string& ssid,
                       const std::string& passphrase) = 0;

  // Scans the available networks.
  virtual void GetNetworks() = 0;

 protected:
  base::ObserverList<Observer> observers_;
};

}  // namespace minios

#endif  // MINIOS_NETWORK_MANAGER_INTERFACE_H__
