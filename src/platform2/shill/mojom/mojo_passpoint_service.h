// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_MOJOM_MOJO_PASSPOINT_SERVICE_H_
#define SHILL_MOJOM_MOJO_PASSPOINT_SERVICE_H_

#include <string>

#include <mojo/public/cpp/bindings/remote_set.h>

#include "mojom/passpoint.mojom.h"
#include "shill/net/ip_address.h"
#include "shill/refptr_types.h"
#include "shill/wifi/wifi_provider.h"

namespace shill {

class Manager;

class MojoPasspointService
    : public chromeos::connectivity::mojom::PasspointService,
      public WiFiProvider::PasspointCredentialsObserver {
 public:
  explicit MojoPasspointService(Manager* manager);
  MojoPasspointService(const MojoPasspointService&) = delete;
  MojoPasspointService& operator=(const MojoPasspointService&) = delete;

  ~MojoPasspointService() override;

  void GetPasspointSubscription(
      const std::string& id,
      GetPasspointSubscriptionCallback callback) override;

  void ListPasspointSubscriptions(
      ListPasspointSubscriptionsCallback callback) override;

  void DeletePasspointSubscription(
      const std::string& id,
      DeletePasspointSubscriptionCallback callback) override;

  void RegisterPasspointListener(
      ::mojo::PendingRemote<
          chromeos::connectivity::mojom::PasspointEventsListener> listener)
      override;

  void OnPasspointCredentialsAdded(
      const PasspointCredentialsRefPtr& creds) override;

  void OnPasspointCredentialsRemoved(
      const PasspointCredentialsRefPtr& creds) override;

 private:
  // CredentialsToSubscription creates a PasspointSubscription from the
  // information contained in a PasspointCredentials.
  chromeos::connectivity::mojom::PasspointSubscriptionPtr
  CredentialsToSubscription(const PasspointCredentialsRefPtr creds);

  // Each listener in |listeners_| will be notified of Passpoint subscription
  // events in the chromeos::connectivity::mojom::PasspointEventListener
  // interface. The RemoteSet manages the lifetime of the endpoints, which are
  // automatically destroyed and removed when the pipe they are bound to is
  // destroyed.
  mojo::RemoteSet<chromeos::connectivity::mojom::PasspointEventsListener>
      listeners_;

  Manager* manager_;
};

}  // namespace shill

#endif  // SHILL_MOJOM_MOJO_PASSPOINT_SERVICE_H_
