// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MIDIS_CLIENT_H_
#define MIDIS_CLIENT_H_

#include <memory>
#include <vector>

#include <base/files/scoped_file.h>
#include <base/memory/weak_ptr.h>
#include <brillo/message_loops/message_loop.h>
#include <mojo/public/cpp/bindings/pending_receiver.h>
#include <mojo/public/cpp/bindings/pending_remote.h>
#include <mojo/public/cpp/bindings/receiver.h>
#include <mojo/public/cpp/bindings/remote.h>

#include "midis/device.h"
#include "midis/device_tracker.h"
#include "mojo/midis.mojom.h"

namespace midis {

class Client : public DeviceTracker::Observer, public arc::mojom::MidisServer {
 public:
  using ClientDeletionCallback = base::OnceCallback<void(uint32_t)>;
  Client(DeviceTracker* device_tracker,
         uint32_t client_id,
         ClientDeletionCallback del_cb,
         mojo::PendingReceiver<arc::mojom::MidisServer> receiver,
         mojo::PendingRemote<arc::mojom::MidisClient> client);
  Client(const Client&) = delete;
  Client& operator=(const Client&) = delete;

  ~Client() override;

  void NotifyDeviceAddedOrRemoved(const Device& dev, bool added);

 private:
  // This function is a DeviceTracker::Observer override.
  void OnDeviceAddedOrRemoved(const Device& dev, bool added) override;

  void TriggerClientDeletion();

  // arc::mojom:MidisServer overrides
  void ListDevices(ListDevicesCallback callback) override;
  void RequestPortDeprecated(arc::mojom::MidisRequestPtr request,
                             RequestPortDeprecatedCallback callback) override;
  void RequestPort(arc::mojom::MidisRequestPtr request,
                   RequestPortCallback callback) override;
  void CloseDevice(arc::mojom::MidisRequestPtr request) override;

  // Function which returns a scoped handle when a port is requested,
  // and an empty handle on error. This can be used by both
  // RequestPort and RequestPortDeprecated.
  mojo::ScopedHandle CreateRequestPortFD(uint32_t card,
                                         uint32_t device,
                                         uint32_t subdevice);

  // The DeviceTracker can be guaranteed to exist for the lifetime of the
  // service. As such, it is safe to maintain this pointer as a means to make
  // updates and derive information regarding devices.
  DeviceTracker* device_tracker_;
  uint32_t client_id_;
  ClientDeletionCallback del_cb_;

  // Handle to the Mojo client interface. This is used to send necessary
  // information to the clients when required.
  mojo::Remote<arc::mojom::MidisClient> client_;
  mojo::Receiver<arc::mojom::MidisServer> receiver_;

  base::WeakPtrFactory<Client> weak_factory_;
};

}  // namespace midis

#endif  // MIDIS_CLIENT_H_
