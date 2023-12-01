// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <midis/client.h>

#include <sys/socket.h>

#include <utility>

#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/posix/eintr_wrapper.h>
#include <mojo/public/cpp/system/handle.h>
#include <mojo/public/cpp/system/platform_handle.h>

#include "midis/constants.h"

namespace midis {

Client::Client(DeviceTracker* device_tracker,
               uint32_t client_id,
               ClientDeletionCallback del_cb,
               mojo::PendingReceiver<arc::mojom::MidisServer> receiver,
               mojo::PendingRemote<arc::mojom::MidisClient> client)
    : device_tracker_(device_tracker),
      client_id_(client_id),
      del_cb_(std::move(del_cb)),
      client_(std::move(client)),
      receiver_(this, std::move(receiver)),
      weak_factory_(this) {
  device_tracker_->AddDeviceObserver(this);
  receiver_.set_disconnect_handler(base::BindOnce(
      &Client::TriggerClientDeletion, weak_factory_.GetWeakPtr()));
}

Client::~Client() {
  LOG(INFO) << "Deleting client: " << client_id_;
  device_tracker_->RemoveDeviceObserver(this);
}

void Client::TriggerClientDeletion() {
  brillo::MessageLoop::TaskId ret_id = brillo::MessageLoop::current()->PostTask(
      FROM_HERE, base::BindOnce(std::move(del_cb_), client_id_));
  if (ret_id == brillo::MessageLoop::kTaskIdNull) {
    LOG(ERROR) << "Couldn't schedule the client deletion callback!";
  }
}

void Client::OnDeviceAddedOrRemoved(const Device& dev, bool added) {
  arc::mojom::MidisDeviceInfoPtr dev_info = arc::mojom::MidisDeviceInfo::New();
  dev_info->card = dev.GetCard();
  dev_info->device_num = dev.GetDeviceNum();
  dev_info->num_subdevices = dev.GetNumSubdevices();
  dev_info->name = dev.GetName();
  dev_info->manufacturer = dev.GetManufacturer();
  if (added) {
    client_->OnDeviceAdded(std::move(dev_info));
  } else {
    client_->OnDeviceRemoved(std::move(dev_info));
  }
}

void Client::ListDevices(ListDevicesCallback callback) {
  // Get all the device information from device_tracker.
  std::vector<arc::mojom::MidisDeviceInfoPtr> device_list;
  device_tracker_->ListDevices(&device_list);
  std::move(callback).Run(std::move(device_list));
}

void Client::RequestPort(arc::mojom::MidisRequestPtr request,
                         RequestPortCallback callback) {
  mojo::ScopedHandle handle = CreateRequestPortFD(
      request->card, request->device_num, request->subdevice_num);
  std::move(callback).Run(std::move(handle));
}

void Client::RequestPortDeprecated(arc::mojom::MidisRequestPtr request,
                                   RequestPortDeprecatedCallback callback) {
  mojo::ScopedHandle handle = CreateRequestPortFD(
      request->card, request->device_num, request->subdevice_num);
  if (!handle.is_valid()) {
    return;
  }
  std::move(callback).Run(std::move(handle));
}

void Client::CloseDevice(arc::mojom::MidisRequestPtr request) {
  device_tracker_->RemoveClientFromDevice(client_id_, request->card,
                                          request->device_num);
}

mojo::ScopedHandle Client::CreateRequestPortFD(uint32_t card,
                                               uint32_t device,
                                               uint32_t subdevice) {
  base::ScopedFD clientfd = device_tracker_->AddClientToReadSubdevice(
      card, device, subdevice, client_id_);
  if (!clientfd.is_valid()) {
    LOG(ERROR) << "CreateRequestPortFD failed for device: " << device;
    // We don't delete the client here, because this could mean an issue with
    // the device h/w.
    return mojo::ScopedHandle();
  }

  return mojo::WrapPlatformFile(std::move(clientfd));
}

}  // namespace midis
