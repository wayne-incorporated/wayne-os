// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include "midis/device.h"

#include <alsa/asoundlib.h>
#include <fcntl.h>
#include <sys/socket.h>

#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/functional/callback.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/stringprintf.h>

#include "midis/constants.h"
#include "midis/subdevice_client_fd_holder.h"

namespace {

const unsigned int kInputPortCaps =
    SND_SEQ_PORT_CAP_READ | SND_SEQ_PORT_CAP_SUBS_READ;
const unsigned int kOutputPortCaps =
    SND_SEQ_PORT_CAP_WRITE | SND_SEQ_PORT_CAP_SUBS_WRITE;

}  // namespace

namespace midis {

Device::Device(const std::string& name,
               const std::string& manufacturer,
               uint32_t card,
               uint32_t device,
               uint32_t num_subdevices,
               uint32_t flags,
               InPort::SubscribeCallback in_sub_cb,
               OutPort::SubscribeCallback out_sub_cb,
               InPort::DeletionCallback in_del_cb,
               OutPort::DeletionCallback out_del_cb,
               OutPort::SendMidiDataCallback send_data_cb,
               const std::map<uint32_t, unsigned int>& port_caps)
    : name_(name),
      manufacturer_(manufacturer),
      card_(card),
      device_(device),
      num_subdevices_(num_subdevices),
      flags_(flags),
      in_sub_cb_(std::move(in_sub_cb)),
      out_sub_cb_(std::move(out_sub_cb)),
      in_del_cb_(std::move(in_del_cb)),
      out_del_cb_(std::move(out_del_cb)),
      send_data_cb_(send_data_cb),
      port_caps_(port_caps),
      weak_factory_(this) {
  LOG(INFO) << "Device created: " << name_;
}

Device::~Device() {
  StopMonitoring();
}

void Device::StopMonitoring() {
  // Cancel all the clients FDs who were listening / writing to this device.
  client_fds_.clear();
  in_ports_.clear();
  out_ports_.clear();
}

bool Device::StartMonitoring() {
  for (auto& it : port_caps_) {
    if (it.second & kInputPortCaps) {
      auto in_port = InPort::Create(device_, it.first, in_sub_cb_, in_del_cb_);
      if (in_port) {
        in_ports_.emplace(it.first, std::move(in_port));
        LOG(INFO) << "Input Port created for port:" << it.first;
      }
    }
    if (it.second & kOutputPortCaps) {
      auto out_port = OutPort::Create(device_, it.first, out_sub_cb_,
                                      out_del_cb_, send_data_cb_);
      if (out_port) {
        out_ports_.emplace(it.first, std::move(out_port));
        LOG(INFO) << "Outpot Port created for port:" << it.first;
      }
    }
  }
  return true;
}

void Device::HandleReceiveData(const char* buffer,
                               uint32_t subdevice,
                               size_t buf_len) const {
  // NOTE: We don't check whether this subdevice can actually receive data
  // because the data is coming in from the a MIDI H/W port, and so if data is
  // being generated here, it must be from a valid source.
  auto list_it = client_fds_.find(subdevice);
  if (list_it != client_fds_.end()) {
    for (const auto& id_fd_entry : list_it->second) {
      id_fd_entry->WriteDeviceDataToClient(buffer, buf_len);
    }
  }
}

void Device::RemoveClientFromDevice(uint32_t client_id) {
  LOG(INFO) << "Removing the client: " << client_id
            << " from all device watchers for device: " << name_;
  for (auto list_it = client_fds_.begin(); list_it != client_fds_.end();) {
    // First remove all clients in a subdevice.
    for (auto it = list_it->second.begin(); it != list_it->second.end();) {
      if (it->get()->GetClientId() == client_id) {
        LOG(INFO) << "Found client: " << client_id << " in list. deleting";
        it = list_it->second.erase(it);
      } else {
        ++it;
      }
    }
    // If no clients remain, remove the subdevice entry from the map.
    if (list_it->second.empty()) {
      client_fds_.erase(list_it++);
    } else {
      ++list_it;
    }
  }

  if (client_fds_.empty()) {
    StopMonitoring();
  }
}

void Device::WriteClientDataToDevice(uint32_t subdevice_id,
                                     const uint8_t* buffer,
                                     size_t buf_len) {
  // Check whether this port supports output, otherwise just drop the data, and
  // print a warning.
  auto it = out_ports_.find(subdevice_id);
  if (it == out_ports_.end()) {
    LOG(WARNING)
        << "Data received on port: " << subdevice_id
        << " which doesn't support writing to MIDI device; dropping data";
    return;
  }
  it->second->SendData(buffer, buf_len);
}

base::ScopedFD Device::AddClientToReadSubdevice(uint32_t client_id,
                                                uint32_t subdevice_id) {
  if (client_fds_.empty()) {
    if (!StartMonitoring()) {
      LOG(ERROR) << "Couldn't start monitoring device: " << name_;
      StopMonitoring();
      return base::ScopedFD();
    }
  }

  int sock_fd[2];
  int ret = socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sock_fd);
  if (ret < 0) {
    PLOG(ERROR) << "socketpair for client_id: " << client_id
                << " device_id: " << device_ << " subdevice: " << subdevice_id
                << "failed.";
    return base::ScopedFD();
  }

  base::ScopedFD server_fd(sock_fd[0]);
  base::ScopedFD client_fd(sock_fd[1]);

  auto id_fd_list = client_fds_.find(subdevice_id);
  if (id_fd_list == client_fds_.end()) {
    std::vector<std::unique_ptr<SubDeviceClientFdHolder>> list_entries;

    list_entries.emplace_back(SubDeviceClientFdHolder::Create(
        client_id, subdevice_id, std::move(server_fd),
        base::BindRepeating(&Device::WriteClientDataToDevice,
                            weak_factory_.GetWeakPtr())));

    client_fds_.emplace(subdevice_id, std::move(list_entries));
  } else {
    for (auto const& pair : id_fd_list->second) {
      if (pair->GetClientId() == client_id) {
        LOG(INFO) << "Client id: " << client_id
                  << " already registered to"
                     " subdevice: "
                  << subdevice_id << ".";
        return base::ScopedFD();
      }
    }
    id_fd_list->second.emplace_back(SubDeviceClientFdHolder::Create(
        client_id, subdevice_id, std::move(server_fd),
        base::BindRepeating(&Device::WriteClientDataToDevice,
                            weak_factory_.GetWeakPtr())));
  }

  return client_fd;
}

}  // namespace midis
