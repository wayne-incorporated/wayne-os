// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <utility>

#include "midis/ports.h"

namespace midis {

InPort::InPort(uint32_t device_id,
               uint32_t port_id,
               SubscribeCallback sub_cb,
               DeletionCallback del_cb)
    : device_id_(device_id),
      port_id_(port_id),
      sub_cb_(std::move(sub_cb)),
      del_cb_(std::move(del_cb)) {}

// static
std::unique_ptr<InPort> InPort::Create(uint32_t device_id,
                                       uint32_t port_id,
                                       SubscribeCallback sub_cb,
                                       DeletionCallback del_cb) {
  std::unique_ptr<InPort> port(
      new InPort(device_id, port_id, std::move(sub_cb), std::move(del_cb)));
  if (!port->Subscribe()) {
    return nullptr;
  }
  return port;
}

InPort::~InPort() {
  del_cb_.Run(device_id_, port_id_);
}

OutPort::OutPort(uint32_t device_id,
                 uint32_t port_id,
                 SubscribeCallback sub_cb,
                 DeletionCallback del_cb,
                 SendMidiDataCallback send_data_cb)
    : device_id_(device_id),
      port_id_(port_id),
      sub_cb_(std::move(sub_cb)),
      del_cb_(std::move(del_cb)),
      send_data_cb_(std::move(send_data_cb)) {}

// static
std::unique_ptr<OutPort> OutPort::Create(uint32_t device_id,
                                         uint32_t port_id,
                                         SubscribeCallback sub_cb,
                                         DeletionCallback del_cb,
                                         SendMidiDataCallback send_data_cb) {
  std::unique_ptr<OutPort> port(
      new OutPort(device_id, port_id, std::move(sub_cb), std::move(del_cb),
                  std::move(send_data_cb)));
  if (port->Subscribe() == -1) {
    return nullptr;
  }
  return port;
}

OutPort::~OutPort() {
  del_cb_.Run(out_port_id_);
}

void OutPort::SendData(const uint8_t* buffer, size_t buf_len) {
  send_data_cb_.Run(out_port_id_, buffer, buf_len);
}

int OutPort::Subscribe() {
  out_port_id_ = sub_cb_.Run(device_id_, port_id_);
  return out_port_id_;
}

}  // namespace midis
