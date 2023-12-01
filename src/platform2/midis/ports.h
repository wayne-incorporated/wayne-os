// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MIDIS_PORTS_H_
#define MIDIS_PORTS_H_

#include <memory>

#include <base/functional/callback.h>

namespace midis {
// Representiation for an input port, i.e, a port on which we receive data
// *from* a MIDI h/w device.
class InPort {
 public:
  using SubscribeCallback =
      base::RepeatingCallback<bool(uint32_t device_id, uint32_t port_id)>;
  using DeletionCallback =
      base::RepeatingCallback<void(uint32_t device_id, uint32_t port_id)>;

  ~InPort();

  // Factory function to create and start a subscription for a port
  static std::unique_ptr<InPort> Create(uint32_t device_id,
                                        uint32_t port_id,
                                        SubscribeCallback sub_cb,
                                        DeletionCallback del_cb);

 private:
  InPort(uint32_t device_id,
         uint32_t port_id,
         SubscribeCallback sub_cb,
         DeletionCallback del_cb);
  InPort(const InPort&) = delete;
  InPort& operator=(const InPort&) = delete;

  // Function to initiate the subscription to a MIDI H/W input port.
  bool Subscribe() { return sub_cb_.Run(device_id_, port_id_); }

  int device_id_;
  int port_id_;
  SubscribeCallback sub_cb_;
  DeletionCallback del_cb_;
};

// Representiation for an output port, i.e, a port on which we send data *to*
// a MIDI h/w device.
class OutPort {
 public:
  using SubscribeCallback =
      base::RepeatingCallback<int(uint32_t device_id, uint32_t port_id)>;
  using DeletionCallback = base::RepeatingCallback<void(int alsa_out_port_id)>;
  using SendMidiDataCallback = base::RepeatingCallback<void(
      int alsa_out_port_id, const uint8_t* buf, size_t buf_len)>;

  ~OutPort();

  static std::unique_ptr<OutPort> Create(uint32_t device_id,
                                         uint32_t port_id,
                                         SubscribeCallback sub_cb,
                                         DeletionCallback del_cb,
                                         SendMidiDataCallback send_data_cb);

  // Function which invokes the callback to send data to the MIDI H/W or
  // external client.
  void SendData(const uint8_t* buffer, size_t buf_len);

 private:
  OutPort(uint32_t device_id,
          uint32_t port_id,
          SubscribeCallback sub_cb,
          DeletionCallback del_cb,
          SendMidiDataCallback send_data_cb);
  OutPort(const OutPort&) = delete;
  OutPort& operator=(const OutPort&) = delete;

  // Function to create a output seq port and initiate the subscription to a
  // MIDI H/W output port.
  int Subscribe();

  int device_id_;
  int port_id_;
  SubscribeCallback sub_cb_;
  DeletionCallback del_cb_;
  SendMidiDataCallback send_data_cb_;
  int out_port_id_;
};

}  // namespace midis

#endif  // MIDIS_PORTS_H_
