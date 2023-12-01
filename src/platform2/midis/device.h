// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MIDIS_DEVICE_H_
#define MIDIS_DEVICE_H_

#include <map>

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/files/file_path.h>
#include <base/files/scoped_file.h>
#include <base/memory/weak_ptr.h>
#include <brillo/message_loops/message_loop.h>
#include <gtest/gtest_prod.h>

#include "midis/ports.h"

namespace midis {

class FileHandler;

class SubDeviceClientFdHolder;

// Class which holds information related to a MIDI device.
// We use the name variable (derived from the ioctl) as a basis
// to arrive at an identifier.
class Device {
 public:
  Device(const std::string& name,
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
         const std::map<uint32_t, unsigned int>& port_caps);
  Device(const Device&) = delete;
  Device& operator=(const Device&) = delete;

  ~Device();

  const std::string& GetName() const { return name_; }
  const std::string& GetManufacturer() const { return manufacturer_; }
  uint32_t GetCard() const { return card_; }
  uint32_t GetDeviceNum() const { return device_; }
  uint32_t GetNumSubdevices() const { return num_subdevices_; }
  uint32_t GetFlags() const { return flags_; }

  // Adds a client which wishes to read data on a particular subdevice
  // This function should return one end of a pipe file descriptor
  // This will be sent back to the client, and it can listen on that for events.
  //
  // A device can be bidirectional, and so we should also have a watch on the
  // pipe FD so that we can read MIDI events and send them to the MIDI
  // H/W.
  //
  // Returns:
  //   A valid base::ScopedFD on success.
  //   An empty base::ScopedFD otherwise.
  base::ScopedFD AddClientToReadSubdevice(uint32_t client_id,
                                          uint32_t subdevice_id);

  // Callback function which is invoked by the FileHandler object when data is
  // received *from* a particular subdevice of a MIDI H/W device or external
  // client.
  void HandleReceiveData(const char* buffer,
                         uint32_t subdevice,
                         size_t buf_len) const;

  // This function is called when a Client is removed from the service for
  // orderly or unorderly reasons (like disconnection). The client is removed
  // from all subdevices.
  void RemoveClientFromDevice(uint32_t client_id);

 private:
  // This function initializes subscriptions for all the listed ports.
  // As the ports are initialized, they get stored in |in_ports_| and
  // |out_ports_| respectively.
  bool StartMonitoring();

  // Removes all the port subscriptions which were started during
  // StartMontoring(). This function is called if : a. Something has gone wrong
  // with the Device monitor and we need to bail b. Something has gone wrong
  // while adding the device. c. During a graceful shutdown.
  void StopMonitoring();

  // Callback function which is invoked by SubDeviceClientFdHolder object when
  // data is received from client to be sent *to* a particular subdevice.
  void WriteClientDataToDevice(uint32_t subdevice_id,
                               const uint8_t* buffer,
                               size_t buf_len);

  std::string name_;
  std::string manufacturer_;
  // TODO(pmalani): Unused, so remove
  uint32_t card_;
  uint32_t device_;
  uint32_t num_subdevices_;
  // TODO(pmalani): Unused, so remove.
  uint32_t flags_;

  // This data-structure performs the following map:
  //
  // subdevice ---> (client_1, pipefd_1), (client_2, pipefd_2), ...., (client_n,
  // pipefd_n).
  std::map<uint32_t, std::vector<std::unique_ptr<SubDeviceClientFdHolder>>>
      client_fds_;

  // Callbacks to be run by the InPort and OutPort objects.
  InPort::SubscribeCallback in_sub_cb_;
  OutPort::SubscribeCallback out_sub_cb_;
  InPort::DeletionCallback in_del_cb_;
  OutPort::DeletionCallback out_del_cb_;
  OutPort::SendMidiDataCallback send_data_cb_;

  // Map storing all the valid seq port_ids and the corresponding caps.
  std::map<uint32_t, unsigned int> port_caps_;

  // This data structure maps the port_id to corresponding InPort we create.
  std::map<uint32_t, std::unique_ptr<InPort>> in_ports_;
  // This data structure maps the port_id to corresponding OutPort we create.
  std::map<uint32_t, std::unique_ptr<OutPort>> out_ports_;

  base::WeakPtrFactory<Device> weak_factory_;
};

}  // namespace midis

#endif  // MIDIS_DEVICE_H_
