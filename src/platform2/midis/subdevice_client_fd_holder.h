// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MIDIS_SUBDEVICE_CLIENT_FD_HOLDER_H_
#define MIDIS_SUBDEVICE_CLIENT_FD_HOLDER_H_

#include <memory>

#include <base/files/file_descriptor_watcher_posix.h>
#include <base/files/scoped_file.h>
#include <base/memory/weak_ptr.h>

#include "media/midi/message_util.h"
#include "media/midi/midi_message_queue.h"

namespace midis {

// Container to store the client_id, pipe FD and file watcher task id for the
// corresponding pipe.
class SubDeviceClientFdHolder {
 public:
  using ClientDataCallback = base::RepeatingCallback<void(
      uint32_t subdevice_id, const uint8_t* buffer, size_t buf_len)>;

  SubDeviceClientFdHolder(uint32_t client_id,
                          uint32_t subdevice_id,
                          base::ScopedFD fd,
                          ClientDataCallback client_data_cb);
  SubDeviceClientFdHolder(const SubDeviceClientFdHolder&) = delete;
  SubDeviceClientFdHolder& operator=(const SubDeviceClientFdHolder&) = delete;

  static std::unique_ptr<SubDeviceClientFdHolder> Create(
      uint32_t client_id,
      uint32_t subdevice_id,
      base::ScopedFD fd,
      ClientDataCallback client_data_cb);
  ~SubDeviceClientFdHolder();
  int GetRawFd() { return fd_.get(); }
  uint32_t GetClientId() const { return client_id_; }
  // This function is used to write data *to* the client when it is received
  // from a MIDI h/w device. NOTE: A failure in this write shouldn't result in
  // the deletion of a client. A faulty / crashed / deleted client will be
  // handled from the Client handling code via TriggerClientDeletion().
  void WriteDeviceDataToClient(const void* buffer, size_t buf_len);

 private:
  // This function is used as the callback which is run when a
  // base::FileDescriptorWatcher is set up on the client's fd for this
  // particular subdevice. It reads the data *from* the client, and in turn
  // invokes client_data_cb_ which writes the data to the device h/w.
  void HandleClientMidiData();
  // Starts to watch the client pipe FD.
  bool StartClientMonitoring();

  uint32_t client_id_;
  uint32_t subdevice_id_;
  base::ScopedFD fd_;
  std::unique_ptr<base::FileDescriptorWatcher::Controller> watcher_;
  ClientDataCallback client_data_cb_;
  std::unique_ptr<midi::MidiMessageQueue> queue_;
  base::WeakPtrFactory<SubDeviceClientFdHolder> weak_factory_;
};

}  // namespace midis

#endif  // MIDIS_SUBDEVICE_CLIENT_FD_HOLDER_H_
