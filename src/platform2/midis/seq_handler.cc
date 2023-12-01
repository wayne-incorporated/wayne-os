// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "midis/seq_handler.h"

#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/functional/bind.h>
#include <base/logging.h>
#include <poll.h>

#include "media/midi/message_util.h"
#include "midis/constants.h"

namespace {

const unsigned int kCreateInputPortCaps =
    SND_SEQ_PORT_CAP_WRITE | SND_SEQ_PORT_CAP_NO_EXPORT;
const unsigned int kCreateOutputPortCaps =
    SND_SEQ_PORT_CAP_READ | SND_SEQ_PORT_CAP_NO_EXPORT;
const unsigned int kCreatePortType =
    SND_SEQ_PORT_TYPE_MIDI_GENERIC | SND_SEQ_PORT_TYPE_APPLICATION;
const char kSndSeqName[] = "hw";

}  // namespace

namespace midis {

SeqHandler::SeqHandler() : weak_factory_(this) {}

SeqHandler::SeqHandler(AddDeviceCallback add_device_cb,
                       RemoveDeviceCallback remove_device_cb,
                       HandleReceiveDataCallback handle_rx_data_cb,
                       IsDevicePresentCallback is_device_present_cb,
                       IsPortPresentCallback is_port_present_cb)
    : add_device_cb_(std::move(add_device_cb)),
      remove_device_cb_(std::move(remove_device_cb)),
      handle_rx_data_cb_(std::move(handle_rx_data_cb)),
      is_device_present_cb_(std::move(is_device_present_cb)),
      is_port_present_cb_(std::move(is_port_present_cb)),
      weak_factory_(this) {}

bool SeqHandler::InitSeq() {
  // Create client handles.
  snd_seq_t* tmp_seq = nullptr;
  int err =
      snd_seq_open(&tmp_seq, kSndSeqName, SND_SEQ_OPEN_INPUT, SND_SEQ_NONBLOCK);
  if (err != 0) {
    LOG(ERROR) << "snd_seq_open fails: " << snd_strerror(err);
    return false;
  }
  ScopedSeqPtr in_client(tmp_seq);
  tmp_seq = nullptr;
  in_client_id_ = snd_seq_client_id(in_client.get());

  err = snd_seq_open(&tmp_seq, kSndSeqName, SND_SEQ_OPEN_OUTPUT, 0);
  if (err != 0) {
    LOG(ERROR) << "snd_seq_open fails: " << snd_strerror(err);
    return false;
  }

  ScopedSeqPtr out_client(tmp_seq);
  tmp_seq = nullptr;
  out_client_id_ = snd_seq_client_id(out_client.get());

  // Name the clients.
  err = snd_seq_set_client_name(in_client.get(), "midis (input)");
  if (err != 0) {
    LOG(ERROR) << "snd_seq_set_client_name fails: " << snd_strerror(err);
    return false;
  }
  err = snd_seq_set_client_name(out_client.get(), "midis (output)");
  if (err != 0) {
    LOG(ERROR) << "snd_seq_set_client_name fails: " << snd_strerror(err);
    return false;
  }

  // Create input port.
  in_port_id_ = snd_seq_create_simple_port(
      in_client.get(), NULL, kCreateInputPortCaps, kCreatePortType);
  if (in_port_id_ < 0) {
    LOG(ERROR) << "snd_seq_create_simple_port fails: "
               << snd_strerror(in_port_id_);
    return false;
  }

  // Subscribe to the announce port.
  snd_seq_port_subscribe_t* subs;
  snd_seq_port_subscribe_alloca(&subs);
  snd_seq_addr_t announce_sender;
  snd_seq_addr_t announce_dest;
  announce_sender.client = SND_SEQ_CLIENT_SYSTEM;
  announce_sender.port = SND_SEQ_PORT_SYSTEM_ANNOUNCE;
  announce_dest.client = in_client_id_;
  announce_dest.port = in_port_id_;
  snd_seq_port_subscribe_set_sender(subs, &announce_sender);
  snd_seq_port_subscribe_set_dest(subs, &announce_dest);
  err = snd_seq_subscribe_port(in_client.get(), subs);
  if (err != 0) {
    LOG(ERROR) << "snd_seq_subscribe_port on the announce port fails: "
               << snd_strerror(err);
    return false;
  }

  in_client_ = std::move(in_client);
  out_client_ = std::move(out_client);

  // Initialize decoder.
  decoder_ = CreateMidiEvent(0);

  EnumerateExistingDevices();

  // Obtain the poll file descriptor to watch.
  pfd_ = std::make_unique<pollfd>();
  snd_seq_poll_descriptors(in_client_.get(), pfd_.get(), 1, POLLIN);

  watcher_ = base::FileDescriptorWatcher::WatchReadable(
      pfd_->fd, base::BindRepeating(&SeqHandler::ProcessAlsaClientFd,
                                    weak_factory_.GetWeakPtr()));
  if (!watcher_) {
    in_client_.reset();
    out_client_.reset();
    decoder_.reset();
    pfd_.reset();
    return false;
  }

  return true;
}

void SeqHandler::ProcessAlsaClientFd() {
  int remaining;
  do {
    snd_seq_event_t* event;
    int err = SndSeqEventInput(in_client_.get(), &event);
    remaining = SndSeqEventInputPending(in_client_.get(), 0);

    if (err == -ENOSPC) {
      // Handle out of space error.
      LOG(ERROR) << "snd_seq_event_input detected buffer overrun";
      // We've lost events: check another way to see if we need to shut
      // down.
    } else if (err == -EAGAIN) {
      // We've read all the data.
    } else if (err < 0) {
      // Handle other errors.
      LOG(ERROR) << "snd_seq_event_input fails: " << snd_strerror(err);
      // TODO(pmalani): Stop the message loop here then.
    } else if (event->source.client == SND_SEQ_CLIENT_SYSTEM &&
               event->source.port == SND_SEQ_PORT_SYSTEM_ANNOUNCE) {
      // Handle announce events.
      switch (event->type) {
        case SND_SEQ_EVENT_PORT_START:
          // Don't use SND_SEQ_EVENT_CLIENT_START because the
          // client name may not be set by the time we query
          // it. It should be set by the time ports are made.
          AddSeqDevice(event->data.addr.client);
          AddSeqPort(event->data.addr.client, event->data.addr.port);
          break;
        case SND_SEQ_EVENT_CLIENT_EXIT:
          // Check for disconnection of our "out" client. This means "shut
          // down".
          if (event->data.addr.client == out_client_id_) {
            // TODO(pmalani): Stop the message loop here then.
            remaining = 0;
          } else {
            RemoveSeqDevice(event->data.addr.client);
          }
          break;
        case SND_SEQ_EVENT_PORT_EXIT:
          RemoveSeqPort(event->data.addr.client, event->data.addr.port);
          break;
      }
    } else {
      // Normal operation.
      ProcessMidiEvent(event);
    }
  } while (remaining > 0);
}

void SeqHandler::AddSeqDevice(uint32_t device_id) {
  if (is_device_present_cb_.Run(0 /* TODO(pmalani): Remove card number */,
                                device_id)) {
    LOG(INFO) << "Device: " << device_id << " already exists.";
    return;
  }

  // Check that the device isn't our own in/our client.
  if (device_id == in_client_id_ || device_id == out_client_id_) {
    return;
  }

  snd_seq_client_info_t* client_info;
  snd_seq_client_info_alloca(&client_info);
  int err =
      snd_seq_get_any_client_info(in_client_.get(), device_id, client_info);
  if (err != 0) {
    LOG(ERROR) << "Failed to get client info.";
    return;
  }

  std::string name(snd_seq_client_info_get_name(client_info));

  // Store the list of MIDI ports and corresponding capabilities in a map.
  std::map<uint32_t, unsigned int> port_caps;
  snd_seq_port_info_t* port_info;
  snd_seq_port_info_alloca(&port_info);
  snd_seq_port_info_set_client(port_info, device_id);
  snd_seq_port_info_set_port(port_info, -1);
  while (!snd_seq_query_next_port(in_client_.get(), port_info)) {
    if (!(snd_seq_port_info_get_type(port_info) &
          SND_SEQ_PORT_TYPE_MIDI_GENERIC)) {
      LOG(INFO) << "Skipping non-MIDI port.";
      continue;
    }
    port_caps.emplace(snd_seq_port_info_get_port(port_info),
                      snd_seq_port_info_get_capability(port_info));
  }

  // If the number of MIDI ports is 0, there is no use in creating
  // a device.
  if (port_caps.size() == 0) {
    LOG(INFO) << "Connected device: " << name << " has no MIDI ports.";
    return;
  }

  auto dev = std::make_unique<Device>(
      name, std::string(),
      0 /* card number; TODO(pmalani) remove card number */, device_id,
      port_caps.size(), 0 /* device flags TODO(pmalani): flags not needed. */,
      base::BindRepeating(&SeqHandler::SubscribeInPort, base::Unretained(this)),
      base::BindRepeating(&SeqHandler::SubscribeOutPort,
                          base::Unretained(this)),
      base::BindRepeating(&SeqHandler::UnsubscribeInPort,
                          weak_factory_.GetWeakPtr()),
      base::BindRepeating(&SeqHandler::UnsubscribeOutPort,
                          weak_factory_.GetWeakPtr()),
      base::BindRepeating(&SeqHandler::SendMidiData,
                          weak_factory_.GetWeakPtr()),
      std::move(port_caps));
  add_device_cb_.Run(std::move(dev));
}

void SeqHandler::AddSeqPort(uint32_t device_id, uint32_t port_id) {
  if (!is_port_present_cb_.Run(0, device_id, port_id)) {
    LOG(WARNING) << "Received port start event for new port: " << port_id
                 << " on  device: " << device_id << "; ignoring";
  }
}

void SeqHandler::RemoveSeqDevice(uint32_t device_id) {
  remove_device_cb_.Run(0 /* FIXME remove card number */, device_id);
}

void SeqHandler::RemoveSeqPort(uint32_t device_id, uint32_t port_id) {
  if (!is_port_present_cb_.Run(0, device_id, port_id)) {
    LOG(WARNING) << "Received port start event for new port: " << port_id
                 << " on  device: " << device_id << "; ignoring";
  }
}

bool SeqHandler::SubscribeInPort(uint32_t device_id, uint32_t port_id) {
  snd_seq_port_subscribe_t* subs;
  snd_seq_port_subscribe_alloca(&subs);
  snd_seq_addr_t sender;
  sender.client = device_id;
  sender.port = port_id;
  snd_seq_port_subscribe_set_sender(subs, &sender);

  snd_seq_addr_t dest;
  dest.client = in_client_id_;
  dest.port = in_port_id_;
  snd_seq_port_subscribe_set_dest(subs, &dest);

  int err = snd_seq_subscribe_port(in_client_.get(), subs);
  if (err != 0) {
    LOG(ERROR) << "snd_seq_subscribe_port fails: " << snd_strerror(err);
    return false;
  }

  return true;
}

int SeqHandler::SubscribeOutPort(uint32_t device_id, uint32_t port_id) {
  int out_port;
  out_port = snd_seq_create_simple_port(out_client_.get(), NULL,
                                        kCreateOutputPortCaps, kCreatePortType);
  if (out_port < 0) {
    LOG(INFO) << "snd_seq_creat_simple_port (output) failed: "
              << snd_strerror(out_port);
    return -1;
  }

  snd_seq_port_subscribe_t* subs;
  snd_seq_port_subscribe_alloca(&subs);
  snd_seq_addr_t sender;
  sender.client = out_client_id_;
  sender.port = out_port;
  snd_seq_port_subscribe_set_sender(subs, &sender);

  snd_seq_addr_t dest;
  dest.client = device_id;
  dest.port = port_id;
  snd_seq_port_subscribe_set_dest(subs, &dest);

  int err = snd_seq_subscribe_port(out_client_.get(), subs);
  if (err != 0) {
    snd_seq_delete_simple_port(out_client_.get(), out_port);
    LOG(ERROR) << "snd_seq_subscribe_port fails: " << snd_strerror(err);
    return -1;
  }

  return out_port;
}

void SeqHandler::UnsubscribeInPort(uint32_t device_id, uint32_t port_id) {
  snd_seq_port_subscribe_t* subs;
  snd_seq_port_subscribe_alloca(&subs);
  snd_seq_addr_t sender;
  sender.client = device_id;
  sender.port = port_id;
  snd_seq_port_subscribe_set_sender(subs, &sender);
  snd_seq_addr_t dest;
  dest.client = in_client_id_;
  dest.port = in_port_id_;
  snd_seq_port_subscribe_set_dest(subs, &dest);

  int err = snd_seq_unsubscribe_port(in_client_.get(), subs);
  if (err != 0) {
    LOG(WARNING) << "snd_seq_unsubscribe_port fails: " << snd_strerror(err);
    return;
  }
}

void SeqHandler::UnsubscribeOutPort(int out_port_id) {
  snd_seq_delete_simple_port(out_client_.get(), out_port_id);
}

bool SeqHandler::EncodeMidiBytes(int out_port_id,
                                 snd_seq_t* out_client,
                                 const uint8_t* buffer,
                                 size_t buf_len,
                                 snd_midi_event_t* encoder) {
  if (buf_len == 0 || buf_len > kMaxBufSize) {
    return false;
  }

  for (int i = 0; i < buf_len; i++) {
    snd_seq_event_t event;
    int result = snd_midi_event_encode_byte(encoder, buffer[i], &event);
    if (result < 0) {
      LOG(ERROR) << "Error snd_midi_event_encode_byte(): " << result;
      return false;
    }
    if (result == 1) {
      // Send the message.
      snd_seq_ev_set_source(&event, out_port_id);
      snd_seq_ev_set_subs(&event);
      snd_seq_ev_set_direct(&event);
      int expected_length = snd_seq_event_length(&event);
      result = SndSeqEventOutputDirect(out_client, &event);
      if (result != expected_length) {
        LOG(WARNING) << "Error in snd_seq_event_output_direct(): " << result;
        return false;
      }
      return true;
    }
  }

  // If we reached here, something went wrong.
  return false;
}

void SeqHandler::SendMidiData(int out_port_id,
                              const uint8_t* buffer,
                              size_t buf_len) {
  std::vector<uint8_t> v(buffer, buffer + buf_len);
  if (!midi::IsValidWebMIDIData(v)) {
    LOG(WARNING) << "Received invalid MIDI Data.";
    return;
  }

  snd_midi_event_t* encoder;
  int ret = snd_midi_event_new(buf_len, &encoder);
  if (ret != 0) {
    LOG(ERROR) << "Error snd_midi_event_new(): " << ret;
    return;
  }
  bool success =
      EncodeMidiBytes(out_port_id, out_client_.get(), buffer, buf_len, encoder);
  if (!success) {
    LOG(WARNING) << "Failed to send MIDI data to output port: " << out_port_id;
  }
  snd_midi_event_free(encoder);
}

void SeqHandler::ProcessMidiEvent(snd_seq_event_t* event) {
  uint32_t device_id = event->source.client;
  uint32_t subdevice_num = event->source.port;

  if (event->type == SND_SEQ_EVENT_SYSEX) {
    // SysEX, so pass it through without decoding.
    handle_rx_data_cb_.Run(0, device_id, subdevice_num,
                           static_cast<char*>(event->data.ext.ptr),
                           event->data.ext.len);
  } else {
    // Normal message, so decode and send.
    unsigned char buf[12];
    int64_t count =
        snd_midi_event_decode(decoder_.get(), buf, sizeof(buf), event);
    if (count <= 0) {
      if (count != -ENOENT) {
        LOG(ERROR) << "snd_midi_event_decoder failed: " << snd_strerror(count);
      }
    } else {
      handle_rx_data_cb_.Run(0, device_id, subdevice_num,
                             reinterpret_cast<char*>(buf), count);
    }
  }
}

int SeqHandler::SndSeqEventOutputDirect(snd_seq_t* out_client,
                                        snd_seq_event_t* event) {
  return snd_seq_event_output_direct(out_client, event);
}

int SeqHandler::SndSeqEventInput(snd_seq_t* in_client, snd_seq_event_t** ev) {
  return snd_seq_event_input(in_client, ev);
}

int SeqHandler::SndSeqEventInputPending(snd_seq_t* in_client,
                                        int fetch_sequencer) {
  return snd_seq_event_input_pending(in_client, fetch_sequencer);
}

void SeqHandler::EnumerateExistingDevices() {
  snd_seq_client_info_t* client_info;
  snd_seq_client_info_alloca(&client_info);
  snd_seq_port_info_t* port_info;
  snd_seq_port_info_alloca(&port_info);

  snd_seq_client_info_set_client(client_info, -1);
  while (!snd_seq_query_next_client(in_client_.get(), client_info)) {
    int device_id = snd_seq_client_info_get_client(client_info);
    AddSeqDevice(device_id);

    // Call AddSeqPort to make sure we "process" all the ports of a client.
    // Note that currently we don't support the dynamic addition / deletion
    // of ports.
    snd_seq_port_info_set_client(port_info, device_id);
    snd_seq_port_info_set_port(port_info, -1);
    while (!snd_seq_query_next_port(in_client_.get(), port_info)) {
      int port_id = snd_seq_port_info_get_port(port_info);
      AddSeqPort(device_id, port_id);
    }
  }
}

SeqHandler::ScopedMidiEventPtr SeqHandler::CreateMidiEvent(size_t buf_size) {
  snd_midi_event_t* tmp = nullptr;
  snd_midi_event_new(buf_size, &tmp);
  ScopedMidiEventPtr ev(tmp);
  tmp = nullptr;
  snd_midi_event_no_status(ev.get(), 1);

  return ev;
}

}  // namespace midis
