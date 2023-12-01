// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ARC_VM_LIBVDA_ENCODE_WRAPPER_H_
#define ARC_VM_LIBVDA_ENCODE_WRAPPER_H_

#include <stdint.h>

#include <memory>

#include <base/files/scoped_file.h>

#include "arc/vm/libvda/event_pipe.h"
#include "arc/vm/libvda/libvda_encode.h"

namespace arc {

// VeaContext is the encode session context created by VeaImpl.
// Implementations should be able to handle method invocations on any thread.
class VeaContext {
 public:
  VeaContext();
  VeaContext(const VeaContext&) = delete;
  VeaContext& operator=(const VeaContext&) = delete;

  virtual ~VeaContext();

  // Encodes the frame pointed to by |fd|.
  virtual int Encode(vea_input_buffer_id_t input_buffer_id,
                     base::ScopedFD fd,
                     size_t num_planes,
                     video_frame_plane_t* planes,
                     uint64_t timestamp,
                     bool force_keyframe) = 0;

  // Provides an output buffer for use by the internal encoder
  // implementation. Encoded frames will be placed at the buffer specified
  // by |fd|. |offset| should specify the offset at the buffer to start
  // placing the encoded content and |size| should specify the buffer size.
  virtual int UseOutputBuffer(vea_output_buffer_id_t output_buffer_id,
                              base::ScopedFD fd,
                              uint32_t offset,
                              uint32_t size) = 0;

  // Requests a change to encoding parameters.
  // The return value will be 0 when the param change request has been
  // successfully sent, and non-zero otherwise.
  virtual int RequestEncodingParamsChange(vea_bitrate_t bitrate,
                                          uint32_t framerate) = 0;

  // Requests to flush the encode session.
  virtual int Flush() = 0;

  // Returns the read-only endpoint of the event pipe file descriptor.
  int GetEventFd();

 protected:
  // Dispatch a REQUIRE_INPUT_BUFFERS event to the event pipe.
  void DispatchRequireInputBuffers(uint32_t input_count,
                                   uint32_t input_frame_width,
                                   uint32_t input_frame_height,
                                   uint32_t output_buffer_size);

  // Dispatch a PROCESSED_INPUT_BUFFER event to the event pipe.
  void DispatchProcessedInputBuffer(vea_input_buffer_id_t input_buffer_id);

  // Dispatch a PROCESSED_OUTPUT_BUFFER event to the event pipe.
  void DispatchProcessedOutputBuffer(vea_output_buffer_id_t output_buffer_id,
                                     uint32_t payload_size,
                                     bool key_frame,
                                     int64_t timestamp);

  // Dispatch a FLUSH_RESPONSE event to the event pipe.
  void DispatchFlushResponse(bool flush_done);

  // Dispatch a NOTIFY_ERROR event to the event pipe.
  void DispatchNotifyError(vea_error_t error);

 private:
  void WriteEvent(const vea_event_t& event);

  EventPipe event_pipe_;
};

// VeaImpl encapsulates a VEA implementation that can be used to create encode
// sessions.
class VeaImpl {
 public:
  VeaImpl();
  VeaImpl(const VeaImpl&) = delete;
  VeaImpl& operator=(const VeaImpl&) = delete;

  virtual ~VeaImpl();

  // Returns the encoding capabilities of this implementation.
  // The returned vea_capabilities_t object is owned by VeaImpl.
  virtual const vea_capabilities_t* const GetCapabilities();

  // Initializes a new encode session and returns a new encode session context.
  virtual VeaContext* InitEncodeSession(vea_config_t* config) = 0;

  // Closes an open encode session.
  virtual void CloseEncodeSession(VeaContext* ctx) = 0;

 protected:
  vea_capabilities_t capabilities_;
};

}  // namespace arc

#endif  // ARC_VM_LIBVDA_ENCODE_WRAPPER_H_
