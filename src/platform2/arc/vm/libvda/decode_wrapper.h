// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ARC_VM_LIBVDA_DECODE_WRAPPER_H_
#define ARC_VM_LIBVDA_DECODE_WRAPPER_H_

#include <stdint.h>

#include <memory>

#include "arc/vm/libvda/event_pipe.h"
#include "arc/vm/libvda/libvda_decode.h"

namespace arc {

// VdaContext is the decode session context created by VdaImpl.
// Implementations should be able to handle method invocations on any thread.
class VdaContext {
 public:
  VdaContext();
  VdaContext(const VdaContext&) = delete;
  VdaContext& operator=(const VdaContext&) = delete;

  virtual ~VdaContext();

  // Decodes the frame pointed to by |fd|. |offset| and |bytes_used|
  // is the buffer offset and the size of the frame.
  virtual vda_result_t Decode(int32_t bitstream_id,
                              base::ScopedFD fd,
                              uint32_t offset,
                              uint32_t bytes_used) = 0;

  // Sets the number of expected output buffers to |num_output_buffers|.
  virtual vda_result_t SetOutputBufferCount(size_t num_output_buffers) = 0;

  // Provides an output buffer |fd| for decoded frames in decode session context
  // |ctx| where |format| is the output pixel format and |planes| is a pointer
  // to an array of |num_planes| objects.
  virtual vda_result_t UseOutputBuffer(int32_t picture_buffer_id,
                                       vda_pixel_format_t format,
                                       base::ScopedFD fd,
                                       size_t num_planes,
                                       video_frame_plane_t* planes,
                                       uint64_t modifier) = 0;

  // Returns the output buffer with id |picture_buffer_id| for reuse.
  virtual vda_result_t ReuseOutputBuffer(int32_t picture_buffer_id) = 0;

  // Requests to reset the decode session, clearing all pending decodes.
  virtual vda_result_t Reset() = 0;

  // Requests to flush the decode session.
  virtual vda_result_t Flush() = 0;

  // Returns the read-only endpoint of the event pipe file descriptor.
  int GetEventFd();

 protected:
  // Dispatch a PROVIDE_PICTURE_BUFFERS event to the event pipe.
  void DispatchProvidePictureBuffers(uint32_t min_num_buffers,
                                     int32_t width,
                                     int32_t height,
                                     int32_t visible_rect_left,
                                     int32_t visible_rect_top,
                                     int32_t visible_rect_right,
                                     int32_t visible_rect_bottom);

  // Dispatch a PICTURE_READY event to the event pipe.
  void DispatchPictureReady(int32_t picture_buffer_id,
                            int32_t bitstream_id,
                            int crop_left,
                            int crop_top,
                            int crop_right,
                            int crop_bottom);

  // Dispatch a NOTIFY_END_OF_BITSTREAM_BUFFER event to the event pipe.
  void DispatchNotifyEndOfBitstreamBuffer(int32_t bitstream_id);

  // Dispatch a NOTIFY_ERROR event to the event pipe.
  void DispatchNotifyError(vda_result_t result);

  // Dispatch a RESET_RESPONSE event to the event pipe.
  void DispatchResetResponse(vda_result_t result);

  // Dispatch a FLUSH_RESPONSE event to the event pipe.
  void DispatchFlushResponse(vda_result_t result);

 private:
  void WriteEvent(const vda_event_t& event);

  EventPipe event_pipe_;
};

// VdaImpl encapsulates a vda implementation that can be used to create decode
// sessions.
class VdaImpl {
 public:
  VdaImpl();
  VdaImpl(const VdaImpl&) = delete;
  VdaImpl& operator=(const VdaImpl&) = delete;

  virtual ~VdaImpl();

  // Returns the decoding capabilities of this implementation.
  // The returned vda_capabilities_t object is owned by VdaImpl.
  virtual const vda_capabilities_t* const GetCapabilities();

  // Initializes a new decode session and returns a new decode session context.
  virtual VdaContext* InitDecodeSession(vda_profile_t profile) = 0;

  // Closes an open decode session.
  virtual void CloseDecodeSession(VdaContext* ctx) = 0;

 protected:
  vda_capabilities_t capabilities_;
};

}  // namespace arc

#endif  // ARC_VM_LIBVDA_DECODE_WRAPPER_H_
