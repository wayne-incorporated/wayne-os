// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ARC_VM_LIBVDA_LIBVDA_DECODE_H_
#define ARC_VM_LIBVDA_LIBVDA_DECODE_H_

#include <stddef.h>
#include <stdint.h>

#include "arc/vm/libvda/libvda_common.h"
#include "arc/vm/libvda/libvda_export.h"

#ifdef __cplusplus
extern "C" {
#endif

// VDA implementation types.
typedef enum vda_impl_type {
  // A fake implementation for testing.
  FAKE,
  // A GpuArcVideoDecodeAccelerator-backed implementation.
  GAVDA,
  // A GpuArcVideoDecoder-backed implementation.
  GAVD
} vda_impl_type_t;

// Copy of VideoDecodeAccelerator::Result.
typedef enum vda_result {
  SUCCESS,
  ILLEGAL_STATE,
  INVALID_ARGUMENT,
  UNREADABLE_INPUT,
  PLATFORM_FAILURE,
  INSUFFICIENT_RESOURCES,
  CANCELLED
} vda_result_t;

// Based on media::DecoderStatus.
typedef enum vd_decoder_status {
  OK,
  ABORTED,
  FAILED,
  INVALID_ARGUMENT_VD,
  CREATION_FAILED
} vd_decoder_status_t;

typedef video_codec_profile_t vda_profile_t;

typedef video_pixel_format_t vda_pixel_format_t;

// Possible VDA event types.
typedef enum vda_event_type {
  UNKNOWN,
  PROVIDE_PICTURE_BUFFERS,
  PICTURE_READY,
  NOTIFY_END_OF_BITSTREAM_BUFFER,
  NOTIFY_ERROR,
  RESET_RESPONSE,
  FLUSH_RESPONSE
} vda_event_type_t;

// Event data for event type PROVIDE_PICTURE_BUFFERS.
// Requests the users to provide output buffers.
typedef struct provide_picture_buffers_event_data {
  uint32_t min_num_buffers;
  int32_t width;
  int32_t height;

  // Visible rect coordinates.
  int32_t visible_rect_left;
  int32_t visible_rect_top;
  int32_t visible_rect_right;
  int32_t visible_rect_bottom;
} provide_picture_buffers_event_data_t;

// Event data for event type PICTURE_READY.
// Notifies the user of a decoded frame ready for display. These events will
// arrive in display order.
typedef struct picture_ready_event_data {
  int32_t picture_buffer_id;
  int32_t bitstream_id;
  int32_t crop_left;
  int32_t crop_top;
  int32_t crop_right;
  int32_t crop_bottom;
} picture_ready_event_data_t;

// Union of possible events.
typedef union vda_event_data {
  // Event data for event type PROVIDE_PICTURE_BUFFERS.
  provide_picture_buffers_event_data_t provide_picture_buffers;
  // Event data for event type PICTURE_READY.
  picture_ready_event_data_t picture_ready;
  // Event data for event type NOTIFY_END_OF_BITSTREAM_BUFFER
  int32_t bitstream_id;
  // Event data for event types NOTIFY_ERROR, RESET_RESPONSE, or FLUSH_RESPONSE.
  vda_result_t result;
} vda_event_data_t;

// VDA input format with profile and min/max resolution.
typedef struct vda_input_format {
  vda_profile_t profile;
  uint32_t min_width;
  uint32_t min_height;
  uint32_t max_width;
  uint32_t max_height;
} vda_input_format_t;

// A struct representing a single VDA event.
typedef struct vda_event {
  vda_event_type_t event_type;
  vda_event_data_t event_data;
} vda_event_t;

// Media capabilities of a VDA implementation.
typedef struct vda_capabilities {
  // Supported input formats.
  size_t num_input_formats;
  const vda_input_format_t* input_formats;

  // Supported output formats, valid for any supported input format.
  size_t num_output_formats;
  const vda_pixel_format_t* output_formats;
} vda_capabilities_t;

// VDA decode session info returned by init_decode_session().
typedef struct vda_session_info {
  // A decode session context used for decoding.
  void* ctx;
  // Event pipe file descriptor. When new decode session events occur,
  // vda_event_t objects can be read from the fd.
  int event_pipe_fd;
} vda_session_info_t;

/*
 * Global implementation object methods
 */

// Initializes libvda and returns an implementation object of type |impl_type|.
// The returned implementation object can be used as a global context
// for creating new decode sessions and querying underlying implementation
// capabilities. If the requested implementation type is not available,
// NULL is returned. Note that for the impl_type GAVDA, it is expected that
// only one implementation object exists at a time.
// This function and deinitialize() should be called from the same thread.
void* LIBVDA_EXPORT initialize(vda_impl_type_t impl_type);

// Deinitializes the implementation object. The provided object will be
// destroyed and no other calls will be possible. This function and initialize()
// should be called from the same thread.
void LIBVDA_EXPORT deinitialize(void* impl);

// Returns the underlying implementation capabilities of the provided
// implementation object. Ownership of the returned vda_capabilities_t object
// is retained by the library. When deinitialize() is called on |impl|, the
// capabilities object is deleted.
const vda_capabilities_t* LIBVDA_EXPORT get_vda_capabilities(void* impl);

// Creates and initializes a new decode session that supports decoding profile
// |profile|, using the provided implementation object. The returned
// vda_session_info_t object contains a decode session context
// which can be passed to vda_decode, vda_use_output_buffer, vda_flush,
// and vda_reset to perform decoding.  NULL is returned if an error occurs
// and a decode session could not be initialized.
vda_session_info_t* LIBVDA_EXPORT init_decode_session(void* impl,
                                                      vda_profile_t profile);

// Closes a previously created decode session specified by |session_info|.
void LIBVDA_EXPORT close_decode_session(void* impl,
                                        vda_session_info_t* session_info);

/*
 * Asychronous decoder session context functions
 */

// Decodes the frame pointed to by |fd| for decode session context |ctx|.
// |offset| and |bytes_used| should point to the buffer offset and the size of
// the frame. Ownership of |fd| is passed to the library. |fd| will be closed
// after decoding has occurred and the fd is no longer needed.
// Returns SUCCESS when the decode request has been processed, else
// the error is indicated.
vda_result_t LIBVDA_EXPORT vda_decode(void* ctx,
                                      int32_t bitstream_id,
                                      int fd,
                                      uint32_t offset,
                                      uint32_t bytes_used);

// Sets the number of expected output buffers to |num_output_buffers|. This call
// should be followed by |num_output_buffers| invocations of
// vda_use_output_buffer.
vda_result_t LIBVDA_EXPORT
vda_set_output_buffer_count(void* ctx, size_t num_output_buffers);

// Provides an output buffer |fd| for decoded frames in decode session context
// |ctx| where |format| is a valid output pixel format listed in
// get_vda_capabilities, and |planes| is a pointer to an array of |num_planes|
// objects. |planes| ownership is retained by the caller. This function takes
// ownership of |fd|.
vda_result_t LIBVDA_EXPORT vda_use_output_buffer(void* ctx,
                                                 int32_t picture_buffer_id,
                                                 vda_pixel_format_t format,
                                                 int fd,
                                                 size_t num_planes,
                                                 video_frame_plane_t* planes,
                                                 uint64_t modifier);

// Returns output buffer with id |picture_buffer_id| for reuse.
vda_result_t LIBVDA_EXPORT vda_reuse_output_buffer(void* ctx,
                                                   int32_t picture_buffer_id);

// Flushes the decode session context |ctx|. When this operation has completed,
// an event of type FLUSH_RESPONSE is sent.
vda_result_t LIBVDA_EXPORT vda_flush(void* ctx);

// Resets the decode session context |ctx|. Pending buffers will not be decoded.
// When this operation has completed, an event of type RESET_RESPONSE is sent
// with the result.
// If vda_reset() is called before a vda_flush() is completed, the flush
// request will be cancelled ie. an event of type FLUSH_RESPONSE with result
// CANCELLED will be sent.
vda_result_t LIBVDA_EXPORT vda_reset(void* ctx);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // ARC_VM_LIBVDA_LIBVDA_DECODE_H_
