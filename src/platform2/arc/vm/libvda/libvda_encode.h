// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ARC_VM_LIBVDA_LIBVDA_ENCODE_H_
#define ARC_VM_LIBVDA_LIBVDA_ENCODE_H_

#include <stddef.h>
#include <stdint.h>

#include "arc/vm/libvda/libvda_common.h"
#include "arc/vm/libvda/libvda_export.h"

#ifdef __cplusplus
extern "C" {
#endif

// VEA implementation types.
typedef enum vea_impl_type {
  // A fake implementation for testing.
  VEA_FAKE,
  // A GpuArcVideoEncodeAccelerator-backed implementation.
  GAVEA
} vea_impl_type_t;

// Adapted from VideoEncodeProfile.
typedef struct vea_profile {
  video_codec_profile_t profile;
  uint32_t max_width;
  uint32_t max_height;
  uint32_t max_framerate_numerator;
  uint32_t max_framerate_denominator;
} vea_profile_t;

// Media capabilities of a VEA implementation.
typedef struct vea_capabilities {
  // Supported input formats.
  size_t num_input_formats;
  const video_pixel_format_t* input_formats;

  // Supported output formats, valid for any supported input format.
  size_t num_output_formats;
  const vea_profile_t* output_formats;
} vea_capabilities_t;

// Adapted from Bitrate.
typedef enum vea_bitrate_mode { VBR, CBR } vea_bitrate_mode_t;

typedef struct vea_bitrate {
  vea_bitrate_mode_t mode;
  uint32_t target;
  uint32_t peak;
} vea_bitrate_t;

// Adapted from VideoEncodeAcceleratorConfig.
typedef struct vea_config {
  video_pixel_format_t input_format;
  uint32_t input_visible_width;
  uint32_t input_visible_height;
  video_codec_profile_t output_profile;
  vea_bitrate_t bitrate;
  uint32_t initial_framerate;
  uint8_t has_initial_framerate;
  uint8_t h264_output_level;
  uint8_t has_h264_output_level;
} vea_config_t;

// Adapted from VideoEncodeAccelerator::Error.
typedef enum vea_error {
  ILLEGAL_STATE_ERROR = 0,
  INVALID_ARGUMENT_ERROR = 1,
  PLATFORM_FAILURE_ERROR = 2
} vea_error_t;

// VEA encode session info returned by init_encode_session().
typedef struct vea_session_info {
  // An encode session context used for encoding.
  void* ctx;
  // Event pipe file descriptor. When new encode session events occur,
  // vea_event_t objects can be read from the fd.
  int event_pipe_fd;
} vea_session_info_t;

// A unique ID assigned to an input buffer sent to the encoder for encoding
// using the function vea_encode.
typedef int32_t vea_input_buffer_id_t;

// A unique ID assigned to an output buffer sent to the encoder using the
// function vea_use_output_buffer.
typedef int32_t vea_output_buffer_id_t;

// Possible VEA event types.
typedef enum vea_event_type {
  REQUIRE_INPUT_BUFFERS,
  PROCESSED_INPUT_BUFFER,
  PROCESSED_OUTPUT_BUFFER,
  VEA_FLUSH_RESPONSE,
  VEA_NOTIFY_ERROR
} vea_event_type_t;

// Event data for VEA event type REQUIRE_INPUT_BUFFERS.
// Requests the users to provide input buffers,
// and specifies the buffer size for output buffers.
typedef struct vea_require_input_buffers_event_data {
  uint32_t input_count;
  uint32_t input_frame_width;
  uint32_t input_frame_height;
  uint32_t output_buffer_size;
} vea_require_input_buffers_event_data_t;

// Event data for VEA event type PROCESSED_OUTPUT_BUFFER.
// This event can be received when an output buffer provided by
// vea_use_output_buffer has been processed. |payload_size|
// will be set to the number of bytes used.
typedef struct vea_processed_output_buffer_event_data {
  vea_output_buffer_id_t output_buffer_id;
  uint32_t payload_size;
  uint8_t key_frame;
  int64_t timestamp;
} vea_processed_output_buffer_event_data_t;

// Union of data provided for possible VEA events.
typedef union vea_event_data {
  // Event data for event type REQUIRE_INPUT_BUFFERS.
  vea_require_input_buffers_event_data_t require_input_buffers;
  // Event data for event type PROCESSED_INPUT_BUFFER.
  vea_input_buffer_id_t processed_input_buffer_id;
  // Event data for event type PROCESSED_OUTPUT_BUFFER.
  vea_processed_output_buffer_event_data_t processed_output_buffer;
  // Event data for event type FLUSH_RESPONSE.
  uint8_t flush_done;
  // Event data for event type NOTIFY_ERROR.
  vea_error_t error;
} vea_event_data_t;

// A struct representing a single VEA event. Structs of this type and size
// can be read from |event_pipe_fd| provided in the vea_session_info_t struct.
typedef struct vea_event {
  vea_event_type_t event_type;
  vea_event_data_t event_data;
} vea_event_t;

// Initializes the livda encode API and return an implementation object of type
// |impl_type|. The returned implementation object can be used as a global
// context for creating new encode sessions.
void* LIBVDA_EXPORT initialize_encode(vea_impl_type_t type);

// Deinitializes the implementation object. This should be called after
// all encoding contexts have been closed with close_encode_session.
// The provided object will be destroyed and can no longer be used as an
// argument for get_vea_capabilities, init_encode_session, or
// close_encode_session.
void LIBVDA_EXPORT deinitialize_encode(void* impl);

// Returns the underlying implementation capabilities of the provided
// implementation object. Ownership of the returned vea_capabilities_t object
// is retained by the library. When deinitialize_encode() is called on |impl|,
// the capabilities object is deleted.
const vea_capabilities_t* LIBVDA_EXPORT get_vea_capabilities(void* impl);

// Creates and initializes a new encode session that supports encoding
// configuration |config|, using the provided implementation object.
//
// The returned vea_session_info_t object contains an initialized encode session
// context, |ctx|. |ctx| can then be used as an argument in invocations of
// vea_encode, vea_use_output_buffer, vea_request_encoding_params_change,
// and vea_flush.
// NULL is returned if an error occurs and an encode session could not be
// initialized.
vea_session_info_t* LIBVDA_EXPORT init_encode_session(void* impl,
                                                      vea_config_t* config);

// Close a previously created encode session specified by |session_info|.
void LIBVDA_EXPORT close_encode_session(void* impl,
                                        vea_session_info_t* session_info);

// Encodes the frame provided by the buffer specified by |fd|.
//
// The caller is responsible for passing in a unique value for
// |input_buffer_id| which it can reference when handling
// PROCESSED_INPUT_BUFFER events.
//
// Setting |force_keyframe| to true will signal to the encoder implementation
// to generate a keyframe from the raw frame at buffer |fd|.
//
// When the frame has been processed and the buffer is no longer needed, a
// vea_event_t struct with type PROCESSED_INPUT_BUFFER and
// processed_input_buffer_id set to |input_buffer_id| can be received from
// the event pipe.
//
// When the buffer has been encoded, a vea_event_t struct with type
// PROCESSED_OUTPUT_BUFFER will be readable from the event pipe with an
// instantiated vea_processed_output_buffer_event_data struct. The timestamp
// field in vea_processed_output_buffer_event_data will be the same as the
// value passed in as |timestamp|. See vea_use_output_buffer() below for
// details on providing output buffers.
//
// The returned value will be 0 when the request was successfully sent.
int LIBVDA_EXPORT vea_encode(void* ctx,
                             vea_input_buffer_id_t input_buffer_id,
                             int fd,
                             size_t num_planes,
                             video_frame_plane_t* planes,
                             int64_t timestamp,
                             uint8_t force_keyframe);

// Provide a buffer for storing encoded output.
//
// The caller is responsible for passing in a unique value for
// |output_buffer_id| which it can reference when handling
// PROCESSED_OUTPUT_BUFFER events.
//
// This function takes ownership of |fd|.
//
// When the output buffer has been filled, a vea_event_t struct with
// type PROCESSED_OUTPUT_BUFFER and processed_output_buffer_id set to
// |output_buffer_id| can be received from the event pipe.
//
// The returned value will be 0 if the request was successfully sent.
int LIBVDA_EXPORT vea_use_output_buffer(void* ctx,
                                        vea_output_buffer_id_t output_buffer_id,
                                        int fd,
                                        uint32_t offset,
                                        uint32_t size);

// Requests a change to encoding parameters.
// The request is not guaranteed to be honored and could be ignored by the
// backing encoder implementation.
// The returned value will be 0 when the param change request has been
// successfully sent.
int LIBVDA_EXPORT vea_request_encoding_params_change(void* ctx,
                                                     vea_bitrate_t bitrate,
                                                     uint32_t framerate);

// Requests the encoder to flush. All pending buffers provided by vea_encode
// will be encoded. When the flush has completed, a vea_event_type_t struct with
// type FLUSH_RESPONSE can be received from the event pipe.
//
// The user should not invoke additional vea_flush or vea_encode calls until
// a FLUSH_RESPONSE has been read from the event pipe.
//
// The returned value will be 0 when the flush request has been successfully
// sent.
int LIBVDA_EXPORT vea_flush(void* ctx);

#ifdef __cplusplus
}
#endif

#endif  // ARC_VM_LIBVDA_LIBVDA_ENCODE_H_
