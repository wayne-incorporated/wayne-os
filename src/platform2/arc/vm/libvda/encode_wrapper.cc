// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/vm/libvda/encode_wrapper.h"

#include <utility>

#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/logging.h>

#include "arc/vm/libvda/encode/fake/fake_vea_impl.h"
#include "arc/vm/libvda/encode/gpu/gpu_vea_impl.h"

namespace arc {

VeaImpl::VeaImpl() {
  capabilities_.num_input_formats = 0;
  capabilities_.input_formats = nullptr;
  capabilities_.num_output_formats = 0;
  capabilities_.output_formats = nullptr;
}

VeaImpl::~VeaImpl() = default;

const vea_capabilities_t* const VeaImpl::GetCapabilities() {
  return &capabilities_;
}

VeaContext::VeaContext() = default;

VeaContext::~VeaContext() = default;

int VeaContext::GetEventFd() {
  return event_pipe_.GetReadFd();
}

void VeaContext::WriteEvent(const vea_event_t& event) {
  event_pipe_.WriteVeaEvent(event);
}

void VeaContext::DispatchRequireInputBuffers(uint32_t input_count,
                                             uint32_t input_frame_width,
                                             uint32_t input_frame_height,
                                             uint32_t output_buffer_size) {
  vea_event_t event;
  event.event_type = REQUIRE_INPUT_BUFFERS;
  event.event_data.require_input_buffers.input_count = input_count;
  event.event_data.require_input_buffers.input_frame_width = input_frame_width;
  event.event_data.require_input_buffers.input_frame_height =
      input_frame_height;
  event.event_data.require_input_buffers.output_buffer_size =
      output_buffer_size;
  WriteEvent(event);
}

void VeaContext::DispatchProcessedInputBuffer(
    vea_input_buffer_id_t input_buffer_id) {
  vea_event_t event;
  event.event_type = PROCESSED_INPUT_BUFFER;
  event.event_data.processed_input_buffer_id = input_buffer_id;
  WriteEvent(event);
}

void VeaContext::DispatchProcessedOutputBuffer(
    vea_output_buffer_id_t output_buffer_id,
    uint32_t payload_size,
    bool key_frame,
    int64_t timestamp) {
  vea_event_t event;
  event.event_type = PROCESSED_OUTPUT_BUFFER;
  event.event_data.processed_output_buffer.output_buffer_id = output_buffer_id;
  event.event_data.processed_output_buffer.payload_size = payload_size;
  event.event_data.processed_output_buffer.key_frame = key_frame;
  event.event_data.processed_output_buffer.timestamp = timestamp;
  WriteEvent(event);
}

void VeaContext::DispatchFlushResponse(bool flush_done) {
  vea_event_t event;
  event.event_type = VEA_FLUSH_RESPONSE;
  event.event_data.flush_done = flush_done;
  WriteEvent(event);
}

void VeaContext::DispatchNotifyError(vea_error_t error) {
  vea_event_t event;
  event.event_type = VEA_NOTIFY_ERROR;
  event.event_data.error = error;
  WriteEvent(event);
}

}  // namespace arc

void* initialize_encode(vea_impl_type_t impl_type) {
  switch (impl_type) {
    case VEA_FAKE:
      return arc::FakeVeaImpl::Create();
    case GAVEA: {
      arc::VafConnection* conn = arc::VafConnection::Get();
      if (conn == nullptr) {
        LOG(ERROR) << "Failed to retrieve VAF connection.";
        return nullptr;
      }
      return arc::GpuVeaImpl::Create(conn);
    }
    default:
      LOG(ERROR) << "Unknown impl type " << impl_type;
      return nullptr;
  }
}

void deinitialize_encode(void* impl) {
  arc::VeaImpl* cast_impl = static_cast<arc::VeaImpl*>(impl);
  delete cast_impl;
}

vea_session_info_t* init_encode_session(void* impl, vea_config_t* config) {
  arc::VeaContext* context =
      static_cast<arc::VeaImpl*>(impl)->InitEncodeSession(config);
  if (!context)
    return nullptr;
  vea_session_info_t* session_info = new vea_session_info_t();
  session_info->ctx = context;
  session_info->event_pipe_fd = context->GetEventFd();
  return session_info;
}

void close_encode_session(void* impl, vea_session_info_t* session_info) {
  static_cast<arc::VeaImpl*>(impl)->CloseEncodeSession(
      static_cast<arc::VeaContext*>(session_info->ctx));
  delete session_info;
}

const vea_capabilities_t* get_vea_capabilities(void* impl) {
  return static_cast<arc::VeaImpl*>(impl)->GetCapabilities();
}

int vea_encode(void* ctx,
               vea_input_buffer_id_t input_buffer_id,
               int fd,
               size_t num_planes,
               video_frame_plane_t* planes,
               int64_t timestamp,
               uint8_t force_keyframe) {
  return static_cast<arc::VeaContext*>(ctx)->Encode(
      input_buffer_id, base::ScopedFD(fd), num_planes, planes, timestamp,
      force_keyframe);
}

int vea_use_output_buffer(void* ctx,
                          vea_output_buffer_id_t output_buffer_id,
                          int fd,
                          uint32_t offset,
                          uint32_t size) {
  return static_cast<arc::VeaContext*>(ctx)->UseOutputBuffer(
      output_buffer_id, base::ScopedFD(fd), offset, size);
}

int vea_request_encoding_params_change(void* ctx,
                                       vea_bitrate_t bitrate,
                                       uint32_t framerate) {
  return static_cast<arc::VeaContext*>(ctx)->RequestEncodingParamsChange(
      bitrate, framerate);
}

int vea_flush(void* ctx) {
  return static_cast<arc::VeaContext*>(ctx)->Flush();
}
