// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/vm/libvda/decode_wrapper.h"

#include <utility>

#include <base/logging.h>

#include "arc/vm/libvda/decode/fake/fake_vda_impl.h"
#include "arc/vm/libvda/decode/gpu/gpu_vd_impl.h"
#include "arc/vm/libvda/decode/gpu/gpu_vda_impl.h"
#include "arc/vm/libvda/gpu/vaf_connection.h"

namespace arc {

VdaImpl::VdaImpl() {
  capabilities_.num_input_formats = 0;
  capabilities_.input_formats = nullptr;
  capabilities_.num_output_formats = 0;
  capabilities_.output_formats = nullptr;
}

VdaImpl::~VdaImpl() = default;

const vda_capabilities_t* const VdaImpl::GetCapabilities() {
  return &capabilities_;
}

VdaContext::VdaContext() = default;

VdaContext::~VdaContext() = default;

int VdaContext::GetEventFd() {
  return event_pipe_.GetReadFd();
}

void VdaContext::WriteEvent(const vda_event_t& event) {
  event_pipe_.WriteVdaEvent(event);
}

void VdaContext::DispatchProvidePictureBuffers(uint32_t min_num_buffers,
                                               int32_t width,
                                               int32_t height,
                                               int32_t visible_rect_left,
                                               int32_t visible_rect_top,
                                               int32_t visible_rect_right,
                                               int32_t visible_rect_bottom) {
  vda_event_t event;
  event.event_type = PROVIDE_PICTURE_BUFFERS;
  event.event_data.provide_picture_buffers.min_num_buffers = min_num_buffers;
  event.event_data.provide_picture_buffers.width = width;
  event.event_data.provide_picture_buffers.height = height;
  event.event_data.provide_picture_buffers.visible_rect_left =
      visible_rect_left;
  event.event_data.provide_picture_buffers.visible_rect_top = visible_rect_top;
  event.event_data.provide_picture_buffers.visible_rect_right =
      visible_rect_right;
  event.event_data.provide_picture_buffers.visible_rect_bottom =
      visible_rect_bottom;
  WriteEvent(event);
}

void VdaContext::DispatchPictureReady(int32_t picture_buffer_id,
                                      int32_t bitstream_id,
                                      int crop_left,
                                      int crop_top,
                                      int crop_right,
                                      int crop_bottom) {
  vda_event_t event;
  event.event_type = PICTURE_READY;
  event.event_data.picture_ready.picture_buffer_id = picture_buffer_id;
  event.event_data.picture_ready.bitstream_id = bitstream_id;
  event.event_data.picture_ready.crop_left = crop_left;
  event.event_data.picture_ready.crop_top = crop_top;
  event.event_data.picture_ready.crop_right = crop_right;
  event.event_data.picture_ready.crop_bottom = crop_bottom;
  WriteEvent(event);
}

void VdaContext::DispatchNotifyEndOfBitstreamBuffer(int32_t bitstream_id) {
  vda_event_t event;
  event.event_type = NOTIFY_END_OF_BITSTREAM_BUFFER;
  event.event_data.bitstream_id = bitstream_id;
  WriteEvent(event);
}

void VdaContext::DispatchNotifyError(vda_result_t result) {
  vda_event_t event;
  event.event_type = NOTIFY_ERROR;
  event.event_data.result = result;
  WriteEvent(event);
}

void VdaContext::DispatchResetResponse(vda_result_t result) {
  vda_event_t event;
  event.event_type = RESET_RESPONSE;
  event.event_data.result = result;
  WriteEvent(event);
}

void VdaContext::DispatchFlushResponse(vda_result_t result) {
  vda_event_t event;
  event.event_type = FLUSH_RESPONSE;
  event.event_data.result = result;
  WriteEvent(event);
}

}  // namespace arc

void* initialize(vda_impl_type_t impl_type) {
  switch (impl_type) {
    case FAKE:
      return arc::FakeVdaImpl::Create();
    case GAVDA: {
      arc::VafConnection* conn = arc::VafConnection::Get();
      if (conn == nullptr) {
        LOG(ERROR) << "Failed to retrieve VAF connection.";
        return nullptr;
      }
      return arc::GpuVdaImpl::Create(conn);
    }
    case GAVD: {
      arc::VafConnection* conn = arc::VafConnection::Get();
      if (conn == nullptr) {
        LOG(ERROR) << "Failed to retrieve VAF connection.";
        return nullptr;
      }
      return arc::GpuVdImpl::Create(conn);
    }
    default:
      LOG(ERROR) << "Unknown impl type " << impl_type;
      return nullptr;
  }
}

void deinitialize(void* impl) {
  arc::VdaImpl* cast_impl = static_cast<arc::VdaImpl*>(impl);
  delete cast_impl;
}

const vda_capabilities_t* get_vda_capabilities(void* impl) {
  return static_cast<arc::VdaImpl*>(impl)->GetCapabilities();
}

vda_session_info_t* init_decode_session(void* impl, vda_profile_t profile) {
  arc::VdaContext* context =
      static_cast<arc::VdaImpl*>(impl)->InitDecodeSession(profile);
  if (!context)
    return nullptr;
  vda_session_info_t* session_info = new vda_session_info_t();
  session_info->ctx = context;
  session_info->event_pipe_fd = context->GetEventFd();
  return session_info;
}

void close_decode_session(void* impl, vda_session_info_t* session_info) {
  static_cast<arc::VdaImpl*>(impl)->CloseDecodeSession(
      static_cast<arc::VdaContext*>(session_info->ctx));
  delete session_info;
}

vda_result_t vda_decode(void* ctx,
                        int32_t bitstream_id,
                        int fd,
                        uint32_t offset,
                        uint32_t bytes_used) {
  return static_cast<arc::VdaContext*>(ctx)->Decode(
      bitstream_id, base::ScopedFD(fd), offset, bytes_used);
}

vda_result_t vda_set_output_buffer_count(void* ctx, size_t num_output_buffers) {
  return static_cast<arc::VdaContext*>(ctx)->SetOutputBufferCount(
      num_output_buffers);
}

vda_result_t vda_use_output_buffer(void* ctx,
                                   int32_t picture_buffer_id,
                                   vda_pixel_format_t format,
                                   int fd,
                                   size_t num_planes,
                                   video_frame_plane_t* planes,
                                   uint64_t modifier) {
  return static_cast<arc::VdaContext*>(ctx)->UseOutputBuffer(
      picture_buffer_id, format, base::ScopedFD(fd), num_planes, planes,
      modifier);
}

vda_result_t vda_reuse_output_buffer(void* ctx, int32_t picture_buffer_id) {
  return static_cast<arc::VdaContext*>(ctx)->ReuseOutputBuffer(
      picture_buffer_id);
}

vda_result vda_reset(void* ctx) {
  return static_cast<arc::VdaContext*>(ctx)->Reset();
}

vda_result vda_flush(void* ctx) {
  return static_cast<arc::VdaContext*>(ctx)->Flush();
}
