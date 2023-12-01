// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/vm/libvda/decode/test/decode_event_thread.h"

#include <fcntl.h>

#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <base/logging.h>
#include <base/notreached.h>
#include <base/posix/eintr_wrapper.h>
#include <gtest/gtest.h>

namespace arc {
namespace test {
namespace {

constexpr int kGbmBoUsage = GBM_BO_USE_TEXTURING | GBM_BO_USE_HW_VIDEO_DECODER;

const char* ConvertVdaFormatToString(vda_pixel_format_t format) {
  switch (format) {
    case YV12:
      return "YV12";
    case NV12:
      return "NV12";
    default:
      NOTREACHED();
  }
}

}  // namespace

DecodeEventThread::DecodeEventThread(const vda_capabilities_t* const caps,
                                     const vda_session_info_t* const session)
    : thread_("DecodeEventThread"), caps_(caps), session_(session) {}

DecodeEventThread::~DecodeEventThread() {
  Stop();
}

void DecodeEventThread::Start() {
  gbm_device_ = arc::ScopedGbmDevice::Create();
  ASSERT_NE(gbm_device_.get(), nullptr);

  vda_format_ = caps_->output_formats[0];
  gbm_format_ = arc::ConvertPixelFormatToGbmFormat(vda_format_);
  ASSERT_NE(gbm_format_, 0);

  end_of_bitstream_buffer_event_count_ = 0;

  LOG(INFO) << "Using pixel format " << ConvertVdaFormatToString(vda_format_)
            << ", gbm format " << gbm_format_;

  ASSERT_TRUE(thread_.StartWithOptions(
      base::Thread::Options(base::MessagePumpType::IO, 0)));

  thread_.task_runner()->PostTask(
      FROM_HERE, base::BindOnce(&DecodeEventThread::StartWatching,
                                base::Unretained(this)));
}

void DecodeEventThread::Stop() {
  DCHECK(thread_.IsRunning());
  thread_.task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(&DecodeEventThread::StopWatching, base::Unretained(this)));
  thread_.Stop();
}

void DecodeEventThread::StartWatching() {
  // Since thread_checker_ binds to whichever thread it's created on, check
  // that we're on the correct thread first using BelongsToCurrentThread.
  DCHECK(thread_.task_runner()->BelongsToCurrentThread());
  DETACH_FROM_THREAD(thread_checker_);
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  event_pipe_fd_controller_ = base::FileDescriptorWatcher::WatchReadable(
      session_->event_pipe_fd,
      base::BindRepeating(&DecodeEventThread::OnEventPipeReadable,
                          weak_factory_.GetWeakPtr()));
}

void DecodeEventThread::StopWatching() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  event_pipe_fd_controller_.reset();
  picture_buffer_id_to_bo_map_.clear();
}

void DecodeEventThread::OnEventPipeReadable() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  vda_event_t event;
  if (!base::ReadFromFD(session_->event_pipe_fd,
                        reinterpret_cast<char*>(&event), sizeof(vda_event_t))) {
    LOG(ERROR) << "Failed to read from event pipe.";
    return;
  }

  switch (event.event_type) {
    case PICTURE_READY:
      OnPictureReady(event.event_data.picture_ready);
      break;
    case PROVIDE_PICTURE_BUFFERS:
      OnProvidePictureBuffers(event.event_data.provide_picture_buffers);
      break;
    case NOTIFY_END_OF_BITSTREAM_BUFFER:
      OnNotifyEndOfBitstreamBuffer(event.event_data.bitstream_id);
      break;
    case NOTIFY_ERROR:
      LOG(ERROR) << "Received NOTIFY_ERROR event with result "
                 << event.event_data.result;
      NOTREACHED();
      break;
    default:
      LOG(ERROR) << "Received unknown event type " << event.event_type;
      NOTREACHED();
      break;
  }
}

void DecodeEventThread::OnNotifyEndOfBitstreamBuffer(int32_t bitstream_id) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  VLOG(3) << "NOTIFY_END_OF_BITSTREAM_BUFFER event: bitstream_id "
          << bitstream_id;
  base::AutoLock lock(end_of_bitstream_buffer_event_count_lock_);
  end_of_bitstream_buffer_event_count_++;
}

uint32_t DecodeEventThread::GetAndClearEndOfBitstreamBufferEventCount() {
  base::AutoLock lock(end_of_bitstream_buffer_event_count_lock_);
  uint32_t ret = end_of_bitstream_buffer_event_count_;
  end_of_bitstream_buffer_event_count_ = 0;
  return ret;
}

void DecodeEventThread::OnPictureReady(const picture_ready_event_data_t& data) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  VLOG(3) << "PICTURE_READY event: picture_buffer_id " << data.picture_buffer_id
          << " bitstream_id " << data.bitstream_id << " crop_left "
          << data.crop_left << " crop_top " << data.crop_top << " crop_right "
          << data.crop_right << " crop_bottom " << data.crop_bottom;

  // Give back the frame buffer.
  auto iter = picture_buffer_id_to_bo_map_.find(data.picture_buffer_id);
  if (iter == picture_buffer_id_to_bo_map_.end()) {
    DLOG(ERROR) << "Could not find picture buffer id: "
                << data.picture_buffer_id;
    return;
  }

  vda_reuse_output_buffer(session_->ctx, data.picture_buffer_id);
}

void DecodeEventThread::CallUseOutputBuffer(int32_t picture_buffer_id,
                                            gbm_bo* bo) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  int plane_count = gbm_bo_get_plane_count(bo);
  int plane_fd = gbm_bo_get_fd(bo);
  uint64_t modifier = gbm_bo_get_modifier(bo);

  std::vector<video_frame_plane_t> vda_planes;

  // video_frame_plane_t* vda_planes = new video_frame_plane_t[plane_count];
  for (int plane_index = 0; plane_index < plane_count; plane_index++) {
    video_frame_plane_t plane;
    plane.offset = gbm_bo_get_offset(bo, plane_index);
    plane.stride = gbm_bo_get_stride_for_plane(bo, plane_index);

    // Check that offsets are increasing which would indicate that all planes
    // are in a single buffer.
    if (vda_planes.size())
      CHECK_GT(plane.offset, vda_planes.back().offset);

    vda_planes.push_back(std::move(plane));
  }

  vda_use_output_buffer(session_->ctx, picture_buffer_id, vda_format_, plane_fd,
                        plane_count, vda_planes.data(), modifier);
}

void DecodeEventThread::OnProvidePictureBuffers(
    const provide_picture_buffers_event_data_t& data) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  VLOG(3) << "PROVIDE_PICTURE_BUFFERS event: min_num_buffers "
          << data.min_num_buffers << " width " << data.width << " height "
          << data.height << " visible_rect " << data.visible_rect_left << " "
          << data.visible_rect_top << " " << data.visible_rect_right << " "
          << data.visible_rect_bottom;

  picture_buffer_id_to_bo_map_.clear();

  vda_set_output_buffer_count(session_->ctx, data.min_num_buffers);

  for (int i = 0; i < data.min_num_buffers; i++) {
    int32_t picture_buffer_id = i;

    arc::ScopedGbmBoPtr bo(gbm_bo_create(
        gbm_device_.get(), data.width, data.height, gbm_format_, kGbmBoUsage));
    CHECK_NE(bo.get(), nullptr);

    CallUseOutputBuffer(picture_buffer_id, bo.get());

    picture_buffer_id_to_bo_map_.insert(
        std::make_pair(picture_buffer_id, std::move(bo)));
  }
}

}  // namespace test
}  // namespace arc
