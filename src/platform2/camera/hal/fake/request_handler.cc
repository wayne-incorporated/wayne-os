/* Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <sync/sync.h>
#include <utility>

#include <base/threading/platform_thread.h>

#include "cros-camera/common.h"
#include "hal/fake/metadata_handler.h"
#include "hal/fake/request_handler.h"

namespace cros {

namespace {

uint64_t CurrentTimestamp() {
  struct timespec ts;
  // TODO(b/271803810#22): android.sensor.timestamp HAL metadata documentation
  // states that HAL should use CLOCK_BOOTTIME, but it doesn't work well with
  // current Chrome VCD implementation, and causing wrong video length after
  // device is back from suspend and CLOCK_BOOTTIME / CLOCK_MONOTONIC is
  // skewed.
  if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0) {
    PLOGF(ERROR) << "Get clock time fails";
    // TODO(pihsun): Handle error
    return 0;
  }

  return ts.tv_sec * 1'000'000'000LL + ts.tv_nsec;
}

}  // namespace

RequestHandler::RequestHandler(
    const int id,
    const camera3_callback_ops_t* callback_ops,
    const android::CameraMetadata& static_metadata,
    const scoped_refptr<base::SequencedTaskRunner>& task_runner,
    const CameraSpec& spec)
    : id_(id),
      callback_ops_(callback_ops),
      task_runner_(task_runner),
      static_metadata_(static_metadata),
      spec_(spec) {}

RequestHandler::~RequestHandler() = default;

void RequestHandler::HandleRequest(std::unique_ptr<CaptureRequest> request) {
  DCHECK(task_runner_->RunsTasksInCurrentSequence());

  uint32_t frame_number = request->GetFrameNumber();
  VLOGFID(1, id_) << "Request Frame: " << frame_number;

  {
    base::AutoLock l(flush_lock_);
    if (flush_started_) {
      VLOGFID(1, id_) << "Request Frame:" << frame_number
                      << " is aborted due to flush";
      AbortGrallocBufferSync(*request);
      HandleAbortedRequest(*request);
      return;
    }
  }

  auto& buffers = request->GetStreamBuffers();

  // TODO(pihsun): Determine the appropriate timeout for the sync wait.
  const int kSyncWaitTimeoutMs = 300;

  for (auto& buffer : buffers) {
    if (buffer.acquire_fence == -1) {
      continue;
    }

    int ret = sync_wait(buffer.acquire_fence, kSyncWaitTimeoutMs);
    if (ret != 0) {
      // If buffer is not ready, set |release_fence| to notify framework to
      // wait the buffer again.
      AbortGrallocBufferSync(*request);
      LOGFID(ERROR, id_) << "Acquire fence sync_wait failed: "
                         << buffer.acquire_fence;
      HandleAbortedRequest(*request);
      return;
    }
    // HAL has to set |acquire_fence| to -1 for output buffers.
    close(buffer.acquire_fence);
    buffer.acquire_fence = -1;
  }

  for (auto& buffer : buffers) {
    if (!FillResultBuffer(buffer)) {
      LOGFID(ERROR, id_) << "failed to fill buffer, aborting request";
      HandleAbortedRequest(*request);
      return;
    }
  }

  const auto request_metadata = request->GetMetadata();

  auto fps_range_tag =
      request_metadata.find(ANDROID_CONTROL_AE_TARGET_FPS_RANGE);

  if (fps_range_tag.count == 0) {
    LOGFID(ERROR, id_)
        << "ANDROID_CONTROL_AE_TARGET_FPS_RANGE not found in request metadata.";
    AbortGrallocBufferSync(*request);
    HandleAbortedRequest(*request);
    return;
  }
  CHECK_EQ(fps_range_tag.count, 2);
  auto max_fps = fps_range_tag.data.i32[1];

  constexpr int64_t kOneSecOfNanoUnit = 1000000000LL;
  int64_t min_frame_duration = kOneSecOfNanoUnit / max_fps;

  uint64_t current_timestamp = CurrentTimestamp();
  if (last_response_timestamp_ != 0 &&
      current_timestamp - last_response_timestamp_ < min_frame_duration) {
    // Sleep so we don't return frame faster than min_frame_duration.
    base::PlatformThread::Sleep(base::Nanoseconds(
        min_frame_duration - (current_timestamp - last_response_timestamp_)));
    current_timestamp = CurrentTimestamp();
  }

  android::CameraMetadata result_metadata = request_metadata;
  CHECK(FillResultMetadata(&result_metadata, current_timestamp).ok());

  last_response_timestamp_ = current_timestamp;
  NotifyShutter(frame_number, current_timestamp);

  camera3_capture_result_t capture_result = {
      .frame_number = frame_number,
      .result = result_metadata.getAndLock(),
      .num_output_buffers = base::checked_cast<uint32_t>(buffers.size()),
      .output_buffers = buffers.data(),
      .partial_result = 1,
  };

  // After process_capture_result, HAL cannot access the output buffer in
  // camera3_stream_buffer anymore unless the release fence is not -1.
  callback_ops_->process_capture_result(callback_ops_, &capture_result);
}

bool RequestHandler::FillResultBuffer(camera3_stream_buffer_t& buffer) {
  DCHECK(task_runner_->RunsTasksInCurrentSequence());

  auto it = fake_streams_.find(buffer.stream);
  if (it == fake_streams_.end()) {
    LOGF(ERROR) << "Unknown stream " << buffer.stream;
    return false;
  }
  return it->second->FillBuffer(*buffer.buffer);
}

void RequestHandler::StreamOn(const std::vector<camera3_stream_t*>& streams,
                              base::OnceCallback<void(absl::Status)> callback) {
  DCHECK(task_runner_->RunsTasksInCurrentSequence());

  auto ret = StreamOnImpl(streams);
  std::move(callback).Run(ret);
}

void RequestHandler::StreamOff(
    base::OnceCallback<void(absl::Status)> callback) {
  DCHECK(task_runner_->RunsTasksInCurrentSequence());

  auto ret = StreamOffImpl();
  std::move(callback).Run(ret);
}

absl::Status RequestHandler::StreamOnImpl(
    const std::vector<camera3_stream_t*>& streams) {
  DCHECK(task_runner_->RunsTasksInCurrentSequence());

  fake_streams_.clear();

  for (auto stream : streams) {
    Size size(stream->width, stream->height);

    auto fake_stream = FakeStream::Create(size, spec_.frames);
    if (fake_stream == nullptr) {
      return absl::InternalError("error initializing fake stream");
    }

    fake_streams_.emplace(stream, std::move(fake_stream));
  }

  return absl::OkStatus();
}

absl::Status RequestHandler::StreamOffImpl() {
  DCHECK(task_runner_->RunsTasksInCurrentSequence());

  fake_streams_.clear();

  return absl::OkStatus();
}

void RequestHandler::FlushDone(base::OnceCallback<void()> callback) {
  DCHECK(task_runner_->RunsTasksInCurrentSequence());
  VLOGFID(1, id_);
  {
    base::AutoLock l(flush_lock_);
    flush_started_ = false;
  }
  std::move(callback).Run();
}

void RequestHandler::HandleFlush(base::OnceCallback<void()> callback) {
  VLOGFID(1, id_);
  {
    base::AutoLock l(flush_lock_);
    flush_started_ = true;
  }
  task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&RequestHandler::FlushDone,
                                base::Unretained(this), std::move(callback)));
}

void RequestHandler::AbortGrallocBufferSync(CaptureRequest& request) {
  DCHECK(task_runner_->RunsTasksInCurrentSequence());
  auto& buffers = request.GetStreamBuffers();
  for (auto& buffer : buffers) {
    buffer.release_fence = buffer.acquire_fence;
    buffer.acquire_fence = -1;
  }
}

void RequestHandler::HandleAbortedRequest(CaptureRequest& request) {
  DCHECK(task_runner_->RunsTasksInCurrentSequence());

  auto& buffers = request.GetStreamBuffers();
  for (auto& buffer : buffers) {
    buffer.status = CAMERA3_BUFFER_STATUS_ERROR;
  }

  uint32_t frame_number = request.GetFrameNumber();

  camera3_capture_result_t capture_result = {
      .frame_number = frame_number,
      .num_output_buffers = static_cast<uint32_t>(buffers.size()),
      .output_buffers = buffers.data(),
  };

  NotifyRequestError(frame_number);
  callback_ops_->process_capture_result(callback_ops_, &capture_result);
}

void RequestHandler::NotifyShutter(uint32_t frame_number, uint64_t timestamp) {
  DCHECK(task_runner_->RunsTasksInCurrentSequence());

  camera3_notify_msg_t msg = {
      .type = CAMERA3_MSG_SHUTTER,
      .message =
          {
              .shutter =
                  {
                      .frame_number = frame_number,
                      .timestamp = timestamp,
                  },
          },
  };

  callback_ops_->notify(callback_ops_, &msg);
}

void RequestHandler::NotifyRequestError(uint32_t frame_number) {
  DCHECK(task_runner_->RunsTasksInCurrentSequence());

  camera3_notify_msg_t msg = {
      .type = CAMERA3_MSG_ERROR,
      .message =
          {
              .error =
                  {
                      .frame_number = frame_number,
                      .error_code = CAMERA3_MSG_ERROR_REQUEST,
                  },
          },
  };

  callback_ops_->notify(callback_ops_, &msg);
}
}  // namespace cros
