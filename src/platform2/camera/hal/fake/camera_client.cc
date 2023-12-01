/* Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "hal/fake/camera_client.h"

#include <utility>
#include <vector>

#include <absl/cleanup/cleanup.h>
#include <base/containers/contains.h>
#include <linux/videodev2.h>
#include <sync/sync.h>

#include "cros-camera/common.h"
#include "cros-camera/future.h"

#include "hal/fake/camera_hal.h"
#include "hal/fake/camera_hal_device_ops.h"
#include "hal/fake/metadata_handler.h"

namespace cros {

CameraClient::CameraClient(int id,
                           const android::CameraMetadata& static_metadata,
                           const android::CameraMetadata& request_template,
                           const hw_module_t* module,
                           hw_device_t** hw_device,
                           const CameraSpec& spec)
    : id_(id),
      // This clones the metadata.
      static_metadata_(static_metadata),
      request_template_(request_template),
      request_thread_("FakeRequestThread"),
      spec_(spec),
      metadata_handler_(request_template_, spec_) {
  camera3_device_ = {
      .common =
          {
              .tag = HARDWARE_DEVICE_TAG,
              .version = CAMERA_DEVICE_API_VERSION_3_5,
              .module = const_cast<hw_module_t*>(module),
              .close = cros::camera_device_close,
          },
      .ops = &g_camera_device_ops,
      .priv = this,
  };
  *hw_device = &camera3_device_.common;

  DETACH_FROM_SEQUENCE(ops_sequence_checker_);
}

CameraClient::~CameraClient() {
  VLOGFID(1, id_);
}

int CameraClient::OpenDevice() {
  VLOGFID(1, id_);
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  return 0;
}

int CameraClient::CloseDevice() {
  VLOGFID(1, id_);
  DCHECK_CALLED_ON_VALID_SEQUENCE(ops_sequence_checker_);

  StreamOff();

  return 0;
}

int CameraClient::Initialize(const camera3_callback_ops_t* callback_ops) {
  VLOGFID(1, id_);
  DCHECK_CALLED_ON_VALID_SEQUENCE(ops_sequence_checker_);

  callback_ops_ = callback_ops;

  return 0;
}

int CameraClient::ConfigureStreams(
    camera3_stream_configuration_t* stream_config) {
  VLOGFID(1, id_);
  DCHECK_CALLED_ON_VALID_SEQUENCE(ops_sequence_checker_);

  std::vector<camera3_stream_t*> streams(
      stream_config->streams,
      stream_config->streams + stream_config->num_streams);

  for (auto stream : streams) {
    if (stream->stream_type != CAMERA3_STREAM_OUTPUT) {
      LOGFID(ERROR, id_) << "Non-output stream is not supported";
      return -EINVAL;
    }
    // TODO(pihsun): Implement rotation.
    if (stream->rotation != CAMERA3_STREAM_ROTATION_0) {
      LOGFID(ERROR, id_) << "Rotations are not supported yet";
      return -EINVAL;
    }
    if (!base::Contains(kSupportedHalFormats, stream->format)) {
      LOGFID(ERROR, id_) << "Stream format " << stream->format
                         << " is not supported";
      return -EINVAL;
    }
  }

  auto ret = StreamOn(streams);
  if (!ret.ok()) {
    return absl::IsInvalidArgument(ret) ? -EINVAL : -ENODEV;
  }

  for (auto stream : streams) {
    // TODO(pihsun): We likely need more than one max buffer here.
    stream->max_buffers = 1;
    stream->usage |= GRALLOC_USAGE_SW_WRITE_OFTEN;
  }

  return 0;
}

absl::Status CameraClient::StreamOn(
    const std::vector<camera3_stream_t*>& streams) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(ops_sequence_checker_);

  if (request_handler_ == nullptr) {
    if (!request_thread_.Start()) {
      LOGFID(ERROR, id_) << "Request thread failed to start";
      return absl::InternalError("Failed to start request thread");
    }
    request_task_runner_ = request_thread_.task_runner();

    request_handler_ = std::make_unique<RequestHandler>(
        id_, callback_ops_, static_metadata_, request_task_runner_, spec_);
  }

  auto future = cros::Future<absl::Status>::Create(nullptr);
  request_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&RequestHandler::StreamOn,
                     base::Unretained(request_handler_.get()),
                     std::ref(streams), cros::GetFutureCallback(future)));
  return future->Get();
}

void CameraClient::StreamOff() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(ops_sequence_checker_);

  if (request_handler_) {
    auto future = cros::Future<absl::Status>::Create(nullptr);
    request_task_runner_->PostTask(
        FROM_HERE, base::BindOnce(&RequestHandler::StreamOff,
                                  base::Unretained(request_handler_.get()),
                                  cros::GetFutureCallback(future)));
    absl::Status ret = future->Get();
    if (!ret.ok()) {
      LOGFID(ERROR, id_) << "StreamOff failed: " << ret;
    }

    request_thread_.Stop();
    request_handler_.reset();
  }
}

const camera_metadata_t* CameraClient::ConstructDefaultRequestSettings(
    int type) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(ops_sequence_checker_);

  return metadata_handler_.GetDefaultRequestSettings(type);
}

int CameraClient::ProcessCaptureRequest(camera3_capture_request_t* request) {
  VLOGFID(1, id_);
  DCHECK_CALLED_ON_VALID_SEQUENCE(ops_sequence_checker_);

  DCHECK(request_handler_ != nullptr);

  if (request == nullptr) {
    LOGFID(ERROR, id_) << "NULL request recieved";
    return -EINVAL;
  }

  VLOGFID(1, id_) << "Request Frame:" << request->frame_number;

  if (request->input_buffer != nullptr) {
    LOGFID(ERROR, id_) << "Input buffer is not supported";
    return -EINVAL;
  }

  if (request->num_output_buffers == 0) {
    LOGFID(ERROR, id_) << "Invalid number of output buffers: "
                       << request->num_output_buffers;
    return -EINVAL;
  }

  if (request->settings) {
    latest_request_metadata_ = request->settings;
    if (VLOG_IS_ON(2)) {
      dump_camera_metadata(request->settings, 1, 1);
    }
  }

  // TODO(pihsun): Check the requested stream format are supported and return
  // error early if not.

  // We cannot use |request| after this function returns. So we have to copy
  // necessary information out to |capture_request|.
  auto capture_request =
      std::make_unique<CaptureRequest>(*request, latest_request_metadata_);
  request_task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&RequestHandler::HandleRequest,
                                base::Unretained(request_handler_.get()),
                                std::move(capture_request)));
  return 0;
}

void CameraClient::Dump(int fd) {
  VLOGFID(1, id_);
}

int CameraClient::Flush(const camera3_device_t* dev) {
  VLOGFID(1, id_);

  if (request_handler_ == nullptr) {
    return 0;
  }

  base::WaitableEvent flushed;
  request_handler_->HandleFlush(
      base::BindOnce(&base::WaitableEvent::Signal, base::Unretained(&flushed)));
  flushed.Wait();
  return 0;
}

}  // namespace cros
