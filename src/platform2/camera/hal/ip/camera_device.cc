/* Copyright 2019 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <cctype>
#include <libyuv.h>
#include <linux/videodev2.h>
#include <memory>
#include <base/check.h>
#include <mojo/core/embedder/embedder.h>
#include <mojo/public/cpp/system/platform_handle.h>
#include <utility>

#include "cros-camera/common.h"
#include "cros-camera/ipc_util.h"
#include "hal/ip/camera_device.h"
#include "hal/ip/camera_hal.h"
#include "hal/ip/metadata_handler.h"

namespace cros {

static int initialize(const camera3_device_t* dev,
                      const camera3_callback_ops_t* callback_ops) {
  CameraDevice* device = reinterpret_cast<CameraDevice*>(dev->priv);
  if (!device) {
    LOGF(ERROR) << "Camera device is NULL";
    return -ENODEV;
  }
  return device->Initialize(callback_ops);
}

static int configure_streams(const camera3_device_t* dev,
                             camera3_stream_configuration_t* stream_list) {
  CameraDevice* device = reinterpret_cast<CameraDevice*>(dev->priv);
  if (!device) {
    LOGF(ERROR) << "Camera device is NULL";
    return -ENODEV;
  }
  return device->ConfigureStreams(stream_list);
}

static const camera_metadata_t* construct_default_request_settings(
    const camera3_device_t* dev, int type) {
  CameraDevice* device = reinterpret_cast<CameraDevice*>(dev->priv);
  if (!device) {
    LOGF(ERROR) << "Camera device is NULL";
    return nullptr;
  }
  return device->ConstructDefaultRequestSettings(type);
}

static int process_capture_request(const camera3_device_t* dev,
                                   camera3_capture_request_t* request) {
  CameraDevice* device = reinterpret_cast<CameraDevice*>(dev->priv);
  if (!device) {
    LOGF(ERROR) << "Camera device is NULL";
    return -ENODEV;
  }
  return device->ProcessCaptureRequest(request);
}

static void dump(const camera3_device_t* dev, int fd) {}

static int flush(const camera3_device_t* dev) {
  CameraDevice* device = reinterpret_cast<CameraDevice*>(dev->priv);
  if (!device) {
    LOGF(ERROR) << "Camera device is NULL";
    return -ENODEV;
  }
  return device->Flush();
}

}  // namespace cros

static camera3_device_ops_t g_camera_device_ops = {
    .initialize = cros::initialize,
    .configure_streams = cros::configure_streams,
    .register_stream_buffers = nullptr,
    .construct_default_request_settings =
        cros::construct_default_request_settings,
    .process_capture_request = cros::process_capture_request,
    .get_metadata_vendor_tag_ops = nullptr,
    .dump = cros::dump,
    .flush = cros::flush,
    .reserved = {},
};

namespace cros {

static int camera_device_close(struct hw_device_t* hw_device) {
  camera3_device_t* dev = reinterpret_cast<camera3_device_t*>(hw_device);
  CameraDevice* device = static_cast<CameraDevice*>(dev->priv);
  if (!device) {
    LOGF(ERROR) << "Camera device is NULL";
    return -EIO;
  }

  dev->priv = nullptr;
  return CameraHal::GetInstance().CloseDevice(device->GetId());
}

CameraDevice::CameraDevice(int id)
    : open_(false),
      id_(id),
      camera3_device_(),
      callback_ops_(nullptr),
      width_(0),
      height_(0),
      receiver_(this),
      buffer_manager_(nullptr),
      jpeg_(false),
      jpeg_thread_("JPEG Processing") {
  memset(&camera3_device_, 0, sizeof(camera3_device_));
  camera3_device_.common.tag = HARDWARE_DEVICE_TAG;
  camera3_device_.common.version = CAMERA_DEVICE_API_VERSION_3_3;
  camera3_device_.common.close = cros::camera_device_close;
  camera3_device_.common.module = nullptr;
  camera3_device_.ops = &g_camera_device_ops;
  camera3_device_.priv = this;

  buffer_manager_ = CameraBufferManager::GetInstance();
}

int CameraDevice::Init(mojo::PendingRemote<mojom::IpCameraDevice> ip_device,
                       const std::string& ip,
                       const std::string& name,
                       std::vector<mojom::IpCameraStreamPtr> streams) {
  ipc_task_runner_ = mojo::core::GetIOTaskRunner();
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());

  ip_device_.Bind(std::move(ip_device));
  streams_ = std::move(streams);

  if (streams_.empty()) {
    LOGF(ERROR) << "No stream data provided.";
    return -EINVAL;
  }

  mojom::PixelFormat format = streams_[0]->format;
  double fps = streams_[0]->fps;
  for (int i = 1; i < streams_.size(); i++) {
    if (format != streams_[i]->format) {
      LOGF(ERROR) << "Streams of different formats not supported.";
      return -EINVAL;
    }
    if (fps != streams_[i]->fps) {
      LOGF(ERROR) << "Streams of different framerates not supported.";
      return -EINVAL;
    }
  }

  switch (format) {
    case mojom::PixelFormat::JPEG:
      jpeg_ = true;
      [[fallthrough]];
    case mojom::PixelFormat::YUV_420:
      break;
    default:
      LOGF(ERROR) << "Unrecognized pixel format: " << format;
      return -EINVAL;
  }

  static_metadata_ = MetadataHandler::CreateStaticMetadata(
      ip, name, HAL_PIXEL_FORMAT_YCbCr_420_888, fps, streams_);

  if (jpeg_) {
    if (!jpeg_thread_.StartWithOptions(
            base::Thread::Options(base::MessagePumpType::IO, 0))) {
      LOGF(ERROR) << "Failed to start jpeg processing thread";
      return -ENODEV;
    }
    jpeg_thread_.task_runner()->PostTask(
        FROM_HERE, base::BindOnce(&CameraDevice::StartJpegProcessor,
                                  base::Unretained(this)));
  }

  mojo::PendingRemote<IpCameraFrameListener> remote =
      receiver_.BindNewPipeAndPassRemote();

  receiver_.set_disconnect_handler(
      base::BindOnce(&CameraDevice::OnConnectionError, base::Unretained(this)));
  ip_device_.set_disconnect_handler(
      base::BindOnce(&CameraDevice::OnConnectionError, base::Unretained(this)));

  if (ip_device_) {
    ip_device_->RegisterFrameListener(std::move(remote));
  }

  return 0;
}

void CameraDevice::Open(const hw_module_t* module, hw_device_t** hw_device) {
  camera3_device_.priv = this;
  camera3_device_.common.module = const_cast<hw_module_t*>(module);
  *hw_device = &camera3_device_.common;
  open_ = true;
}

CameraDevice::~CameraDevice() {
  if (jpeg_thread_.IsRunning()) {
    jpeg_thread_.Stop();
  }
  jda_.reset();

  auto return_val = Future<void>::Create(nullptr);
  if (!ipc_task_runner_->RunsTasksInCurrentSequence()) {
    ipc_task_runner_->PostTask(
        FROM_HERE, base::BindOnce(&CameraDevice::DestroyOnIpcThread,
                                  base::Unretained(this), return_val));
  } else {
    DestroyOnIpcThread(return_val);
  }
  return_val->Wait(-1);
}

void CameraDevice::DestroyOnIpcThread(scoped_refptr<Future<void>> return_val) {
  ip_device_.reset();
  receiver_.reset();
  return_val->Set();
}

android::CameraMetadata* CameraDevice::GetStaticMetadata() {
  return &static_metadata_;
}

int CameraDevice::GetId() {
  return id_;
}

int CameraDevice::Initialize(const camera3_callback_ops_t* callback_ops) {
  callback_ops_ = callback_ops;
  request_queue_.SetCallbacks(callback_ops_);

  return 0;
}

void CameraDevice::Close() {
  open_ = false;
  request_queue_.Flush();

  // If called from the HAL it won't be on the IPC thread, and we should tell
  // the IP camera to stop streaming. If called from the IPC thread, it's
  // because the connection was lost or the device was reported as disconnected,
  // so no need to tell it to stop streaming (the pointer probably isn't valid
  // anyway).
  if (!ipc_task_runner_->RunsTasksInCurrentSequence()) {
    auto return_val = Future<void>::Create(nullptr);
    ipc_task_runner_->PostTask(
        FROM_HERE, base::BindOnce(&CameraDevice::StopStreamingOnIpcThread,
                                  base::Unretained(this), return_val));
    return_val->Wait(-1);
  }
}

void CameraDevice::StopStreamingOnIpcThread(
    scoped_refptr<Future<void>> return_val) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());
  if (ip_device_) {
    ip_device_->StopStreaming();
  }
  return_val->Set();
}

bool CameraDevice::ValidateStream(camera3_stream_t* stream) {
  if (!stream) {
    LOGFID(ERROR, id_) << "NULL stream";
    return false;
  }

  if (stream->stream_type != CAMERA3_STREAM_OUTPUT) {
    LOGFID(ERROR, id_) << "Unsupported stream type: " << stream->stream_type;
    return false;
  }

  if (stream->rotation != CAMERA3_STREAM_ROTATION_0) {
    LOGFID(ERROR, id_) << "Unsupported stream rotation: " << stream->rotation;
    return false;
  }

  if (stream->format != HAL_PIXEL_FORMAT_YCbCr_420_888) {
    LOGFID(ERROR, id_) << "Unsupported stream format: " << stream->format;
    return false;
  }

  return true;
}

int CameraDevice::ConfigureStreams(
    camera3_stream_configuration_t* stream_list) {
  DCHECK(!ipc_task_runner_->RunsTasksInCurrentSequence());

  if (callback_ops_ == nullptr) {
    LOGFID(ERROR, id_) << "Device is not initialized";
    return -EINVAL;
  }

  if (stream_list == nullptr) {
    LOGFID(ERROR, id_) << "Null stream list array";
    return -EINVAL;
  }

  if (stream_list->num_streams != 1) {
    LOGFID(ERROR, id_) << "Unsupported number of streams: "
                       << stream_list->num_streams;
    return -EINVAL;
  }

  if (stream_list->operation_mode != CAMERA3_STREAM_CONFIGURATION_NORMAL_MODE) {
    LOGFID(ERROR, id_) << "Unsupported operation mode: "
                       << stream_list->operation_mode;
    return -EINVAL;
  }

  if (!ValidateStream(stream_list->streams[0])) {
    return -EINVAL;
  }

  mojom::IpCameraStreamPtr stream;
  for (const auto& s : streams_) {
    if (stream_list->streams[0]->width == s->width &&
        stream_list->streams[0]->height == s->height) {
      width_ = stream_list->streams[0]->width;
      height_ = stream_list->streams[0]->height;
      stream = s->Clone();
      break;
    }
  }

  if (!stream) {
    LOGFID(ERROR, id_) << "Unsupported resolution: "
                       << stream_list->streams[0]->width << " x "
                       << stream_list->streams[0]->height;
    return -EINVAL;
  }

  // TODO(pceballos): revisit these two values, the number of buffers may need
  // to be adjusted by each different device
  stream_list->streams[0]->usage |= GRALLOC_USAGE_SW_WRITE_OFTEN;
  stream_list->streams[0]->max_buffers = 4;

  auto return_val = Future<void>::Create(nullptr);
  ipc_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&CameraDevice::StartStreamingOnIpcThread,
                     base::Unretained(this), std::move(stream), return_val));

  return_val->Wait(-1);
  return 0;
}

void CameraDevice::StartStreamingOnIpcThread(
    mojom::IpCameraStreamPtr stream, scoped_refptr<Future<void>> return_val) {
  DCHECK(ipc_task_runner_->RunsTasksInCurrentSequence());
  if (ip_device_) {
    ip_device_->StartStreaming(std::move(stream));
  }
  return_val->Set();
}

const camera_metadata_t* CameraDevice::ConstructDefaultRequestSettings(
    int type) {
  if (type != CAMERA3_TEMPLATE_PREVIEW) {
    LOGFID(ERROR, id_) << "Unsupported request template:" << type;
    return nullptr;
  }
  return MetadataHandler::GetDefaultRequestSettings();
}

int CameraDevice::ProcessCaptureRequest(camera3_capture_request_t* request) {
  if (!request) {
    LOGFID(ERROR, id_) << "Received a NULL request";
    return -EINVAL;
  }

  if (request->input_buffer) {
    LOGFID(ERROR, id_) << "Input buffers are not supported";
    return -EINVAL;
  }

  if (request->num_output_buffers != 1) {
    LOGFID(ERROR, id_) << "Invalid number of output buffers: "
                       << request->num_output_buffers;
    return -EINVAL;
  }

  const camera3_stream_buffer_t* buffer = request->output_buffers;

  if (!ValidateStream(buffer->stream)) {
    return -EINVAL;
  }

  if (buffer->stream->width != width_) {
    LOGFID(ERROR, id_) << "Invalid buffer width: " << buffer->stream->width;
    return -EINVAL;
  }

  if (buffer->stream->height != height_) {
    LOGFID(ERROR, id_) << "Invalid buffer height: " << buffer->stream->height;
    return -EINVAL;
  }

  if (!open_) {
    LOGFID(ERROR, id_) << "Device is not open";
    return -ENODEV;
  }

  if (request->settings) {
    latest_request_metadata_ = request->settings;
  }

  auto capture_request =
      std::make_unique<CaptureRequest>(*request, latest_request_metadata_);
  request_queue_.Push(std::move(capture_request));

  return 0;
}

int CameraDevice::Flush() {
  request_queue_.Flush();
  return 0;
}

void CameraDevice::CopyFromMappingToOutputBuffer(
    base::ReadOnlySharedMemoryMapping* mapping, buffer_handle_t* buffer) {
  buffer_manager_->Register(*buffer);
  struct android_ycbcr ycbcr;

  if (buffer_manager_->GetV4L2PixelFormat(*buffer) != V4L2_PIX_FMT_NV12) {
    LOGF(FATAL)
        << "Output buffer is wrong pixel format, only NV12 is supported";
  }

  buffer_manager_->LockYCbCr(*buffer, 0, 0, 0, width_, height_, &ycbcr);

  // Convert from I420 to NV12 while copying the buffer since the buffer manager
  // allocates an NV12 buffer
  const uint8_t* in_y = reinterpret_cast<const uint8_t*>(mapping->memory());
  const uint8_t* in_u =
      reinterpret_cast<const uint8_t*>(mapping->memory()) + width_ * height_;
  const uint8_t* in_v = reinterpret_cast<const uint8_t*>(mapping->memory()) +
                        width_ * height_ * 5 / 4;
  uint8_t* out_y = reinterpret_cast<uint8_t*>(ycbcr.y);
  uint8_t* out_uv = reinterpret_cast<uint8_t*>(ycbcr.cb);

  int res = libyuv::I420ToNV12(in_y, width_, in_u, width_ / 4, in_v, width_ / 4,
                               out_y, ycbcr.ystride, out_uv, ycbcr.cstride,
                               width_, height_);
  if (res != 0) {
    LOGF(ERROR) << "Conversion from I420 to NV12 returned error: " << res;
  }

  buffer_manager_->Unlock(*buffer);
  buffer_manager_->Deregister(*buffer);
}

void CameraDevice::ReturnBufferOnIpcThread(int32_t id) {
  if (ip_device_) {
    ip_device_->ReturnBuffer(id);
  }
}

void CameraDevice::DecodeJpeg(base::ReadOnlySharedMemoryRegion shm,
                              int32_t id,
                              uint32_t size) {
  std::unique_ptr<CaptureRequest> request = request_queue_.Pop();
  if (!request) {
    ipc_task_runner_->PostTask(
        FROM_HERE, base::BindOnce(&CameraDevice::ReturnBufferOnIpcThread,
                                  base::Unretained(this), id));
    return;
  }
  buffer_handle_t* buffer = request->GetOutputBuffer()->buffer;

  base::subtle::ScopedFDPair fd =
      base::ReadOnlySharedMemoryRegion::TakeHandleForSerialization(
          std::move(shm))
          .PassPlatformHandle();
  JpegDecodeAccelerator::Error err =
      jda_->DecodeSync(fd.get().fd, size, 0, *buffer);
  if (err == JpegDecodeAccelerator::Error::TRY_START_AGAIN) {
    LOGFID(WARNING, id_) << "Restarting JPEG processor";
    if (!jda_->Start()) {
      LOGFID(ERROR, id_) << "Failed to restart JPEG processor";
    } else {
      err = jda_->DecodeSync(fd.get().fd, size, 0, *buffer);
    }
  }
  if (err != JpegDecodeAccelerator::Error::NO_ERRORS) {
    LOGFID(ERROR, id_) << "Jpeg decoder returned error";
    request_queue_.NotifyError(std::move(request));
    ipc_task_runner_->PostTask(
        FROM_HERE, base::BindOnce(&CameraDevice::ReturnBufferOnIpcThread,
                                  base::Unretained(this), id));
    return;
  }
  ipc_task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&CameraDevice::ReturnBufferOnIpcThread,
                                base::Unretained(this), id));

  // TODO(pceballos): Currently the JPEG decoder doesn't sync output buffer
  // memory. Force it to sync by locking then unlocking it.
  buffer_manager_->Register(*buffer);
  struct android_ycbcr ycbcr;
  buffer_manager_->LockYCbCr(*buffer, 0, 0, 0, width_, height_, &ycbcr);
  buffer_manager_->Unlock(*buffer);
  buffer_manager_->Deregister(*buffer);

  request_queue_.NotifyCapture(std::move(request));
}

void CameraDevice::OnFrameCaptured(mojo::ScopedSharedBufferHandle shm_handle,
                                   int32_t id,
                                   uint32_t size) {
  if (request_queue_.IsEmpty()) {
    if (ip_device_) {
      ip_device_->ReturnBuffer(id);
    }
    return;
  }

  base::ReadOnlySharedMemoryRegion shm =
      mojo::UnwrapReadOnlySharedMemoryRegion(std::move(shm_handle));
  if (!shm.IsValid()) {
    LOGFID(ERROR, id_) << "Error receiving shared memory region";
    if (ip_device_) {
      ip_device_->ReturnBuffer(id);
    }
    return;
  }

  if (jpeg_) {
    jpeg_thread_.task_runner()->PostTask(
        FROM_HERE,
        base::BindOnce(&CameraDevice::DecodeJpeg, base::Unretained(this),
                       std::move(shm), id, size));
    return;
  }

  base::ReadOnlySharedMemoryMapping mapping = shm.Map();
  if (!mapping.IsValid()) {
    LOGFID(ERROR, id_) << "Error mapping shm, unable to handle captured frame";
    if (ip_device_) {
      ip_device_->ReturnBuffer(id);
    }
    return;
  }

  std::unique_ptr<CaptureRequest> request = request_queue_.Pop();
  if (!request) {
    if (ip_device_) {
      ip_device_->ReturnBuffer(id);
    }
    return;
  }

  CopyFromMappingToOutputBuffer(&mapping, request->GetOutputBuffer()->buffer);

  if (ip_device_) {
    ip_device_->ReturnBuffer(id);
  }
  request_queue_.NotifyCapture(std::move(request));
}

void CameraDevice::OnConnectionError() {
  LOGF(ERROR) << "Lost connection to IP Camera";
  ip_device_.reset();
  receiver_.reset();
}

void CameraDevice::StartJpegProcessor() {
  jda_ = JpegDecodeAccelerator::CreateInstance(
      CameraHal::GetInstance().GetMojoManagerToken());
  if (!jda_->Start()) {
    LOGF(ERROR) << "Error starting JPEG processor";
  }
}

}  // namespace cros
