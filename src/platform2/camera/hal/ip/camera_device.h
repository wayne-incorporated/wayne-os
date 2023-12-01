/* Copyright 2019 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_HAL_IP_CAMERA_DEVICE_H_
#define CAMERA_HAL_IP_CAMERA_DEVICE_H_

#include <memory>
#include <string>
#include <vector>

#include <base/memory/read_only_shared_memory_region.h>
#include <base/threading/thread.h>
#include <camera/camera_metadata.h>
#include <hardware/camera3.h>
#include <hardware/camera_common.h>
#include <hardware/hardware.h>
#include <mojo/public/cpp/bindings/pending_remote.h>
#include <mojo/public/cpp/bindings/receiver.h>
#include <mojo/public/cpp/bindings/remote.h>

#include "camera/mojo/ip/ip_camera.mojom.h"
#include "cros-camera/camera_buffer_manager.h"
#include "cros-camera/future.h"
#include "cros-camera/jpeg_decode_accelerator.h"
#include "hal/ip/request_queue.h"

namespace cros {

class CameraDevice : public mojom::IpCameraFrameListener {
 public:
  explicit CameraDevice(int id);
  CameraDevice(const CameraDevice&) = delete;
  CameraDevice& operator=(const CameraDevice&) = delete;

  ~CameraDevice();

  int Init(mojo::PendingRemote<mojom::IpCameraDevice> ip_device,
           const std::string& ip,
           const std::string& name,
           std::vector<mojom::IpCameraStreamPtr> streams);
  void Open(const hw_module_t* module, hw_device_t** hw_device);
  void Close();
  android::CameraMetadata* GetStaticMetadata();
  int GetId();

  // Implementations of camera3_device_ops_t
  int Initialize(const camera3_callback_ops_t* callback_ops);
  int ConfigureStreams(camera3_stream_configuration_t* stream_list);
  const camera_metadata_t* ConstructDefaultRequestSettings(int type);
  int ProcessCaptureRequest(camera3_capture_request_t* request);
  int Flush();

 private:
  void StartStreamingOnIpcThread(mojom::IpCameraStreamPtr stream,
                                 scoped_refptr<Future<void>> return_val);
  void StopStreamingOnIpcThread(scoped_refptr<Future<void>> return_val);
  bool ValidateStream(camera3_stream_t* stream);
  void OnFrameCaptured(mojo::ScopedSharedBufferHandle shm_handle,
                       int32_t id,
                       uint32_t size) override;
  void OnConnectionError();
  void CopyFromMappingToOutputBuffer(base::ReadOnlySharedMemoryMapping* mapping,
                                     buffer_handle_t* buffer);
  void StartJpegProcessor();
  void DecodeJpeg(base::ReadOnlySharedMemoryRegion shm,
                  int32_t id,
                  uint32_t size);
  void ReturnBufferOnIpcThread(int32_t id);
  void DestroyOnIpcThread(scoped_refptr<Future<void>> return_val);

  std::atomic<bool> open_;
  const int id_;
  mojo::Remote<mojom::IpCameraDevice> ip_device_;
  camera3_device_t camera3_device_;
  const camera3_callback_ops_t* callback_ops_;
  int width_;
  int height_;
  std::vector<mojom::IpCameraStreamPtr> streams_;
  RequestQueue request_queue_;
  scoped_refptr<base::SingleThreadTaskRunner> ipc_task_runner_;
  mojo::Receiver<IpCameraFrameListener> receiver_;
  CameraBufferManager* buffer_manager_;
  android::CameraMetadata static_metadata_;
  android::CameraMetadata latest_request_metadata_;

  // for JPEG decoding
  bool jpeg_;
  // The JPEG decoder will deadlock if it's called from the MOJO IPC thread, so
  // we need a separate thread to call it.
  base::Thread jpeg_thread_;
  std::unique_ptr<JpegDecodeAccelerator> jda_;
};

}  // namespace cros

#endif  // CAMERA_HAL_IP_CAMERA_DEVICE_H_
