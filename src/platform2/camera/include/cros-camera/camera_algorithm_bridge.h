/*
 * Copyright 2017 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_INCLUDE_CROS_CAMERA_CAMERA_ALGORITHM_BRIDGE_H_
#define CAMERA_INCLUDE_CROS_CAMERA_CAMERA_ALGORITHM_BRIDGE_H_

#include <cinttypes>
#include <memory>
#include <string>
#include <vector>

#include "cros-camera/camera_algorithm.h"
#include "cros-camera/camera_mojo_channel_manager_token.h"
#include "cros-camera/export.h"

namespace cros {

// Specifies the backend algorithm service that will be connected through IPC.
enum class CameraAlgorithmBackend {
  // Platform-specific 3A and extra algorithms running on CPU.
  kVendorCpu,
  // Platform-specific imaging algorithms running on GPU.
  kVendorGpu,
  // Google camera algorithms using GPU, e.g. Portrait Mode.
  kGoogleGpu,
  // For testing.
  kTest,
};

// The class is for a camera HAL to access camera algorithm library.
//
// The class is thread-safe.
//
// Example usage:
//
//  #include <cros-camera/camera_algorithm_bridge.h>
//  auto* token = GetMojoChannelManagerToken();
//  auto algo = CameraAlgorithmBridge::CreateInstance(backend, token);
//  algo->Initialize(this);
//  std::vector<int32_t> handles(2);
//  handles[0] = algo->RegisterBuffer(buffer_fd0);
//  handles[1] = algo->RegisterBuffer(buffer_fd1);
//  std::vector<uint8_t> req_headers(2);
//  algo->Request(req_headers[0], handles[0]);
//  algo->Request(req_headers[1], handles[1]);
//  /* |return_callback_fn| is called to return buffer */
//  algo->Deregister(handles);

class CROS_CAMERA_EXPORT CameraAlgorithmBridge {
 public:
  // Disallow copy and assign
  CameraAlgorithmBridge(const CameraAlgorithmBridge&) = delete;
  void operator=(const CameraAlgorithmBridge&) = delete;

  // [DEPRECATED]
  //
  // This method creates and returns the CameraAlgorithmBridge instance of
  // vendor algorithms.
  //
  // Returns:
  //    Unique pointer to instance on success; nullptr on failure.
  static std::unique_ptr<CameraAlgorithmBridge> CreateInstance(
      CameraAlgorithmBackend backend);

  // This method creates and returns the CameraAlgorithmBridge instance of
  // vendor algorithms.
  //
  // Args:
  //    |token|: The camera mojo channel manager token which is used for mojo
  //             communication.
  // Returns:
  //    Unique pointer to instance on success; nullptr on failure.
  static std::unique_ptr<CameraAlgorithmBridge> CreateInstance(
      CameraAlgorithmBackend backend, CameraMojoChannelManagerToken* token);

  virtual ~CameraAlgorithmBridge() = default;

  // This method is one-time initialization that registers a callback function
  // for the camera algorithm library to return a buffer handle. It must be
  // called before any other functions.
  //
  // Args:
  //    |callback_ops|: Pointer to callback functions. The callback functions
  //      will be called on a different thread from the one calling
  //      Initialize, and the caller needs to take care of the
  //      synchronization.
  //
  // Returns:
  //    0 on success; corresponding error code on failure.
  virtual int32_t Initialize(
      const camera_algorithm_callback_ops_t* callback_ops) = 0;

  // This method registers a buffer to the camera algorithm library and gets
  // the handle associated with it.
  //
  // Args:
  //    |buffer_fd|: The buffer file descriptor to register.
  //
  // Returns:
  //    A handle on success; corresponding error code on failure.
  virtual int32_t RegisterBuffer(int buffer_fd) = 0;

  // This method posts a request for the camera algorithm library to process the
  // given buffer. This method is asynchronous and returns immediately after the
  // bridge sends the IPC message out. A callback to the registered
  // |callback_ops| will be invoked to return the processing status and buffer
  // handle.
  //
  // Args:
  //    |req_id|: The ID that uniquely identifies this request and needs to be
  //      sent back in camera_algorithm_callback_ops_t.return_callback().
  //    |req_header|: The request header indicating request details. The
  //      interpretation depends on the HAL implementation.
  //    |buffer_handle|: Handle of the buffer to process.
  virtual void Request(uint32_t req_id,
                       const std::vector<uint8_t>& req_header,
                       int32_t buffer_handle) = 0;

  // This method deregisters buffers to the camera algorithm library. The camera
  // algorithm shall release all the registered buffers on return of this
  // function.
  //
  // Args:
  //    |buffer_handles|: The buffer handles to deregister.
  //
  // Returns:
  //    A handle on success; -1 on failure.
  virtual void DeregisterBuffers(
      const std::vector<int32_t>& buffer_handles) = 0;

  // This method returns the result for an update from the camera algorithm
  // library.
  //
  // Args:
  //    |upd_id|: The ID that uniquely identifies the update from camera
  //      algorithm library.
  //    |status|: Result of the update.
  //    |buffer_fd|: The buffer file descriptor to return.
  virtual void UpdateReturn(uint32_t upd_id,
                            uint32_t status,
                            int buffer_fd) = 0;

 protected:
  CameraAlgorithmBridge() = default;
};

}  // namespace cros

#endif  // CAMERA_INCLUDE_CROS_CAMERA_CAMERA_ALGORITHM_BRIDGE_H_
