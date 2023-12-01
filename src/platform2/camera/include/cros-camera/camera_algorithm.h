/*
 * Copyright 2017 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_INCLUDE_CROS_CAMERA_CAMERA_ALGORITHM_H_
#define CAMERA_INCLUDE_CROS_CAMERA_CAMERA_ALGORITHM_H_

#include <stdint.h>

// This is the interfaces that the camera algorithm library shall implement.

#define CAMERA_ALGORITHM_MODULE_INFO_SYM CAMI
#define CAMERA_ALGORITHM_MODULE_INFO_SYM_AS_STR "CAMI"

extern "C" {

typedef enum camera_algorithm_error_msg_code {
  /**
   * A serious failure occured. The client must free the bridge and create it
   * again to use it.
   */
  CAMERA_ALGORITHM_MSG_IPC_ERROR = 1,
} camera_algorithm_error_msg_code_t;

typedef struct camera_algorithm_callback_ops {
  void (*return_callback)(const struct camera_algorithm_callback_ops* callback,
                          uint32_t req_id,
                          uint32_t status,
                          int32_t buffer_handle);
  void (*notify)(const struct camera_algorithm_callback_ops* callback,
                 camera_algorithm_error_msg_code_t msg);

  // This method allows the camera algorithm library to update status and/or
  // control data to the HAL.
  //
  // Args:
  //    |upd_id|: The ID that uniquely identifies this update and needs to be
  //      sent back in camera_algorithm_ops_t.update_return().
  //    |upd_header|: The update header indicating update details. The
  //      interpretation depends on the HAL implementation. This is only valid
  //      during the function call and is invalidated after the function
  //      returns.
  //    |size|: Size of update header.
  //    |buffer_fd|: The buffer file descriptor to process. The buffer is
  //    allocated and managed by the camera algorithm library.
  void (*update)(const struct camera_algorithm_callback_ops* callback,
                 uint32_t upd_id,
                 const uint8_t upd_header[],
                 uint32_t size,
                 int buffer_fd) = nullptr;
} camera_algorithm_callback_ops_t;

typedef struct camera_algorithm_ops {
  // This method is one-time initialization that registers a callback function
  // for the camera algorithm library to return a buffer handle. It must be
  // called before any other functions.
  //
  // Args:
  //    |callback_ops|: Pointer to callback functions.
  //
  // Returns:
  //    0 on success; corresponding error code on failure.
  int32_t (*initialize)(const camera_algorithm_callback_ops_t* callback_ops);

  // This method registers a buffer to the camera algorithm library and gets
  // the handle associated with it.
  //
  // Args:
  //    |buffer_fd|: The buffer file descriptor to register.
  //
  // Returns:
  //    A handle on success; corresponding error code on failure.
  int32_t (*register_buffer)(int buffer_fd);

  // This method posts a request for the camera algorithm library to process the
  // given buffer. The camera algorithm library is expected to implement this
  // method as an asynchronous one. It should return the function call
  // immediately after delegating the task to another thread or timer, and then
  // the latter will invoke the callback function with the processing status and
  // buffer handle.
  //
  // Args:
  //    |req_id|: The ID that uniquely identifies this request and needs to be
  //      sent back in camera_algorithm_callback_ops_t.return_callback().
  //    |req_header|: The request header indicating request details. The
  //      interpretation depends on the HAL implementation. This is only valid
  //      during the function call and is invalidated after the function
  //      returns.
  //    |size|: Size of request header.
  //    |buffer_handle|: Handle of the buffer to process.
  void (*request)(uint32_t req_id,
                  const uint8_t req_header[],
                  uint32_t size,
                  int32_t buffer_handle);

  // This method deregisters buffers to the camera algorithm library. The camera
  // algorithm shall release all the registered buffers on return of this
  // function.
  //
  // Args:
  //    |buffer_handles|: The buffer handles to deregister. This is only valid
  //      during the function call and is invalidated after the function
  //      returns.
  //    |size|: Size of the buffer handle array.
  //
  // Returns:
  //    A handle on success; -1 on failure.
  void (*deregister_buffers)(const int32_t buffer_handles[], uint32_t size);

  // This method returns the result for an update from the camera algorithm
  // library.
  //
  // Args:
  //    |upd_id|: The ID that uniquely identifies the update from camera
  //      algorithm library.
  //    |status|: Result of the update.
  //    |buffer_fd|: The buffer file descriptor to return.
  //
  // Returns:
  //    0 on success; corresponding error code on failure.
  void (*update_return)(uint32_t upd_id, uint32_t status, int buffer_fd);

  // Deinitializes the implementation object. The provided object can be
  // destroyed safely after this call.
  void (*deinitialize)() = nullptr;
} camera_algorithm_ops_t;
}

#endif  // CAMERA_INCLUDE_CROS_CAMERA_CAMERA_ALGORITHM_H_
