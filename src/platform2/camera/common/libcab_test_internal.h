/*
 * Copyright 2017 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_COMMON_LIBCAB_TEST_INTERNAL_H_
#define CAMERA_COMMON_LIBCAB_TEST_INTERNAL_H_

namespace libcab_test {

// This test command is carried in the first byte of the |req_header|
// parameter for the Request() function call, and the fake camera algorithm
// library should operate as instructed.
enum RequestTestCommand {
  // This is to test normal behavior.
  REQUEST_TEST_COMMAND_NORMAL,
  // This is to verify that the request header and callback status is passed
  // through IPC correctly. Upon receiving this command, the fake camera
  // algorithm library should calculate the hashcode from the entire
  // |req_header| and invoke the return callback using the hashcode as the
  // |status| parameter.
  REQUEST_TEST_COMMAND_VERIFY_STATUS,
  // This is to emulate a dead lock.
  REQUEST_TEST_COMMAND_DEAD_LOCK,
  // This is to verify the update callback. Upon receiving this command, the
  // fake camera algorithm library should invoke the update callback with a
  // buffer of random content and its hashcode as the header.
  REQUEST_TEST_COMMAND_VERIFY_UPDATE,
};

inline uint32_t SimpleHash(const uint8_t buf[], uint32_t size) {
  uint32_t hash, i;
  for (hash = size, i = 0; i < size; ++i) {
    hash = (hash << 4) ^ (hash >> 28) ^ buf[i];
  }
  return hash;
}

}  // namespace libcab_test

#endif  // CAMERA_COMMON_LIBCAB_TEST_INTERNAL_H_
