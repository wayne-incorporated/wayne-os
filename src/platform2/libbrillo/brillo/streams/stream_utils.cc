// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/check_op.h>
#include <brillo/streams/stream_utils.h>

#include <algorithm>
#include <limits>
#include <memory>
#include <utility>
#include <vector>

#include <base/functional/bind.h>
#include <brillo/message_loops/message_loop.h>
#include <brillo/streams/stream_errors.h>

namespace brillo {
namespace stream_utils {

bool ErrorStreamClosed(const base::Location& location, ErrorPtr* error) {
  Error::AddTo(error, location, errors::stream::kDomain,
               errors::stream::kStreamClosed, "Stream is closed");
  return false;
}

bool ErrorOperationNotSupported(const base::Location& location,
                                ErrorPtr* error) {
  Error::AddTo(error, location, errors::stream::kDomain,
               errors::stream::kOperationNotSupported,
               "Stream operation not supported");
  return false;
}

bool ErrorReadPastEndOfStream(const base::Location& location, ErrorPtr* error) {
  Error::AddTo(error, location, errors::stream::kDomain,
               errors::stream::kPartialData, "Reading past the end of stream");
  return false;
}

bool ErrorOperationTimeout(const base::Location& location, ErrorPtr* error) {
  Error::AddTo(error, location, errors::stream::kDomain,
               errors::stream::kTimeout, "Operation timed out");
  return false;
}

bool CheckInt64Overflow(const base::Location& location,
                        uint64_t position,
                        int64_t offset,
                        ErrorPtr* error) {
  if (offset < 0) {
    // Subtracting the offset. Make sure we do not underflow.
    uint64_t unsigned_offset = static_cast<uint64_t>(-offset);
    if (position >= unsigned_offset)
      return true;
  } else {
    // Adding the offset. Make sure we do not overflow unsigned 64 bits first.
    if (position <= std::numeric_limits<uint64_t>::max() - offset) {
      // We definitely will not overflow the unsigned 64 bit integer.
      // Now check that we end up within the limits of signed 64 bit integer.
      uint64_t new_position = position + offset;
      uint64_t max = std::numeric_limits<int64_t>::max();
      if (new_position <= max)
        return true;
    }
  }
  Error::AddTo(error, location, errors::stream::kDomain,
               errors::stream::kInvalidParameter,
               "The stream offset value is out of range");
  return false;
}

bool CalculateStreamPosition(const base::Location& location,
                             int64_t offset,
                             Stream::Whence whence,
                             uint64_t current_position,
                             uint64_t stream_size,
                             uint64_t* new_position,
                             ErrorPtr* error) {
  uint64_t pos = 0;
  switch (whence) {
    case Stream::Whence::FROM_BEGIN:
      pos = 0;
      break;

    case Stream::Whence::FROM_CURRENT:
      pos = current_position;
      break;

    case Stream::Whence::FROM_END:
      pos = stream_size;
      break;

    default:
      Error::AddTo(error, location, errors::stream::kDomain,
                   errors::stream::kInvalidParameter,
                   "Invalid stream position whence");
      return false;
  }

  if (!CheckInt64Overflow(location, pos, offset, error))
    return false;

  *new_position = static_cast<uint64_t>(pos + offset);
  return true;
}

}  // namespace stream_utils
}  // namespace brillo
