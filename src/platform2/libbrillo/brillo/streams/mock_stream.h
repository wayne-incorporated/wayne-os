// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_BRILLO_STREAMS_MOCK_STREAM_H_
#define LIBBRILLO_BRILLO_STREAMS_MOCK_STREAM_H_

#include <gmock/gmock.h>

#include <brillo/streams/stream.h>

namespace brillo {

// Mock Stream implementation for testing.
class MockStream : public Stream {
 public:
  MockStream() = default;
  MockStream(const MockStream&) = delete;
  MockStream& operator=(const MockStream&) = delete;

  MOCK_METHOD(bool, IsOpen, (), (const, override));
  MOCK_METHOD(bool, CanRead, (), (const, override));
  MOCK_METHOD(bool, CanWrite, (), (const, override));
  MOCK_METHOD(bool, CanSeek, (), (const, override));
  MOCK_METHOD(bool, CanGetSize, (), (const, override));

  MOCK_METHOD(uint64_t, GetSize, (), (const, override));
  MOCK_METHOD(bool, SetSizeBlocking, (uint64_t, ErrorPtr*), (override));
  MOCK_METHOD(uint64_t, GetRemainingSize, (), (const, override));

  MOCK_METHOD(uint64_t, GetPosition, (), (const, override));
  MOCK_METHOD(bool, Seek, (int64_t, Whence, uint64_t*, ErrorPtr*), (override));

  MOCK_METHOD(bool,
              ReadAsync,
              (void*,
               size_t,
               base::OnceCallback<void(size_t)>,
               ErrorCallback,
               ErrorPtr*),
              (override));
  MOCK_METHOD(bool,
              ReadAllAsync,
              (void*, size_t, base::OnceClosure, ErrorCallback, ErrorPtr*),
              (override));
  MOCK_METHOD(bool,
              ReadNonBlocking,
              (void*, size_t, size_t*, bool*, ErrorPtr*),
              (override));
  MOCK_METHOD(bool,
              ReadBlocking,
              (void*, size_t, size_t*, ErrorPtr*),
              (override));
  MOCK_METHOD(bool, ReadAllBlocking, (void*, size_t, ErrorPtr*), (override));

  MOCK_METHOD(bool,
              WriteAsync,
              (const void*,
               size_t,
               base::OnceCallback<void(size_t)>,
               ErrorCallback,
               ErrorPtr*),
              (override));
  MOCK_METHOD(
      bool,
      WriteAllAsync,
      (const void*, size_t, base::OnceClosure, ErrorCallback, ErrorPtr*),
      (override));
  MOCK_METHOD(bool,
              WriteNonBlocking,
              (const void*, size_t, size_t*, ErrorPtr*),
              (override));
  MOCK_METHOD(bool,
              WriteBlocking,
              (const void*, size_t, size_t*, ErrorPtr*),
              (override));
  MOCK_METHOD(bool,
              WriteAllBlocking,
              (const void*, size_t, ErrorPtr*),
              (override));

  MOCK_METHOD(bool, FlushBlocking, (ErrorPtr*), (override));
  MOCK_METHOD(bool, CloseBlocking, (ErrorPtr*), (override));

  MOCK_METHOD(bool,
              WaitForDataRead,
              (base::OnceClosure, ErrorPtr*),
              (override));
  MOCK_METHOD(bool,
              WaitForDataReadBlocking,
              (base::TimeDelta, ErrorPtr*),
              (override));
  MOCK_METHOD(bool,
              WaitForDataWrite,
              (base::OnceClosure, ErrorPtr*),
              (override));
  MOCK_METHOD(bool,
              WaitForDataWriteBlocking,
              (base::TimeDelta, ErrorPtr*),
              (override));
};

}  // namespace brillo

#endif  // LIBBRILLO_BRILLO_STREAMS_MOCK_STREAM_H_
