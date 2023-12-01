// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef FACED_UTIL_STREAM_H_
#define FACED_UTIL_STREAM_H_

#include <optional>

#include <base/functional/callback_forward.h>

namespace faced {

// A value read from a StreamReader<T>.
template <typename T>
struct StreamValue {
  // The item read from the Stream.
  //
  // If the underlying Stream is closed, the item will be `std::nullopt`.
  std::optional<T> value = std::nullopt;

  // Whether processing of this item should be expedited.
  //
  // If true, the underlying stream is a real-time and already has additional
  // items waiting to be processed. Always false for batch streams.
  bool expedite = false;
};

// Provide read-only access to a stream.
//
// A _Stream_ is a simple reader/writer data structure, allowing objects to be
// written to the stream by a writer, and later read from the stream by
// a reader. The read API is asynchronous only: reads take place by calling the
// `Read` function; when an object is ready, the corresponding callback is
// called.
//
// The Stream structure helps reader and writers to remain decoupled from each
// other: the lifetime of the `StreamReader` class is independent of the
// underlying Stream, allowing either the writer or reader to close and clean up
// their data structures without having to coordinate with the other side.
//
// Streams require the type `T` to be moveable. Non-movable types can be
// supported by allocating them on the heap and using a Stream of type
// `std::unique_ptr<T>`.
template <typename T>
class StreamReader {
 public:
  virtual ~StreamReader() = default;

  // The type of the object published on the stream.
  using value_type = T;

  // Read the next item from the stream.
  //
  // When an item is next written to the stream, the given callback will be
  // called with that item. If an item is already ready, the callback will
  // be dispatched immediately.
  //
  // If the Stream is closed (either by the reader or the writer), the callback
  // will be immediately dispatched with a `std::nullopt` result.
  //
  // Only one pending read is supported at a time. Callers must ensure they do
  // not call `Read` while an existing request is outstanding, however issuing
  // a new `Read` from within the callback is supported.
  //
  // Closing the Stream, and deleting the Stream are both supported from within
  // the callback.
  using ReadCallback = base::OnceCallback<void(StreamValue<T>)>;
  virtual void Read(ReadCallback callback) = 0;

  // Close the stream.
  //
  // Items already on the queued on the stream will be dropped. Any pending or
  // future Read operations will be immediately completed with a `std::nullopt`
  // result.
  //
  // May be safely called multiple times, and may be called from within the
  // `Read` callback.
  virtual void Close() = 0;
};

}  // namespace faced

#endif  // FACED_UTIL_STREAM_H_
