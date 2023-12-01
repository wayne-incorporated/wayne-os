// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef FACED_UTIL_QUEUEING_STREAM_H_
#define FACED_UTIL_QUEUEING_STREAM_H_

#include <cstddef>
#include <deque>
#include <memory>
#include <utility>

#include <base/functional/bind.h>
#include <base/memory/scoped_refptr.h>

#include "faced/util/stream.h"
#include "faced/util/task.h"

namespace faced {

// A Stream that allows synchronous, non-blocking writes, queueing elements if
// required.
template <typename T>
class QueueingStream {
 public:
  // Create a QueueingStream, with an internal queue of at most
  // `max_queue_size` elements.
  //
  // A `max_queue_size` of zero is supported; if specified, written
  // frames will be dropped unless there is a pending read of the
  // frame when a `Write` takes place.
  explicit QueueingStream(size_t max_queue_size);

  // Close and destroy the stream.
  //
  // This is safe to call even if a reader is still present on the
  // stream.
  ~QueueingStream();

  // Return a StreamReader that reads from this queue.
  //
  // May only be called once.
  typename std::unique_ptr<StreamReader<T>> GetReader();

  // Write the given item to the Stream.
  //
  // Returns true if the write was successful, or false if the stream
  // is closed (and hence `item` was discarded).
  bool Write(T item);

  // Close the Stream.
  //
  // Any items already on the queue will continue to be available by
  // the reader. However, once the queue is empty, all future reads
  // will immediately be cancelled.
  void Close();

 private:
  // State shared by the reader and writer.
  struct State : public base::RefCounted<State> {
    // Maximum number of elements in `queue`.
    size_t max_queue_size GUARDED_BY_CONTEXT(sequence_checker) = 0;

    // If true, the stream is closed, and no new writes will be accepted.
    bool closed GUARDED_BY_CONTEXT(sequence_checker) = false;

    // The queue and any pending callback.
    //
    // Invariant: `pending_callback` is non-null only if `queue` is empty.
    // That is, we should never have both items in the queue and a pending
    // callback.
    typename StreamReader<T>::ReadCallback pending_callback
        GUARDED_BY_CONTEXT(sequence_checker);
    std::deque<T> queue GUARDED_BY_CONTEXT(sequence_checker);

    SEQUENCE_CHECKER(sequence_checker);
  };

  // `StreamReader` implementation for this Stream object.
  class Reader final : public StreamReader<T> {
   public:
    explicit Reader(scoped_refptr<State> state);
    ~Reader();

    // `StreamReader<T>` implementation.
    void Read(typename StreamReader<T>::ReadCallback callback) override;
    void Close() override;

   private:
    scoped_refptr<State> state_;
  };

  bool reader_created_ = false;
  scoped_refptr<State> state_;
};

//
// Implementation details follow.
//

template <typename T>
QueueingStream<T>::QueueingStream(size_t max_queue_size) {
  state_ = base::MakeRefCounted<State>();
  state_->max_queue_size = max_queue_size;
  DETACH_FROM_SEQUENCE(state_->sequence_checker);
}

template <typename T>
QueueingStream<T>::~QueueingStream() {
  Close();
}

template <typename T>
bool QueueingStream<T>::Write(T item) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(state_->sequence_checker);
  // If the reader has been closed, simply drop the item.
  if (state_->closed) {
    return false;
  }

  // If there is a pending callback, directly dispatch the item to it.
  if (!state_->pending_callback.is_null()) {
    // Invariant: `pending_callback` is only non-null if the queue is empty.
    DCHECK(state_->queue.empty());
    PostToCurrentSequence(base::BindOnce(
        std::move(state_->pending_callback),
        StreamValue<T>{.value = std::move(item), .expedite = false}));
    return true;
  }

  // If we are not queueing items and the reader wasn't ready, simply drop the
  // item.
  if (state_->max_queue_size == 0) {
    return true;
  }

  // Ensure there is sufficient space in the queue.
  while (state_->queue.size() >= state_->max_queue_size) {
    state_->queue.pop_front();
  }

  // Enqueue the item.
  state_->queue.push_back(std::move(item));
  return true;
}

template <typename T>
void QueueingStream<T>::Close() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(state_->sequence_checker);

  // Mark the stream as closed.
  state_->closed = true;

  // No new elements will ever be added, so abort any pending reads.
  if (!state_->pending_callback.is_null()) {
    PostToCurrentSequence(
        base::BindOnce(std::move(state_->pending_callback), StreamValue<T>{}));
  }
}

template <typename T>
typename std::unique_ptr<StreamReader<T>> QueueingStream<T>::GetReader() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(state_->sequence_checker);
  CHECK(!reader_created_) << "GetReader() incorrectly called more than once "
                             "on a single QueueingStream.";
  reader_created_ = true;
  return std::make_unique<QueueingStream::Reader>(state_);
}

template <typename T>
QueueingStream<T>::Reader::Reader(scoped_refptr<State> state) : state_(state) {}

template <typename T>
QueueingStream<T>::Reader::~Reader() {
  Close();
}

template <typename T>
void QueueingStream<T>::Reader::Read(
    typename StreamReader<T>::ReadCallback callback) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(state_->sequence_checker);

  // Ensure there is no existing pending read.
  CHECK(state_->pending_callback.is_null())
      << "Attempted to call Read() while an existing Read() operation was "
         "still in progress.";

  // If there is already an item on the queue, immediately dispatch it.
  if (!state_->queue.empty()) {
    StreamValue<T> result;

    // Fetch the first item in the queue.
    result.value = std::move(state_->queue.front());
    state_->queue.pop_front();

    // Warn the reader they need to process items faster if there are still
    // items in the queue.
    result.expedite = (state_->queue.size() >= 1);

    PostToCurrentSequence(
        base::BindOnce(std::move(callback), std::move(result)));
    return;
  }

  // If the stream is closed, nothing new is ever going to be added, so
  // immediately call the callback.
  if (state_->queue.empty() && state_->closed) {
    PostToCurrentSequence(
        base::BindOnce(std::move(callback), StreamValue<T>{}));
    return;
  }

  // Otherwise, wait for the next item to arrive.
  state_->pending_callback = std::move(callback);
}

template <typename T>
void QueueingStream<T>::Reader::Close() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(state_->sequence_checker);

  // Close and clear the queue.
  state_->closed = true;
  state_->queue.clear();

  // Abort any pending reads.
  if (!state_->pending_callback.is_null()) {
    PostToCurrentSequence(
        base::BindOnce(std::move(state_->pending_callback), StreamValue<T>{}));
  }
}

}  // namespace faced

#endif  // FACED_UTIL_QUEUEING_STREAM_H_
