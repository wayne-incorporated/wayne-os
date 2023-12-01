// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "faced/util/queueing_stream.h"

#include <string>
#include <tuple>
#include <utility>

#include <base/test/bind.h>
#include <base/test/task_environment.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "faced/util/blocking_future.h"
#include "faced/util/stream.h"

namespace faced {
namespace {

using testing::Eq;
using testing::Optional;
using testing::Pointee;

class QueuedStreamTest : public ::testing::Test {
 protected:
  // A fake task environment, required for Stream implementations
  // to dispatch tasks.
  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};
};

// Read from the given StreamReader object, blocking until an item arrives.
template <typename T>
StreamValue<T> BlockingRead(StreamReader<T>& reader) {
  BlockingFuture<StreamValue<T>> future;
  reader.Read(future.PromiseCallback());
  future.Wait();
  return std::move(future.value());
}

TEST_F(QueuedStreamTest, WriteRead) {
  QueueingStream<int> stream(/*max_queue_size=*/1);
  std::unique_ptr<StreamReader<int>> reader = stream.GetReader();

  // Write an item.
  stream.Write(42);

  // Ensure we can read it.
  EXPECT_EQ(BlockingRead(*reader).value, 42);
}

TEST_F(QueuedStreamTest, QueueOrder) {
  QueueingStream<int> stream(/*max_queue_size=*/10);
  std::unique_ptr<StreamReader<int>> reader = stream.GetReader();

  // Write items.
  stream.Write(1);
  stream.Write(2);
  stream.Write(3);

  // Ensure they are read in FIFO order.
  EXPECT_EQ(BlockingRead(*reader).value, 1);
  EXPECT_EQ(BlockingRead(*reader).value, 2);
  EXPECT_EQ(BlockingRead(*reader).value, 3);
}

TEST_F(QueuedStreamTest, FiniteQueueSize) {
  QueueingStream<int> stream(/*max_queue_size=*/3);
  std::unique_ptr<StreamReader<int>> reader = stream.GetReader();

  // Write enough items to exceed the queue size.
  for (int i = 0; i < 10; i++) {
    stream.Write(i);
  }

  // The queue should drop the earliest items, and return to the reader the last
  // 3.
  EXPECT_EQ(BlockingRead(*reader).value, 7);
  EXPECT_EQ(BlockingRead(*reader).value, 8);
  EXPECT_EQ(BlockingRead(*reader).value, 9);
}

TEST_F(QueuedStreamTest, ReaderCloseDiscardsQueue) {
  QueueingStream<int> stream(/*max_queue_size=*/3);
  std::unique_ptr<StreamReader<int>> reader = stream.GetReader();

  // Write some items into the queue.
  for (int i = 0; i < 10; i++) {
    stream.Write(i);
  }

  // Close the reader.
  reader->Close();

  // Items in the queue should be dropped.
  EXPECT_EQ(BlockingRead(*reader).value, std::nullopt);
}

TEST_F(QueuedStreamTest, WriterClosePreservesQueue) {
  QueueingStream<int> stream(/*max_queue_size=*/3);
  std::unique_ptr<StreamReader<int>> reader = stream.GetReader();

  // Write some items into the queue.
  stream.Write(1);
  stream.Write(2);
  stream.Write(3);

  // Close the writer.
  stream.Close();

  // Items in the queue should be preserved in order.
  EXPECT_EQ(BlockingRead(*reader).value, 1);
  EXPECT_EQ(BlockingRead(*reader).value, 2);
  EXPECT_EQ(BlockingRead(*reader).value, 3);
}

TEST_F(QueuedStreamTest, ReadBeforeWrite) {
  QueueingStream<int> stream(/*max_queue_size=*/3);
  std::unique_ptr<StreamReader<int>> reader = stream.GetReader();

  // Start a read.
  BlockingFuture<StreamValue<int>> future;
  reader->Read(future.PromiseCallback());

  // Next, write to the stream.
  stream.Write(42);

  // Ensure the value is received.
  EXPECT_EQ(future.Wait().value, 42);
}

TEST_F(QueuedStreamTest, ReadCancelledOnReaderClose) {
  QueueingStream<int> stream(/*max_queue_size=*/3);
  std::unique_ptr<StreamReader<int>> reader = stream.GetReader();

  // Start a read.
  BlockingFuture<StreamValue<int>> future;
  reader->Read(future.PromiseCallback());

  // Close the reader.
  reader->Close();

  // Ensure the callback is called with a nullopt arg.
  EXPECT_THAT(future.Wait().value, std::nullopt);
}

TEST_F(QueuedStreamTest, ReadCancelledOnWriterClose) {
  QueueingStream<int> stream(/*max_queue_size=*/3);
  std::unique_ptr<StreamReader<int>> reader = stream.GetReader();

  // Start a read.
  BlockingFuture<StreamValue<int>> future;
  reader->Read(future.PromiseCallback());

  // Close the writer.
  stream.Close();

  // Ensure the callback is called.
  EXPECT_THAT(future.Wait().value, std::nullopt);
}

TEST_F(QueuedStreamTest, WriterDeleteDoesNotAffectReader) {
  auto stream = std::make_unique<QueueingStream<int>>(/*max_queue_size=*/3);
  std::unique_ptr<StreamReader<int>> reader = stream->GetReader();

  // Start a read.
  BlockingFuture<StreamValue<int>> future;
  reader->Read(future.PromiseCallback());

  // Delete the writer.
  stream.reset();

  // Ensure the pending callback is called.
  EXPECT_EQ(future.Wait().value, std::nullopt);

  // Additional reads should just return immediately with no value.
  EXPECT_EQ(BlockingRead(*reader).value, std::nullopt);
}

TEST_F(QueuedStreamTest, ExpeditedFlagSet) {
  QueueingStream<int> stream(/*max_queue_size=*/3);
  std::unique_ptr<StreamReader<int>> reader = stream.GetReader();

  // If nothing else is on the queue, the expedited flag should be clear.
  stream.Write(0);
  EXPECT_FALSE(BlockingRead(*reader).expedite);

  // If multiple items are on the queue, the flag should be set until
  // we reach the last item.
  stream.Write(1);
  stream.Write(2);
  stream.Write(3);
  EXPECT_TRUE(BlockingRead(*reader).expedite);
  EXPECT_TRUE(BlockingRead(*reader).expedite);
  EXPECT_FALSE(BlockingRead(*reader).expedite);

  // If the read is pending when a write comes in, the expedited flag
  // should be clear.
  BlockingFuture<StreamValue<int>> future;
  reader->Read(future.PromiseCallback());
  stream.Write(4);
  EXPECT_FALSE(future.Wait().expedite);
}

TEST_F(QueuedStreamTest, NewReadInReadcallback) {
  QueueingStream<int> stream(/*max_queue_size=*/3);
  std::unique_ptr<StreamReader<int>> reader = stream.GetReader();

  // Start a read. On completion, start a new read from within the callback.
  BlockingFuture<StreamValue<int>> future;
  reader->Read(base::BindLambdaForTesting(
      [&future, &reader](StreamValue<int> result) mutable {
        // Ensure we got the first item.
        EXPECT_EQ(result.value, 1);

        // Start another read.
        reader->Read(future.PromiseCallback());
      }));

  // Enqueue some items.
  stream.Write(1);
  stream.Write(2);

  // Expect a second read to arrive.
  EXPECT_EQ(future.Wait().value, 2);
}

TEST_F(QueuedStreamTest, DeleteReaderInReadCallback) {
  QueueingStream<int> stream(/*max_queue_size=*/3);
  std::unique_ptr<StreamReader<int>> reader = stream.GetReader();

  // Start a read. On completion, delete the reader from within the callback.
  BlockingFuture<void> future;
  reader->Read(base::BindLambdaForTesting(
      [&future, &reader](StreamValue<int> result) mutable {
        // Ensure we got the correct value.
        EXPECT_EQ(result.value, 1);

        // Delete the reader.
        reader.reset();

        future.PromiseCallback().Run();
      }));

  // Write an item, and wait for it to be processed.
  stream.Write(1);
  future.Wait();

  // Ensure the reader was deleted.
  EXPECT_EQ(reader.get(), nullptr);
}

TEST_F(QueuedStreamTest, EnqueueMoveOnlyItem) {
  QueueingStream<std::unique_ptr<int>> stream(/*max_queue_size=*/3);
  std::unique_ptr<StreamReader<std::unique_ptr<int>>> reader =
      stream.GetReader();

  // Enqueue a move-only item, and make sure we can read it again.
  stream.Write(std::make_unique<int>(1));
  EXPECT_THAT(BlockingRead(*reader).value, Optional(Pointee(1)));
}

}  // namespace
}  // namespace faced
