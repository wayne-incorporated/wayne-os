// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This is a copy of the fmq_unit_tests.cpp file from libfmq before
// the AIDL integration was brought in. We don't want (or need) to support
// that, so we'll need to keep our unit tests at this snapshot.

// Changes: clang-format for ChromeOS conventions
//          remove #include <thread> and tests that rely on it

#include <asm-generic/mman.h>
#include <gtest/gtest.h>
#include <atomic>
#include <cstdlib>
#include <sstream>
#include <vector>
#include <fmq/MessageQueue.h>
#include <fmq/EventFlag.h>

enum EventFlagBits : uint32_t {
  kFmqNotEmpty = 1 << 0,
  kFmqNotFull = 1 << 1,
};

typedef android::hardware::
    MessageQueue<uint8_t, android::hardware::kSynchronizedReadWrite>
        MessageQueueSync;
typedef android::hardware::MessageQueue<uint8_t,
                                        android::hardware::kUnsynchronizedWrite>
    MessageQueueUnsync;

class SynchronizedReadWrites : public ::testing::Test {
 protected:
  virtual void TearDown() { delete mQueue; }

  virtual void SetUp() {
    static constexpr size_t kNumElementsInQueue = 2048;
    mQueue = new (std::nothrow) MessageQueueSync(kNumElementsInQueue);
    ASSERT_NE(nullptr, mQueue);
    ASSERT_TRUE(mQueue->isValid());
    mNumMessagesMax = mQueue->getQuantumCount();
    ASSERT_EQ(kNumElementsInQueue, mNumMessagesMax);
  }

  MessageQueueSync* mQueue = nullptr;
  size_t mNumMessagesMax = 0;
};

class UnsynchronizedWrite : public ::testing::Test {
 protected:
  virtual void TearDown() { delete mQueue; }

  virtual void SetUp() {
    static constexpr size_t kNumElementsInQueue = 2048;
    mQueue = new (std::nothrow) MessageQueueUnsync(kNumElementsInQueue);
    ASSERT_NE(nullptr, mQueue);
    ASSERT_TRUE(mQueue->isValid());
    mNumMessagesMax = mQueue->getQuantumCount();
    ASSERT_EQ(kNumElementsInQueue, mNumMessagesMax);
  }

  MessageQueueUnsync* mQueue = nullptr;
  size_t mNumMessagesMax = 0;
};

class BlockingReadWrites : public ::testing::Test {
 protected:
  virtual void TearDown() { delete mQueue; }
  virtual void SetUp() {
    static constexpr size_t kNumElementsInQueue = 2048;
    mQueue = new (std::nothrow) MessageQueueSync(kNumElementsInQueue);
    ASSERT_NE(nullptr, mQueue);
    ASSERT_TRUE(mQueue->isValid());
    mNumMessagesMax = mQueue->getQuantumCount();
    ASSERT_EQ(kNumElementsInQueue, mNumMessagesMax);
    /*
     * Initialize the EventFlag word to indicate Queue is not full.
     */
    std::atomic_init(&mFw, static_cast<uint32_t>(kFmqNotFull));
  }

  MessageQueueSync* mQueue;
  std::atomic<uint32_t> mFw;
  size_t mNumMessagesMax = 0;
};

class QueueSizeOdd : public ::testing::Test {
 protected:
  virtual void TearDown() { delete mQueue; }
  virtual void SetUp() {
    static constexpr size_t kNumElementsInQueue = 2049;
    mQueue = new (std::nothrow) MessageQueueSync(
        kNumElementsInQueue, true /* configureEventFlagWord */);
    ASSERT_NE(nullptr, mQueue);
    ASSERT_TRUE(mQueue->isValid());
    mNumMessagesMax = mQueue->getQuantumCount();
    ASSERT_EQ(kNumElementsInQueue, mNumMessagesMax);
    auto evFlagWordPtr = mQueue->getEventFlagWord();
    ASSERT_NE(nullptr, evFlagWordPtr);
    /*
     * Initialize the EventFlag word to indicate Queue is not full.
     */
    std::atomic_init(evFlagWordPtr, static_cast<uint32_t>(kFmqNotFull));
  }

  MessageQueueSync* mQueue;
  size_t mNumMessagesMax = 0;
};

class BadQueueConfig : public ::testing::Test {};

/*
 * Utility function to initialize data to be written to the FMQ
 */
inline void initData(uint8_t* data, size_t count) {
  for (size_t i = 0; i < count; i++) {
    data[i] = i & 0xFF;
  }
}

/*
 * This thread will attempt to read and block. When wait returns
 * it checks if the kFmqNotEmpty bit is actually set.
 * If the read is successful, it signals Wake to kFmqNotFull.
 */
void ReaderThreadBlocking(android::hardware::MessageQueue<
                              uint8_t,
                              android::hardware::kSynchronizedReadWrite>* fmq,
                          std::atomic<uint32_t>* fwAddr) {
  const size_t kDataLen = 64;
  uint8_t data[kDataLen];
  android::hardware::EventFlag* efGroup = nullptr;
  android::status_t status =
      android::hardware::EventFlag::createEventFlag(fwAddr, &efGroup);
  ASSERT_EQ(android::NO_ERROR, status);
  ASSERT_NE(nullptr, efGroup);

  while (true) {
    uint32_t efState = 0;
    android::status_t ret = efGroup->wait(kFmqNotEmpty, &efState,
                                          5000000000 /* timeoutNanoSeconds */);
    /*
     * Wait should not time out here after 5s
     */
    ASSERT_NE(android::TIMED_OUT, ret);

    if ((efState & kFmqNotEmpty) && fmq->read(data, kDataLen)) {
      efGroup->wake(kFmqNotFull);
      break;
    }
  }

  status = android::hardware::EventFlag::deleteEventFlag(&efGroup);
  ASSERT_EQ(android::NO_ERROR, status);
}

/*
 * This thread will attempt to read and block using the readBlocking() API and
 * passes in a pointer to an EventFlag object.
 */
void ReaderThreadBlocking2(android::hardware::MessageQueue<
                               uint8_t,
                               android::hardware::kSynchronizedReadWrite>* fmq,
                           std::atomic<uint32_t>* fwAddr) {
  const size_t kDataLen = 64;
  uint8_t data[kDataLen];
  android::hardware::EventFlag* efGroup = nullptr;
  android::status_t status =
      android::hardware::EventFlag::createEventFlag(fwAddr, &efGroup);
  ASSERT_EQ(android::NO_ERROR, status);
  ASSERT_NE(nullptr, efGroup);
  bool ret =
      fmq->readBlocking(data, kDataLen, static_cast<uint32_t>(kFmqNotFull),
                        static_cast<uint32_t>(kFmqNotEmpty),
                        5000000000 /* timeOutNanos */, efGroup);
  ASSERT_TRUE(ret);
  status = android::hardware::EventFlag::deleteEventFlag(&efGroup);
  ASSERT_EQ(android::NO_ERROR, status);
}

TEST_F(BadQueueConfig, QueueSizeTooLarge) {
  typedef android::hardware::MessageQueue<
      uint16_t, android::hardware::kSynchronizedReadWrite>
      MessageQueueSync16;
  size_t numElementsInQueue = SIZE_MAX / sizeof(uint16_t) + 1;
  MessageQueueSync16* fmq =
      new (std::nothrow) MessageQueueSync16(numElementsInQueue);
  ASSERT_NE(nullptr, fmq);
  /*
   * Should fail due to size being too large to fit into size_t.
   */
  ASSERT_FALSE(fmq->isValid());
}

/*
 * Test that basic blocking times out as intended.
 */
TEST_F(BlockingReadWrites, BlockingTimeOutTest) {
  android::hardware::EventFlag* efGroup = nullptr;
  android::status_t status =
      android::hardware::EventFlag::createEventFlag(&mFw, &efGroup);

  ASSERT_EQ(android::NO_ERROR, status);
  ASSERT_NE(nullptr, efGroup);

  /* Block on an EventFlag bit that no one will wake and time out in 1s */
  uint32_t efState = 0;
  android::status_t ret = efGroup->wait(kFmqNotEmpty, &efState,
                                        1000000000 /* timeoutNanoSeconds */);
  /*
   * Wait should time out in a second.
   */
  EXPECT_EQ(android::TIMED_OUT, ret);

  status = android::hardware::EventFlag::deleteEventFlag(&efGroup);
  ASSERT_EQ(android::NO_ERROR, status);
}

/*
 * Test that odd queue sizes do not cause unaligned error
 * on access to EventFlag object.
 */
TEST_F(QueueSizeOdd, EventFlagTest) {
  const size_t kDataLen = 64;
  uint8_t data[kDataLen] = {0};

  bool ret = mQueue->writeBlocking(
      data, kDataLen, static_cast<uint32_t>(kFmqNotFull),
      static_cast<uint32_t>(kFmqNotEmpty), 5000000000 /* timeOutNanos */);
  ASSERT_TRUE(ret);
}

/*
 * Verify that a few bytes of data can be successfully written and read.
 */
TEST_F(SynchronizedReadWrites, SmallInputTest1) {
  const size_t kDataLen = 16;
  ASSERT_LE(kDataLen, mNumMessagesMax);
  uint8_t data[kDataLen];

  initData(data, kDataLen);

  ASSERT_TRUE(mQueue->write(data, kDataLen));
  uint8_t readData[kDataLen] = {};
  ASSERT_TRUE(mQueue->read(readData, kDataLen));
  ASSERT_EQ(0, memcmp(data, readData, kDataLen));
}

/*
 * Verify that a few bytes of data can be successfully written and read using
 * beginRead/beginWrite/CommitRead/CommitWrite
 */
TEST_F(SynchronizedReadWrites, SmallInputTest2) {
  const size_t kDataLen = 16;
  ASSERT_LE(kDataLen, mNumMessagesMax);
  uint8_t data[kDataLen];

  initData(data, kDataLen);

  MessageQueueSync::MemTransaction tx;
  ASSERT_TRUE(mQueue->beginWrite(kDataLen, &tx));

  ASSERT_TRUE(tx.copyTo(data, 0 /* startIdx */, kDataLen));

  ASSERT_TRUE(mQueue->commitWrite(kDataLen));

  uint8_t readData[kDataLen] = {};

  ASSERT_TRUE(mQueue->beginRead(kDataLen, &tx));

  ASSERT_TRUE(tx.copyFrom(readData, 0 /* startIdx */, kDataLen));

  ASSERT_TRUE(mQueue->commitRead(kDataLen));

  ASSERT_EQ(0, memcmp(data, readData, kDataLen));
}

/*
 * Verify that a few bytes of data can be successfully written and read using
 * beginRead/beginWrite/CommitRead/CommitWrite as well as getSlot().
 */
TEST_F(SynchronizedReadWrites, SmallInputTest3) {
  const size_t kDataLen = 16;
  ASSERT_LE(kDataLen, mNumMessagesMax);
  uint8_t data[kDataLen];

  initData(data, kDataLen);
  MessageQueueSync::MemTransaction tx;
  ASSERT_TRUE(mQueue->beginWrite(kDataLen, &tx));

  auto first = tx.getFirstRegion();
  auto second = tx.getSecondRegion();

  ASSERT_EQ(first.getLength() + second.getLength(), kDataLen);
  for (size_t i = 0; i < kDataLen; i++) {
    uint8_t* ptr = tx.getSlot(i);
    *ptr = data[i];
  }

  ASSERT_TRUE(mQueue->commitWrite(kDataLen));

  uint8_t readData[kDataLen] = {};

  ASSERT_TRUE(mQueue->beginRead(kDataLen, &tx));

  first = tx.getFirstRegion();
  second = tx.getSecondRegion();

  ASSERT_EQ(first.getLength() + second.getLength(), kDataLen);

  for (size_t i = 0; i < kDataLen; i++) {
    uint8_t* ptr = tx.getSlot(i);
    readData[i] = *ptr;
  }

  ASSERT_TRUE(mQueue->commitRead(kDataLen));

  ASSERT_EQ(0, memcmp(data, readData, kDataLen));
}

/*
 * Verify that read() returns false when trying to read from an empty queue.
 */
TEST_F(SynchronizedReadWrites, ReadWhenEmpty1) {
  ASSERT_EQ(0UL, mQueue->availableToRead());
  const size_t kDataLen = 2;
  ASSERT_LE(kDataLen, mNumMessagesMax);
  uint8_t readData[kDataLen];
  ASSERT_FALSE(mQueue->read(readData, kDataLen));
}

/*
 * Verify that beginRead() returns a MemTransaction object with null pointers
 * when trying to read from an empty queue.
 */
TEST_F(SynchronizedReadWrites, ReadWhenEmpty2) {
  ASSERT_EQ(0UL, mQueue->availableToRead());
  const size_t kDataLen = 2;
  ASSERT_LE(kDataLen, mNumMessagesMax);

  MessageQueueSync::MemTransaction tx;
  ASSERT_FALSE(mQueue->beginRead(kDataLen, &tx));

  auto first = tx.getFirstRegion();
  auto second = tx.getSecondRegion();

  ASSERT_EQ(nullptr, first.getAddress());
  ASSERT_EQ(nullptr, second.getAddress());
}

/*
 * Write the queue until full. Verify that another write is unsuccessful.
 * Verify that availableToWrite() returns 0 as expected.
 */
TEST_F(SynchronizedReadWrites, WriteWhenFull1) {
  ASSERT_EQ(0UL, mQueue->availableToRead());
  std::vector<uint8_t> data(mNumMessagesMax);

  initData(&data[0], mNumMessagesMax);
  ASSERT_TRUE(mQueue->write(&data[0], mNumMessagesMax));
  ASSERT_EQ(0UL, mQueue->availableToWrite());
  ASSERT_FALSE(mQueue->write(&data[0], 1));

  std::vector<uint8_t> readData(mNumMessagesMax);
  ASSERT_TRUE(mQueue->read(&readData[0], mNumMessagesMax));
  ASSERT_EQ(data, readData);
}

/*
 * Write the queue until full. Verify that beginWrite() returns
 * a MemTransaction object with null base pointers.
 */
TEST_F(SynchronizedReadWrites, WriteWhenFull2) {
  ASSERT_EQ(0UL, mQueue->availableToRead());
  std::vector<uint8_t> data(mNumMessagesMax);

  initData(&data[0], mNumMessagesMax);
  ASSERT_TRUE(mQueue->write(&data[0], mNumMessagesMax));
  ASSERT_EQ(0UL, mQueue->availableToWrite());

  MessageQueueSync::MemTransaction tx;
  ASSERT_FALSE(mQueue->beginWrite(1, &tx));

  auto first = tx.getFirstRegion();
  auto second = tx.getSecondRegion();

  ASSERT_EQ(nullptr, first.getAddress());
  ASSERT_EQ(nullptr, second.getAddress());
}

/*
 * Write a chunk of data equal to the queue size.
 * Verify that the write is successful and the subsequent read
 * returns the expected data.
 */
TEST_F(SynchronizedReadWrites, LargeInputTest1) {
  std::vector<uint8_t> data(mNumMessagesMax);
  initData(&data[0], mNumMessagesMax);
  ASSERT_TRUE(mQueue->write(&data[0], mNumMessagesMax));
  std::vector<uint8_t> readData(mNumMessagesMax);
  ASSERT_TRUE(mQueue->read(&readData[0], mNumMessagesMax));
  ASSERT_EQ(data, readData);
}

/*
 * Attempt to write a chunk of data larger than the queue size.
 * Verify that it fails. Verify that a subsequent read fails and
 * the queue is still empty.
 */
TEST_F(SynchronizedReadWrites, LargeInputTest2) {
  ASSERT_EQ(0UL, mQueue->availableToRead());
  const size_t kDataLen = 4096;
  ASSERT_GT(kDataLen, mNumMessagesMax);
  std::vector<uint8_t> data(kDataLen);

  initData(&data[0], kDataLen);
  ASSERT_FALSE(mQueue->write(&data[0], kDataLen));
  std::vector<uint8_t> readData(mNumMessagesMax);
  ASSERT_FALSE(mQueue->read(&readData[0], mNumMessagesMax));
  ASSERT_NE(data, readData);
  ASSERT_EQ(0UL, mQueue->availableToRead());
}

/*
 * After the queue is full, try to write more data. Verify that
 * the attempt returns false. Verify that the attempt did not
 * affect the pre-existing data in the queue.
 */
TEST_F(SynchronizedReadWrites, LargeInputTest3) {
  std::vector<uint8_t> data(mNumMessagesMax);
  initData(&data[0], mNumMessagesMax);
  ASSERT_TRUE(mQueue->write(&data[0], mNumMessagesMax));
  ASSERT_FALSE(mQueue->write(&data[0], 1));
  std::vector<uint8_t> readData(mNumMessagesMax);
  ASSERT_TRUE(mQueue->read(&readData[0], mNumMessagesMax));
  ASSERT_EQ(data, readData);
}

/*
 * Verify that beginWrite() returns a MemTransaction with
 * null base pointers when attempting to write data larger
 * than the queue size.
 */
TEST_F(SynchronizedReadWrites, LargeInputTest4) {
  ASSERT_EQ(0UL, mQueue->availableToRead());
  const size_t kDataLen = 4096;
  ASSERT_GT(kDataLen, mNumMessagesMax);

  MessageQueueSync::MemTransaction tx;
  ASSERT_FALSE(mQueue->beginWrite(kDataLen, &tx));

  auto first = tx.getFirstRegion();
  auto second = tx.getSecondRegion();

  ASSERT_EQ(nullptr, first.getAddress());
  ASSERT_EQ(nullptr, second.getAddress());
}

/*
 * Verify that multiple reads one after the other return expected data.
 */
TEST_F(SynchronizedReadWrites, MultipleRead) {
  const size_t chunkSize = 100;
  const size_t chunkNum = 5;
  const size_t kDataLen = chunkSize * chunkNum;
  ASSERT_LE(kDataLen, mNumMessagesMax);
  uint8_t data[kDataLen];

  initData(data, kDataLen);
  ASSERT_TRUE(mQueue->write(data, kDataLen));
  uint8_t readData[kDataLen] = {};
  for (size_t i = 0; i < chunkNum; i++) {
    ASSERT_TRUE(mQueue->read(readData + i * chunkSize, chunkSize));
  }
  ASSERT_EQ(0, memcmp(readData, data, kDataLen));
}

/*
 * Verify that multiple writes one after the other happens correctly.
 */
TEST_F(SynchronizedReadWrites, MultipleWrite) {
  const int chunkSize = 100;
  const int chunkNum = 5;
  const size_t kDataLen = chunkSize * chunkNum;
  ASSERT_LE(kDataLen, mNumMessagesMax);
  uint8_t data[kDataLen];

  initData(data, kDataLen);
  for (unsigned int i = 0; i < chunkNum; i++) {
    ASSERT_TRUE(mQueue->write(data + i * chunkSize, chunkSize));
  }
  uint8_t readData[kDataLen] = {};
  ASSERT_TRUE(mQueue->read(readData, kDataLen));
  ASSERT_EQ(0, memcmp(readData, data, kDataLen));
}

/*
 * Write enough messages into the FMQ to fill half of it
 * and read back the same.
 * Write mNumMessagesMax messages into the queue. This will cause a
 * wrap around. Read and verify the data.
 */
TEST_F(SynchronizedReadWrites, ReadWriteWrapAround1) {
  size_t numMessages = mNumMessagesMax - 1;
  std::vector<uint8_t> data(mNumMessagesMax);
  std::vector<uint8_t> readData(mNumMessagesMax);
  initData(&data[0], mNumMessagesMax);
  ASSERT_TRUE(mQueue->write(&data[0], numMessages));
  ASSERT_TRUE(mQueue->read(&readData[0], numMessages));
  ASSERT_TRUE(mQueue->write(&data[0], mNumMessagesMax));
  ASSERT_TRUE(mQueue->read(&readData[0], mNumMessagesMax));
  ASSERT_EQ(data, readData);
}

/*
 * Use beginRead/CommitRead/beginWrite/commitWrite APIs
 * to test wrap arounds are handled correctly.
 * Write enough messages into the FMQ to fill half of it
 * and read back the same.
 * Write mNumMessagesMax messages into the queue. This will cause a
 * wrap around. Read and verify the data.
 */
TEST_F(SynchronizedReadWrites, ReadWriteWrapAround2) {
  size_t kDataLen = mNumMessagesMax - 1;
  std::vector<uint8_t> data(mNumMessagesMax);
  std::vector<uint8_t> readData(mNumMessagesMax);
  initData(&data[0], mNumMessagesMax);
  ASSERT_TRUE(mQueue->write(&data[0], kDataLen));
  ASSERT_TRUE(mQueue->read(&readData[0], kDataLen));

  /*
   * The next write and read will have to deal with with wrap arounds.
   */
  MessageQueueSync::MemTransaction tx;
  ASSERT_TRUE(mQueue->beginWrite(mNumMessagesMax, &tx));

  auto first = tx.getFirstRegion();
  auto second = tx.getSecondRegion();

  ASSERT_EQ(first.getLength() + second.getLength(), mNumMessagesMax);

  ASSERT_TRUE(tx.copyTo(&data[0], 0 /* startIdx */, mNumMessagesMax));

  ASSERT_TRUE(mQueue->commitWrite(mNumMessagesMax));

  ASSERT_TRUE(mQueue->beginRead(mNumMessagesMax, &tx));

  first = tx.getFirstRegion();
  second = tx.getSecondRegion();

  ASSERT_EQ(first.getLength() + second.getLength(), mNumMessagesMax);

  ASSERT_TRUE(tx.copyFrom(&readData[0], 0 /* startIdx */, mNumMessagesMax));
  ASSERT_TRUE(mQueue->commitRead(mNumMessagesMax));

  ASSERT_EQ(data, readData);
}

/*
 * Verify that a few bytes of data can be successfully written and read.
 */
TEST_F(UnsynchronizedWrite, SmallInputTest1) {
  const size_t kDataLen = 16;
  ASSERT_LE(kDataLen, mNumMessagesMax);
  uint8_t data[kDataLen];

  initData(data, kDataLen);
  ASSERT_TRUE(mQueue->write(data, kDataLen));
  uint8_t readData[kDataLen] = {};
  ASSERT_TRUE(mQueue->read(readData, kDataLen));
  ASSERT_EQ(0, memcmp(data, readData, kDataLen));
}

/*
 * Verify that read() returns false when trying to read from an empty queue.
 */
TEST_F(UnsynchronizedWrite, ReadWhenEmpty) {
  ASSERT_EQ(0UL, mQueue->availableToRead());
  const size_t kDataLen = 2;
  ASSERT_TRUE(kDataLen < mNumMessagesMax);
  uint8_t readData[kDataLen];
  ASSERT_FALSE(mQueue->read(readData, kDataLen));
}

/*
 * Write the queue when full. Verify that a subsequent writes is successful.
 * Verify that availableToWrite() returns 0 as expected.
 */
TEST_F(UnsynchronizedWrite, WriteWhenFull1) {
  ASSERT_EQ(0UL, mQueue->availableToRead());
  std::vector<uint8_t> data(mNumMessagesMax);

  initData(&data[0], mNumMessagesMax);
  ASSERT_TRUE(mQueue->write(&data[0], mNumMessagesMax));
  ASSERT_EQ(0UL, mQueue->availableToWrite());
  ASSERT_TRUE(mQueue->write(&data[0], 1));

  std::vector<uint8_t> readData(mNumMessagesMax);
  ASSERT_FALSE(mQueue->read(&readData[0], mNumMessagesMax));
}

/*
 * Write the queue when full. Verify that a subsequent writes
 * using beginRead()/commitRead() is successful.
 * Verify that the next read fails as expected for unsynchronized flavor.
 */
TEST_F(UnsynchronizedWrite, WriteWhenFull2) {
  ASSERT_EQ(0UL, mQueue->availableToRead());
  std::vector<uint8_t> data(mNumMessagesMax);
  ASSERT_TRUE(mQueue->write(&data[0], mNumMessagesMax));

  MessageQueueUnsync::MemTransaction tx;
  ASSERT_TRUE(mQueue->beginWrite(1, &tx));

  ASSERT_EQ(tx.getFirstRegion().getLength(), 1U);

  ASSERT_TRUE(tx.copyTo(&data[0], 0 /* startIdx */));

  ASSERT_TRUE(mQueue->commitWrite(1));

  std::vector<uint8_t> readData(mNumMessagesMax);
  ASSERT_FALSE(mQueue->read(&readData[0], mNumMessagesMax));
}

/*
 * Write a chunk of data equal to the queue size.
 * Verify that the write is successful and the subsequent read
 * returns the expected data.
 */
TEST_F(UnsynchronizedWrite, LargeInputTest1) {
  std::vector<uint8_t> data(mNumMessagesMax);
  initData(&data[0], mNumMessagesMax);
  ASSERT_TRUE(mQueue->write(&data[0], mNumMessagesMax));
  std::vector<uint8_t> readData(mNumMessagesMax);
  ASSERT_TRUE(mQueue->read(&readData[0], mNumMessagesMax));
  ASSERT_EQ(data, readData);
}

/*
 * Attempt to write a chunk of data larger than the queue size.
 * Verify that it fails. Verify that a subsequent read fails and
 * the queue is still empty.
 */
TEST_F(UnsynchronizedWrite, LargeInputTest2) {
  ASSERT_EQ(0UL, mQueue->availableToRead());
  const size_t kDataLen = 4096;
  ASSERT_GT(kDataLen, mNumMessagesMax);
  std::vector<uint8_t> data(kDataLen);
  initData(&data[0], kDataLen);
  ASSERT_FALSE(mQueue->write(&data[0], kDataLen));
  std::vector<uint8_t> readData(mNumMessagesMax);
  ASSERT_FALSE(mQueue->read(&readData[0], mNumMessagesMax));
  ASSERT_NE(data, readData);
  ASSERT_EQ(0UL, mQueue->availableToRead());
}

/*
 * After the queue is full, try to write more data. Verify that
 * the attempt is successful. Verify that the read fails
 * as expected.
 */
TEST_F(UnsynchronizedWrite, LargeInputTest3) {
  std::vector<uint8_t> data(mNumMessagesMax);
  initData(&data[0], mNumMessagesMax);
  ASSERT_TRUE(mQueue->write(&data[0], mNumMessagesMax));
  ASSERT_TRUE(mQueue->write(&data[0], 1));
  std::vector<uint8_t> readData(mNumMessagesMax);
  ASSERT_FALSE(mQueue->read(&readData[0], mNumMessagesMax));
}

/*
 * Verify that multiple reads one after the other return expected data.
 */
TEST_F(UnsynchronizedWrite, MultipleRead) {
  const size_t chunkSize = 100;
  const size_t chunkNum = 5;
  const size_t kDataLen = chunkSize * chunkNum;
  ASSERT_LE(kDataLen, mNumMessagesMax);
  uint8_t data[kDataLen];
  initData(data, kDataLen);
  ASSERT_TRUE(mQueue->write(data, kDataLen));
  uint8_t readData[kDataLen] = {};
  for (size_t i = 0; i < chunkNum; i++) {
    ASSERT_TRUE(mQueue->read(readData + i * chunkSize, chunkSize));
  }
  ASSERT_EQ(0, memcmp(readData, data, kDataLen));
}

/*
 * Verify that multiple writes one after the other happens correctly.
 */
TEST_F(UnsynchronizedWrite, MultipleWrite) {
  const size_t chunkSize = 100;
  const size_t chunkNum = 5;
  const size_t kDataLen = chunkSize * chunkNum;
  ASSERT_LE(kDataLen, mNumMessagesMax);
  uint8_t data[kDataLen];

  initData(data, kDataLen);
  for (size_t i = 0; i < chunkNum; i++) {
    ASSERT_TRUE(mQueue->write(data + i * chunkSize, chunkSize));
  }

  uint8_t readData[kDataLen] = {};
  ASSERT_TRUE(mQueue->read(readData, kDataLen));
  ASSERT_EQ(0, memcmp(readData, data, kDataLen));
}

/*
 * Write enough messages into the FMQ to fill half of it
 * and read back the same.
 * Write mNumMessagesMax messages into the queue. This will cause a
 * wrap around. Read and verify the data.
 */
TEST_F(UnsynchronizedWrite, ReadWriteWrapAround) {
  size_t numMessages = mNumMessagesMax - 1;
  std::vector<uint8_t> data(mNumMessagesMax);
  std::vector<uint8_t> readData(mNumMessagesMax);

  initData(&data[0], mNumMessagesMax);
  ASSERT_TRUE(mQueue->write(&data[0], numMessages));
  ASSERT_TRUE(mQueue->read(&readData[0], numMessages));
  ASSERT_TRUE(mQueue->write(&data[0], mNumMessagesMax));
  ASSERT_TRUE(mQueue->read(&readData[0], mNumMessagesMax));
  ASSERT_EQ(data, readData);
}
