// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <random>
#include <string>

#include <gtest/gtest.h>

#include "vm_tools/pstore_dump/persistent_ram_buffer.h"

#include <base/check.h>

namespace vm_tools {
namespace pstore_dump {

class PersistentRamBufferTest : public ::testing::Test {
 public:
  PersistentRamBufferTest() = default;
  ~PersistentRamBufferTest() override = default;

 private:
  std::default_random_engine gen;

 public:
  std::string GetRandomString(size_t length) {
    std::string s;
    std::uniform_int_distribution<uint16_t> dist('A', 'Z');
    while (s.length() < length) {
      s.push_back(static_cast<char>(dist(gen)));
    }
    return s;
  }
};

void InitializePersistentRamBuffer(persistent_ram_buffer* buf,
                                   size_t buf_capacity) {
  DCHECK(buf);
  buf->sig = PERSISTENT_RAM_SIG;
  buf->start = 0;
  buf->size = 0;
  memset(buf->data, 0, buf_capacity);
}

void StorePersistentRamBuffer(persistent_ram_buffer* buf,
                              size_t buf_capacity,
                              const std::string& data) {
  DCHECK(buf);
  DCHECK(data.length() <= buf_capacity);

  if (buf->start + data.length() <= buf_capacity) {
    memcpy(buf->data + buf->start, data.c_str(), data.length());
    buf->start += data.length();
    buf->size += data.length();
  } else {
    int remaining_capacity = buf_capacity - buf->start;
    memcpy(buf->data + buf->start, data.c_str(), remaining_capacity);
    memcpy(buf->data, data.c_str() + remaining_capacity,
           data.length() - remaining_capacity);
    buf->start = (buf->start + data.length()) % buf_capacity;
    buf->size = buf_capacity;
  }
}

const int kBufferSize = 0x10000;
const int kBufferCapacity = kBufferSize - sizeof(persistent_ram_buffer);

TEST_F(PersistentRamBufferTest, checkGetContentWithoutRotation) {
  std::unique_ptr<char[]> buf_ = std::make_unique<char[]>(kBufferSize);
  persistent_ram_buffer* buf =
      reinterpret_cast<persistent_ram_buffer*>(buf_.get());
  InitializePersistentRamBuffer(buf, kBufferCapacity);

  std::string expected = GetRandomString(100);
  StorePersistentRamBuffer(buf, kBufferCapacity, expected);

  std::string actual;
  EXPECT_TRUE(GetPersistentRamBufferContent(buf, kBufferCapacity, &actual));
  EXPECT_EQ(actual, expected);
  EXPECT_EQ(buf->start, expected.size());
}

TEST_F(PersistentRamBufferTest, checkGetContentWithRotation) {
  std::unique_ptr<char[]> buf_ = std::make_unique<char[]>(kBufferSize);
  persistent_ram_buffer* buf =
      reinterpret_cast<persistent_ram_buffer*>(buf_.get());
  InitializePersistentRamBuffer(buf, kBufferCapacity);

  std::string data1 =
      GetRandomString(static_cast<size_t>(kBufferCapacity * 0.8));
  StorePersistentRamBuffer(buf, kBufferCapacity, data1);
  std::string data2 =
      GetRandomString(static_cast<size_t>(kBufferCapacity * 0.8));
  StorePersistentRamBuffer(buf, kBufferCapacity, data2);
  std::string expected =
      data1.substr(data1.length() + data2.length() - kBufferCapacity) + data2;

  std::string actual;
  EXPECT_TRUE(GetPersistentRamBufferContent(buf, kBufferCapacity, &actual));
  EXPECT_EQ(actual, expected);
  EXPECT_EQ(buf->start, data1.length() + data2.length() - kBufferCapacity);
}

}  // namespace pstore_dump
}  // namespace vm_tools
