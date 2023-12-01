// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "p2p/common/struct_serializer.h"

#include <fcntl.h>
#include <glib.h>
#include <unistd.h>

#include <string>

#include <gtest/gtest.h>

#include "p2p/common/testutil.h"

using p2p::testutil::RunGMainLoopMaxIterations;
using std::string;

namespace {

struct TestStruct {
  int a, b, c;
};

bool operator==(const TestStruct& left, const TestStruct& right) {
  return left.a == right.a && left.b == right.b && left.c == right.c;
}

class TestStructCalls {
 public:
  TestStructCalls() : num_calls(0) {}

  static void CountCalls(const TestStruct& data, void* user_data) {
    TestStructCalls* calls = reinterpret_cast<TestStructCalls*>(user_data);
    calls->num_calls++;
    calls->last_call = data;
  }

  TestStruct last_call;
  int num_calls;
};

bool SetupPipes(int fds[2]) {
  if (pipe(fds) != 0)
    return false;

  // Set the reading end as non-blocking.
  int flags = fcntl(fds[0], F_GETFL, 0);
  fcntl(fds[0], F_SETFL, flags | O_NONBLOCK);

  return true;
}

}  // namespace

namespace p2p {

namespace util {

TEST(StructSerializer, SimpleWriteTest) {
  int fds[2];
  ASSERT_TRUE(SetupPipes(fds));

  const TestStruct sample = {1, 2, 3};
  char buffer[sizeof(TestStruct)];

  EXPECT_TRUE(StructSerializerWrite<TestStruct>(fds[1], sample));
  EXPECT_EQ(sizeof(TestStruct), read(fds[0], buffer, sizeof(TestStruct)));
  EXPECT_EQ(0, memcmp(&sample, buffer, sizeof(TestStruct)));

  close(fds[0]);
  close(fds[1]);
}

TEST(StructSerializer, WatchSeveralMessages) {
  int fds[2];
  ASSERT_TRUE(SetupPipes(fds));

  TestStructCalls calls = TestStructCalls();
  StructSerializerWatcher<TestStruct> watch(fds[0], TestStructCalls::CountCalls,
                                            &calls);

  TestStruct sample = {1, 2, 3};
  EXPECT_TRUE(StructSerializerWrite<TestStruct>(fds[1], sample));
  sample.b = 4;
  EXPECT_TRUE(StructSerializerWrite<TestStruct>(fds[1], sample));
  sample.c = 5;
  EXPECT_TRUE(StructSerializerWrite<TestStruct>(fds[1], sample));

  // Run the main loop until all the events are dispatched.
  while (g_main_context_iteration(NULL, FALSE)) {
  }

  EXPECT_EQ(calls.num_calls, 3);
  const TestStruct result = {1, 4, 5};
  EXPECT_EQ(calls.last_call, result);

  close(fds[0]);
  close(fds[1]);
}

TEST(StructSerializer, WatchNoMessages) {
  int fds[2];
  ASSERT_TRUE(SetupPipes(fds));

  TestStructCalls calls = TestStructCalls();
  StructSerializerWatcher<TestStruct> watch(fds[0], TestStructCalls::CountCalls,
                                            &calls);

  // Close the write end.
  close(fds[1]);

  // Run the main loop until all the events are dispatched.
  int iterations = RunGMainLoopMaxIterations(10);

  // No call is received but the callback is called once due to the hangup.
  EXPECT_EQ(iterations, 1);
  EXPECT_EQ(calls.num_calls, 0);
  close(fds[0]);
}

TEST(StructSerializer, WatchPartialMessage) {
  int fds[2];
  ASSERT_TRUE(SetupPipes(fds));

  TestStructCalls calls = TestStructCalls();
  StructSerializerWatcher<TestStruct> watch(fds[0], TestStructCalls::CountCalls,
                                            &calls);

  // Write a partial message.
  int x = -1;
  ASSERT_EQ(sizeof(int), write(fds[1], &x, sizeof(x)));

  // Run the main loop until all the events are dispatched.
  int iterations = RunGMainLoopMaxIterations(10);
  EXPECT_EQ(iterations, 1);

  // Write the second part of the message.
  x = 2;
  ASSERT_EQ(sizeof(int), write(fds[1], &x, sizeof(x)));
  x = 4;
  ASSERT_EQ(sizeof(int), write(fds[1], &x, sizeof(x)));

  iterations = RunGMainLoopMaxIterations(10);
  EXPECT_EQ(iterations, 1);

  EXPECT_EQ(calls.num_calls, 1);
  const TestStruct result = {-1, 2, 4};
  EXPECT_EQ(calls.last_call, result);
  close(fds[0]);
  close(fds[1]);
}

}  // namespace util

}  // namespace p2p
