// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <functional>

#include <gtest/gtest.h>

#include "dlcservice/unique_queue.h"

namespace dlcservice {

TEST(UniqueQueueTest, Clear) {
  UniqueQueue<int, std::hash<int>> unique_queue;
  unique_queue.Push(1);
  EXPECT_FALSE(unique_queue.Empty());
  unique_queue.Clear();
  EXPECT_TRUE(unique_queue.Empty());
}

TEST(UniqueQueueTest, Has) {
  UniqueQueue<int, std::hash<int>> unique_queue;
  EXPECT_FALSE(unique_queue.Has(1));
  EXPECT_FALSE(unique_queue.Has(2));

  unique_queue.Push(1);
  EXPECT_TRUE(unique_queue.Has(1));
  EXPECT_FALSE(unique_queue.Has(2));

  unique_queue.Push(2);
  EXPECT_TRUE(unique_queue.Has(1));
  EXPECT_TRUE(unique_queue.Has(2));
}

TEST(UniqueQueueTest, ActuallyUnique) {
  UniqueQueue<int, std::hash<int>> unique_queue;
  unique_queue.Push(1);
  unique_queue.Push(1);
  unique_queue.Pop();
  EXPECT_TRUE(unique_queue.Empty());
}

TEST(UniqueQueueTest, Erase) {
  UniqueQueue<int, std::hash<int>> unique_queue;
  unique_queue.Push(1);
  unique_queue.Push(2);
  unique_queue.Erase(1);
  EXPECT_EQ(2, unique_queue.Peek());
}

}  // namespace dlcservice
