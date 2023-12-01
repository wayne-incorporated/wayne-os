// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "smbprovider/id_map.h"

namespace smbprovider {

class IdMapTest : public testing::Test {
 public:
  IdMapTest() : map_(0 /* initial_value */) {}
  IdMapTest(const IdMapTest&) = delete;
  IdMapTest& operator=(const IdMapTest&) = delete;

  ~IdMapTest() override = default;

 protected:
  void ExpectFound(int32_t id, std::string expected) const {
    const auto iter = map_.Find(id);
    EXPECT_NE(map_.End(), iter);
    EXPECT_TRUE(map_.Contains(id));
    EXPECT_EQ(expected, iter->second);
  }

  void ExpectNotFound(int32_t id) const {
    const auto iter = map_.Find(id);
    EXPECT_EQ(map_.End(), iter);
    EXPECT_FALSE(map_.Contains(id));
  }

  IdMap<const std::string> map_;
};

TEST_F(IdMapTest, FindOnEmpty) {
  EXPECT_EQ(0, map_.Count());
  ExpectNotFound(0);
}

TEST_F(IdMapTest, TestInsertandFind) {
  const std::string expected = "Foo";
  const int32_t id = map_.Insert(expected);

  EXPECT_GE(id, 0);
  ExpectFound(id, expected);
  EXPECT_EQ(1, map_.Count());
}

TEST_F(IdMapTest, TestInsertAndContains) {
  const std::string expected = "Foo";
  const int32_t id = map_.Insert(expected);

  EXPECT_GE(id, 0);
  EXPECT_TRUE(map_.Contains(id));
  EXPECT_FALSE(map_.Contains(id + 1));
}

TEST_F(IdMapTest, TestInsertandFindNonExistent) {
  const std::string expected = "Foo";
  const int32_t id = map_.Insert(expected);

  EXPECT_GE(id, 0);
  ExpectFound(id, expected);
  ExpectNotFound(id + 1);
}

TEST_F(IdMapTest, TestInsertMultipleAndFind) {
  const std::string expected1 = "Foo1";
  const std::string expected2 = "Foo2";
  const int32_t id1 = map_.Insert(expected1);
  EXPECT_EQ(1, map_.Count());
  const int32_t id2 = map_.Insert(expected2);
  EXPECT_EQ(2, map_.Count());

  // Both ids are >= 0 and not the same.
  EXPECT_GE(id1, 0);
  EXPECT_GE(id2, 0);
  EXPECT_NE(id1, id2);

  ExpectFound(id1, expected1);
  ExpectFound(id2, expected2);
}

TEST_F(IdMapTest, TestRemoveOnEmpty) {
  EXPECT_FALSE(map_.Remove(0));
}

TEST_F(IdMapTest, TestRemoveNonExistent) {
  const std::string expected = "Foo";
  const int32_t id = map_.Insert(expected);

  EXPECT_GE(id, 0);
  ExpectFound(id, expected);
  ExpectNotFound(id + 1);
  EXPECT_FALSE(map_.Remove(id + 1));
}

TEST_F(IdMapTest, TestInsertAndRemove) {
  const std::string expected = "Foo";
  const int32_t id = map_.Insert(expected);

  EXPECT_GE(id, 0);
  EXPECT_TRUE(map_.Contains(id));
  EXPECT_EQ(1, map_.Count());

  EXPECT_TRUE(map_.Remove(id));
  ExpectNotFound(id);
  EXPECT_EQ(0, map_.Count());
}

TEST_F(IdMapTest, TestInsertRemoveInsertRemove) {
  const std::string expected = "Foo";
  const int32_t id1 = map_.Insert(expected);

  EXPECT_GE(id1, 0);
  EXPECT_TRUE(map_.Contains(id1));
  EXPECT_EQ(1, map_.Count());

  EXPECT_TRUE(map_.Remove(id1));
  ExpectNotFound(id1);
  EXPECT_EQ(0, map_.Count());

  const int32_t id2 = map_.Insert(expected);
  EXPECT_GE(id2, 0);
  EXPECT_TRUE(map_.Contains(id2));
  EXPECT_EQ(1, map_.Count());

  EXPECT_TRUE(map_.Remove(id2));
  ExpectNotFound(id2);
  EXPECT_EQ(0, map_.Count());
}

TEST_F(IdMapTest, TestIdReuse) {
  const int32_t id1 = map_.Insert("Foo");
  const int32_t id2 = map_.Insert("Bar");

  EXPECT_GE(id1, 0);
  EXPECT_GE(id2, 0);
  EXPECT_NE(id1, id2);

  // Remove the id and check that it is reused.
  map_.Remove(id2);
  const int32_t id3 = map_.Insert("Baz");
  EXPECT_EQ(id3, id2);

  // Get another unused id.
  const int32_t id4 = map_.Insert("Qux");
  EXPECT_GE(id4, 0);
  EXPECT_NE(id1, id4);
  EXPECT_NE(id3, id4);
}

TEST_F(IdMapTest, TestInsertAndAt) {
  const std::string expected = "Foo";
  const int32_t id = map_.Insert(expected);

  EXPECT_GE(id, 0);
  // Ensure At() is safe to use.
  ExpectFound(id, expected);
  EXPECT_EQ(expected, map_.At(id));
  EXPECT_EQ(1, map_.Count());
}

TEST_F(IdMapTest, TestInitialMapValue) {
  // Construct an IdMap with initial Id of 1.
  IdMap<const std::string> map(1 /* initial_value */);

  const std::string expected = "Foo";
  const int32_t id = map.Insert(expected);
  EXPECT_EQ(1, id);

  const int32_t id2 = map.Insert("Bar");
  EXPECT_EQ(2, id2);
}

TEST_F(IdMapTest, TestEmpty) {
  EXPECT_TRUE(map_.Empty());

  const std::string expected = "Foo";
  const int32_t id = map_.Insert(expected);

  EXPECT_GE(id, 0);
  EXPECT_EQ(1, map_.Count());
  EXPECT_FALSE(map_.Empty());

  map_.Reset();
  EXPECT_TRUE(map_.Empty());
}

TEST_F(IdMapTest, TestResetOnEmptyMap) {
  EXPECT_EQ(map_.Begin(), map_.End());
  EXPECT_TRUE(map_.Empty());

  map_.Reset();
  EXPECT_EQ(map_.Begin(), map_.End());
  EXPECT_TRUE(map_.Empty());

  const std::string expected = "Foo";
  const int32_t id = map_.Insert(expected);
  EXPECT_EQ(0, id);
  EXPECT_EQ(1, map_.Count());
  EXPECT_FALSE(map_.Empty());
}

TEST_F(IdMapTest, TestReset) {
  const std::string expected = "Foo";
  const int32_t id = map_.Insert(expected);
  EXPECT_EQ(0, id);
  EXPECT_EQ(1, map_.Count());
  EXPECT_FALSE(map_.Empty());

  map_.Reset();
  EXPECT_TRUE(map_.Empty());
  ExpectNotFound(id);

  const std::string expected2 = "bar";
  const int32_t id2 = map_.Insert(expected2);
  EXPECT_EQ(0, id2);
  EXPECT_EQ(1, map_.Count());
  EXPECT_FALSE(map_.Empty());
  ExpectFound(id2, expected2);
}

TEST_F(IdMapTest, TestNonConstFind) {
  IdMap<std::string> map(0 /* initial_value */);
  int32_t id = map.Insert("Foo");
  EXPECT_GE(id, 0);

  std::string expected = "Bar";
  auto map_iter = map.Find(id);
  map_iter->second = expected;
  EXPECT_EQ(expected, map.Find(id)->second);
}

TEST_F(IdMapTest, TestNonConstBeginAndEnd) {
  IdMap<std::string> map(0 /* initial_value */);
  map.Insert("Foo1");
  map.Insert("Foo2");
  map.Insert("Foo3");

  std::vector<std::string> expected{"Bar1", "Bar2", "Bar3"};

  EXPECT_EQ(expected.size(), map.Count());

  int counter = 0;
  // Iterate through the map and update each entry to the value in expected.
  for (auto it = map.Begin(); it != map.End(); ++it) {
    it->second = expected[counter++];
  }

  counter = 0;
  for (auto it = map.Begin(); it != map.End(); ++it) {
    EXPECT_EQ(expected[counter++], it->second);
  }
}
}  // namespace smbprovider
