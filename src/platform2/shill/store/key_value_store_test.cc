// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/store/key_value_store.h"

#include <limits>
#include <map>
#include <string>
#include <vector>

#include <gtest/gtest.h>

using testing::Test;

namespace shill {

namespace {
const char kBoolKey[] = "BoolKey";
const char kBoolsKey[] = "BoolsKey";
const char kByteArraysKey[] = "ByteArraysKey";
const char kIntKey[] = "IntKey";
const char kIntsKey[] = "IntsKey";
const char kInt16Key[] = "Int16Key";
const char kInt64Key[] = "Int64Key";
const char kInt64sKey[] = "Int64sKey";
const char kDoubleKey[] = "DoubleKey";
const char kDoublesKey[] = "DoublesKey";
const char kKeyValueStoreKey[] = "KeyValueStoreKey";
const char kRpcIdentifierKey[] = "RpcIdentifierKey";
const char kRpcIdentifiersKey[] = "RpcIdentifiersKey";
const char kStringKey[] = "StringKey";
const char kStringmapKey[] = "StringmapKey";
const char kStringmapsKey[] = "StringmapsKey";
const char kStringsKey[] = "StringsKey";
const char kUintKey[] = "UintKey";
const char kUint16Key[] = "Uint16Key";
const char kUint8Key[] = "Uint8Key";
const char kUint8sKey[] = "Uint8sKey";
const char kUint32sKey[] = "Uint32sKey";
const char kUint64sKey[] = "Uint64sKey";
const char kNestedInt32Key[] = "NestedInt32Key";

const bool kBoolValue = true;
const std::vector<bool> kBoolsValue{true, false, false};
const std::vector<std::vector<uint8_t>> kByteArraysValue{{1}, {2}};
const int32_t kIntValue = 123;
const std::vector<int32_t> kIntsValue{123, 456, 789};
const int16_t kInt16Value = 123;
const int64_t kInt64Value = 0x1234000000000000;
const std::vector<int64_t> kInt64sValue{0x2345000000000000, 0x6789000000000000};
const double kDoubleValue = 1.1;
const std::vector<double> kDoublesValue{2.2, 3.3};
const size_t kDoublesValueSize = kDoublesValue.size();
const RpcIdentifier kRpcIdentifierValue("/org/chromium/test");
const std::vector<RpcIdentifier> kRpcIdentifiersValue{
    RpcIdentifier("/org/chromium/test0"), RpcIdentifier("/org/chromium/test1"),
    RpcIdentifier("/org/chromium/test2")};
const char kStringValue[] = "StringValue";
const std::map<std::string, std::string> kStringmapValue = {{"key", "value"}};
const std::vector<std::map<std::string, std::string>> kStringmapsValue = {
    {{"key1", "value1"}}, {{"key2", "value2"}}};
const std::vector<std::string> kStringsValue = {"StringsValue1",
                                                "StringsValue2"};
const uint32_t kUintValue = 654;
const uint16_t kUint16Value = 123;
const uint8_t kUint8Value = 3;
const std::vector<uint8_t> kUint8sValue{1, 2};
const std::vector<uint32_t> kUint32sValue{1, 2};
const std::vector<uint64_t> kUint64sValue{1,
                                          std::numeric_limits<uint64_t>::min(),
                                          std::numeric_limits<uint64_t>::max()};
const int32_t kNestedInt32Value = 1;
}  // namespace

class KeyValueStoreTest : public Test {
 public:
  KeyValueStoreTest() = default;

  void SetOneOfEachType(KeyValueStore* store,
                        const KeyValueStore& nested_key_value_store_value) {
    store->Set<bool>(kBoolKey, kBoolValue);
    store->Set<std::vector<bool>>(kBoolsKey, kBoolsValue);
    store->Set<ByteArrays>(kByteArraysKey, kByteArraysValue);
    store->Set<int32_t>(kIntKey, kIntValue);
    store->Set<std::vector<int32_t>>(kIntsKey, kIntsValue);
    store->Set<int16_t>(kInt16Key, kInt16Value);
    store->Set<int64_t>(kInt64Key, kInt64Value);
    store->Set<std::vector<int64_t>>(kInt64sKey, kInt64sValue);
    store->Set<double>(kDoubleKey, kDoubleValue);
    store->Set<std::vector<double>>(kDoublesKey, kDoublesValue);
    store->Set<KeyValueStore>(kKeyValueStoreKey, nested_key_value_store_value);
    store->Set<RpcIdentifier>(kRpcIdentifierKey, kRpcIdentifierValue);
    store->Set<RpcIdentifiers>(kRpcIdentifiersKey, kRpcIdentifiersValue);
    store->Set<std::string>(kStringKey, kStringValue);
    store->Set<Stringmap>(kStringmapKey, kStringmapValue);
    store->Set<Stringmaps>(kStringmapsKey, kStringmapsValue);
    store->Set<Strings>(kStringsKey, kStringsValue);
    store->Set<uint32_t>(kUintKey, kUintValue);
    store->Set<uint16_t>(kUint16Key, kUint16Value);
    store->Set<uint8_t>(kUint8Key, kUint8Value);
    store->Set<std::vector<uint8_t>>(kUint8sKey, kUint8sValue);
    store->Set<std::vector<uint32_t>>(kUint32sKey, kUint32sValue);
    store->Set<std::vector<uint64_t>>(kUint64sKey, kUint64sValue);
  }

 protected:
  KeyValueStore store_;
};

TEST_F(KeyValueStoreTest, Any) {
  EXPECT_FALSE(store_.ContainsVariant(kStringKey));
  store_.SetVariant(kStringKey, brillo::Any(std::string(kStringValue)));
  EXPECT_TRUE(store_.ContainsVariant(kStringKey));
  EXPECT_EQ(std::string(kStringValue),
            store_.GetVariant(kStringKey).Get<std::string>());
  store_.Remove(kStringKey);
  EXPECT_FALSE(store_.ContainsVariant(kStringKey));
}

TEST_F(KeyValueStoreTest, Bool) {
  const bool kDefaultValue = true;
  const bool kValue = false;
  EXPECT_FALSE(store_.Contains<bool>(kBoolKey));
  EXPECT_EQ(kDefaultValue, store_.Lookup<bool>(kBoolKey, kDefaultValue));
  store_.Set<bool>(kBoolKey, kValue);
  EXPECT_TRUE(store_.Contains<bool>(kBoolKey));
  // TODO(shenhan): investigate if a newer version of gtest handles EXPECT_EQ
  // for bools in a manner that gcc 4.7 is happy with. (Improper conversion from
  // "false" to "NULL").
  EXPECT_EQ(static_cast<int>(kValue),
            static_cast<int>(store_.Lookup<bool>(kBoolKey, kDefaultValue)));
  EXPECT_EQ(static_cast<int>(kValue),
            static_cast<int>(store_.Get<bool>(kBoolKey)));
}

TEST_F(KeyValueStoreTest, Bools) {
  EXPECT_FALSE(store_.Contains<std::vector<bool>>(kBoolsKey));
  store_.Set<std::vector<bool>>(kBoolsKey, kBoolsValue);
  EXPECT_TRUE(store_.Contains<std::vector<bool>>(kBoolsKey));
  EXPECT_EQ(kBoolsValue, store_.Get<std::vector<bool>>(kBoolsKey));
}

TEST_F(KeyValueStoreTest, ByteArrays) {
  EXPECT_FALSE(store_.Contains<ByteArrays>(kByteArraysKey));
  store_.Set<ByteArrays>(kByteArraysKey, kByteArraysValue);
  EXPECT_TRUE(store_.Contains<ByteArrays>(kByteArraysKey));
  EXPECT_EQ(kByteArraysValue, store_.Get<ByteArrays>(kByteArraysKey));
  store_.Remove(kByteArraysKey);
  EXPECT_FALSE(store_.Contains<ByteArrays>(kByteArraysKey));
}

TEST_F(KeyValueStoreTest, Int) {
  EXPECT_FALSE(store_.Contains<int32_t>(kIntKey));
  const int kDefaultValue = 789;
  const int kValue = 456;
  EXPECT_EQ(kDefaultValue, store_.Lookup<int32_t>(kIntKey, kDefaultValue));
  store_.Set<int32_t>(kIntKey, kValue);
  EXPECT_TRUE(store_.Contains<int32_t>(kIntKey));
  EXPECT_EQ(kValue, store_.Get<int32_t>(kIntKey));
  EXPECT_EQ(kValue, store_.Lookup<int32_t>(kIntKey, kDefaultValue));
  store_.Remove(kIntKey);
  EXPECT_FALSE(store_.Contains<int32_t>(kIntKey));
}

TEST_F(KeyValueStoreTest, Ints) {
  EXPECT_FALSE(store_.Contains<std::vector<int32_t>>(kIntsKey));
  store_.Set<std::vector<int32_t>>(kIntsKey, kIntsValue);
  EXPECT_TRUE(store_.Contains<std::vector<int32_t>>(kIntsKey));
  EXPECT_EQ(kIntsValue, store_.Get<std::vector<int32_t>>(kIntsKey));
}

TEST_F(KeyValueStoreTest, Int16) {
  EXPECT_FALSE(store_.Contains<int16_t>(kInt16Key));
  store_.Set<int16_t>(kInt16Key, kInt16Value);
  EXPECT_TRUE(store_.Contains<int16_t>(kInt16Key));
  EXPECT_EQ(kInt16Value, store_.Get<int16_t>(kInt16Key));
  store_.Remove(kInt16Key);
  EXPECT_FALSE(store_.Contains<int16_t>(kInt16Key));
}

TEST_F(KeyValueStoreTest, Int64) {
  EXPECT_FALSE(store_.Contains<int64_t>(kInt64Key));
  store_.Set<int64_t>(kInt64Key, kInt64Value);
  EXPECT_TRUE(store_.Contains<int64_t>(kInt64Key));
  EXPECT_EQ(kInt64Value, store_.Get<int64_t>(kInt64Key));
}

TEST_F(KeyValueStoreTest, Int64s) {
  EXPECT_FALSE(store_.Contains<std::vector<int64_t>>(kInt64sKey));
  store_.Set<std::vector<int64_t>>(kInt64sKey, kInt64sValue);
  EXPECT_TRUE(store_.Contains<std::vector<int64_t>>(kInt64sKey));
  EXPECT_EQ(kInt64sValue, store_.Get<std::vector<int64_t>>(kInt64sKey));
}

TEST_F(KeyValueStoreTest, Double) {
  EXPECT_FALSE(store_.Contains<double>(kDoubleKey));
  store_.Set<double>(kDoubleKey, kDoubleValue);
  EXPECT_TRUE(store_.Contains<double>(kDoubleKey));
  EXPECT_DOUBLE_EQ(kDoubleValue, store_.Get<double>(kDoubleKey));
}

TEST_F(KeyValueStoreTest, Doubles) {
  EXPECT_FALSE(store_.Contains<std::vector<double>>(kDoublesKey));
  store_.Set<std::vector<double>>(kDoublesKey, kDoublesValue);
  EXPECT_TRUE(store_.Contains<std::vector<double>>(kDoublesKey));
  std::vector<double> ret = store_.Get<std::vector<double>>(kDoublesKey);
  EXPECT_EQ(kDoublesValueSize, ret.size());
  for (size_t i = 0; i < kDoublesValueSize; ++i) {
    EXPECT_DOUBLE_EQ(kDoublesValue[i], ret[i]);
  }
}

TEST_F(KeyValueStoreTest, KeyValueStore) {
  KeyValueStore value;
  value.Set<Stringmap>(kStringmapKey, kStringmapValue);
  EXPECT_FALSE(store_.Contains<KeyValueStore>(kKeyValueStoreKey));
  store_.Set<KeyValueStore>(kKeyValueStoreKey, value);
  EXPECT_TRUE(store_.Contains<KeyValueStore>(kKeyValueStoreKey));
  EXPECT_EQ(value, store_.Get<KeyValueStore>(kKeyValueStoreKey));
  store_.Remove(kKeyValueStoreKey);
  EXPECT_FALSE(store_.Contains<KeyValueStore>(kKeyValueStoreKey));
}

TEST_F(KeyValueStoreTest, RpcIdentifier) {
  EXPECT_FALSE(store_.Contains<RpcIdentifier>(kRpcIdentifierKey));
  store_.Set<RpcIdentifier>(kRpcIdentifierKey, kRpcIdentifierValue);
  EXPECT_TRUE(store_.Contains<RpcIdentifier>(kRpcIdentifierKey));
  EXPECT_EQ(kRpcIdentifierValue, store_.Get<RpcIdentifier>(kRpcIdentifierKey));
  store_.Remove(kRpcIdentifierKey);
  EXPECT_FALSE(store_.Contains<RpcIdentifier>(kRpcIdentifierKey));
}

TEST_F(KeyValueStoreTest, RpcIdentifiers) {
  EXPECT_FALSE(store_.Contains<RpcIdentifiers>(kRpcIdentifiersKey));
  store_.Set<RpcIdentifiers>(kRpcIdentifiersKey, kRpcIdentifiersValue);
  EXPECT_TRUE(store_.Contains<RpcIdentifiers>(kRpcIdentifiersKey));
  EXPECT_EQ(kRpcIdentifiersValue,
            store_.Get<RpcIdentifiers>(kRpcIdentifiersKey));
  store_.Remove(kRpcIdentifiersKey);
  EXPECT_FALSE(store_.Contains<RpcIdentifiers>(kRpcIdentifiersKey));
}

TEST_F(KeyValueStoreTest, String) {
  const std::string kDefaultValue("bar");
  const std::string kValue("baz");
  EXPECT_FALSE(store_.Contains<std::string>(kStringKey));
  EXPECT_EQ(kDefaultValue,
            store_.Lookup<std::string>(kStringKey, kDefaultValue));
  store_.Set<std::string>(kStringKey, kValue);
  EXPECT_TRUE(store_.Contains<std::string>(kStringKey));
  EXPECT_EQ(kValue, store_.Lookup<std::string>(kStringKey, kDefaultValue));
  EXPECT_EQ(kValue, store_.Get<std::string>(kStringKey));
  store_.Remove(kStringKey);
  EXPECT_FALSE(store_.Contains<std::string>(kStringKey));
  EXPECT_EQ(kDefaultValue,
            store_.Lookup<std::string>(kStringKey, kDefaultValue));
}

TEST_F(KeyValueStoreTest, Stringmap) {
  EXPECT_FALSE(store_.Contains<Stringmap>(kStringmapKey));
  store_.Set<Stringmap>(kStringmapKey, kStringmapValue);
  EXPECT_TRUE(store_.Contains<Stringmap>(kStringmapKey));
  EXPECT_EQ(kStringmapValue, store_.Get<Stringmap>(kStringmapKey));
  store_.Remove(kStringmapKey);
  EXPECT_FALSE(store_.Contains<Stringmap>(kStringmapKey));
}

TEST_F(KeyValueStoreTest, Stringmaps) {
  EXPECT_FALSE(store_.Contains<Stringmaps>(kStringmapsKey));
  store_.Set<Stringmaps>(kStringmapsKey, kStringmapsValue);
  EXPECT_TRUE(store_.Contains<Stringmaps>(kStringmapsKey));
  EXPECT_EQ(kStringmapsValue, store_.Get<Stringmaps>(kStringmapsKey));
  store_.Remove(kStringmapsKey);
  EXPECT_FALSE(store_.Contains<Stringmaps>(kStringmapsKey));
}

TEST_F(KeyValueStoreTest, Strings) {
  EXPECT_FALSE(store_.Contains<Strings>(kStringsKey));
  store_.Set<Strings>(kStringsKey, kStringsValue);
  EXPECT_TRUE(store_.Contains<Strings>(kStringsKey));
  EXPECT_EQ(kStringsValue, store_.Get<Strings>(kStringsKey));
  store_.Remove(kStringsKey);
  EXPECT_FALSE(store_.Contains<Strings>(kStringsKey));
}

TEST_F(KeyValueStoreTest, Uint) {
  EXPECT_FALSE(store_.Contains<uint32_t>(kUintKey));
  store_.Set<uint32_t>(kUintKey, kUintValue);
  EXPECT_TRUE(store_.Contains<uint32_t>(kUintKey));
  EXPECT_EQ(kUintValue, store_.Get<uint32_t>(kUintKey));
}

TEST_F(KeyValueStoreTest, Uint16) {
  EXPECT_FALSE(store_.Contains<uint16_t>(kUint16Key));
  store_.Set<uint16_t>(kUint16Key, kUint16Value);
  EXPECT_TRUE(store_.Contains<uint16_t>(kUint16Key));
  EXPECT_EQ(kUint16Value, store_.Get<uint16_t>(kUint16Key));
}

TEST_F(KeyValueStoreTest, Uint8) {
  EXPECT_FALSE(store_.Contains<uint8_t>(kUint8Key));
  store_.Set<uint8_t>(kUint8Key, kUint8Value);
  EXPECT_TRUE(store_.Contains<uint8_t>(kUint8Key));
  EXPECT_EQ(kUint8Value, store_.Get<uint8_t>(kUint8Key));
  store_.Remove(kUint8Key);
  EXPECT_FALSE(store_.Contains<uint8_t>(kUint8Key));
}

TEST_F(KeyValueStoreTest, Uint8s) {
  EXPECT_FALSE(store_.Contains<std::vector<uint8_t>>(kUint8sKey));
  store_.Set<std::vector<uint8_t>>(kUint8sKey, kUint8sValue);
  EXPECT_TRUE(store_.Contains<std::vector<uint8_t>>(kUint8sKey));
  EXPECT_EQ(kUint8sValue, store_.Get<std::vector<uint8_t>>(kUint8sKey));
  store_.Remove(kUint8sKey);
  EXPECT_FALSE(store_.Contains<std::vector<uint8_t>>(kUint8sKey));
}

TEST_F(KeyValueStoreTest, Uint32s) {
  EXPECT_FALSE(store_.Contains<std::vector<uint32_t>>(kUint32sKey));
  store_.Set<std::vector<uint32_t>>(kUint32sKey, kUint32sValue);
  EXPECT_TRUE(store_.Contains<std::vector<uint32_t>>(kUint32sKey));
  EXPECT_EQ(kUint32sValue, store_.Get<std::vector<uint32_t>>(kUint32sKey));
  store_.Remove(kUint32sKey);
  EXPECT_FALSE(store_.Contains<std::vector<uint32_t>>(kUint32sKey));
}

TEST_F(KeyValueStoreTest, Uint64s) {
  EXPECT_FALSE(store_.Contains<std::vector<uint64_t>>(kUint64sKey));
  store_.Set<std::vector<uint64_t>>(kUint64sKey, kUint64sValue);
  EXPECT_TRUE(store_.Contains<std::vector<uint64_t>>(kUint64sKey));
  EXPECT_EQ(kUint64sValue, store_.Get<std::vector<uint64_t>>(kUint64sKey));
  store_.Remove(kUint64sKey);
  EXPECT_FALSE(store_.Contains<std::vector<uint64_t>>(kUint64sKey));
}

TEST_F(KeyValueStoreTest, DoubleRemove) {
  const std::string kKey("foo");
  // Make sure we don't get an exception/infinite loop if we do a
  // "Remove()" when the key does not exist.
  store_.Remove(kKey);
  store_.Remove(kKey);
  store_.Remove(kKey);
  store_.Remove(kKey);
}

TEST_F(KeyValueStoreTest, Clear) {
  EXPECT_TRUE(store_.IsEmpty());
  SetOneOfEachType(&store_, KeyValueStore());

  EXPECT_TRUE(store_.Contains<bool>(kBoolKey));
  EXPECT_TRUE(store_.Contains<std::vector<bool>>(kBoolsKey));
  EXPECT_TRUE(store_.Contains<ByteArrays>(kByteArraysKey));
  EXPECT_TRUE(store_.Contains<int32_t>(kIntKey));
  EXPECT_TRUE(store_.Contains<std::vector<int32_t>>(kIntsKey));
  EXPECT_TRUE(store_.Contains<int16_t>(kInt16Key));
  EXPECT_TRUE(store_.Contains<int64_t>(kInt64Key));
  EXPECT_TRUE(store_.Contains<std::vector<int64_t>>(kInt64sKey));
  EXPECT_TRUE(store_.Contains<double>(kDoubleKey));
  EXPECT_TRUE(store_.Contains<std::vector<double>>(kDoublesKey));
  EXPECT_TRUE(store_.Contains<KeyValueStore>(kKeyValueStoreKey));
  EXPECT_TRUE(store_.Contains<RpcIdentifier>(kRpcIdentifierKey));
  EXPECT_TRUE(store_.Contains<std::string>(kStringKey));
  EXPECT_TRUE(store_.Contains<Stringmap>(kStringmapKey));
  EXPECT_TRUE(store_.Contains<Stringmaps>(kStringmapsKey));
  EXPECT_TRUE(store_.Contains<Strings>(kStringsKey));
  EXPECT_TRUE(store_.Contains<uint32_t>(kUintKey));
  EXPECT_TRUE(store_.Contains<uint16_t>(kUint16Key));
  EXPECT_TRUE(store_.Contains<std::vector<uint8_t>>(kUint8sKey));
  EXPECT_TRUE(store_.Contains<std::vector<uint32_t>>(kUint32sKey));
  EXPECT_TRUE(store_.Contains<std::vector<uint64_t>>(kUint64sKey));
  EXPECT_FALSE(store_.IsEmpty());
  store_.Clear();
  EXPECT_TRUE(store_.IsEmpty());
  EXPECT_FALSE(store_.Contains<bool>(kBoolKey));
  EXPECT_FALSE(store_.Contains<std::vector<bool>>(kBoolsKey));
  EXPECT_FALSE(store_.Contains<ByteArrays>(kByteArraysKey));
  EXPECT_FALSE(store_.Contains<int32_t>(kIntKey));
  EXPECT_FALSE(store_.Contains<std::vector<int32_t>>(kIntsKey));
  EXPECT_FALSE(store_.Contains<int16_t>(kInt16Key));
  EXPECT_FALSE(store_.Contains<int64_t>(kInt64Key));
  EXPECT_FALSE(store_.Contains<std::vector<int64_t>>(kInt64sKey));
  EXPECT_FALSE(store_.Contains<double>(kDoubleKey));
  EXPECT_FALSE(store_.Contains<std::vector<double>>(kDoublesKey));
  EXPECT_FALSE(store_.Contains<KeyValueStore>(kKeyValueStoreKey));
  EXPECT_FALSE(store_.Contains<RpcIdentifier>(kRpcIdentifierKey));
  EXPECT_FALSE(store_.Contains<std::string>(kStringKey));
  EXPECT_FALSE(store_.Contains<Stringmap>(kStringmapKey));
  EXPECT_FALSE(store_.Contains<Stringmaps>(kStringmapsKey));
  EXPECT_FALSE(store_.Contains<Strings>(kStringsKey));
  EXPECT_FALSE(store_.Contains<uint32_t>(kUintKey));
  EXPECT_FALSE(store_.Contains<uint16_t>(kUint16Key));
  EXPECT_FALSE(store_.Contains<std::vector<uint8_t>>(kUint8sKey));
  EXPECT_FALSE(store_.Contains<std::vector<uint32_t>>(kUint32sKey));
  EXPECT_FALSE(store_.Contains<std::vector<uint64_t>>(kUint64sKey));
}

TEST_F(KeyValueStoreTest, Equals) {
  KeyValueStore first, second;

  first.Set<bool>("boolKey", true);
  EXPECT_NE(first, second);

  first.Clear();
  second.Clear();
  second.Set<bool>("boolKey", true);
  EXPECT_NE(first, second);

  first.Clear();
  second.Clear();
  first.Set<bool>("boolKey", true);
  second.Set<bool>("boolOtherKey", true);
  EXPECT_NE(first, second);

  first.Clear();
  second.Clear();
  first.Set<bool>("boolKey", true);
  second.Set<bool>("boolKey", false);
  EXPECT_NE(first, second);

  const std::vector<bool> kBools1{true, false};
  const std::vector<bool> kBools2{false, true};

  first.Clear();
  second.Clear();
  first.Set<std::vector<bool>>("boolsKey", kBools1);
  second.Set<std::vector<bool>>("boolsOtherKey", kBools1);
  EXPECT_NE(first, second);

  first.Clear();
  second.Clear();
  first.Set<std::vector<bool>>("boolsKey", kBools1);
  second.Set<std::vector<bool>>("boolsKey", kBools2);
  EXPECT_NE(first, second);

  const std::vector<std::vector<uint8_t>> kByteArrays1{{1, 2}};
  const std::vector<std::vector<uint8_t>> kByteArrays2{{3, 4}};

  first.Clear();
  second.Clear();
  first.Set<ByteArrays>("byteArraysKey", kByteArrays1);
  second.Set<ByteArrays>("byteArraysOtherKey", kByteArrays1);
  EXPECT_NE(first, second);

  first.Clear();
  second.Clear();
  first.Set<ByteArrays>("byteArraysKey", kByteArrays1);
  second.Set<ByteArrays>("byteArraysKey", kByteArrays2);
  EXPECT_NE(first, second);

  first.Clear();
  second.Clear();
  first.Set<int32_t>("intKey", 123);
  second.Set<int32_t>("intOtherKey", 123);
  EXPECT_NE(first, second);

  first.Clear();
  second.Clear();
  first.Set<int32_t>("intKey", 123);
  second.Set<int32_t>("intKey", 456);
  EXPECT_NE(first, second);

  const std::vector<int32_t> kInts1{1, 2};
  const std::vector<int32_t> kInts2{3, 4};

  first.Clear();
  second.Clear();
  first.Set<std::vector<int32_t>>("intsKey", kInts1);
  second.Set<std::vector<int32_t>>("intsOtherKey", kInts1);
  EXPECT_NE(first, second);

  first.Clear();
  second.Clear();
  first.Set<std::vector<int32_t>>("intsKey", kInts1);
  second.Set<std::vector<int32_t>>("intsKey", kInts2);
  EXPECT_NE(first, second);

  first.Clear();
  second.Clear();
  first.Set<int16_t>("int16Key", 123);
  second.Set<int16_t>("int16OtherKey", 123);
  EXPECT_NE(first, second);

  first.Clear();
  second.Clear();
  first.Set<int16_t>("int16Key", 123);
  second.Set<int16_t>("int16Key", 456);
  EXPECT_NE(first, second);

  first.Clear();
  second.Clear();
  first.Set<int64_t>("int64Key", 0x1234000000000000);
  second.Set<int64_t>("int64OtherKey", 0x1234000000000000);
  EXPECT_NE(first, second);

  first.Clear();
  second.Clear();
  first.Set<int64_t>("int64Key", 0x6789000000000000);
  second.Set<int64_t>("int64Key", 0x2345000000000000);
  EXPECT_NE(first, second);

  const std::vector<int64_t> kInt64s1{0x1000000000000000, 0x2000000000000000};
  const std::vector<int64_t> kInt64s2{0x3000000000000000, 0x4000000000000000};

  first.Clear();
  second.Clear();
  first.Set<std::vector<int64_t>>("int64sKey", kInt64s1);
  second.Set<std::vector<int64_t>>("int64sOtherKey", kInt64s1);
  EXPECT_NE(first, second);

  first.Clear();
  second.Clear();
  first.Set<std::vector<int64_t>>("int64sKey", kInt64s1);
  second.Set<std::vector<int64_t>>("int64sKey", kInt64s2);
  EXPECT_NE(first, second);

  first.Clear();
  second.Clear();
  first.Set<double>("doubleKey", 1.1);
  second.Set<double>("doubleOtherKey", 1.1);
  EXPECT_NE(first, second);

  first.Clear();
  second.Clear();
  first.Set<double>("doubleKey", 2.3);
  second.Set<double>("doubleKey", 4.5);
  EXPECT_NE(first, second);

  const std::vector<double> kDoubles1{1.1, 2.2};
  const std::vector<double> kDoubles2{3.3, 4.4};

  first.Clear();
  second.Clear();
  first.Set<std::vector<double>>("doublesKey", kDoubles1);
  second.Set<std::vector<double>>("doublesOtherKey", kDoubles1);
  EXPECT_NE(first, second);

  first.Clear();
  second.Clear();
  first.Set<std::vector<double>>("doublesKey", kDoubles1);
  second.Set<std::vector<double>>("doublesKey", kDoubles2);
  EXPECT_NE(first, second);

  KeyValueStore key_value0;
  key_value0.Set<int32_t>("intKey", 123);
  KeyValueStore key_value1;
  key_value1.Set<int32_t>("intOtherKey", 123);

  first.Clear();
  second.Clear();
  first.Set<KeyValueStore>("keyValueKey", key_value0);
  second.Set<KeyValueStore>("keyValueKey", key_value1);
  EXPECT_NE(first, second);

  first.Clear();
  second.Clear();
  first.Set<KeyValueStore>("keyValueKey", key_value0);
  second.Set<KeyValueStore>("keyValueOtherKey", key_value0);
  EXPECT_NE(first, second);

  first.Clear();
  second.Clear();
  first.Set<RpcIdentifier>("rpcIdentifierKey", RpcIdentifier("rpcIdentifier"));
  second.Set<RpcIdentifier>("rpcIdentifierOtherKey",
                            RpcIdentifier("rpcIdentifier"));
  EXPECT_NE(first, second);

  first.Clear();
  second.Clear();
  first.Set<RpcIdentifier>("rpcIdentifierKey", RpcIdentifier("rpcIdentifier"));
  second.Set<RpcIdentifier>("rpcIdentifierKey",
                            RpcIdentifier("otherRpcIdentifier"));
  EXPECT_NE(first, second);

  first.Clear();
  second.Clear();
  first.Set<std::string>("stringKey", "string");
  second.Set<std::string>("stringOtherKey", "string");
  EXPECT_NE(first, second);

  first.Clear();
  second.Clear();
  first.Set<std::string>("stringKey", "string");
  second.Set<std::string>("stringKey", "otherString");
  EXPECT_NE(first, second);

  const std::map<std::string, std::string> kStringmap1{{"key", "value"}};
  const std::map<std::string, std::string> kStringmap2{{"otherKey", "value"}};
  const std::map<std::string, std::string> kStringmap3{{"key", "otherValue"}};

  first.Clear();
  second.Clear();
  first.Set<Stringmap>("stringmapKey", kStringmap1);
  second.Set<Stringmap>("stringmapOtherKey", kStringmap1);
  EXPECT_NE(first, second);

  first.Clear();
  second.Clear();
  first.Set<Stringmap>("stringmapKey", kStringmap1);
  second.Set<Stringmap>("stringmapKey", kStringmap2);
  EXPECT_NE(first, second);

  first.Clear();
  second.Clear();
  first.Set<Stringmap>("stringmapKey", kStringmap1);
  second.Set<Stringmap>("stringmapKey", kStringmap3);
  EXPECT_NE(first, second);

  const std::vector<std::map<std::string, std::string>> kStringmaps1{
      kStringmap1, kStringmap2};
  const std::vector<std::map<std::string, std::string>> kStringmaps2{
      kStringmap2, kStringmap1};
  const std::vector<std::map<std::string, std::string>> kStringmaps3{
      kStringmap1};

  first.Clear();
  second.Clear();
  first.Set<Stringmaps>("stringmapsKey", kStringmaps1);
  second.Set<Stringmaps>("stringmapsOtherKey", kStringmaps1);
  EXPECT_NE(first, second);

  first.Clear();
  second.Clear();
  first.Set<Stringmaps>("stringmapsKey", kStringmaps1);
  second.Set<Stringmaps>("stringmapsKey", kStringmaps2);
  EXPECT_NE(first, second);

  first.Clear();
  second.Clear();
  first.Set<Stringmaps>("stringmapsKey", kStringmaps1);
  second.Set<Stringmaps>("stringmapsKey", kStringmaps3);
  EXPECT_NE(first, second);

  const std::vector<std::string> kStrings1{"value"};
  const std::vector<std::string> kStrings2{"otherValue"};

  first.Clear();
  second.Clear();
  first.Set<Strings>("stringsKey", kStrings1);
  second.Set<Strings>("stringsOtherKey", kStrings1);
  EXPECT_NE(first, second);

  first.Clear();
  second.Clear();
  first.Set<Strings>("stringsKey", kStrings1);
  second.Set<Strings>("stringsKey", kStrings2);
  EXPECT_NE(first, second);

  first.Clear();
  second.Clear();
  first.Set<uint32_t>("uintKey", 1);
  second.Set<uint32_t>("uintOtherKey", 1);
  EXPECT_NE(first, second);

  first.Clear();
  second.Clear();
  first.Set<uint32_t>("uintKey", 1);
  second.Set<uint32_t>("uintKey", 2);
  EXPECT_NE(first, second);

  first.Clear();
  second.Clear();
  first.Set<uint16_t>("uint16Key", 1);
  second.Set<uint16_t>("uint16OtherKey", 1);
  EXPECT_NE(first, second);

  first.Clear();
  second.Clear();
  first.Set<uint16_t>("uint16Key", 1);
  second.Set<uint16_t>("uint16Key", 2);
  EXPECT_NE(first, second);

  const std::vector<uint8_t> kUint8s1{1};
  const std::vector<uint8_t> kUint8s2{2};

  first.Clear();
  second.Clear();
  first.Set<std::vector<uint8_t>>("uint8sKey", kUint8s1);
  second.Set<std::vector<uint8_t>>("uint8sOtherKey", kUint8s1);
  EXPECT_NE(first, second);

  first.Clear();
  second.Clear();
  first.Set<std::vector<uint8_t>>("uint8sKey", kUint8s1);
  second.Set<std::vector<uint8_t>>("uint8sKey", kUint8s2);
  EXPECT_NE(first, second);

  const std::vector<uint32_t> kUint32s1{1};
  const std::vector<uint32_t> kUint32s2{2};

  first.Clear();
  second.Clear();
  first.Set<std::vector<uint32_t>>("uint32sKey", kUint32s1);
  second.Set<std::vector<uint32_t>>("uint32sOtherKey", kUint32s1);
  EXPECT_NE(first, second);

  first.Clear();
  second.Clear();
  first.Set<std::vector<uint32_t>>("uint32sKey", kUint32s1);
  second.Set<std::vector<uint32_t>>("uint32sKey", kUint32s2);
  EXPECT_NE(first, second);

  const std::vector<uint64_t> kUint64s1{1};
  const std::vector<uint64_t> kUint64s2{2};

  first.Clear();
  second.Clear();
  first.Set<std::vector<uint64_t>>("uint64sKey", kUint64s1);
  second.Set<std::vector<uint64_t>>("uint64sOtherKey", kUint64s1);
  EXPECT_NE(first, second);

  first.Clear();
  second.Clear();
  first.Set<std::vector<uint64_t>>("uint64sKey", kUint64s1);
  second.Set<std::vector<uint64_t>>("uint64sKey", kUint64s2);
  EXPECT_NE(first, second);

  first.Clear();
  second.Clear();
  first.Set<bool>("boolKey", true);
  first.Set<std::vector<bool>>("boolsKey", kBools1);
  first.Set<ByteArrays>("byteArraysKey", kByteArrays1);
  first.Set<int32_t>("intKey", 123);
  first.Set<std::vector<int32_t>>("intsKey", kInts1);
  first.Set<int16_t>("int16Key", 123);
  first.Set<int64_t>("int64Key", 0x1234000000000000);
  first.Set<std::vector<int64_t>>("int64sKey", kInt64s1);
  first.Set<double>("doubleKey", 1.1);
  first.Set<std::vector<double>>("doublesKey", kDoubles1);
  first.Set<RpcIdentifier>("rpcIdentifierKey", RpcIdentifier("rpcid"));
  first.Set<std::string>("stringKey", "value");
  first.Set<Stringmap>("stringmapKey", kStringmap1);
  first.Set<Stringmaps>("stringmapsKey", kStringmaps1);
  first.Set<Strings>("stringsKey", kStrings1);
  first.Set<uint32_t>("uintKey", 1);
  first.Set<uint16_t>("uint16Key", 1);
  first.Set<std::vector<uint8_t>>("uint8sKey", kUint8s1);
  first.Set<std::vector<uint32_t>>("uint32sKey", kUint32s1);
  first.Set<std::vector<uint64_t>>("uint64sKey", kUint64s1);
  second.Set<bool>("boolKey", true);
  second.Set<std::vector<bool>>("boolsKey", kBools1);
  second.Set<ByteArrays>("byteArraysKey", kByteArrays1);
  second.Set<int32_t>("intKey", 123);
  second.Set<std::vector<int32_t>>("intsKey", kInts1);
  second.Set<int16_t>("int16Key", 123);
  second.Set<int64_t>("int64Key", 0x1234000000000000);
  second.Set<std::vector<int64_t>>("int64sKey", kInt64s1);
  second.Set<double>("doubleKey", 1.1);
  second.Set<std::vector<double>>("doublesKey", kDoubles1);
  second.Set<RpcIdentifier>("rpcIdentifierKey", RpcIdentifier("rpcid"));
  second.Set<std::string>("stringKey", "value");
  second.Set<Stringmap>("stringmapKey", kStringmap1);
  second.Set<Stringmaps>("stringmapsKey", kStringmaps1);
  second.Set<Strings>("stringsKey", kStrings1);
  second.Set<uint32_t>("uintKey", 1);
  second.Set<uint16_t>("uint16Key", 1);
  second.Set<std::vector<uint8_t>>("uint8sKey", kUint8s1);
  second.Set<std::vector<uint32_t>>("uint32sKey", kUint32s1);
  second.Set<std::vector<uint64_t>>("uint64sKey", kUint64s1);
  EXPECT_EQ(first, second);
}

TEST_F(KeyValueStoreTest, CopyFrom) {
  KeyValueStore donor;
  KeyValueStore keyValueStoreValue;
  keyValueStoreValue.Set<int32_t>(kIntKey, kIntValue);
  SetOneOfEachType(&donor, keyValueStoreValue);

  EXPECT_TRUE(store_.IsEmpty());
  store_.CopyFrom(donor);
  EXPECT_FALSE(store_.IsEmpty());
  EXPECT_EQ(donor, store_);
}

TEST_F(KeyValueStoreTest, ConvertToVariantDictionary) {
  KeyValueStore store;
  KeyValueStore nested_store;
  nested_store.Set<int32_t>(kNestedInt32Key, kNestedInt32Value);
  SetOneOfEachType(&store, nested_store);

  brillo::VariantDictionary dict =
      KeyValueStore::ConvertToVariantDictionary(store);
  EXPECT_EQ(23, dict.size());
  EXPECT_EQ(kStringValue, dict[kStringKey].Get<std::string>());
  std::map<std::string, std::string> stringmap_value =
      dict[kStringmapKey].Get<std::map<std::string, std::string>>();
  EXPECT_EQ(kStringmapValue, stringmap_value);
  std::vector<std::map<std::string, std::string>> stringmaps_value =
      dict[kStringmapsKey]
          .Get<std::vector<std::map<std::string, std::string>>>();
  EXPECT_EQ(kStringmapsValue, stringmaps_value);
  EXPECT_EQ(kStringsValue, dict[kStringsKey].Get<std::vector<std::string>>());
  EXPECT_EQ(kBoolValue, dict[kBoolKey].Get<bool>());
  EXPECT_EQ(kBoolsValue, dict[kBoolsKey].Get<std::vector<bool>>());
  EXPECT_EQ(kIntValue, dict[kIntKey].Get<int32_t>());
  EXPECT_EQ(kIntsValue, dict[kIntsKey].Get<std::vector<int32_t>>());
  EXPECT_EQ(kUintValue, dict[kUintKey].Get<uint32_t>());
  EXPECT_EQ(kByteArraysValue,
            dict[kByteArraysKey].Get<std::vector<std::vector<uint8_t>>>());
  EXPECT_EQ(kInt16Value, dict[kInt16Key].Get<int16_t>());
  EXPECT_EQ(kRpcIdentifierValue, dict[kRpcIdentifierKey].Get<RpcIdentifier>());
  EXPECT_EQ(kUint16Value, dict[kUint16Key].Get<uint16_t>());
  EXPECT_EQ(kInt64Value, dict[kInt64Key].Get<int64_t>());
  EXPECT_EQ(kInt64sValue, dict[kInt64sKey].Get<std::vector<int64_t>>());
  EXPECT_DOUBLE_EQ(kDoubleValue, dict[kDoubleKey].Get<double>());
  std::vector<double> doubles_value =
      dict[kDoublesKey].Get<std::vector<double>>();
  EXPECT_EQ(kDoublesValueSize, doubles_value.size());
  for (size_t i = 0; i < kDoublesValueSize; ++i) {
    EXPECT_DOUBLE_EQ(kDoublesValue[i], doubles_value[i]);
  }
  EXPECT_EQ(kUint8sValue, dict[kUint8sKey].Get<std::vector<uint8_t>>());
  EXPECT_EQ(kUint32sValue, dict[kUint32sKey].Get<std::vector<uint32_t>>());
  EXPECT_EQ(kUint64sValue, dict[kUint64sKey].Get<std::vector<uint64_t>>());
  brillo::VariantDictionary nested_dict =
      dict[kKeyValueStoreKey].Get<brillo::VariantDictionary>();
  EXPECT_EQ(kNestedInt32Value, nested_dict[kNestedInt32Key].Get<int32_t>());
}

TEST_F(KeyValueStoreTest, ConvertFromVariantDictionary) {
  brillo::VariantDictionary dict;
  dict[kStringKey] = brillo::Any(std::string(kStringValue));
  dict[kStringmapKey] = brillo::Any(kStringmapValue);
  dict[kStringmapsKey] = brillo::Any(kStringmapsValue);
  dict[kStringsKey] = brillo::Any(kStringsValue);
  dict[kBoolKey] = brillo::Any(kBoolValue);
  dict[kBoolsKey] = brillo::Any(kBoolsValue);
  dict[kIntKey] = brillo::Any(kIntValue);
  dict[kIntsKey] = brillo::Any(kIntsValue);
  dict[kUintKey] = brillo::Any(kUintValue);
  dict[kByteArraysKey] = brillo::Any(kByteArraysValue);
  dict[kInt16Key] = brillo::Any(kInt16Value);
  dict[kInt64Key] = brillo::Any(kInt64Value);
  dict[kInt64sKey] = brillo::Any(kInt64sValue);
  dict[kDoubleKey] = brillo::Any(kDoubleValue);
  dict[kDoublesKey] = brillo::Any(kDoublesValue);
  dict[kRpcIdentifierKey] = brillo::Any(kRpcIdentifierValue);
  dict[kUint16Key] = brillo::Any(kUint16Value);
  dict[kUint8sKey] = brillo::Any(kUint8sValue);
  dict[kUint32sKey] = brillo::Any(kUint32sValue);
  dict[kUint64sKey] = brillo::Any(kUint64sValue);
  brillo::VariantDictionary nested_dict;
  nested_dict[kNestedInt32Key] = brillo::Any(kNestedInt32Value);
  dict[kKeyValueStoreKey] = brillo::Any(nested_dict);

  KeyValueStore store = KeyValueStore::ConvertFromVariantDictionary(dict);
  EXPECT_TRUE(store.Contains<std::string>(kStringKey));
  EXPECT_EQ(kStringValue, store.Get<std::string>(kStringKey));
  EXPECT_TRUE(store.Contains<Stringmap>(kStringmapKey));
  EXPECT_EQ(kStringmapValue, store.Get<Stringmap>(kStringmapKey));
  EXPECT_TRUE(store.Contains<Stringmaps>(kStringmapsKey));
  EXPECT_EQ(kStringmapsValue, store.Get<Stringmaps>(kStringmapsKey));
  EXPECT_TRUE(store.Contains<Strings>(kStringsKey));
  EXPECT_EQ(kStringsValue, store.Get<Strings>(kStringsKey));
  EXPECT_TRUE(store.Contains<bool>(kBoolKey));
  EXPECT_EQ(kBoolValue, store.Get<bool>(kBoolKey));
  EXPECT_TRUE(store.Contains<std::vector<bool>>(kBoolsKey));
  EXPECT_EQ(kBoolsValue, store.Get<std::vector<bool>>(kBoolsKey));
  EXPECT_TRUE(store.Contains<int32_t>(kIntKey));
  EXPECT_EQ(kIntValue, store.Get<int32_t>(kIntKey));
  EXPECT_TRUE(store.Contains<std::vector<int32_t>>(kIntsKey));
  EXPECT_EQ(kIntsValue, store.Get<std::vector<int32_t>>(kIntsKey));
  EXPECT_TRUE(store.Contains<uint32_t>(kUintKey));
  EXPECT_EQ(kUintValue, store.Get<uint32_t>(kUintKey));
  EXPECT_TRUE(store.Contains<ByteArrays>(kByteArraysKey));
  EXPECT_EQ(kByteArraysValue, store.Get<ByteArrays>(kByteArraysKey));
  EXPECT_TRUE(store.Contains<int16_t>(kInt16Key));
  EXPECT_EQ(kInt16Value, store.Get<int16_t>(kInt16Key));
  EXPECT_TRUE(store.Contains<int64_t>(kInt64Key));
  EXPECT_EQ(kInt64Value, store.Get<int64_t>(kInt64Key));
  EXPECT_TRUE(store.Contains<std::vector<int64_t>>(kInt64sKey));
  EXPECT_EQ(kInt64sValue, store.Get<std::vector<int64_t>>(kInt64sKey));
  EXPECT_TRUE(store.Contains<double>(kDoubleKey));
  EXPECT_DOUBLE_EQ(kDoubleValue, store.Get<double>(kDoubleKey));
  EXPECT_TRUE(store.Contains<std::vector<double>>(kDoublesKey));
  std::vector<double> doubles_value =
      store.Get<std::vector<double>>(kDoublesKey);
  EXPECT_EQ(kDoublesValueSize, doubles_value.size());
  for (size_t i = 0; i < kDoublesValueSize; ++i) {
    EXPECT_DOUBLE_EQ(kDoublesValue[i], doubles_value[i]);
  }
  EXPECT_TRUE(store.Contains<RpcIdentifier>(kRpcIdentifierKey));
  EXPECT_EQ(kRpcIdentifierValue, store.Get<RpcIdentifier>(kRpcIdentifierKey));
  EXPECT_TRUE(store.Contains<uint16_t>(kUint16Key));
  EXPECT_EQ(kUint16Value, store.Get<uint16_t>(kUint16Key));
  EXPECT_TRUE(store.Contains<std::vector<uint8_t>>(kUint8sKey));
  EXPECT_EQ(kUint8sValue, store.Get<std::vector<uint8_t>>(kUint8sKey));
  EXPECT_TRUE(store.Contains<std::vector<uint32_t>>(kUint32sKey));
  EXPECT_EQ(kUint32sValue, store.Get<std::vector<uint32_t>>(kUint32sKey));
  EXPECT_TRUE(store.Contains<std::vector<uint64_t>>(kUint64sKey));
  EXPECT_EQ(kUint64sValue, store.Get<std::vector<uint64_t>>(kUint64sKey));
  EXPECT_TRUE(store.Contains<KeyValueStore>(kKeyValueStoreKey));
  KeyValueStore nested_store;
  nested_store.Set<int32_t>(kNestedInt32Key, kNestedInt32Value);
  EXPECT_EQ(nested_store, store.Get<KeyValueStore>(kKeyValueStoreKey));
}

}  // namespace shill
