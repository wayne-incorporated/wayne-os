// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/store/property_accessor.h"

#include <limits>
#include <map>
#include <string>

#include <base/containers/contains.h>
#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "shill/error.h"

using ::testing::Test;

namespace shill {

TEST(PropertyAccessorTest, SignedIntCorrectness) {
  int32_t int_store = 0;
  {
    Error error;
    int32_t orig_value = int_store;
    Int32Accessor accessor(new PropertyAccessor<int32_t>(&int_store));
    EXPECT_EQ(int_store, accessor->Get(&error));

    int32_t expected_int32 = 127;
    EXPECT_TRUE(accessor->Set(expected_int32, &error));
    EXPECT_TRUE(error.IsSuccess());
    EXPECT_EQ(expected_int32, accessor->Get(&error));
    // Resetting to the same value should return false, but without
    // an error.
    EXPECT_FALSE(accessor->Set(expected_int32, &error));
    EXPECT_TRUE(error.IsSuccess());

    accessor->Clear(&error);
    EXPECT_TRUE(error.IsSuccess());
    EXPECT_EQ(orig_value, accessor->Get(&error));

    int_store = std::numeric_limits<int32_t>::max();
    EXPECT_EQ(std::numeric_limits<int32_t>::max(), accessor->Get(&error));
  }
  {
    Error error;
    Int32Accessor accessor(new ConstPropertyAccessor<int32_t>(&int_store));
    EXPECT_EQ(int_store, accessor->Get(&error));

    int32_t expected_int32 = 127;
    accessor->Set(expected_int32, &error);
    ASSERT_FALSE(error.IsSuccess());
    EXPECT_EQ(Error::kInvalidArguments, error.type());
    EXPECT_EQ(int_store, accessor->Get(&error));

    int_store = std::numeric_limits<int32_t>::max();
    EXPECT_EQ(std::numeric_limits<int32_t>::max(), accessor->Get(&error));
  }
  {
    Error error;
    Int32Accessor accessor(new ConstPropertyAccessor<int32_t>(&int_store));
    accessor->Clear(&error);
    ASSERT_FALSE(error.IsSuccess());
  }
  {
    Error error;
    Int32Accessor accessor(new WriteOnlyPropertyAccessor<int32_t>(&int_store));
    accessor->Get(&error);
    EXPECT_TRUE(error.IsFailure());
    EXPECT_EQ(Error::kPermissionDenied, error.type());
  }
  {
    Error error;
    int32_t expected_int32 = 127;
    WriteOnlyPropertyAccessor<int32_t> accessor(&int_store);
    EXPECT_TRUE(accessor.Set(expected_int32, &error));
    EXPECT_TRUE(error.IsSuccess());
    EXPECT_EQ(expected_int32, *accessor.property_);
    // Resetting to the same value should return false, but without
    // an error.
    EXPECT_FALSE(accessor.Set(expected_int32, &error));
    EXPECT_TRUE(error.IsSuccess());
    // As a write-only, the value can't be read.
    EXPECT_EQ(int32_t(), accessor.Get(&error));
    ASSERT_FALSE(error.IsSuccess());

    int_store = std::numeric_limits<int32_t>::max();
    EXPECT_EQ(std::numeric_limits<int32_t>::max(), *accessor.property_);
  }
  {
    Error error;
    int32_t orig_value = int_store = 0;
    WriteOnlyPropertyAccessor<int32_t> accessor(&int_store);

    EXPECT_TRUE(accessor.Set(127, &error));
    accessor.Clear(&error);
    EXPECT_TRUE(error.IsSuccess());
    EXPECT_EQ(orig_value, *accessor.property_);
  }
}

TEST(PropertyAccessorTest, UnsignedIntCorrectness) {
  uint32_t int_store = 0;
  {
    Error error;
    uint32_t orig_value = int_store;
    Uint32Accessor accessor(new PropertyAccessor<uint32_t>(&int_store));
    EXPECT_EQ(int_store, accessor->Get(&error));

    uint32_t expected_uint32 = 127;
    EXPECT_TRUE(accessor->Set(expected_uint32, &error));
    EXPECT_TRUE(error.IsSuccess());
    EXPECT_EQ(expected_uint32, accessor->Get(&error));
    // Resetting to the same value should return false, but without
    // an error.
    EXPECT_FALSE(accessor->Set(expected_uint32, &error));
    EXPECT_TRUE(error.IsSuccess());

    accessor->Clear(&error);
    EXPECT_TRUE(error.IsSuccess());
    EXPECT_EQ(orig_value, accessor->Get(&error));

    int_store = std::numeric_limits<uint32_t>::max();
    EXPECT_EQ(std::numeric_limits<uint32_t>::max(), accessor->Get(&error));
  }
  {
    Error error;
    Uint32Accessor accessor(new ConstPropertyAccessor<uint32_t>(&int_store));
    EXPECT_EQ(int_store, accessor->Get(&error));

    uint32_t expected_uint32 = 127;
    EXPECT_FALSE(accessor->Set(expected_uint32, &error));
    ASSERT_FALSE(error.IsSuccess());
    EXPECT_EQ(Error::kInvalidArguments, error.type());
    EXPECT_EQ(int_store, accessor->Get(&error));

    int_store = std::numeric_limits<uint32_t>::max();
    EXPECT_EQ(std::numeric_limits<uint32_t>::max(), accessor->Get(&error));
  }
  {
    Error error;
    Uint32Accessor accessor(new ConstPropertyAccessor<uint32_t>(&int_store));
    accessor->Clear(&error);
    ASSERT_FALSE(error.IsSuccess());
  }
  {
    Error error;
    Uint32Accessor accessor(
        new WriteOnlyPropertyAccessor<uint32_t>(&int_store));
    accessor->Get(&error);
    EXPECT_TRUE(error.IsFailure());
    EXPECT_EQ(Error::kPermissionDenied, error.type());
  }
  {
    Error error;
    uint32_t expected_uint32 = 127;
    WriteOnlyPropertyAccessor<uint32_t> accessor(&int_store);
    EXPECT_TRUE(accessor.Set(expected_uint32, &error));
    EXPECT_TRUE(error.IsSuccess());
    EXPECT_EQ(expected_uint32, *accessor.property_);
    // Resetting to the same value should return false, but without
    // an error.
    EXPECT_FALSE(accessor.Set(expected_uint32, &error));
    EXPECT_TRUE(error.IsSuccess());
    // As a write-only, the value can't be read.
    EXPECT_EQ(uint32_t(), accessor.Get(&error));
    ASSERT_FALSE(error.IsSuccess());

    int_store = std::numeric_limits<uint32_t>::max();
    EXPECT_EQ(std::numeric_limits<uint32_t>::max(), *accessor.property_);
  }
  {
    Error error;
    uint32_t orig_value = int_store = 0;
    WriteOnlyPropertyAccessor<uint32_t> accessor(&int_store);

    EXPECT_TRUE(accessor.Set(127, &error));
    accessor.Clear(&error);
    EXPECT_TRUE(error.IsSuccess());
    EXPECT_EQ(orig_value, *accessor.property_);
  }
}

TEST(PropertyAccessorTest, StringCorrectness) {
  std::string storage;
  {
    Error error;
    std::string orig_value = storage;
    StringAccessor accessor(new PropertyAccessor<std::string>(&storage));
    EXPECT_EQ(storage, accessor->Get(&error));

    std::string expected_string("what");
    EXPECT_TRUE(accessor->Set(expected_string, &error));
    EXPECT_TRUE(error.IsSuccess());
    EXPECT_EQ(expected_string, accessor->Get(&error));
    // Resetting to the same value should return false, but without
    // an error.
    EXPECT_FALSE(accessor->Set(expected_string, &error));
    EXPECT_TRUE(error.IsSuccess());

    accessor->Clear(&error);
    EXPECT_TRUE(error.IsSuccess());
    EXPECT_EQ(orig_value, accessor->Get(&error));

    storage = "nooooo";
    EXPECT_EQ(storage, accessor->Get(&error));
  }
  {
    Error error;
    StringAccessor accessor(new ConstPropertyAccessor<std::string>(&storage));
    EXPECT_EQ(storage, accessor->Get(&error));

    std::string expected_string("what");
    EXPECT_FALSE(accessor->Set(expected_string, &error));
    ASSERT_FALSE(error.IsSuccess());
    EXPECT_EQ(Error::kInvalidArguments, error.type());
    EXPECT_EQ(storage, accessor->Get(&error));

    storage = "nooooo";
    EXPECT_EQ(storage, accessor->Get(&error));
  }
  {
    Error error;
    StringAccessor accessor(new ConstPropertyAccessor<std::string>(&storage));
    accessor->Clear(&error);
    ASSERT_FALSE(error.IsSuccess());
  }
  {
    Error error;
    StringAccessor accessor(
        new WriteOnlyPropertyAccessor<std::string>(&storage));
    accessor->Get(&error);
    EXPECT_TRUE(error.IsFailure());
    EXPECT_EQ(Error::kPermissionDenied, error.type());
  }
  {
    Error error;
    std::string expected_string = "what";
    WriteOnlyPropertyAccessor<std::string> accessor(&storage);
    EXPECT_TRUE(accessor.Set(expected_string, &error));
    EXPECT_TRUE(error.IsSuccess());
    EXPECT_EQ(expected_string, *accessor.property_);
    // Resetting to the same value should return false, but without
    // an error.
    EXPECT_FALSE(accessor.Set(expected_string, &error));
    EXPECT_TRUE(error.IsSuccess());
    // As a write-only, the value can't be read.
    EXPECT_EQ(std::string(), accessor.Get(&error));
    ASSERT_FALSE(error.IsSuccess());

    storage = "nooooo";
    EXPECT_EQ("nooooo", *accessor.property_);
  }
  {
    Error error;
    std::string orig_value = storage = "original value";
    WriteOnlyPropertyAccessor<std::string> accessor(&storage);
    EXPECT_TRUE(accessor.Set("new value", &error));
    accessor.Clear(&error);
    EXPECT_TRUE(error.IsSuccess());
    EXPECT_EQ(orig_value, *accessor.property_);
  }
}

TEST(PropertyAccessorTest, ByteArrayCorrectness) {
  ByteArray byte_array;
  {
    Error error;
    ByteArray orig_byte_array = byte_array;
    ByteArrayAccessor accessor(new PropertyAccessor<ByteArray>(&byte_array));
    EXPECT_EQ(byte_array, accessor->Get(&error));

    ByteArray expected_byte_array({0x01, 0x7F, 0x80, 0xFF});
    EXPECT_TRUE(accessor->Set(expected_byte_array, &error));
    EXPECT_TRUE(error.IsSuccess());
    EXPECT_EQ(expected_byte_array, accessor->Get(&error));

    // Resetting to the same value should return false, but without
    // an error.
    EXPECT_FALSE(accessor->Set(expected_byte_array, &error));
    EXPECT_TRUE(error.IsSuccess());

    accessor->Clear(&error);
    EXPECT_TRUE(error.IsSuccess());
    EXPECT_EQ(orig_byte_array, accessor->Get(&error));

    byte_array = ByteArray({0xFF, 0x7F, 0x80, 0x00});
    EXPECT_EQ(byte_array, accessor->Get(&error));
  }
  {
    Error error;
    ByteArrayAccessor accessor(
        new ConstPropertyAccessor<ByteArray>(&byte_array));
    EXPECT_EQ(byte_array, accessor->Get(&error));

    ByteArray expected_byte_array({0x01, 0x7F, 0x80, 0xFF});
    EXPECT_FALSE(accessor->Set(expected_byte_array, &error));
    ASSERT_FALSE(error.IsSuccess());
    EXPECT_EQ(Error::kInvalidArguments, error.type());
    EXPECT_EQ(byte_array, accessor->Get(&error));

    byte_array = ByteArray({0xFF, 0x7F, 0x80, 0x00});
    EXPECT_EQ(byte_array, accessor->Get(&error));
  }
  {
    Error error;
    ByteArrayAccessor accessor(
        new ConstPropertyAccessor<ByteArray>(&byte_array));
    accessor->Clear(&error);
    ASSERT_FALSE(error.IsSuccess());
  }
  {
    Error error;
    ByteArrayAccessor accessor(
        new WriteOnlyPropertyAccessor<ByteArray>(&byte_array));
    accessor->Get(&error);
    EXPECT_TRUE(error.IsFailure());
    EXPECT_EQ(Error::kPermissionDenied, error.type());
  }
  {
    Error error;
    ByteArray expected_byte_array({0x01, 0x7F, 0x80, 0xFF});
    WriteOnlyPropertyAccessor<ByteArray> accessor(&byte_array);

    EXPECT_TRUE(accessor.Set(expected_byte_array, &error));
    EXPECT_TRUE(error.IsSuccess());
    EXPECT_EQ(expected_byte_array, *accessor.property_);

    // Resetting to the same value should return false, but without
    // an error.
    EXPECT_FALSE(accessor.Set(expected_byte_array, &error));
    EXPECT_TRUE(error.IsSuccess());

    // As a write-only, the value can't be read.
    EXPECT_EQ(ByteArray(), accessor.Get(&error));
    EXPECT_FALSE(error.IsSuccess());

    byte_array = ByteArray({0xFF, 0x7F, 0x80, 0x00});
    EXPECT_EQ(ByteArray({0xFF, 0x7F, 0x80, 0x00}), *accessor.property_);
  }
  {
    Error error;
    ByteArray orig_byte_array = byte_array =
        ByteArray({0x00, 0x7F, 0x80, 0xFF});
    WriteOnlyPropertyAccessor<ByteArray> accessor(&byte_array);

    EXPECT_TRUE(accessor.Set(ByteArray({0xFF, 0x7F, 0x80, 0x00}), &error));
    accessor.Clear(&error);
    EXPECT_TRUE(error.IsSuccess());
    EXPECT_EQ(orig_byte_array, *accessor.property_);
  }
}

class StringWrapper {
 public:
  std::string Get(Error* /*error*/) { return value_; }
  std::string ConstGet(Error* /*error*/) const { return value_; }
  bool Set(const std::string& value, Error* /*error*/) {
    if (value_ == value) {
      return false;
    }
    value_ = value;
    return true;
  }
  void Clear(Error* /*error*/) { value_.clear(); }

  std::string value_;
};

TEST(PropertyAccessorTest, CustomAccessorCorrectness) {
  StringWrapper wrapper;
  {
    // Custom accessor: read, write, write-same, clear, read-updated.
    // Together, write and write-same verify that the CustomAccessor
    // template passes through the value from the called function.
    Error error;
    const std::string orig_value = wrapper.value_ = "original value";
    CustomAccessor<StringWrapper, std::string> accessor(
        &wrapper, &StringWrapper::Get, &StringWrapper::Set);
    EXPECT_EQ(orig_value, accessor.Get(&error));
    EXPECT_TRUE(error.IsSuccess());

    const std::string expected_string = "new value";
    EXPECT_TRUE(accessor.Set(expected_string, &error));
    EXPECT_TRUE(error.IsSuccess());
    EXPECT_EQ(expected_string, accessor.Get(&error));
    // Set to same value.
    EXPECT_FALSE(accessor.Set(expected_string, &error));
    EXPECT_TRUE(error.IsSuccess());

    accessor.Clear(&error);
    EXPECT_TRUE(error.IsSuccess());
    EXPECT_EQ(orig_value, accessor.Get(&error));

    wrapper.value_ = "nooooo";
    EXPECT_EQ(wrapper.value_, accessor.Get(&error));
  }
  {
    // Custom read-only accessor: read, write, read-updated.
    Error error;
    CustomAccessor<StringWrapper, std::string> accessor(
        &wrapper, &StringWrapper::Get, nullptr);
    EXPECT_EQ(wrapper.value_, accessor.Get(&error));

    const std::string expected_string = "what";
    EXPECT_FALSE(accessor.Set(expected_string, &error));
    ASSERT_FALSE(error.IsSuccess());
    EXPECT_EQ(Error::kInvalidArguments, error.type());
    EXPECT_EQ(wrapper.value_, accessor.Get(&error));

    wrapper.value_ = "nooooo";
    EXPECT_EQ(wrapper.value_, accessor.Get(&error));
  }
  {
    // Custom read-only accessor: clear.
    Error error;
    CustomAccessor<StringWrapper, std::string> accessor(
        &wrapper, &StringWrapper::Get, nullptr);
    accessor.Clear(&error);
    ASSERT_FALSE(error.IsSuccess());
  }
  {
    // Custom read-only accessor with custom clear method.
    Error error;
    CustomAccessor<StringWrapper, std::string> accessor(
        &wrapper, &StringWrapper::Get, nullptr, &StringWrapper::Clear);
    wrapper.value_ = "empty this";
    accessor.Clear(&error);
    ASSERT_TRUE(error.IsSuccess());
    EXPECT_TRUE(wrapper.value_.empty());
  }
}

TEST(PropertyAccessorTest, CustomWriteOnlyAccessorWithDefault) {
  StringWrapper wrapper;
  {
    // Test reading.
    Error error;
    const std::string default_value = "default value";
    CustomWriteOnlyAccessor<StringWrapper, std::string> accessor(
        &wrapper, &StringWrapper::Set, nullptr, &default_value);
    wrapper.value_ = "can't read this";
    EXPECT_EQ(std::string(), accessor.Get(&error));
    EXPECT_TRUE(error.IsFailure());
    EXPECT_EQ(Error::kPermissionDenied, error.type());
  }
  {
    // Test writing.
    Error error;
    const std::string default_value = "default value";
    const std::string expected_string = "what";
    CustomWriteOnlyAccessor<StringWrapper, std::string> accessor(
        &wrapper, &StringWrapper::Set, nullptr, &default_value);
    EXPECT_TRUE(accessor.Set(expected_string, &error));
    EXPECT_TRUE(error.IsSuccess());
    EXPECT_EQ(expected_string, wrapper.value_);
    // Set to same value. With the above, this verifies that the
    // CustomWriteOnlyAccessor template passes through the return
    // value.
    EXPECT_FALSE(accessor.Set(expected_string, &error));
    EXPECT_TRUE(error.IsSuccess());
  }
  {
    // Test clearing.
    Error error;
    const std::string default_value = "default value";
    CustomWriteOnlyAccessor<StringWrapper, std::string> accessor(
        &wrapper, &StringWrapper::Set, nullptr, &default_value);
    accessor.Set("new value", &error);
    EXPECT_EQ("new value", wrapper.value_);
    accessor.Clear(&error);
    EXPECT_TRUE(error.IsSuccess());
    EXPECT_EQ(default_value, wrapper.value_);
  }
}

TEST(PropertyAccessorTest, CustomWriteOnlyAccessorWithClear) {
  StringWrapper wrapper;
  {
    // Test reading.
    Error error;
    CustomWriteOnlyAccessor<StringWrapper, std::string> accessor(
        &wrapper, &StringWrapper::Set, &StringWrapper::Clear, nullptr);
    wrapper.value_ = "can't read this";
    EXPECT_EQ(std::string(), accessor.Get(&error));
    EXPECT_TRUE(error.IsFailure());
    EXPECT_EQ(Error::kPermissionDenied, error.type());
  }
  {
    // Test writing.
    Error error;
    const std::string expected_string = "what";
    CustomWriteOnlyAccessor<StringWrapper, std::string> accessor(
        &wrapper, &StringWrapper::Set, &StringWrapper::Clear, nullptr);
    EXPECT_TRUE(accessor.Set(expected_string, &error));
    EXPECT_TRUE(error.IsSuccess());
    EXPECT_EQ(expected_string, wrapper.value_);
    // Set to same value. With the above, this verifies that the
    // CustomWriteOnlyAccessor template passes through the return
    // value.
    EXPECT_FALSE(accessor.Set(expected_string, &error));
    EXPECT_TRUE(error.IsSuccess());
  }
  {
    // Test clearing.
    Error error;
    CustomWriteOnlyAccessor<StringWrapper, std::string> accessor(
        &wrapper, &StringWrapper::Set, &StringWrapper::Clear, nullptr);
    EXPECT_TRUE(accessor.Set("new value", &error));
    EXPECT_EQ("new value", wrapper.value_);
    accessor.Clear(&error);
    EXPECT_TRUE(error.IsSuccess());
    EXPECT_EQ("", wrapper.value_);
  }
}

TEST(PropertyAccessorTest, CustomReadOnlyAccessor) {
  StringWrapper wrapper;
  CustomReadOnlyAccessor<StringWrapper, std::string> accessor(
      &wrapper, &StringWrapper::ConstGet);
  const std::string orig_value = wrapper.value_ = "original value";
  {
    // Test reading.
    Error error;
    EXPECT_EQ(orig_value, accessor.Get(&error));
    EXPECT_TRUE(error.IsSuccess());
  }
  {
    // Test writing.
    Error error;
    EXPECT_FALSE(accessor.Set("new value", &error));
    EXPECT_EQ(Error::kInvalidArguments, error.type());
    EXPECT_EQ(orig_value, accessor.Get(&error));
  }
  {
    // Test writing original value -- this also fails.
    Error error;
    EXPECT_FALSE(accessor.Set(orig_value, &error));
    EXPECT_EQ(Error::kInvalidArguments, error.type());
    EXPECT_EQ(orig_value, accessor.Get(&error));
  }
  {
    // Test clearing.
    Error error;
    accessor.Clear(&error);
    EXPECT_EQ(Error::kInvalidArguments, error.type());
    EXPECT_EQ(orig_value, accessor.Get(&error));
  }
}

class StringMapWrapper {
 public:
  void Clear(const std::string& key, Error* /*error*/) { value_.erase(key); }
  std::string Get(const std::string& key, Error* /*error*/) {
    EXPECT_TRUE(base::Contains(value_, key));
    return value_[key];
  }
  bool Set(const std::string& key, const std::string& value, Error* /*error*/) {
    if (value_[key] == value) {
      return false;
    }
    value_[key] = value;
    return true;
  }

  std::map<std::string, std::string> value_;
};

TEST(PropertyAccessorTest, CustomMappedAccessor) {
  const std::string kKey = "entry_key";
  const std::string kValue = "entry_value";
  {
    // Test reading.
    StringMapWrapper wrapper;
    CustomMappedAccessor<StringMapWrapper, std::string, std::string> accessor(
        &wrapper, &StringMapWrapper::Clear, &StringMapWrapper::Get,
        &StringMapWrapper::Set, kKey);
    wrapper.value_[kKey] = kValue;
    Error error;
    EXPECT_EQ(kValue, accessor.Get(&error));
    EXPECT_TRUE(error.IsSuccess());
  }
  {
    // Test writing.
    StringMapWrapper wrapper;
    CustomMappedAccessor<StringMapWrapper, std::string, std::string> accessor(
        &wrapper, &StringMapWrapper::Clear, &StringMapWrapper::Get,
        &StringMapWrapper::Set, kKey);
    Error error;
    EXPECT_TRUE(accessor.Set(kValue, &error));
    EXPECT_TRUE(error.IsSuccess());
    EXPECT_EQ(kValue, wrapper.value_[kKey]);
    // Set to same value. With the above, this verifies that the
    // CustomMappedAccessor template passes through the return
    // value.
    EXPECT_FALSE(accessor.Set(kValue, &error));
    EXPECT_TRUE(error.IsSuccess());
  }
  {
    // Test clearing.
    StringMapWrapper wrapper;
    CustomMappedAccessor<StringMapWrapper, std::string, std::string> accessor(
        &wrapper, &StringMapWrapper::Clear, &StringMapWrapper::Get,
        &StringMapWrapper::Set, kKey);
    wrapper.value_[kKey] = kValue;
    Error error;
    accessor.Clear(&error);
    EXPECT_TRUE(error.IsSuccess());
    EXPECT_FALSE(base::Contains(wrapper.value_, kKey));
  }
}

}  // namespace shill
