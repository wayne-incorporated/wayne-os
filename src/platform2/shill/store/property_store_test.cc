// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/store/property_store_test.h"

#include <string>
#include <utility>
#include <vector>

#include <chromeos/dbus/service_constants.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "shill/error.h"
#include "shill/event_dispatcher.h"
#include "shill/manager.h"
#include "shill/mock_control.h"
#include "shill/store/property_accessor.h"
#include "shill/store/property_store.h"

using ::testing::_;
using ::testing::Return;
using ::testing::Values;

namespace shill {

// static
const brillo::Any PropertyStoreTest::kBoolV = brillo::Any(false);
// static
const brillo::Any PropertyStoreTest::kByteV = brillo::Any(uint8_t(0));
// static
const brillo::Any PropertyStoreTest::kInt16V = brillo::Any(int16_t(0));
// static
const brillo::Any PropertyStoreTest::kInt32V = brillo::Any(int32_t(0));
// static
const brillo::Any PropertyStoreTest::kKeyValueStoreV =
    brillo::Any(brillo::VariantDictionary());
// static
const brillo::Any PropertyStoreTest::kStringV = brillo::Any(std::string());
// static
const brillo::Any PropertyStoreTest::kStringmapV = brillo::Any(Stringmap());
// static
const brillo::Any PropertyStoreTest::kStringmapsV = brillo::Any(Stringmaps());
// static
const brillo::Any PropertyStoreTest::kStringsV = brillo::Any(Strings());
// static
const brillo::Any PropertyStoreTest::kUint16V = brillo::Any(uint16_t(0));
// static
const brillo::Any PropertyStoreTest::kUint16sV = brillo::Any(Uint16s());
// static
const brillo::Any PropertyStoreTest::kUint32V = brillo::Any(uint32_t(0));
// static
const brillo::Any PropertyStoreTest::kUint64V = brillo::Any(uint64_t(0));

PropertyStoreTest::PropertyStoreTest()
    : internal_error_(kErrorResultInternalError),
      invalid_args_(kErrorResultInvalidArguments),
      invalid_prop_(kErrorResultInvalidProperty),
      path_(dir_.CreateUniqueTempDir() ? dir_.GetPath().value() : ""),
      manager_(control_interface(),
               dispatcher(),
               metrics(),
               run_path(),
               storage_path(),
               std::string()) {}

PropertyStoreTest::~PropertyStoreTest() = default;

void PropertyStoreTest::SetUp() {
  ASSERT_FALSE(run_path().empty());
  ASSERT_FALSE(storage_path().empty());
}

TEST_P(PropertyStoreTest, SetPropertyNonexistent) {
  // Ensure that an attempt to write unknown properties returns
  // InvalidProperty, and does not yield a PropertyChange callback.
  PropertyStore store(base::BindRepeating(&PropertyStoreTest::TestCallback,
                                          base::Unretained(this)));
  Error error;
  EXPECT_CALL(*this, TestCallback(_)).Times(0);
  store.SetAnyProperty("", GetParam(), &error);
  EXPECT_EQ(Error::kInvalidProperty, error.type());
}

INSTANTIATE_TEST_SUITE_P(PropertyStoreTestInstance,
                         PropertyStoreTest,
                         Values(PropertyStoreTest::kBoolV,
                                PropertyStoreTest::kByteV,
                                PropertyStoreTest::kInt16V,
                                PropertyStoreTest::kInt32V,
                                PropertyStoreTest::kStringV,
                                PropertyStoreTest::kStringmapV,
                                PropertyStoreTest::kStringmapsV,
                                PropertyStoreTest::kStringsV,
                                PropertyStoreTest::kUint16V,
                                PropertyStoreTest::kUint16sV,
                                PropertyStoreTest::kUint32V,
                                PropertyStoreTest::kUint64V));

template <typename T>
class PropertyStoreTypedTest : public PropertyStoreTest {
 protected:
  void SetProperty(PropertyStore* store, const std::string& name, Error* error);
};

TYPED_TEST_SUITE(PropertyStoreTypedTest, PropertyStoreTest::PropertyTypes);

TYPED_TEST(PropertyStoreTypedTest, RegisterProperty) {
  PropertyStore store(base::BindRepeating(&PropertyStoreTest::TestCallback,
                                          base::Unretained(this)));
  Error error;
  TypeParam property{};  // value-initialize primitives
  PropertyStoreTest::RegisterProperty(&store, "some property", &property);
  EXPECT_TRUE(store.Contains("some property"));
}

TYPED_TEST(PropertyStoreTypedTest, GetProperty) {
  PropertyStore store(base::BindRepeating(&PropertyStoreTest::TestCallback,
                                          base::Unretained(this)));
  Error error;
  TypeParam property{};  // value-initialize primitives
  PropertyStoreTest::RegisterProperty(&store, "some property", &property);

  TypeParam read_value;
  EXPECT_CALL(*this, TestCallback(_)).Times(0);
  EXPECT_TRUE(PropertyStoreTest::GetProperty(store, "some property",
                                             &read_value, &error));
  EXPECT_EQ(property, read_value);
}

TYPED_TEST(PropertyStoreTypedTest, ClearProperty) {
  PropertyStore store(base::BindRepeating(&PropertyStoreTest::TestCallback,
                                          base::Unretained(this)));
  Error error;
  TypeParam property{};  // value-initialize primitives
  PropertyStoreTest::RegisterProperty(&store, "some property", &property);
  EXPECT_CALL(*this, TestCallback(_));
  EXPECT_TRUE(store.ClearProperty("some property", &error));
}

TYPED_TEST(PropertyStoreTypedTest, SetProperty) {
  PropertyStore store(base::BindRepeating(&PropertyStoreTest::TestCallback,
                                          base::Unretained(this)));
  Error error;
  TypeParam property{};  // value-initialize primitives
  PropertyStoreTest::RegisterProperty(&store, "some property", &property);

  // Change the value from the default (initialized above).  Should
  // generate a change callback. The second SetProperty, however,
  // should not. Hence, we should get exactly one callback.
  EXPECT_CALL(*this, TestCallback(_)).Times(1);
  this->SetProperty(&store, "some property", &error);
  EXPECT_TRUE(error.IsSuccess());
  this->SetProperty(&store, "some property", &error);
  EXPECT_TRUE(error.IsSuccess());
}

template <>
void PropertyStoreTypedTest<bool>::SetProperty(PropertyStore* store,
                                               const std::string& name,
                                               Error* error) {
  bool new_value = true;
  store->SetBoolProperty(name, new_value, error);
}

template <>
void PropertyStoreTypedTest<int16_t>::SetProperty(PropertyStore* store,
                                                  const std::string& name,
                                                  Error* error) {
  int16_t new_value = 1;
  store->SetInt16Property(name, new_value, error);
}

template <>
void PropertyStoreTypedTest<int32_t>::SetProperty(PropertyStore* store,
                                                  const std::string& name,
                                                  Error* error) {
  int32_t new_value = 1;
  store->SetInt32Property(name, new_value, error);
}

template <>
void PropertyStoreTypedTest<std::string>::SetProperty(PropertyStore* store,
                                                      const std::string& name,
                                                      Error* error) {
  std::string new_value = "new value";
  store->SetStringProperty(name, new_value, error);
}

template <>
void PropertyStoreTypedTest<Stringmap>::SetProperty(PropertyStore* store,
                                                    const std::string& name,
                                                    Error* error) {
  Stringmap new_value;
  new_value["new key"] = "new value";
  store->SetStringmapProperty(name, new_value, error);
}

template <>
void PropertyStoreTypedTest<Stringmaps>::SetProperty(PropertyStore* store,
                                                     const std::string& name,
                                                     Error* error) {
  Stringmaps new_value(1);
  new_value[0]["new key"] = "new value";
  store->SetStringmapsProperty(name, new_value, error);
}

template <>
void PropertyStoreTypedTest<Strings>::SetProperty(PropertyStore* store,
                                                  const std::string& name,
                                                  Error* error) {
  Strings new_value(1);
  new_value[0] = "new value";
  store->SetStringsProperty(name, new_value, error);
}

template <>
void PropertyStoreTypedTest<uint8_t>::SetProperty(PropertyStore* store,
                                                  const std::string& name,
                                                  Error* error) {
  uint8_t new_value = 1;
  store->SetUint8Property(name, new_value, error);
}

template <>
void PropertyStoreTypedTest<uint16_t>::SetProperty(PropertyStore* store,
                                                   const std::string& name,
                                                   Error* error) {
  uint16_t new_value = 1;
  store->SetUint16Property(name, new_value, error);
}

template <>
void PropertyStoreTypedTest<Uint16s>::SetProperty(PropertyStore* store,
                                                  const std::string& name,
                                                  Error* error) {
  Uint16s new_value{1};
  store->SetUint16sProperty(name, new_value, error);
}

template <>
void PropertyStoreTypedTest<uint32_t>::SetProperty(PropertyStore* store,
                                                   const std::string& name,
                                                   Error* error) {
  uint32_t new_value = 1;
  store->SetUint32Property(name, new_value, error);
}

TEST_F(PropertyStoreTest, ClearBoolProperty) {
  // We exercise both possibilities for the default value here,
  // to ensure that Clear actually resets the property based on
  // the property's initial value (rather than the language's
  // default value for the type).
  for (bool default_value : {true, false}) {
    PropertyStore store;
    Error error;

    bool flag = default_value;
    store.RegisterBool("some bool", &flag);

    EXPECT_TRUE(store.ClearProperty("some bool", &error));
    EXPECT_EQ(default_value, flag);
  }
}

TEST_F(PropertyStoreTest, ClearPropertyNonexistent) {
  PropertyStore store(base::BindRepeating(&PropertyStoreTest::TestCallback,
                                          base::Unretained(this)));
  Error error;

  EXPECT_CALL(*this, TestCallback(_)).Times(0);
  EXPECT_FALSE(store.ClearProperty("", &error));
  EXPECT_EQ(Error::kInvalidProperty, error.type());
}

// KeyValueStoreProperty is only defined for derived types so handle
// this case manually here.
TEST_F(PropertyStoreTest, KeyValueStorePropertyNonExistent) {
  PropertyStore store(base::BindRepeating(&PropertyStoreTest::TestCallback,
                                          base::Unretained(this)));
  Error error;
  EXPECT_CALL(*this, TestCallback(_)).Times(0);
  store.SetAnyProperty("", PropertyStoreTest::kKeyValueStoreV, &error);
  EXPECT_EQ(Error::kInvalidProperty, error.type());
}

TEST_F(PropertyStoreTest, KeyValueStoreProperty) {
  PropertyStore store(base::BindRepeating(&PropertyStoreTest::TestCallback,
                                          base::Unretained(this)));
  const char kKey[] = "key";
  EXPECT_CALL(*this, GetKeyValueStoreCallback(_))
      .WillOnce(Return(KeyValueStore()));
  store.RegisterDerivedKeyValueStore(
      kKey, KeyValueStoreAccessor(
                new CustomAccessor<PropertyStoreTest, KeyValueStore>(
                    this, &PropertyStoreTest::GetKeyValueStoreCallback,
                    &PropertyStoreTest::SetKeyValueStoreCallback)));
  EXPECT_CALL(*this, TestCallback(_));
  EXPECT_CALL(*this, SetKeyValueStoreCallback(_, _)).WillOnce(Return(true));
  Error error;
  store.SetAnyProperty(kKey, kKeyValueStoreV, &error);
  EXPECT_TRUE(error.IsSuccess());
}

TEST_F(PropertyStoreTest, WriteOnlyProperties) {
  // Test that properties registered as write-only are not returned
  // when using GetProperties().
  PropertyStore store;

  bool bool_wo = true;
  int16_t int16_wo = 1;
  int32_t int32_wo = 2;
  uint8_t uint8_wo = 3;
  uint16_t uint16_wo = 4;
  std::string string_wo = "foobar";
  std::vector<std::string> strings_wo = {"foo", "bar"};
  std::map<std::string, std::string> stringmap_wo = {{"k1", "x1"},
                                                     {"k2", "x2"}};
  std::vector<std::map<std::string, std::string>> stringmaps_wo = {
      {{"k11", "x1"}, {"k12", "x2"}}, {{"k21", "x3"}, {"k22", "x4"}}};
  store.RegisterWriteOnlyBool("bool_wo", &bool_wo);
  store.RegisterWriteOnlyInt16("int16_wo", &int16_wo);
  store.RegisterWriteOnlyInt32("int32_wo", &int32_wo);
  store.RegisterWriteOnlyUint8("uint8_wo", &uint8_wo);
  store.RegisterWriteOnlyUint16("uint16_wo", &uint16_wo);
  store.RegisterWriteOnlyString("string_wo", &string_wo);
  store.RegisterWriteOnlyStrings("strings_wo", &strings_wo);
  store.RegisterWriteOnlyStringmap("stringmap_wo", &stringmap_wo);
  store.RegisterWriteOnlyStringmaps("stringmaps_wo", &stringmaps_wo);

  bool bool_v = false;
  int16_t int16_v = 101;
  int32_t int32_v = 102;
  uint8_t uint8_v = 103;
  uint16_t uint16_v = 104;
  std::string string_v = "barfoo";
  std::vector<std::string> strings_v = {"bar", "foo"};
  std::map<std::string, std::string> stringmap_v = {{"q1", "y1"}, {"q2", "y2"}};
  std::vector<std::map<std::string, std::string>> stringmaps_v = {
      {{"q11", "y1"}, {"q12", "y2"}}, {{"q21", "y3"}, {"q22", "y4"}}};
  store.RegisterBool("bool", &bool_v);
  store.RegisterInt16("int16", &int16_v);
  store.RegisterInt32("int32", &int32_v);
  store.RegisterUint8("uint8", &uint8_v);
  store.RegisterUint16("uint16", &uint16_v);
  store.RegisterString("string", &string_v);
  store.RegisterStrings("strings", &strings_v);
  store.RegisterStringmap("stringmap", &stringmap_v);
  store.RegisterStringmaps("stringmaps", &stringmaps_v);

  brillo::VariantDictionary properties;
  store.GetProperties(&properties, nullptr);

  ASSERT_EQ(properties.find("bool_wo"), properties.end());
  ASSERT_EQ(properties.find("int16_wo"), properties.end());
  ASSERT_EQ(properties.find("int32_wo"), properties.end());
  ASSERT_EQ(properties.find("uint8_wo"), properties.end());
  ASSERT_EQ(properties.find("uint16_wo"), properties.end());
  ASSERT_EQ(properties.find("string_wo"), properties.end());
  ASSERT_EQ(properties.find("strings_wo"), properties.end());
  ASSERT_EQ(properties.find("stringmap_wo"), properties.end());
  ASSERT_EQ(properties.find("stringmaps_wo"), properties.end());

  ASSERT_NE(properties.find("bool"), properties.end());
  ASSERT_NE(properties.find("int16"), properties.end());
  ASSERT_NE(properties.find("int32"), properties.end());
  ASSERT_NE(properties.find("uint8"), properties.end());
  ASSERT_NE(properties.find("uint16"), properties.end());
  ASSERT_NE(properties.find("string"), properties.end());
  ASSERT_NE(properties.find("strings"), properties.end());
  ASSERT_NE(properties.find("stringmap"), properties.end());
  ASSERT_NE(properties.find("stringmaps"), properties.end());

  ASSERT_EQ(properties["bool"].Get<bool>(), bool_v);
  ASSERT_EQ(properties["int16"].Get<int16_t>(), int16_v);
  ASSERT_EQ(properties["int32"].Get<int32_t>(), int32_v);
  ASSERT_EQ(properties["uint8"].Get<uint8_t>(), uint8_v);
  ASSERT_EQ(properties["uint16"].Get<uint16_t>(), uint16_v);
  ASSERT_EQ(properties["string"].Get<std::string>(), string_v);
  ASSERT_EQ(properties["strings"].Get<Strings>(), strings_v);
  ASSERT_EQ(properties["stringmap"].Get<Stringmap>(), stringmap_v);
  ASSERT_EQ(properties["stringmaps"].Get<Stringmaps>(), stringmaps_v);
}

TEST_F(PropertyStoreTest, SetAnyProperty) {
  // Test that registered properties can be set using brillo::Any variant
  // type.
  PropertyStore store;
  {
    // Register property value.
    const std::string key = "boolp";
    bool value = true;
    store.RegisterBool(key, &value);

    // Verify property value.
    bool test_value;
    Error error;
    EXPECT_TRUE(store.GetBoolProperty(key, &test_value, &error));
    EXPECT_EQ(value, test_value);

    // Set property using brillo::Any variant type.
    bool new_value = false;
    store.SetAnyProperty(key, brillo::Any(new_value), &error);
    EXPECT_TRUE(error.IsSuccess());
    EXPECT_TRUE(store.GetBoolProperty(key, &test_value, &error));
    EXPECT_EQ(new_value, test_value);
  }
  {
    // Register property value.
    const std::string key = "int16p";
    int16_t value = 127;
    store.RegisterInt16(key, &value);

    // Verify property value.
    int16_t test_value;
    Error error;
    EXPECT_TRUE(store.GetInt16Property(key, &test_value, &error));
    EXPECT_EQ(value, test_value);

    // Set property using brillo::Any variant type.
    int16_t new_value = 128;
    store.SetAnyProperty(key, brillo::Any(new_value), &error);
    EXPECT_TRUE(error.IsSuccess());
    EXPECT_TRUE(store.GetInt16Property(key, &test_value, &error));
    EXPECT_EQ(new_value, test_value);
  }
  {
    // Register property value.
    const std::string key = "int32p";
    int32_t value = 127;
    store.RegisterInt32(key, &value);

    // Verify property value.
    int32_t test_value;
    Error error;
    EXPECT_TRUE(store.GetInt32Property(key, &test_value, &error));
    EXPECT_EQ(value, test_value);

    // Set property using brillo::Any variant type.
    int32_t new_value = 128;
    store.SetAnyProperty(key, brillo::Any(new_value), &error);
    EXPECT_TRUE(error.IsSuccess());
    EXPECT_TRUE(store.GetInt32Property(key, &test_value, &error));
    EXPECT_EQ(new_value, test_value);
  }
  {
    // Register property value.
    const std::string key = "stringp";
    std::string value = "noooo";
    store.RegisterString(key, &value);

    // Verify property value.
    std::string test_value;
    Error error;
    EXPECT_TRUE(store.GetStringProperty(key, &test_value, &error));
    EXPECT_EQ(value, test_value);

    // Set property using brillo::Any variant type.
    std::string new_value = "yesss";
    store.SetAnyProperty(key, brillo::Any(new_value), &error);
    EXPECT_TRUE(error.IsSuccess());
    EXPECT_TRUE(store.GetStringProperty(key, &test_value, &error));
    EXPECT_EQ(new_value, test_value);
  }
  {
    // Register property value.
    const std::string key = "stringmapp";
    Stringmap value;
    value["noooo"] = "yesss";
    store.RegisterStringmap(key, &value);

    // Verify property value.
    Stringmap test_value;
    Error error;
    EXPECT_TRUE(store.GetStringmapProperty(key, &test_value, &error));
    EXPECT_TRUE(value == test_value);

    // Set property using brillo::Any variant type.
    Stringmap new_value;
    new_value["yesss"] = "noooo";
    store.SetAnyProperty(key, brillo::Any(new_value), &error);
    EXPECT_TRUE(error.IsSuccess());
    EXPECT_TRUE(store.GetStringmapProperty(key, &test_value, &error));
    EXPECT_TRUE(new_value == test_value);
  }
  {
    // Register property value.
    const std::string key = "stringmapsp";
    Stringmaps value(1);
    value[0]["noooo"] = "yesss";
    store.RegisterStringmaps(key, &value);

    // Verify property value.
    Stringmaps test_value;
    Error error;
    EXPECT_TRUE(store.GetStringmapsProperty(key, &test_value, &error));
    EXPECT_TRUE(value == test_value);

    // Set property using brillo::Any variant type.
    Stringmaps new_value(1);
    new_value[0]["yesss"] = "noooo";
    store.SetAnyProperty(key, brillo::Any(new_value), &error);
    EXPECT_TRUE(error.IsSuccess());
    EXPECT_TRUE(store.GetStringmapsProperty(key, &test_value, &error));
    EXPECT_TRUE(new_value == test_value);
  }
  {
    // Register property value.
    const std::string key = "stringsp";
    Strings value;
    std::string element;
    element = "noooo";
    value.push_back(element);
    store.RegisterStrings(key, &value);

    // Verify property value.
    Strings test_value;
    Error error;
    EXPECT_TRUE(store.GetStringsProperty(key, &test_value, &error));
    EXPECT_TRUE(value == test_value);

    // Set property using brillo::Any variant type.
    Strings new_value;
    std::string new_element;
    new_element = "yesss";
    new_value.push_back(new_element);
    store.SetAnyProperty(key, brillo::Any(new_value), &error);
    EXPECT_TRUE(error.IsSuccess());
    EXPECT_TRUE(store.GetStringsProperty(key, &test_value, &error));
    EXPECT_TRUE(new_value == test_value);
  }
  {
    // Register property value.
    const std::string key = "uint8p";
    uint8_t value = 127;
    store.RegisterUint8(key, &value);

    // Verify property value.
    uint8_t test_value;
    Error error;
    EXPECT_TRUE(store.GetUint8Property(key, &test_value, &error));
    EXPECT_EQ(value, test_value);

    // Set property using brillo::Any variant type.
    uint8_t new_value = 128;
    store.SetAnyProperty(key, brillo::Any(new_value), &error);
    EXPECT_TRUE(error.IsSuccess());
    EXPECT_TRUE(store.GetUint8Property(key, &test_value, &error));
    EXPECT_EQ(new_value, test_value);
  }
  {
    // Register property value.
    const std::string key = "uint16p";
    uint16_t value = 127;
    store.RegisterUint16(key, &value);

    // Verify property value.
    uint16_t test_value;
    Error error;
    EXPECT_TRUE(store.GetUint16Property(key, &test_value, &error));
    EXPECT_EQ(value, test_value);

    // Set property using brillo::Any variant type.
    uint16_t new_value = 128;
    store.SetAnyProperty(key, brillo::Any(new_value), &error);
    EXPECT_TRUE(error.IsSuccess());
    EXPECT_TRUE(store.GetUint16Property(key, &test_value, &error));
    EXPECT_EQ(new_value, test_value);
  }
  {
    // Register property value.
    const std::string key = "uint32p";
    uint32_t value = 127;
    store.RegisterUint32(key, &value);

    // Verify property value.
    uint32_t test_value;
    Error error;
    EXPECT_TRUE(store.GetUint32Property(key, &test_value, &error));
    EXPECT_EQ(value, test_value);

    // Set property using brillo::Any variant type.
    uint32_t new_value = 128;
    store.SetAnyProperty(key, brillo::Any(new_value), &error);
    EXPECT_TRUE(error.IsSuccess());
    EXPECT_TRUE(store.GetUint32Property(key, &test_value, &error));
    EXPECT_EQ(new_value, test_value);
  }
}

TEST_F(PropertyStoreTest, SetAnyPropertyKeyValueStore) {
  PropertyStore store;

  // Register property value.
  const std::string key = "key_value_store";
  const bool bool_value = true;
  const std::string string_value = "string1";
  KeyValueStore value;
  value.Set("bool_key", bool_value);
  value.Set("string_key", string_value);
  store.RegisterKeyValueStore(key, &value);

  // Verify property value.
  KeyValueStore test_value;
  Error error;
  EXPECT_TRUE(store.GetKeyValueStoreProperty(key, &test_value, &error));
  EXPECT_EQ(value, test_value);

  // Set property using brillo::Any variant type. Note: This modifies value.
  const bool new_bool_value = false;
  const std::string new_string_value = "string2";
  brillo::VariantDictionary new_value;
  new_value["bool_key"] = new_bool_value;
  new_value["string_key"] = new_string_value;
  store.SetAnyProperty(key, brillo::Any(new_value), &error);
  EXPECT_TRUE(error.IsSuccess());
  test_value.Clear();
  EXPECT_TRUE(store.GetKeyValueStoreProperty(key, &test_value, &error));
  KeyValueStore new_key_value_store =
      KeyValueStore::ConvertFromVariantDictionary(new_value);
  EXPECT_EQ(new_key_value_store, test_value);
}

TEST_F(PropertyStoreTest, SetAnyPropertyKeyValueStores) {
  PropertyStore store;

  // Register property value.
  const std::string key = "key_value_stores";
  const bool bool_value = true;
  const std::string string_value = "string1";
  KeyValueStores values;
  KeyValueStore value;
  value.Set("bool_key", bool_value);
  value.Set("string_key", string_value);
  values.push_back(value);
  store.RegisterKeyValueStores(key, &values);

  // Verify property value.
  KeyValueStores test_values;
  Error error;
  EXPECT_TRUE(store.GetKeyValueStoresProperty(key, &test_values, &error));
  EXPECT_EQ(values, test_values);

  // Set property using brillo::Any variant type. Note: This modifies values.
  std::vector<brillo::VariantDictionary> new_values;
  const bool new_bool_value = false;
  const std::string new_string_value = "string2";
  brillo::VariantDictionary new_value;
  new_value["bool_key"] = new_bool_value;
  new_value["string_key"] = new_string_value;
  new_values.push_back(new_value);
  store.SetAnyProperty(key, new_values, &error);
  EXPECT_TRUE(error.IsSuccess());
  test_values.clear();
  EXPECT_TRUE(store.GetKeyValueStoresProperty(key, &test_values, &error));
  EXPECT_EQ(test_values.size(), 1u);
  EXPECT_EQ(new_values[0], test_values[0].properties());
}

TEST_F(PropertyStoreTest, SetAndGetProperties) {
  PropertyStore store;

  // Register properties.
  const std::string kBoolKey = "boolp";
  const std::string kKeyValueStoreKey = "keyvaluestorep";
  const std::string kKeyValueStoresKey = "keyvaluestoresp";
  const std::string kInt16Key = "int16p";
  const std::string kInt32Key = "int32p";
  const std::string kStringKey = "stringp";
  const std::string kStringsKey = "stringsp";
  const std::string kStringmapKey = "stringmapp";
  const std::string kStringmapsKey = "stringmapsp";
  const std::string kUint8Key = "uint8p";
  const std::string kUint16Key = "uint16p";
  const std::string kUint32Key = "uint32p";
  bool bool_value = true;
  int16_t int16_value = 16;
  int32_t int32_value = 32;
  std::string string_value = "string";
  Stringmap stringmap_value;
  stringmap_value["noooo"] = "yesss";
  Stringmaps stringmaps_value(1);
  stringmaps_value[0]["noooo"] = "yesss";
  Strings strings_value;
  strings_value.push_back("yesss");
  uint8_t uint8_value = 8;
  uint16_t uint16_value = 16;
  uint32_t uint32_value = 32;

  store.RegisterBool(kBoolKey, &bool_value);
  store.RegisterInt16(kInt16Key, &int16_value);
  store.RegisterInt32(kInt32Key, &int32_value);
  store.RegisterString(kStringKey, &string_value);
  store.RegisterStrings(kStringsKey, &strings_value);
  store.RegisterStringmap(kStringmapKey, &stringmap_value);
  store.RegisterStringmaps(kStringmapsKey, &stringmaps_value);
  store.RegisterUint8(kUint8Key, &uint8_value);
  store.RegisterUint16(kUint16Key, &uint16_value);
  store.RegisterUint32(kUint32Key, &uint32_value);

  // Special handling for KeyValueStore property.
  EXPECT_CALL(*this, GetKeyValueStoreCallback(_))
      .WillOnce(Return(KeyValueStore()));
  store.RegisterDerivedKeyValueStore(
      kKeyValueStoreKey,
      KeyValueStoreAccessor(
          new CustomAccessor<PropertyStoreTest, KeyValueStore>(
              this, &PropertyStoreTest::GetKeyValueStoreCallback,
              &PropertyStoreTest::SetKeyValueStoreCallback)));

  // Special handling for KeyValueStores property.
  EXPECT_CALL(*this, GetKeyValueStoresCallback(_))
      .WillOnce(Return(KeyValueStores()));
  store.RegisterDerivedKeyValueStores(
      kKeyValueStoresKey,
      KeyValueStoresAccessor(
          new CustomAccessor<PropertyStoreTest, KeyValueStores>(
              this, &PropertyStoreTest::GetKeyValueStoresCallback,
              &PropertyStoreTest::SetKeyValueStoresCallback)));

  // Update properties.
  bool new_bool_value = false;
  brillo::VariantDictionary new_key_value_store_value;
  std::vector<brillo::VariantDictionary> new_key_value_stores_value;
  int16_t new_int16_value = 17;
  int32_t new_int32_value = 33;
  std::string new_string_value = "strings";
  Stringmap new_stringmap_value;
  new_stringmap_value["yesss"] = "noooo";
  Stringmaps new_stringmaps_value(1);
  new_stringmaps_value[0]["yesss"] = "noooo";
  Strings new_strings_value;
  new_strings_value.push_back("noooo");
  uint8_t new_uint8_value = 9;
  uint16_t new_uint16_value = 17;
  uint32_t new_uint32_value = 33;

  brillo::VariantDictionary dict;
  dict.insert(std::make_pair(kBoolKey, brillo::Any(new_bool_value)));
  dict.insert(std::make_pair(kKeyValueStoreKey,
                             brillo::Any(new_key_value_store_value)));
  dict.insert(std::make_pair(kKeyValueStoresKey,
                             brillo::Any(new_key_value_stores_value)));
  dict.insert(std::make_pair(kInt16Key, brillo::Any(new_int16_value)));
  dict.insert(std::make_pair(kInt32Key, brillo::Any(new_int32_value)));
  dict.insert(std::make_pair(kStringKey, brillo::Any(new_string_value)));
  dict.insert(std::make_pair(kStringmapKey, brillo::Any(new_stringmap_value)));
  dict.insert(
      std::make_pair(kStringmapsKey, brillo::Any(new_stringmaps_value)));
  dict.insert(std::make_pair(kStringsKey, brillo::Any(new_strings_value)));
  dict.insert(std::make_pair(kUint8Key, brillo::Any(new_uint8_value)));
  dict.insert(std::make_pair(kUint16Key, brillo::Any(new_uint16_value)));
  dict.insert(std::make_pair(kUint32Key, brillo::Any(new_uint32_value)));

  EXPECT_CALL(*this, SetKeyValueStoreCallback(_, _)).WillOnce(Return(true));
  EXPECT_CALL(*this, SetKeyValueStoresCallback(_, _)).WillOnce(Return(true));

  Error error;
  store.SetProperties(dict, &error);
  EXPECT_TRUE(error.IsSuccess());

  // Retrieve properties.
  EXPECT_CALL(*this, GetKeyValueStoreCallback(_))
      .WillOnce(Return(KeyValueStore()));
  EXPECT_CALL(*this, GetKeyValueStoresCallback(_))
      .WillOnce(Return(KeyValueStores()));

  brillo::VariantDictionary result_dict;
  EXPECT_TRUE(store.GetProperties(&result_dict, &error));

  // Verify property values.
  EXPECT_EQ(new_bool_value, result_dict[kBoolKey].Get<bool>());
  EXPECT_EQ(new_int16_value, result_dict[kInt16Key].Get<int16_t>());
  EXPECT_EQ(new_int32_value, result_dict[kInt32Key].Get<int32_t>());
  EXPECT_EQ(new_string_value, result_dict[kStringKey].Get<std::string>());
  EXPECT_TRUE(new_stringmap_value ==
              result_dict[kStringmapKey].Get<Stringmap>());
  EXPECT_TRUE(new_stringmaps_value ==
              result_dict[kStringmapsKey].Get<Stringmaps>());
  EXPECT_TRUE(new_strings_value == result_dict[kStringsKey].Get<Strings>());
  EXPECT_EQ(new_uint8_value, result_dict[kUint8Key].Get<uint8_t>());
  EXPECT_EQ(new_uint16_value, result_dict[kUint16Key].Get<uint16_t>());
  EXPECT_EQ(new_uint32_value, result_dict[kUint32Key].Get<uint32_t>());
}

}  // namespace shill
