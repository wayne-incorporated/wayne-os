// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>

#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/json/json_string_value_serializer.h>
#include <base/memory/scoped_refptr.h>
#include <base/values.h>
#include <gtest/gtest.h>

#include "rmad/utils/json_store.h"

namespace rmad {

// File name.
const char kTestFileName[] = "test.json";

// Valid JSON dictionary.
const char kValidJson[] = R"(
  {
    "trigger": true,
    "state": "RMAD_STATE_RMA_NOT_REQUIRED",
    "replaced_components": [
      "screen",
      "keyboard"
    ]
  })";
// Invalid JSON string, missing '}'.
const char kInvalidFormatJson[] = "{ \"trigger\": true";
// Invalid JSON dictionary.
const char kWrongTypeJson[] = "[1, 2]";

const char kExistingKey[] = "trigger";
const bool kExistingValue = true;
const char kNewKey[] = "NewKey";
const int kNewValue = 10;
const char kNewStringValue[] = "value";
const char kNotStringValue[] = "not value";

class JsonStoreTest : public testing::Test {
 public:
  JsonStoreTest() {}

  base::FilePath CreateInputFile(std::string file_name,
                                 const char* str,
                                 int size) {
    base::FilePath file_path = temp_dir_.GetPath().AppendASCII(file_name);
    base::WriteFile(file_path, str, size);
    return file_path;
  }

 protected:
  void SetUp() override { ASSERT_TRUE(temp_dir_.CreateUniqueTempDir()); }

  base::ScopedTempDir temp_dir_;
};

TEST_F(JsonStoreTest, InitializeNormal) {
  base::FilePath input_file =
      CreateInputFile(kTestFileName, kValidJson, std::size(kValidJson) - 1);
  auto json_store = base::MakeRefCounted<JsonStore>(input_file);
  EXPECT_EQ(json_store->GetReadError(), JsonStore::READ_ERROR_NONE);
  EXPECT_FALSE(json_store->ReadOnly());

  JSONStringValueDeserializer deserializer(kValidJson);
  int error_code;
  std::string error_message;
  base::Value::Dict expected_value = std::move(
      deserializer.Deserialize(&error_code, &error_message)->GetDict());
  EXPECT_EQ(json_store->GetValues(), expected_value);
}

TEST_F(JsonStoreTest, InitializeInvalidString) {
  base::FilePath input_file = CreateInputFile(
      kTestFileName, kInvalidFormatJson, std::size(kInvalidFormatJson) - 1);
  auto json_store = base::MakeRefCounted<JsonStore>(input_file);
  EXPECT_EQ(json_store->GetReadError(), JsonStore::READ_ERROR_JSON_PARSE);
  EXPECT_TRUE(json_store->ReadOnly());
  EXPECT_EQ(json_store->GetValues(), base::Value::Dict());
}

TEST_F(JsonStoreTest, InitializeInvalidType) {
  base::FilePath input_file = CreateInputFile(kTestFileName, kWrongTypeJson,
                                              std::size(kWrongTypeJson) - 1);
  auto json_store = base::MakeRefCounted<JsonStore>(input_file);
  EXPECT_EQ(json_store->GetReadError(), JsonStore::READ_ERROR_JSON_TYPE);
  EXPECT_TRUE(json_store->ReadOnly());
  EXPECT_EQ(json_store->GetValues(), base::Value::Dict());
}

TEST_F(JsonStoreTest, InitializeNoFile) {
  base::FilePath input_file = temp_dir_.GetPath().AppendASCII(kTestFileName);
  auto json_store = base::MakeRefCounted<JsonStore>(input_file);
  EXPECT_EQ(json_store->GetReadError(), JsonStore::READ_ERROR_NO_SUCH_FILE);
  EXPECT_FALSE(json_store->ReadOnly());
  EXPECT_EQ(json_store->GetValues(), base::Value::Dict());
}

TEST_F(JsonStoreTest, GetValue) {
  base::FilePath input_file =
      CreateInputFile(kTestFileName, kValidJson, std::size(kValidJson) - 1);
  auto json_store = base::MakeRefCounted<JsonStore>(input_file);
  // Get by const pointer.
  const base::Value* value_ptr;
  EXPECT_FALSE(json_store->GetValue(kNewKey, &value_ptr));
  EXPECT_TRUE(json_store->GetValue(kExistingKey, &value_ptr));
  EXPECT_EQ(*value_ptr, base::Value(kExistingValue));
  // Get by copy.
  base::Value value;
  EXPECT_FALSE(json_store->GetValue(kNewKey, &value));
  EXPECT_TRUE(json_store->GetValue(kExistingKey, &value));
  EXPECT_EQ(value, base::Value(kExistingValue));
}

TEST_F(JsonStoreTest, SetValue) {
  base::FilePath input_file =
      CreateInputFile(kTestFileName, kValidJson, std::size(kValidJson) - 1);
  auto json_store = base::MakeRefCounted<JsonStore>(input_file);
  base::Value value;
  // Add new key.
  EXPECT_FALSE(json_store->GetValue(kNewKey, &value));
  EXPECT_TRUE(json_store->SetValue(kNewKey, base::Value(kNewValue)));
  EXPECT_TRUE(json_store->GetValue(kNewKey, &value));
  EXPECT_EQ(value, base::Value(kNewValue));
  // Overwrite existing key.
  EXPECT_TRUE(json_store->GetValue(kExistingKey, &value));
  EXPECT_EQ(value, base::Value(kExistingValue));
  EXPECT_NE(base::Value(kExistingValue), base::Value(kNewValue));
  EXPECT_TRUE(json_store->SetValue(kExistingKey, base::Value(kNewValue)));
  EXPECT_TRUE(json_store->GetValue(kExistingKey, &value));
  EXPECT_EQ(value, base::Value(kNewValue));
}

TEST_F(JsonStoreTest, StoreValue) {
  base::FilePath input_file =
      CreateInputFile(kTestFileName, kValidJson, std::size(kValidJson) - 1);
  auto json_store = base::MakeRefCounted<JsonStore>(input_file);
  base::Value value;
  // Add new key.
  EXPECT_FALSE(json_store->GetValue(kNewKey, &value));
  EXPECT_TRUE(json_store->SetValue(kNewKey, base::Value(kNewValue)));
  // Create a new JsonStore that reads the same file.
  auto json_store_new = base::MakeRefCounted<JsonStore>(input_file);
  EXPECT_TRUE(json_store_new->GetValue(kNewKey, &value));
  EXPECT_EQ(value, base::Value(kNewValue));
}

TEST_F(JsonStoreTest, SetValue_Template) {
  base::FilePath input_file =
      CreateInputFile(kTestFileName, kValidJson, std::size(kValidJson) - 1);
  auto json_store = base::MakeRefCounted<JsonStore>(input_file);
  int value = kNewValue - 1;
  // Add new key.
  EXPECT_FALSE(json_store->GetValue(kNewKey, &value));
  EXPECT_EQ(value, kNewValue - 1);
  EXPECT_TRUE(json_store->SetValue(kNewKey, kNewValue));
  EXPECT_TRUE(json_store->GetValue(kNewKey, &value));
  EXPECT_EQ(value, kNewValue);
  // Overwrite existing key.
  bool bool_value = !kExistingValue;
  EXPECT_TRUE(json_store->GetValue(kExistingKey, &bool_value));
  EXPECT_EQ(bool_value, kExistingValue);
  EXPECT_NE(kExistingValue, kNewValue);
  EXPECT_TRUE(json_store->SetValue(kExistingKey, kNewValue));
  bool_value = !kExistingValue;
  EXPECT_FALSE(json_store->GetValue(kExistingKey, &bool_value));
  EXPECT_EQ(bool_value, !kExistingValue);
  EXPECT_TRUE(json_store->GetValue(kExistingKey, &value));
  EXPECT_EQ(value, kNewValue);
}

TEST_F(JsonStoreTest, GetValue_TemplateWrongType) {
  base::FilePath input_file =
      CreateInputFile(kTestFileName, kValidJson, std::size(kValidJson) - 1);
  auto json_store = base::MakeRefCounted<JsonStore>(input_file);
  std::string value = "hello";
  EXPECT_FALSE(json_store->GetValue(kExistingKey, &value));
  EXPECT_EQ(value, "hello");
}

TEST_F(JsonStoreTest, GetValue_TemplateChangeType) {
  base::FilePath input_file =
      CreateInputFile(kTestFileName, kValidJson, std::size(kValidJson) - 1);
  auto json_store = base::MakeRefCounted<JsonStore>(input_file);
  bool bool_value = !kExistingValue;
  std::string string_value = kNotStringValue;
  EXPECT_TRUE(json_store->GetValue(kExistingKey, &bool_value));
  EXPECT_EQ(bool_value, kExistingValue);
  EXPECT_FALSE(json_store->GetValue(kExistingKey, &string_value));
  EXPECT_EQ(string_value, kNotStringValue);
  EXPECT_TRUE(json_store->SetValue(kExistingKey, kNewStringValue));
  bool_value = !kExistingValue;
  EXPECT_FALSE(json_store->GetValue(kExistingKey, &bool_value));
  EXPECT_EQ(bool_value, !kExistingValue);
  EXPECT_TRUE(json_store->GetValue(kExistingKey, &string_value));
  EXPECT_EQ(string_value, kNewStringValue);
}

TEST_F(JsonStoreTest, SetValue_TemplateList) {
  base::FilePath input_file =
      CreateInputFile(kTestFileName, kValidJson, std::size(kValidJson) - 1);
  auto json_store = base::MakeRefCounted<JsonStore>(input_file);
  std::vector<double> values = {0.12, 34.5, 678.9};
  // Add new key.
  EXPECT_FALSE(json_store->GetValue(kNewKey, &values));
  EXPECT_EQ(values.size(), 3);
  EXPECT_EQ(values[0], 0.12);
  EXPECT_EQ(values[1], 34.5);
  EXPECT_EQ(values[2], 678.9);
  EXPECT_TRUE(json_store->SetValue(kNewKey, values));
  values.clear();
  EXPECT_TRUE(json_store->GetValue(kNewKey, &values));
  EXPECT_EQ(values.size(), 3);
  EXPECT_EQ(values[0], 0.12);
  EXPECT_EQ(values[1], 34.5);
  EXPECT_EQ(values[2], 678.9);
  // Overwrite existing key.
  bool bool_value = !kExistingValue;
  EXPECT_TRUE(json_store->GetValue(kExistingKey, &bool_value));
  EXPECT_EQ(bool_value, kExistingValue);
  values = {987.6, 5.43, 2.1};
  EXPECT_FALSE(json_store->GetValue(kExistingKey, &values));
  EXPECT_EQ(values.size(), 3);
  EXPECT_EQ(values[0], 987.6);
  EXPECT_EQ(values[1], 5.43);
  EXPECT_EQ(values[2], 2.1);
  EXPECT_TRUE(json_store->SetValue(kExistingKey, values));
  values.clear();
  EXPECT_TRUE(json_store->GetValue(kExistingKey, &values));
  EXPECT_EQ(values.size(), 3);
  EXPECT_EQ(values[0], 987.6);
  EXPECT_EQ(values[1], 5.43);
  EXPECT_EQ(values[2], 2.1);
  // Confirm the new key was not modified.
  EXPECT_TRUE(json_store->GetValue(kNewKey, &values));
  EXPECT_EQ(values.size(), 3);
  EXPECT_EQ(values[0], 0.12);
  EXPECT_EQ(values[1], 34.5);
  EXPECT_EQ(values[2], 678.9);
}

TEST_F(JsonStoreTest, SetValue_TemplateNestedMapList) {
  base::FilePath input_file =
      CreateInputFile(kTestFileName, kValidJson, std::size(kValidJson) - 1);
  auto json_store = base::MakeRefCounted<JsonStore>(input_file);
  std::map<std::string, std::vector<int>> values = {{"a", {1, 2}},
                                                    {"b", {3, 4}}};
  // Add new key.
  EXPECT_FALSE(json_store->GetValue(kNewKey, &values));
  EXPECT_EQ(values.size(), 2);
  EXPECT_EQ(values["a"].size(), 2);
  EXPECT_EQ(values["b"].size(), 2);
  EXPECT_EQ(values["a"][0], 1);
  EXPECT_EQ(values["a"][1], 2);
  EXPECT_EQ(values["b"][0], 3);
  EXPECT_EQ(values["b"][1], 4);
  EXPECT_TRUE(json_store->SetValue(kNewKey, values));
  values.clear();
  EXPECT_TRUE(json_store->GetValue(kNewKey, &values));
  EXPECT_EQ(values.size(), 2);
  EXPECT_EQ(values["a"].size(), 2);
  EXPECT_EQ(values["b"].size(), 2);
  EXPECT_EQ(values["a"][0], 1);
  EXPECT_EQ(values["a"][1], 2);
  EXPECT_EQ(values["b"][0], 3);
  EXPECT_EQ(values["b"][1], 4);
  // Overwrite existing key.
  bool bool_value = !kExistingValue;
  EXPECT_TRUE(json_store->GetValue(kExistingKey, &bool_value));
  EXPECT_EQ(bool_value, kExistingValue);
  values = {{"c", {9}}, {"d", {8, 7, 6}}};
  EXPECT_FALSE(json_store->GetValue(kExistingKey, &values));
  EXPECT_EQ(values.size(), 2);
  EXPECT_EQ(values["c"].size(), 1);
  EXPECT_EQ(values["d"].size(), 3);
  EXPECT_EQ(values["c"][0], 9);
  EXPECT_EQ(values["d"][0], 8);
  EXPECT_EQ(values["d"][1], 7);
  EXPECT_EQ(values["d"][2], 6);
  EXPECT_TRUE(json_store->SetValue(kExistingKey, values));
  values.clear();
  EXPECT_TRUE(json_store->GetValue(kExistingKey, &values));
  EXPECT_EQ(values.size(), 2);
  EXPECT_EQ(values["c"].size(), 1);
  EXPECT_EQ(values["d"].size(), 3);
  EXPECT_EQ(values["c"][0], 9);
  EXPECT_EQ(values["d"][0], 8);
  EXPECT_EQ(values["d"][1], 7);
  EXPECT_EQ(values["d"][2], 6);
  // Confirm the new key was not modified.
  EXPECT_TRUE(json_store->GetValue(kNewKey, &values));
  EXPECT_EQ(values.size(), 2);
  EXPECT_EQ(values["a"].size(), 2);
  EXPECT_EQ(values["b"].size(), 2);
  EXPECT_EQ(values["a"][0], 1);
  EXPECT_EQ(values["a"][1], 2);
  EXPECT_EQ(values["b"][0], 3);
  EXPECT_EQ(values["b"][1], 4);
}

TEST_F(JsonStoreTest, RemoveValue) {
  base::FilePath input_file =
      CreateInputFile(kTestFileName, kValidJson, std::size(kValidJson) - 1);
  auto json_store = base::MakeRefCounted<JsonStore>(input_file);
  bool value;
  EXPECT_TRUE(json_store->GetValue(kExistingKey, &value));
  EXPECT_EQ(value, kExistingValue);
  // Remove existing key.
  EXPECT_TRUE(json_store->RemoveKey(kExistingKey));
  EXPECT_FALSE(json_store->GetValue(kExistingKey, &value));
  // Remove non-existing key.
  EXPECT_FALSE(json_store->RemoveKey(kNewKey));
}

TEST_F(JsonStoreTest, Clear) {
  base::FilePath input_file =
      CreateInputFile(kTestFileName, kValidJson, std::size(kValidJson) - 1);
  auto json_store = base::MakeRefCounted<JsonStore>(input_file);

  base::Value value;
  EXPECT_TRUE(json_store->GetValue(kExistingKey, &value));

  // Clear the data.
  EXPECT_TRUE(json_store->Clear());
  EXPECT_FALSE(json_store->GetValue(kExistingKey, &value));
}

TEST_F(JsonStoreTest, ClearAndDeleteFile) {
  base::FilePath input_file =
      CreateInputFile(kTestFileName, kValidJson, std::size(kValidJson) - 1);
  auto json_store = base::MakeRefCounted<JsonStore>(input_file);

  base::Value value;
  EXPECT_TRUE(base::PathExists(input_file));
  EXPECT_TRUE(json_store->GetValue(kExistingKey, &value));

  // Delete the file.
  EXPECT_TRUE(json_store->ClearAndDeleteFile());
  EXPECT_FALSE(base::PathExists(input_file));
  EXPECT_FALSE(json_store->GetValue(kExistingKey, &value));
}

}  // namespace rmad
