// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "federated/test_utils.h"

#include <string>
#include <vector>

namespace federated {
namespace {

using ::chromeos::federated::mojom::Example;
using ::chromeos::federated::mojom::ExamplePtr;
using ::chromeos::federated::mojom::Features;
using ::chromeos::federated::mojom::FloatList;
using ::chromeos::federated::mojom::Int64List;
using ::chromeos::federated::mojom::StringList;
using ::chromeos::federated::mojom::ValueList;
using ::chromeos::federated::mojom::ValueListPtr;

ValueListPtr CreateInt64List(const std::vector<int64_t>& values) {
  ValueListPtr value_list = ValueList::NewInt64List(Int64List::New());
  value_list->get_int64_list()->value = std::vector<int64_t>();
  value_list->get_int64_list()->value = values;
  return value_list;
}

ValueListPtr CreateFloatList(const std::vector<double>& values) {
  ValueListPtr value_list = ValueList::NewFloatList(FloatList::New());
  value_list->get_float_list()->value = std::vector<double>();
  value_list->get_float_list()->value = values;
  return value_list;
}

ValueListPtr CreateStringList(const std::vector<std::string>& values) {
  ValueListPtr value_list = ValueList::NewStringList(StringList::New());
  value_list->get_string_list()->value = std::vector<std::string>();
  value_list->get_string_list()->value = values;
  return value_list;
}

}  // namespace

ExamplePtr CreateExamplePtr() {
  ExamplePtr example = Example::New();
  example->features = Features::New();
  auto& feature_map = example->features->feature;
  feature_map["int_feature1"] = CreateInt64List({1, 2, 3, 4, 5});
  feature_map["int_feature2"] = CreateInt64List({10, 20, 30, 40, 50});
  feature_map["float_feature1"] = CreateFloatList({1.1, 2.1, 3.1, 4.1, 5.1});
  feature_map["string_feature1"] = CreateStringList({"abc", "123", "xyz"});

  return example;
}

base::Time SecondsAfterEpoch(const int64_t s) {
  return base::Time::UnixEpoch() + base::Seconds(s);
}

}  // namespace federated
