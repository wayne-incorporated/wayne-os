// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_BINDINGS_CONNECTIVITY_TEST_MY_TYPE_MAPPING_TRAITS_H_
#define DIAGNOSTICS_BINDINGS_CONNECTIVITY_TEST_MY_TYPE_MAPPING_TRAITS_H_

#include <memory>

#include <mojo/public/cpp/bindings/struct_traits.h>

#include "diagnostics/bindings/connectivity/data_generator.h"
#include "diagnostics/bindings/connectivity/test/my_type_mapping.h"
#include "diagnostics/bindings/connectivity/test/test_common.mojom.h"

namespace ash::cros_healthd::connectivity::test {

class MyTypeMappingGenerator : public DataGeneratorInterface<MyTypeMapping> {
 public:
  MyTypeMappingGenerator(const MyTypeMappingGenerator&) = delete;
  MyTypeMappingGenerator& operator=(const MyTypeMappingGenerator&) = delete;
  virtual ~MyTypeMappingGenerator() = default;

  static std::unique_ptr<MyTypeMappingGenerator> Create(Context*) {
    return std::unique_ptr<MyTypeMappingGenerator>(
        new MyTypeMappingGenerator());
  }

 public:
  MyTypeMapping Generate() override {
    if (cnt_ > 0)
      --cnt_;
    return MyTypeMapping();
  }

  bool HasNext() override { return cnt_ > 0; }

 protected:
  MyTypeMappingGenerator() = default;

 private:
  int cnt_ = 42;
};

}  // namespace ash::cros_healthd::connectivity::test

namespace mojo {

template <>
struct StructTraits<
    ash::cros_healthd::connectivity::test::common::mojom::TypeMappingDataView,
    ash::cros_healthd::connectivity::test::MyTypeMapping> {
  static int32_t n(const ash::cros_healthd::connectivity::test::MyTypeMapping&
                       my_type_mapping) {
    return 42;
  }

  static bool Read(
      ash::cros_healthd::connectivity::test::common::mojom::TypeMappingDataView
          data,
      ash::cros_healthd::connectivity::test::MyTypeMapping* my_type_mapping) {
    return true;
  }
};

}  // namespace mojo

#endif  // DIAGNOSTICS_BINDINGS_CONNECTIVITY_TEST_MY_TYPE_MAPPING_TRAITS_H_
