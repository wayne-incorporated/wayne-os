// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <hidladapter/HidlBinderAdapter.h>
#include <map>

namespace android {
namespace hardware {
namespace details {

// This is copied from libhidl/adapter/HidlBinderAdapter.cpp.
// There is a lot of other uncompilable content in that file, so just
// taking this fairly simple implementation in isolation.

// If an interface is adapted to 1.0, it can then not be adapted to 1.1 in the
// same process.
// This poses a problem in the following scenario:
// auto interface = new V1_1::implementation::IFoo;
// hidlObject1_0->foo(interface) // adaptation set at 1.0
// hidlObject1_1->bar(interface) // adaptation still is 1.0
// This could be solved by keeping a map of IBase,fqName -> IBase, but then
// you end up with multiple names for the same interface.
sp<IBase> adaptWithDefault(const sp<IBase>& something,
                           const std::function<sp<IBase>()>& makeDefault) {
  static std::map<sp<IBase>, sp<IBase>> sAdapterMap;

  if (something == nullptr) {
    return something;
  }

  auto it = sAdapterMap.find(something);
  if (it == sAdapterMap.end()) {
    it = sAdapterMap.insert(it, {something, makeDefault()});
  }

  return it->second;
}

}  // namespace details
}  // namespace hardware
}  // namespace android
