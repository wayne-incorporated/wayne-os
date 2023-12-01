// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NNAPI_INCLUDES_HIDLADAPTER_HIDLBINDERADAPTER_H_
#define NNAPI_INCLUDES_HIDLADAPTER_HIDLBINDERADAPTER_H_

#include <android/hidl/base/1.0/IBase.h>
#include <hidl/HidlSupport.h>

#include <map>
#include <string>

namespace android {
namespace hardware {

namespace details {

using IBase = ::android::hidl::base::V1_0::IBase;

// AdapterFactory(impl) -> adapter
using AdapterFactory = std::function<sp<IBase>(sp<IBase>)>;
// AdaptersFactory(package@interface)(impl) -> adapter
using AdaptersFactory = std::map<std::string, AdapterFactory>;

int adapterMain(const std::string& package,
                int argc,
                char** argv,
                const AdaptersFactory& adapters);

sp<IBase> adaptWithDefault(const sp<IBase>& something,
                           const std::function<sp<IBase>()>& makeDefault);

}  // namespace details

template <typename... Adapters>
int adapterMain(const std::string& package, int argc, char** argv) {
  return details::adapterMain(
      package, argc, argv,
      {{Adapters::Pure::descriptor,
        [](sp<::android::hidl::base::V1_0::IBase> base) {
          return details::adaptWithDefault(base, [&] {
            return new Adapters(Adapters::Pure::castFrom(base));
          });
        }}...});
}

}  // namespace hardware
}  // namespace android
#endif  // NNAPI_INCLUDES_HIDLADAPTER_HIDLBINDERADAPTER_H_"
