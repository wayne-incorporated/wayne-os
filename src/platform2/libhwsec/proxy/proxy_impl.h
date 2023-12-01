// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_PROXY_PROXY_IMPL_H_
#define LIBHWSEC_PROXY_PROXY_IMPL_H_

#include <memory>

#include "libhwsec/proxy/proxy.h"

namespace hwsec {

class ProxyImpl : public Proxy {
 public:
  ProxyImpl();
  ~ProxyImpl() override;

  // Initialize the proxy data. Returns true on success.
  virtual bool Init();

 private:
  // The InnerData implementation is in the cpp file.
  struct InnerData;
  std::unique_ptr<InnerData> inner_data_;
};

}  // namespace hwsec

#endif  // LIBHWSEC_PROXY_PROXY_IMPL_H_
