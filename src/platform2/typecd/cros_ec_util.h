// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TYPECD_CROS_EC_UTIL_H_
#define TYPECD_CROS_EC_UTIL_H_

#include <memory>

#include <base/memory/ref_counted.h>
#include <dbus/bus.h>
#include <debugd/dbus-proxies.h>
#include <gtest/gtest_prod.h>

#include "typecd/ec_util.h"

namespace typecd {

// ECUtil implementation which communicates with the Chrome EC via debugd.
class CrosECUtil : public ECUtil {
 public:
  explicit CrosECUtil(scoped_refptr<dbus::Bus> bus);
  CrosECUtil(const CrosECUtil&) = delete;
  CrosECUtil& operator=(const CrosECUtil&) = delete;

  bool ModeEntrySupported() override;
  bool EnterMode(int port, TypeCMode mode) override;
  bool ExitMode(int port) override;
  bool DpState(int port, bool* entered) override;
  bool HpdState(int port, bool* hpd) override;

 private:
  FRIEND_TEST(CrosEcUtilTest, ModeEntrySupported);
  std::unique_ptr<org::chromium::debugdProxyInterface> debugd_proxy_;
};

}  // namespace typecd

#endif  // TYPECD_CROS_EC_UTIL_H_
