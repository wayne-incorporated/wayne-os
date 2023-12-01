// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ML_DLCSERVICE_CLIENT_H_
#define ML_DLCSERVICE_CLIENT_H_

#include <string>

#include <base/functional/callback.h>
#include <dbus/bus.h>
#include <dbus/object_proxy.h>
#include <gtest/gtest_prod.h>  // for FRIEND_TEST

namespace ml {

// DlcserviceClient is used to communicate with the dlcservice daemon.
class DlcserviceClient {
 public:
  // Constructed on the `bus` which will be passed in from the ml::Daemon.
  explicit DlcserviceClient(dbus::Bus* bus);

  using GetDlcRootPathCallback =
      base::OnceCallback<void(const std::string& root_path)>;
  // Get the root_path of the `dlc_id`; calls the `callback' if the root_path
  // is returned correctly; otherwise calls the 'callback' on empty string.
  void GetDlcRootPath(const std::string& dlc_id,
                      GetDlcRootPathCallback callback);

 private:
  friend class DlcserviceClientTest;
  FRIEND_TEST(DlcserviceClientTest,
              ShouldInitializeAndCallWithCorrectDbusInterface);

  // Calls `callback` either on root_path or empty string based on the
  // `response`.
  static void OnGetDlcStateComplete(GetDlcRootPathCallback callback,
                                    dbus::Response* response,
                                    dbus::ErrorResponse* err_response);

  dbus::ObjectProxy* dlcservice_proxy_ = nullptr;
};

}  // namespace ml

#endif  // ML_DLCSERVICE_CLIENT_H_
