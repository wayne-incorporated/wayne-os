// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef U2FD_U2FHID_SERVICE_IMPL_H_
#define U2FD_U2FHID_SERVICE_IMPL_H_

#include "u2fd/u2fhid_service.h"

#include <functional>
#include <memory>
#include <optional>

#include <attestation/proto_bindings/interface.pb.h>
#include <brillo/dbus/dbus_method_response.h>
#include <metrics/metrics_library.h>
#include <session_manager/dbus-proxies.h>

#include "u2fd/client/user_state.h"
#include "u2fd/u2f_corp_processor_interface.h"
#include "u2fd/u2f_msg_handler.h"
#include "u2fd/u2fhid.h"
#include "u2fd/uhid_device.h"

namespace u2f {

// U2F HID service. Initialized by U2F Daemon.
class U2fHidServiceImpl : public U2fHidService {
 public:
  explicit U2fHidServiceImpl(
      std::unique_ptr<const hwsec::U2fVendorFrontend> u2f_frontend);
  U2fHidServiceImpl(const U2fHidServiceImpl&) = delete;
  U2fHidServiceImpl& operator=(const U2fHidServiceImpl&) = delete;

  ~U2fHidServiceImpl() override {}

  bool InitializeDBusProxies(dbus::Bus* bus) override;

  bool CreateU2fHid(bool allow_g2f_attestation,
                    bool include_g2f_allowlisting_data,
                    bool enable_corp_protocol,
                    std::function<void()> request_user_presence,
                    UserState* user_state,
                    org::chromium::SessionManagerInterfaceProxy* sm_proxy,
                    MetricsLibraryInterface* metrics) override;

  // Returns a certified copy of the G2F certificate from attestationd, or
  // std::nullopt on error. The size of the G2F certificate is variable, and
  // must be specified in |g2f_cert_size|.
  std::optional<attestation::GetCertifiedNvIndexReply> GetCertifiedG2fCert(
      int g2f_cert_size) override;

 private:
  std::unique_ptr<const hwsec::U2fVendorFrontend> u2f_frontend_;
  dbus::ObjectProxy* attestation_proxy_;  // Not Owned.

  // Virtual USB Device
  std::unique_ptr<U2fHid> u2fhid_;
  std::unique_ptr<U2fMessageHandler> u2f_msg_handler_;
  std::unique_ptr<U2fCorpProcessorInterface> u2f_corp_processor_;
};

}  // namespace u2f

#endif  // U2FD_U2FHID_SERVICE_IMPL_H_
