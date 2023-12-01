// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_WILCO_DTC_SUPPORTD_MOCK_MOJO_CLIENT_H_
#define DIAGNOSTICS_WILCO_DTC_SUPPORTD_MOCK_MOJO_CLIENT_H_

#include <string>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <mojo/public/cpp/system/buffer.h>
#include <mojo/public/cpp/bindings/pending_receiver.h>

#include "diagnostics/mojom/public/cros_healthd.mojom.h"
#include "diagnostics/mojom/public/wilco_dtc_supportd.mojom.h"

namespace diagnostics {
namespace wilco {

class MockMojoClient
    : public chromeos::wilco_dtc_supportd::mojom::WilcoDtcSupportdClient {
 public:
  using MojoWilcoDtcSupportdWebRequestHttpMethod =
      chromeos::wilco_dtc_supportd::mojom::WilcoDtcSupportdWebRequestHttpMethod;
  using MojoWilcoDtcSupportdWebRequestStatus =
      chromeos::wilco_dtc_supportd::mojom::WilcoDtcSupportdWebRequestStatus;
  using MojoWilcoDtcSupportdEvent =
      chromeos::wilco_dtc_supportd::mojom::WilcoDtcSupportdEvent;
  using MojoPerformWebRequestCallback = base::OnceCallback<void(
      MojoWilcoDtcSupportdWebRequestStatus, int32_t, mojo::ScopedHandle)>;
  using MojoGetConfigurationDataCallback =
      base::OnceCallback<void(const std::string&)>;
  using MojoCrosHealthdDiagnosticsServicePendingReceiver =
      mojo::PendingReceiver<
          ash::cros_healthd::mojom::CrosHealthdDiagnosticsService>;
  using MojoCrosHealthdProbeServicePendingReceiver =
      mojo::PendingReceiver<ash::cros_healthd::mojom::CrosHealthdProbeService>;

  void SendWilcoDtcMessageToUi(
      mojo::ScopedHandle json_message,
      SendWilcoDtcMessageToUiCallback callback) override;

  void PerformWebRequest(MojoWilcoDtcSupportdWebRequestHttpMethod http_method,
                         mojo::ScopedHandle url,
                         std::vector<mojo::ScopedHandle> headers,
                         mojo::ScopedHandle request_body,
                         MojoPerformWebRequestCallback callback) override;

  MOCK_METHOD(void,
              SendWilcoDtcMessageToUiImpl,
              (const std::string&, SendWilcoDtcMessageToUiCallback));
  MOCK_METHOD(void,
              PerformWebRequestImpl,
              (MojoWilcoDtcSupportdWebRequestHttpMethod,
               const std::string&,
               const std::vector<std::string>&,
               const std::string&,
               MojoPerformWebRequestCallback));
  MOCK_METHOD(void,
              GetConfigurationData,
              (MojoGetConfigurationDataCallback),
              (override));
  MOCK_METHOD(void, HandleEvent, (const MojoWilcoDtcSupportdEvent), (override));
  MOCK_METHOD(void,
              GetCrosHealthdDiagnosticsService,
              (MojoCrosHealthdDiagnosticsServicePendingReceiver),
              (override));
  MOCK_METHOD(void,
              GetCrosHealthdProbeService,
              (MojoCrosHealthdProbeServicePendingReceiver),
              (override));
};

}  // namespace wilco
}  // namespace diagnostics

#endif  // DIAGNOSTICS_WILCO_DTC_SUPPORTD_MOCK_MOJO_CLIENT_H_
