// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/functional/bind.h>
#include <base/functional/callback.h>
#include <base/run_loop.h>
#include <base/strings/string_piece.h>
#include <base/test/task_environment.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <mojo/core/embedder/embedder.h>
#include <mojo/public/cpp/system/buffer.h>

#include "diagnostics/wilco_dtc_supportd/grpc_client_manager.h"
#include "diagnostics/wilco_dtc_supportd/mock_mojo_client.h"
#include "diagnostics/wilco_dtc_supportd/mojo_grpc_adapter.h"
#include "diagnostics/wilco_dtc_supportd/mojo_service.h"
#include "diagnostics/wilco_dtc_supportd/utils/mojo_test_utils.h"
#include "diagnostics/wilco_dtc_supportd/utils/mojo_utils.h"

#include "diagnostics/mojom/public/wilco_dtc_supportd.mojom.h"

using testing::_;
using testing::Invoke;
using testing::StrictMock;
using testing::WithArg;

using MojomWilcoDtcSupportdClient =
    chromeos::wilco_dtc_supportd::mojom::WilcoDtcSupportdClient;
using MojomWilcoDtcSupportdService =
    chromeos::wilco_dtc_supportd::mojom::WilcoDtcSupportdService;
using MojomWilcoDtcSupportdWebRequestStatus =
    chromeos::wilco_dtc_supportd::mojom::WilcoDtcSupportdWebRequestStatus;
using MojomWilcoDtcSupportdWebRequestHttpMethod =
    chromeos::wilco_dtc_supportd::mojom::WilcoDtcSupportdWebRequestHttpMethod;

namespace diagnostics {
namespace wilco {
namespace {

// Tests for the MojoService class.
class MojoServiceTest : public testing::Test {
 protected:
  MojoServiceTest() : mojo_client_receiver_(&mojo_client_) {
    // Obtain Mojo pending remote that talks to |mojo_client_| - the
    // connection between them will be maintained by |mojo_client_receiver_|.
    mojo::PendingRemote<MojomWilcoDtcSupportdClient> mojo_client;
    mojo_client_receiver_.Bind(mojo_client.InitWithNewPipeAndPassReceiver());
    DCHECK(mojo_client);

    mojo::Remote<MojomWilcoDtcSupportdService> mojo_service;
    mojo_service_ = std::make_unique<MojoService>(
        &mojo_grpc_adapter_, mojo_service.BindNewPipeAndPassReceiver(),
        std::move(mojo_client));
  }

  MockMojoClient* mojo_client() { return &mojo_client_; }
  MojoService* mojo_service() { return mojo_service_.get(); }

 private:
  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::ThreadingMode::MAIN_THREAD_ONLY};

  StrictMock<MockMojoClient> mojo_client_;
  mojo::Receiver<MojomWilcoDtcSupportdClient> mojo_client_receiver_;

  GrpcClientManager grpc_client_manager_;
  MojoGrpcAdapter mojo_grpc_adapter_{&grpc_client_manager_};

  std::unique_ptr<MojoService> mojo_service_;
};

TEST_F(MojoServiceTest, SendWilcoDtcMessageToUi) {
  constexpr char kJsonMessageToUi[] = "{\"message\": \"ping\"}";
  constexpr char kJsonMessageFromUi[] = "{\"message\": \"pong\"}";

  EXPECT_CALL(*mojo_client(), SendWilcoDtcMessageToUiImpl(kJsonMessageToUi, _))
      .WillOnce(WithArg<1>(
          Invoke([kJsonMessageFromUi](
                     MockMojoClient::SendWilcoDtcMessageToUiCallback callback) {
            std::move(callback).Run(
                CreateReadOnlySharedMemoryRegionMojoHandle(kJsonMessageFromUi));
          })));

  base::RunLoop run_loop;
  mojo_service()->SendWilcoDtcMessageToUi(
      kJsonMessageToUi,
      base::BindOnce(
          [](base::OnceClosure quit_closure,
             base::StringPiece expected_json_message, grpc::Status status,
             base::StringPiece json_message) {
            EXPECT_EQ(json_message, expected_json_message);
            std::move(quit_closure).Run();
          },
          run_loop.QuitClosure(), kJsonMessageFromUi));
  run_loop.Run();
}

TEST_F(MojoServiceTest, SendWilcoDtcMessageToUiEmptyMessage) {
  base::RunLoop run_loop;
  auto callback = base::BindOnce(
      [](base::OnceClosure quit_closure, grpc::Status status,
         base::StringPiece json_message) {
        EXPECT_TRUE(json_message.empty());
        std::move(quit_closure).Run();
      },
      run_loop.QuitClosure());
  mojo_service()->SendWilcoDtcMessageToUi("", std::move(callback));
  run_loop.Run();
}

TEST_F(MojoServiceTest, PerformWebRequest) {
  constexpr auto kHttpMethod = MojomWilcoDtcSupportdWebRequestHttpMethod::kPost;
  constexpr char kHttpsUrl[] = "https://www.google.com";
  constexpr char kHeader1[] = "Accept-Language: en-US";
  constexpr char kHeader2[] = "Accept: text/html";
  constexpr char kBodyRequest[] = "<html>Request</html>";

  constexpr auto kWebRequestStatus = MojomWilcoDtcSupportdWebRequestStatus::kOk;
  constexpr int kHttpStatusOk = 200;
  constexpr char kBodyResponse[] = "<html>Response</html>";

  EXPECT_CALL(*mojo_client(), PerformWebRequestImpl(
                                  kHttpMethod, kHttpsUrl,
                                  std::vector<std::string>{kHeader1, kHeader2},
                                  kBodyRequest, _))
      .WillOnce(WithArg<4>(
          Invoke([kBodyResponse](
                     MockMojoClient::MojoPerformWebRequestCallback callback) {
            std::move(callback).Run(
                kWebRequestStatus, kHttpStatusOk,
                CreateReadOnlySharedMemoryRegionMojoHandle(kBodyResponse));
          })));

  base::RunLoop run_loop;
  mojo_service()->PerformWebRequest(
      kHttpMethod, kHttpsUrl, {kHeader1, kHeader2}, kBodyRequest,
      base::BindOnce(
          [](base::OnceClosure quit_closure,
             MojomWilcoDtcSupportdWebRequestStatus expected_status,
             int expected_http_status, std::string expected_response_body,
             MojomWilcoDtcSupportdWebRequestStatus status, int http_status,
             base::StringPiece response_body) {
            EXPECT_EQ(expected_status, status);
            EXPECT_EQ(expected_http_status, http_status);
            EXPECT_EQ(expected_response_body, response_body);
            std::move(quit_closure).Run();
          },
          run_loop.QuitClosure(), kWebRequestStatus, kHttpStatusOk,
          kBodyResponse));
  run_loop.Run();
}

TEST_F(MojoServiceTest, GetConfigurationData) {
  constexpr char kFakeJsonConfigurationData[] = "Fake JSON configuration data";

  EXPECT_CALL(*mojo_client(), GetConfigurationData(_))
      .WillOnce(WithArg<0>(
          Invoke([kFakeJsonConfigurationData](
                     base::OnceCallback<void(const std::string&)> callback) {
            std::move(callback).Run(kFakeJsonConfigurationData);
          })));

  base::RunLoop run_loop;
  mojo_service()->GetConfigurationData(base::BindOnce(
      [](base::OnceClosure quit_closure, const std::string& expected_data,
         const std::string& json_configuration_data) {
        EXPECT_EQ(json_configuration_data, expected_data);
        std::move(quit_closure).Run();
      },
      run_loop.QuitClosure(), kFakeJsonConfigurationData));
  run_loop.Run();
}

}  // namespace
}  // namespace wilco
}  // namespace diagnostics
