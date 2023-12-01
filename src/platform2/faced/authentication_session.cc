// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "faced/authentication_session.h"

#include <cstdint>
#include <memory>
#include <utility>
#include <vector>

#include <absl/status/status.h>
#include <base/functional/bind.h>
#include <base/location.h>
#include <base/task/sequenced_task_runner.h>

#include "faced/mojom/faceauth.mojom.h"
#include "faced/util/task.h"

namespace faced {

using ::chromeos::faceauth::mojom::AuthenticationCompleteMessage;
using ::chromeos::faceauth::mojom::AuthenticationSessionConfigPtr;
using ::chromeos::faceauth::mojom::AuthenticationUpdateMessage;
using ::chromeos::faceauth::mojom::AuthenticationUpdateMessagePtr;
using ::chromeos::faceauth::mojom::FaceAuthenticationSession;
using ::chromeos::faceauth::mojom::FaceAuthenticationSessionDelegate;
using ::chromeos::faceauth::mojom::FaceOperationStatus;
using ::chromeos::faceauth::mojom::SessionCreationError;
using ::chromeos::faceauth::mojom::SessionError;
using ::chromeos::faceauth::mojom::SessionInfo;

absl::StatusOr<std::unique_ptr<AuthenticationSession>>
AuthenticationSession::Create(
    absl::BitGen& bitgen,
    mojo::PendingReceiver<FaceAuthenticationSession> receiver,
    mojo::PendingRemote<FaceAuthenticationSessionDelegate> delegate,
    AuthenticationSessionConfigPtr config,
    Lease<brillo::AsyncGrpcClient<faceauth::eora::FaceService>> client) {
  uint64_t session_id = GenerateSessionId(bitgen);

  // Using `new` to access private constructor of `AuthenticationSession`.
  std::unique_ptr<AuthenticationSession> session(new AuthenticationSession(
      session_id, std::move(receiver), std::move(delegate), std::move(client)));

  session->delegate_.set_disconnect_handler(
      base::BindOnce(&AuthenticationSession::OnDelegateDisconnect,
                     base::Unretained(session.get())));

  session->receiver_.set_disconnect_handler(
      base::BindOnce(&AuthenticationSession::OnSessionDisconnect,
                     base::Unretained(session.get())));

  return session;
}

AuthenticationSession::AuthenticationSession(
    uint64_t session_id,
    mojo::PendingReceiver<FaceAuthenticationSession> receiver,
    mojo::PendingRemote<FaceAuthenticationSessionDelegate> delegate,
    Lease<brillo::AsyncGrpcClient<faceauth::eora::FaceService>> client)
    : session_id_(session_id),
      receiver_(this, std::move(receiver)),
      delegate_(std::move(delegate)),
      rpc_client_(std::move(client)) {}

void AuthenticationSession::Start(StartCallback start_callback,
                                  CompletionCallback completion_callback) {
  PostToCurrentSequence(
      base::BindOnce(std::move(completion_callback),
                     absl::UnimplementedError("Not yet implemented")));
}

void AuthenticationSession::NotifyUpdate(FaceOperationStatus status) {
  AuthenticationUpdateMessagePtr message(
      AuthenticationUpdateMessage::New(status));
  delegate_->OnAuthenticationUpdate(std::move(message));
}

void AuthenticationSession::NotifyComplete() {
  delegate_->OnAuthenticationComplete(AuthenticationCompleteMessage::New());

  FinishSession(absl::OkStatus());
}

void AuthenticationSession::NotifyCancelled() {
  delegate_->OnAuthenticationCancelled();

  FinishSession(absl::CancelledError());
}

void AuthenticationSession::NotifyError(absl::Status error) {
  // TODO(bkersten): map absl::Status to SessionError
  SessionError session_error = SessionError::UNKNOWN;
  delegate_->OnAuthenticationError(session_error);

  FinishSession(error);
}

void AuthenticationSession::OnSessionDisconnect() {
  // TODO(b/249184053): cancel authentication session operation

  NotifyCancelled();
}

void AuthenticationSession::OnDelegateDisconnect() {
  // TODO(b/249184053): cancel authentication session operation

  FinishSession(absl::CancelledError());
}

void AuthenticationSession::FinishSession(absl::Status status) {
  // Close the connections to the authentication session interfaces.
  delegate_.reset();
  receiver_.reset();

  if (completion_callback_) {
    PostToCurrentSequence(
        base::BindOnce(std::move(completion_callback_), status));
  }
}

}  // namespace faced
