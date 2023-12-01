// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/fido/fido_constants.h"

namespace cryptohome {
namespace fido_device {

const base::TimeDelta kDeviceTimeout = base::Seconds(20);
const base::TimeDelta kU2fRetryDelay = base::Milliseconds(200);

const char kFormatKey[] = "fmt";
const char kAttestationStatementKey[] = "attStmt";
const char kAuthDataKey[] = "authData";
const char kNoneAttestationValue[] = "none";

const char kPublicKey[] = "public-key";

const std::array<uint8_t, 24> kCableDeviceEncryptionKeyInfo = {
    'F', 'I', 'D', 'O', ' ', 'c', 'a', 'B', 'L', 'E', ' ', 'v',
    '1', ' ', 's', 'e', 's', 's', 'i', 'o', 'n', 'K', 'e', 'y',
};
const char kCableAuthenticatorHelloMessage[] = "caBLE v1 authenticator hello";
const char kCableClientHelloMessage[] = "caBLE v1 client hello";

}  // namespace fido_device
}  // namespace cryptohome
