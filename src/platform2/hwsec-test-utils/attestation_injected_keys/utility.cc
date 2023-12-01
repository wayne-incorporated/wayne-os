// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "hwsec-test-utils/attestation_injected_keys/utility.h"

#include <string>
#include <utility>

#include <base/logging.h>

namespace hwsec_test_utils {

namespace {

constexpr char kDefaultACAPublicKey[] =
    "d1808eaef97c87f98f4bf982523d34800e15e417333082b29791e85489794ffb"
    "a053c194d55ecb97593b7762421d60dce7b92171788064cb51c45a78afac368d"
    "e6944039787c400c9479bc49e67a191c51ed8cb92083b070c6a3531d9eca8173"
    "3c2021ef21f9ed63a8116aeecd120428fc1220ad2475dab6aa968def6888ddab"
    "295ae7ea9eb2b39398b5b044dcab98a404ac506afe3fd8dcf0b382072487dc17"
    "7bb20b20b07baac5599e6e50aca73dd68cc92403f05a6638847ac782333a90d6"
    "7e3d19b3e82560498efa96a231b5a0089bf131db827fec2925f56bdbd8c9f69b"
    "ee89eebde9d872d303daa2f8e3cc567468779e80609680304e6dbdc7a3023d73";
constexpr char kDefaultACAPublicKeyID[] = "CaEnc";

constexpr char kDefaultVASigningPublicKey[] =
    "e7cb0cc9d2f904ec3f09a379b8fe09a7ef621f15657523138e886ebbc000826e"
    "189a947a62d50679f8c19cfd84065388d627dd11f7e8e7bf77813579d6fb8a96"
    "77e4508aa26a66beb69d3c616c628d51be350c59d6988d86645c54c6ec13da9d"
    "451b44a386c9699da809a2ecec6f053ad6ddd761d3023d944f1b0b5e138543c3"
    "948f8a7f0f0684f284ed38b4cd37dc15505049f0923e2ab49fc85dc87027c5cc"
    "bd86d486616623976965877486be656427a2ee56c195ee38becc153369f8d43e"
    "2ccda18e53f763925406581adcbeb0766b898f279ea5161359bc79d300028fe8"
    "a3f52077d50aaaf82aadb7273483702ffc17d68f0f413459edca974d76ca3c9f";

constexpr char kDefaultVAEncryptionPublicKey[] =
    "bc435db064ecf44b650ead16f2934035a0e6ecfc76c4f3f7c26ce459482c66f6"
    "747b8e510c03e94808608f076b4d3ad3470d710c1b8d731cbe2d4c53e2df7367"
    "7ced201df57c8c86503cc2442faa71c88a66f86726b5791b8d7888df1357defb"
    "d1b5cddffe10e2ec9ef7a47eede4d74c33ca4e34f0801bed065188f035e729ff"
    "f10b46432ed320f993d75ecccebff88d197a0f20dfefa438d5f58c69578e6037"
    "821943721c21daeab845716f4823748ea8080a4bb43786e1cc70f3363bfb98d5"
    "1a3b77a5b3a44b18a029296ad075e93df31abe2105c68a6fafb8b47ad52ec01e"
    "adde56c522e1369a9fb5175ea5e8ebd8c35c0cd16ee1d6930f34821f12f46459";
constexpr char kDefaultVAEncryptionPublicKeyID[] = "VaEnc";

}  // namespace

attestation::DefaultGoogleRsaPublicKeySet GenerateAttestationGoogleKeySet() {
  attestation::DefaultGoogleRsaPublicKeySet keyset;
  attestation::GoogleRsaPublicKey key;

  key.set_modulus_in_hex(kDefaultACAPublicKey);
  key.set_key_id(kDefaultACAPublicKeyID);
  *keyset.mutable_default_ca_encryption_key() = std::move(key);

  key.set_modulus_in_hex(kDefaultVASigningPublicKey);
  *keyset.mutable_default_va_signing_key() = std::move(key);

  key.set_modulus_in_hex(kDefaultVAEncryptionPublicKey);
  key.set_key_id(kDefaultVAEncryptionPublicKeyID);
  *keyset.mutable_default_va_encryption_key() = std::move(key);

  return keyset;
}

}  // namespace hwsec_test_utils
