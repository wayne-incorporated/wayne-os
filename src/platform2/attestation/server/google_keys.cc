// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "attestation/server/google_keys.h"

#include <base/check.h>
#include <base/check_op.h>
#include <base/logging.h>

namespace attestation {

namespace {
// Google Attestation Certificate Authority (ACA) production instance.
// https://chromeos-ca.gstatic.com
constexpr char kDefaultACAPublicKey[] =
    "A2976637E113CC457013F4334312A416395B08D4B2A9724FC9BAD65D0290F39C"
    "866D1163C2CD6474A24A55403C968CF78FA153C338179407FE568C6E550949B1"
    "B3A80731BA9311EC16F8F66060A2C550914D252DB90B44D19BC6C15E923FFCFB"
    "E8A366038772803EE57C7D7E5B3D5E8090BF0960D4F6A6644CB9A456708508F0"
    "6C19245486C3A49F807AB07C65D5E9954F4F8832BC9F882E9EE1AAA2621B1F43"
    "4083FD98758745CBFFD6F55DA699B2EE983307C14C9990DDFB48897F26DF8FB2"
    "CFFF03E631E62FAE59CBF89525EDACD1F7BBE0BA478B5418E756FF3E14AC9970"
    "D334DB04A1DF267D2343C75E5D282A287060D345981ABDA0B2506AD882579FEF";
constexpr char kDefaultACAPublicKeyID[] = "\x00\xc7\x0e\x50\xb1";

// Google Attestation Certificate Authority (ACA) test instance.
// https://asbestos-qa.corp.google.com
constexpr char kTestACAPublicKey[] =
    "A1D50D088994000492B5F3ED8A9C5FC8772706219F4C063B2F6A8C6B74D3AD6B"
    "212A53D01DABB34A6261288540D420D3BA59ED279D859DE6227A7AB6BD88FADD"
    "FC3078D465F4DF97E03A52A587BD0165AE3B180FE7B255B7BEDC1BE81CB1383F"
    "E9E46F9312B1EF28F4025E7D332E33F4416525FEB8F0FC7B815E8FBB79CDABE6"
    "327B5A155FEF13F559A7086CB8A543D72AD6ECAEE2E704FF28824149D7F4E393"
    "D3C74E721ACA97F7ADBE2CCF7B4BCC165F7380F48065F2C8370F25F066091259"
    "D14EA362BAF236E3CD8771A94BDEDA3900577143A238AB92B6C55F11DEFAFB31"
    "7D1DC5B6AE210C52B008D87F2A7BFF6EB5C4FB32D6ECEC6505796173951A3167";
constexpr char kTestACAPublicKeyID[] = "\x00\xc2\xb0\x56\x2d";

// VA server instance for prod.
// http://test-dvproxy-server.sandbox.google.com
constexpr char kDefaultVASigningPublicKey[] =
    "bf7fefa3a661437b26aed0801db64d7ba8b58875c351d3bdc9f653847d4a67b3"
    "b67479327724d56aa0f71a3f57c2290fdc1ff05df80589715e381dfbbda2c4ac"
    "114c30d0a73c5b7b2e22178d26d8b65860aa8dd65e1b3d61a07c81de87c1e7e4"
    "590145624936a011ece10434c1d5d41f917c3dc4b41dd8392479130c4fd6eafc"
    "3bb4e0dedcc8f6a9c28428bf8fbba8bd6438a325a9d3eabee1e89e838138ad99"
    "69c292c6d9f6f52522333b84ddf9471ffe00f01bf2de5faa1621f967f49e158b"
    "f2b305360f886826cc6fdbef11a12b2d6002d70d8d1e8f40e0901ff94c203cb2"
    "01a36a0bd6e83955f14b494f4f2f17c0c826657b85c25ffb8a73599721fa17ab";
constexpr char kDefaultVAEncryptionPublicKey[] =
    "edba5e723da811e41636f792c7a77aef633fbf39b542aa537c93c93eaba7a3b1"
    "0bc3e484388c13d625ef5573358ec9e7fbeb6baaaa87ca87d93fb61bf5760e29"
    "6813c435763ed2c81f631e26e3ff1a670261cdc3c39a4640b6bbf4ead3d6587b"
    "e43ef7f1f08e7596b628ec0b44c9b7ad71c9ee3a1258852c7a986c7614f0c4ec"
    "f0ce147650a53b6aa9ae107374a2d6d4e7922065f2f6eb537a994372e1936c87"
    "eb08318611d44daf6044f8527687dc7ce5319b51eae6ab12bee6bd16e59c499e"
    "fa53d80232ae886c7ee9ad8bc1cbd6e4ac55cb8fa515671f7e7ad66e98769f52"
    "c3c309f98bf08a3b8fbb0166e97906151b46402217e65c5d01ddac8514340e8b";
constexpr char kDefaultVAEncryptionPublicKeyID[] = "\x00\x4a\xe2\xdc\xae";

// VA server instance for QA.
// https://qa-dvproxy-server-gws.sandbox.google.com
constexpr char kTestVASigningPublicKey[] =
    "baab3e277518c65b1b98290bb55061df9a50b9f32a4b0ff61c7c61c51e966fcd"
    "c891799a39ee0b7278f204a2b45a7e615080ff8f69f668e05adcf3486b319f80"
    "f9da814d9b86b16a3e68b4ce514ab5591112838a68dc3bfdcc4043a5aa8de52c"
    "ae936847a271971ecaa188172692c13f3b0321239c90559f3b7ba91e66d38ef4"
    "db4c75104ac5f2f15e55a463c49753a88e56906b1725fd3f0c1372beb16d4904"
    "752c74452b0c9f757ee12877a859dd0666cafaccbfc33fe67d98a89a2c12ef52"
    "5e4b16ea8972577dbfc567c2625a3eee6bcaa6cb4939b941f57236d1d57243f8"
    "c9766938269a8034d82fbd44044d2ee6a5c7275589afc3790b60280c0689900f";
constexpr char kTestVAEncryptionPublicKey[] =
    "c0c116e7ded8d7c1e577f9c8fb0d267c3c5c3e3b6800abb0309c248eaa5cd9bf"
    "91945132e4bb0111711356a388b756788e20bc1ecc9261ea9bcae8369cfd050e"
    "d8dc00b50fbe36d2c1c8a9b335f2e11096be76bebce8b5dcb0dc39ac0fd963b0"
    "51474f794d4289cc0c52d0bab451b9e69a43ecd3a84330b0b2de4365c038ffce"
    "ec0f1999d789615849c2f3c29d1d9ed42ccb7f330d5b56f40fb7cc6556190c3b"
    "698c20d83fb341a442fd69701fe0bdc41bdcf8056ccbc8d9b4275e8e43ec6b63"
    "c1ae70d52838dfa90a9cd9e7b6bd88ed3abf4fab444347104e30e635f4f296ac"
    "4c91939103e317d0eca5f36c48102e967f176a19a42220f3cf14634b6773be07";
constexpr char kTestVAEncryptionPublicKeyID[] = "\x00\xef\x22\x0f\xb0";

// Ignores the extra null-terminated element and converts only the effective
// part to std::string.
template <size_t size>
std::string ZeroTerminatedCharArrayToString(
    const char (&array)[size]) noexcept {
  CHECK_GE(size, 0);
  return std::string(std::begin(array), std::end(array) - 1);
}

}  // namespace

GoogleKeys ::GoogleKeys() {
  ca_encryption_keys_[attestation::DEFAULT_ACA].set_modulus_in_hex(
      kDefaultACAPublicKey);
  ca_encryption_keys_[attestation::DEFAULT_ACA].set_key_id(
      ZeroTerminatedCharArrayToString(kDefaultACAPublicKeyID));
  ca_encryption_keys_[attestation::TEST_ACA].set_modulus_in_hex(
      kTestACAPublicKey);
  ca_encryption_keys_[attestation::TEST_ACA].set_key_id(
      ZeroTerminatedCharArrayToString(kTestACAPublicKeyID));

  // No key_id for signing key.
  va_signing_keys_[attestation::DEFAULT_VA].set_modulus_in_hex(
      kDefaultVASigningPublicKey);
  va_signing_keys_[attestation::TEST_VA].set_modulus_in_hex(
      kTestVASigningPublicKey);

  va_encryption_keys_[attestation::DEFAULT_VA].set_modulus_in_hex(
      kDefaultVAEncryptionPublicKey);
  va_encryption_keys_[attestation::DEFAULT_VA].set_key_id(
      ZeroTerminatedCharArrayToString(kDefaultVAEncryptionPublicKeyID));
  va_encryption_keys_[attestation::TEST_VA].set_modulus_in_hex(
      kTestVAEncryptionPublicKey);
  va_encryption_keys_[attestation::TEST_VA].set_key_id(
      ZeroTerminatedCharArrayToString(kTestVAEncryptionPublicKeyID));
}

GoogleKeys::GoogleKeys(const DefaultGoogleRsaPublicKeySet& default_key_set)
    : GoogleKeys() {
  ca_encryption_keys_[attestation::DEFAULT_ACA] =
      default_key_set.default_ca_encryption_key();
  va_signing_keys_[attestation::DEFAULT_VA] =
      default_key_set.default_va_signing_key();
  va_encryption_keys_[attestation::DEFAULT_VA] =
      default_key_set.default_va_encryption_key();
}

const GoogleRsaPublicKey& GoogleKeys ::ca_encryption_key(
    ACAType aca_type) const {
  CHECK(static_cast<int>(aca_type) < ACAType_ARRAYSIZE);
  return ca_encryption_keys_[aca_type];
}
const GoogleRsaPublicKey& GoogleKeys::va_signing_key(VAType va_type) const {
  CHECK(static_cast<int>(va_type) < VAType_ARRAYSIZE);
  return va_signing_keys_[va_type];
}
const GoogleRsaPublicKey& GoogleKeys::va_encryption_key(VAType va_type) const {
  CHECK(static_cast<int>(va_type) < VAType_ARRAYSIZE);
  return va_encryption_keys_[va_type];
}

}  // namespace attestation
