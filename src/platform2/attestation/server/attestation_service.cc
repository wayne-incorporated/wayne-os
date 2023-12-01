// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "attestation/server/attestation_service.h"

#include <algorithm>
#include <climits>
#include <iterator>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include <attestation/proto_bindings/attestation_ca.pb.h>
#include <base/check.h>
#include <base/check_op.h>
#include <base/functional/bind.h>
#include <base/functional/callback.h>
#include <base/functional/callback_helpers.h>
#include <base/hash/sha1.h>
#include <base/logging.h>
#include <base/notreached.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/stringprintf.h>
#include <base/time/time.h>
#include <brillo/cryptohome.h>
#include <brillo/data_encoding.h>
#include <crypto/sha2.h>
#include <libhwsec/factory/factory_impl.h>
#include <libhwsec/frontend/attestation/frontend.h>
#include <libhwsec-foundation/status/status_chain_macros.h>
#include <libhwsec-foundation/tpm/tpm_version.h>
#include <openssl/objects.h>
#include <policy/device_policy.h>
#include <policy/libpolicy.h>
extern "C" {
#include <vboot/crossystem.h>
}

#include "attestation/common/database.pb.h"
#include "attestation/common/nvram_quoter_factory.h"
#include "attestation/common/tpm_utility_factory.h"
#include "attestation/server/attestation_flow.h"
#include "attestation/server/database_impl.h"
#include "attestation/server/google_keys.h"

using brillo::BlobFromString;
using brillo::BlobToString;
using hwsec::DeviceConfig;
using hwsec::TPMError;

namespace {

const size_t kNonceSize = 20;  // As per TPM_NONCE definition.
const int kNumTemporalValues = 5;

const char kKnownBootModes[8][3] = {{0, 0, 0}, {0, 0, 1}, {0, 1, 0}, {0, 1, 1},
                                    {1, 0, 0}, {1, 0, 1}, {1, 1, 0}, {1, 1, 1}};
const char kVerifiedBootMode[3] = {0, 0, 1};

// Default identity features for newly created identities.
constexpr int kDefaultIdentityFeatures =
    static_cast<int>(attestation::IDENTITY_FEATURE_ENTERPRISE_ENROLLMENT_ID);

// Context name to derive stable secret for attestation-based enterprise
// enrollment.
const char kAttestationBasedEnterpriseEnrollmentContextName[] =
    "attestation_based_enrollment";

struct CertificateAuthority {
  const char* issuer;
  const char* modulus;  // In hex format.
};

const CertificateAuthority kKnownEndorsementCA[] = {
    {"IFX TPM EK Intermediate CA 06",
     "de9e58a353313d21d683c687d6aaaab240248717557c077161c5e515f41d8efa"
     "48329f45658fb550f43f91d1ba0c2519429fb6ef964f89657098c90a9783ad6d"
     "3baea625db044734c478768db53b6022c556d8174ed744bd6e4455665715cd5c"
     "beb7c3fcb822ab3dfab1ecee1a628c3d53f6085983431598fb646f04347d5ae0"
     "021d5757cc6e3027c1e13f10633ae48bbf98732c079c17684b0db58bd0291add"
     "e277b037dd13fa3db910e81a4969622a79c85ac768d870f079b54c2b98c856e7"
     "15ef0ba9c01ee1da1241838a1307fe94b1ddfa65cdf7eeaa7e5b4b8a94c3dcd0"
     "29bb5ebcfc935e56641f4c8cb5e726c68f9dd6b41f8602ef6dc78d870a773571"},
    {"IFX TPM EK Intermediate CA 07",
     "f04c9b5b9f3cbc2509179f5e0f31dceb302900f528458e002c3e914d6b29e5e0"
     "924b0bcab2dd053f65d9d4a8eea8269c85c419dba640a88e14dc5f8c8c1a4269"
     "7a5ac4594b36f923110f91d1803d385540c01a433140b06054c77a144ee3a6a6"
     "5950c20f9215be3473b1002eb6b1756a22fbc18d21efacbbc8c270c66cf74982"
     "e24f057825cab51c0dd840a4f2d059032239c33e3f52c6ca06fe49bf4f60cc28"
     "a0fb1173d2ee05a141d30e8ffa32dbb86c1aeb5b309f76c2e462965612ec929a"
     "0d3b04acfa4525912c76f765e948be71f505d619cc673a889f0ed9e1d75f237b"
     "7af6a68550253cb4c3a8ff16c8091dbcbdea0ff8eee3d5bd92f49c53c5a15c93"},
    {"IFX TPM EK Intermediate CA 14",
     "D5B2EB8F8F23DD0B5CA0C15D4376E27A0380FD8EB1E52C2C270D961E8C0F66FD"
     "62E6ED6B3660FFBD8B0735179476F5E9C2EA4C762F5FEEDD3B5EB91785A724BC"
     "4C0617B83966336DD9DC407640871BF99DF4E1701EB5A1F5647FC57879CBB973"
     "B2A72BABA8536B2646A37AA5B73E32A4C8F03E35C8834B391AD363F1F7D1DF2B"
     "EE39233F47384F3E2D2E8EF83C9539B4DFC360C8AEB88B6111E757AF646DC01A"
     "68DAA908C7F8068894E9E991C59005068DD9B0F87113E6A80AB045DB4C1B23FF"
     "38A106098C2E184E1CF42A43EA68753F2649999048E8A3C3406032BEB1457070"
     "BCBE3A93E122638F6F18FF505C35FB827CE5D0C12F27F45C0F59C8A4A8697849"},
    {"IFX TPM EK Intermediate CA 16",
     "B98D42D5284620036A6613ED05A1BE11431AE7DE435EC55F72814652B9265EC2"
     "9035D401B538A9C84BB5B875450FAE8FBEDEF3430C4108D8516404F3DE4D4615"
     "2F471013673A7C7F236304C7363B91C0E0FD9FC7A9EC751521A60A6042839CF7"
     "7AEDE3243D0F51F47ACC39676D236BD5298E18B9A4783C60B2A1CD1B32124909"
     "D5844649EE4539D6AA05A5902C147B4F062D5145708EAE224EC65A8B51D7A418"
     "6327DA8F3B9E7C796F8B2DB3D2BDB39B829BDEBA8D2BF882CBADDB75D76FA8FA"
     "313682688BCD2835533A3A68A4AFDF7E597D8B965402FF22A5A4A418FDB4B549"
     "F218C3908E66BDCEAB3E2FE5EE0A4A1D9EB41A286ED07B6C112581FDAEA088D9"},
    {"IFX TPM EK Intermediate CA 17",
     "B0F3CC6F02E8C0486501102731069644A815F631ED41676C05CE3F7E5E5E40DF"
     "B3BF6D99787F2A9BE8F8B8035C03D5C2226072985230D4CE8407ACD6403F72E1"
     "A4DBF069504E56FA8C0807A704526EAC1E379AE559EB4BBAD9DB4E652B3B14E5"
     "38497A5E7768BCE0BFFAF800C61F1F2262775C526E1790A2BECF9A072A58F6A0"
     "F3042B5279FE9957BCADC3C9725428B66B15D5263F00C528AC47716DE6938199"
     "0FF23BC28F2C33B72D89B5F8EEEF9053B60D230431081D656EA8EC16C7CEFD9E"
     "F5A9061A3C921394D453D9AC77397D59B4C3BAF258266F65559469C3007987D5"
     "A8338E10FC54CD930303C37007D6E1E6C63F36BCFBA1E494AFB3ECD9A2407FF9"},
    {"IFX TPM EK Intermediate CA 21",
     "8149397109974D6C0850C8A60304ED7D209B1B88F435B695394DAD9FB4E64180"
     "02A3940966D2F04103C88659600EEA8E2A5C697C5F989F62D33A06DA10B50075"
     "F37F3CE6AD070413A0E109E16FE652B393C4DAFC5579CCB9915E9A70F5C05BCE"
     "0D341D6B887F43C4334BD8EC6A293FFAB737F77A45069CD0345D3D534E84D029"
     "029C37A267C0CC2D8DCE3E2C76F21A40F5D8D463882A8CBB92D8235685266753"
     "E8F051E78B681E87810A5B21EF719662A8208DFD94C55A126A112E39E0D732D7"
     "3C599095FAFF52BBC0E8C5B3DCD904D05DE00D5C5112F3DF7B76602ABE5DC0F8"
     "F89B55889A24C54EDBA1234AE498BE9B02CB5C8048D1DC90210705BAFC0E2837"},
    {"IFX TPM EK Intermediate CA 29",
     "cd424370776890ace339c62d7faae843bb2c765d27685c0441d278361a929062"
     "b4c95cc57213c864e91cbb92b1151f17a346a4e754c666f2a3e07ea9ffb9c80f"
     "e54d9479f73458c64bf7b0ca4e38821dd318e82d6fe387903ca73ca3e59db48e"
     "fe3b3c7c89599be87bb5e439a6f5843a412d4a321f154955448b71ca0b5fda47"
     "5c86a1c999dde7a01aa16436e65f0b04874c0db3970546bd806157058c5576a5"
     "c00b2bce7173c887f388dc4d5267c68fa5c47fcee3d8491071cd7742d43162cb"
     "285f5ba5e0daa0e910fdce566c5bbf7b3701d51660090344195fd7278456bd98"
     "48382fc5fceaebf93a2ec88c5722723519692e90d23f869c34d8b1af499d4127"},
    {"IFX TPM EK Intermediate CA 30",
     "a01cc43c4b66076d483086d0713a336f435e33ed23d3cda05f3c60a6f707416a"
     "9e53f0ef0de62c82a720e9ad94df29805b56b44279fd7389de4c60d498c81e3b"
     "a27692a045d993e9aaae152768588e5c62213721154529c95b09b201bcb3e573"
     "3d98e398d6e05215867d94e3d222e5b7df9f948c14533285821658b282be4bd7"
     "fe7197baa642f556d4f18738adef26b2eebfc64045cf4c5dcbff661aa95429f4"
     "e2c4921a8723bd8116f0efc038cd4530bb6e9299b7d70327e3fe8790d3d6db3a"
     "ebd3ccd12aef3d43cf89463a28ad1306a9d430b08c3411bfeeda63b9fdcc9a23"
     "1ff5cc203a7f5ee713d50e1930add1cd32ff64637fc740edb63380a5e6725381"},
    {"IFX TPM EK Intermediate CA 49",
     "b0bd7dd4a197edae12edeb5c98a31f57af00142ca98ed9d412e1a1e8c3d1f81b"
     "c152936ee6b1259cb49a870f358a7dca0c98d866df332727e6f897edcac5ea14"
     "2ec2be2f0bb814a72d5986dead0ad20ecefa492966c1ca44fefb0533c311783c"
     "d48d3f4027b996b6703d110a257d4bd0326f09e8f928020a6b953de4fb8f1dcb"
     "ec3eaa6142f6068c38b4c8e41e85444965a04dfe64cc2ea1c09e374cfd1f4d4d"
     "a76f31b57057ae79a803a8e96f5fd158920928ebcf1ff0fee75abce44ade9e71"
     "56122cc4a11a4baa0ddf73f926ae58743b493d8c4bc8a393018041b543d8b223"
     "d294de1d4fe8ec8f4d4e84646d1b6b78deadd34e507cccf472de1ca9ed0455bb"},
    {"NTC TPM EK Root CA 01",
     "e836ac61b43e3252d5e1a8a4061997a6a0a272ba3d519d6be6360cc8b4b79e8c"
     "d53c07a7ce9e9310ca84b82bbdad32184544ada357d458cf224c4a3130c97d00"
     "4933b5db232d8b6509412eb4777e9e1b093c58b82b1679c84e57a6b218b4d61f"
     "6dd4c3a66b2dd33b52cb1ffdff543289fa36dd71b7c83b66c1aae37caf7fe88d"
     "851a3523e3ea92b59a6b0ca095c5e1d191484c1bff8a33048c3976e826d4c12a"
     "e198f7199d183e0e70c8b46e8106edec3914397e051ae2b9a7f0b4bb9cd7f2ed"
     "f71064eb0eb473df27b7ccef9a018d715c5fe6ab012a8315f933c7f4fc35d34c"
     "efc27de224b2e3de3b3ba316d5df8b90b2eb879e219d270141b78dbb671a3a05"},
    {"STM TPM EK Intermediate CA 03",
     "a5152b4fbd2c70c0c9a0dd919f48ddcde2b5c0c9988cff3b04ecd844f6cc0035"
     "6c4e01b52463deb5179f36acf0c06d4574327c37572292fcd0f272c2d45ea7f2"
     "2e8d8d18aa62354c279e03be9220f0c3822d16de1ea1c130b59afc56e08f22f1"
     "902a07f881ebea3703badaa594ecbdf8fd1709211ba16769f73e76f348e2755d"
     "bba2f94c1869ef71e726f56f8ece987f345c622e8b5c2a5466d41093c0dc2982"
     "e6203d96f539b542347a08e87fc6e248a346d61a505f52add7f768a5203d70b8"
     "68b6ec92ef7a83a4e6d1e1d259018705755d812175489fae83c4ab2957f69a99"
     "9394ac7a243a5c1cd85f92b8648a8e0d23165fdd86fad06990bfd16fb3293379"},
    {"CROS TPM DEV EK ROOT CA",
     "cdc108745dc50dd6a1098c31486fb31578607fd64f64b0d91b994244ca1a9a69"
     "a74c6bccc7f24923e1513e132dc0d9dbcb1b22089299bb6cb669cbf4b704c992"
     "27bb769fa1f91ab11f67fb464a065b34b1a0e824136af5e59d1ac04bda22c199"
     "9f7a5b34bd6b50c81b4a88cc097d4dfeb4dc695096463d9529d69f116e2a26de"
     "070ef3118287072bdbe94466b8737049809bb8e1276b245930051b2bbbad71dd"
     "20d26349d1d83cdb2ff9c65251a17dae4f400ecc3e77f89e27a75fe0709dc81f"
     "e172008a3e65de685d9df43e036c557e88f1a9aedf7a91644391523d9728f946"
     "45c0e8adaf37e9a15777021ad43b675583302402912d66233c59ad05fa3b34ed"},
    {"CROS TPM PRD EK ROOT CA",
     "bd6f0198ffa7f7d20c15f81642096e335e2cd74734f73008265fc9957bbe018d"
     "fbac0d2a0ea99f5fb7bbff6f0d367b81199e837c390527972aa5392c2ca0f2a3"
     "506ee7d4a938f47158a7c56a390df2b781344a82b885a62f1de78f37ec105749"
     "69d8abf3163f0cf5c67fa05dd4fb3eb07a7571888b7a87ed57735ce476156bf7"
     "d6eff6cb8c8b303c21ebfe0e11b660edbdf903c70ac16927345d0b38c72f1e60"
     "1460743584f5a3eaef303dbc5cfda48e4c7a1f338108c7f0c70a694f814b6691"
     "ba9d058ab988152bb7097a010e400462187811c3e062001bce8aa808db485bd8"
     "2f7f0e1e2a2ddb95c364dffea4c23e872fc3874c4756e85e6cf8eca6eb6a07bf"},
    {"Infineon OPTIGA(TM) TPM 2.0 RSA CA 055",
     "9e502b0e792c885d628ad9ddd9268afbae74b00fc6c65a607dd528b5136dc2f5"
     "dbb932ca9b6613e39fd648460a438229adc3b7c40998519d99386c5dccab49bf"
     "d06a5b82d24b596bc890274e40ad7018f34f39c9b3e6b7f8d5eac264d243e5f9"
     "054d0f26ecb75e45dd4e25b3d6ef606b3a646a593b3e4841bb7de7519489c560"
     "2442aeef11ab30c211f4706ab39c2cbbcf2ad2f8d6b2a1517298a37cd12f24e5"
     "f8e4f7c8adb19faa3420592ce368ae599affbb97daad11a2baccd7c1714ca8e0"
     "c6620434771b12005c51f25ee32383e6fa5f4b0ba6248e27fb57c6ff22b12b3c"
     "52c2cb774bd6a86ca2c7f1f24ee4e2c06e3e215f61d5a9462cf3c45f2b1f2c13"},
    // TODO(b/183476655): Remove this once we don't care about FW-upgraded
    // chips.
    {"Infineon OPTIGA(TM) RSA Manufacturing CA 034",
     "c8b75bd5398fe9f84495140cab9be80cac0529985a71b475f06a77134d4af6ce"
     "1872c7569f07181e1b6fed0fcb1e4a48dd66a64553934ca54ee4865527f3dffc"
     "89e6ef5c73d9f9457a8ad01a0caefe6ce5209f09c10bfccd96575fd56c14aeb9"
     "15d2d10d06f058571e5cc32577e6cfee0fdfded376e8468454e9295861d44511"
     "92ea1e81a15b72b209d524e487a949949ee191f771eb6fb1c0640aa4ea920ced"
     "c4b8783c177c7c02468ca67393859c7cc2d61aa1f2815dda51e930cc6b834095"
     "9bade2e0bb2e0d45c203f09bf6b661ce105af962ebf2d62714c153599a32a864"
     "24de5775b22f26aede04bdcb91725849c6cc90401d05d458fa896baf4588f8ef"},
    // TODO(b/183476655): Remove this once we don't care about FW-upgraded
    // chips.
    {"Infineon OPTIGA(TM) RSA Manufacturing CA 033",
     "a85eb214d5ef5c642dfc70ee8dfbd7b6fcc765692e5065fb3c0bfa049f456190"
     "5098cbba4ecb490d96233093d5393deb3660a0aeab79c1297b97755e03e477c9"
     "401e8c820aeed9143eaa11edd2a99a852d6e56ed8e7f9a0f594c432a6689a5b0"
     "3001b023ce22d9d1b045b429f755b89f6a69f593154397aec0c8d2b296cb1fe7"
     "f6c27bd717537ac1210b79557e3f6fd5de589223f7780a3af4cc9d8d1526348c"
     "d3e0b41578cd9309d578668b18912626f764b5e334be9b1532aaf09c4effd31a"
     "228723fd91c61d3f2f07852ce6bc33ecddcf66dd583c04e6483f8d58791e86ae"
     "f12f156d9662d544e29795f79a2a750bf821c2465873db5c1dc26509490e4afd"},
};

struct CertificateAuthoritySubjectPublicKeyInfo {
  const char* issuer;
  const char* subject_public_key_info;
};

const CertificateAuthoritySubjectPublicKeyInfo
    kKnownEndorsementCASubjectKeyInfo[] = {
        {"Infineon OPTIGA(TM) TPM 2.0 ECC CA 055",
         "3059301306072a8648ce3d020106082a8648ce3d03010703420004c84758541d"
         "d419adcfec8e9868ba4b59755a7c1e3bcf892d11e7bd0afe9714de3043063afe"
         "9face5b5d53ebcabc3de7df2a67726fde0a7f1f4c1ed070e942e92"},
        // TODO(b/183476655): Remove this once we don't care about FW-upgraded
        // chips.
        {"Infineon OPTIGA(TM) ECC Manufacturing CA 034",
         "3059301306072a8648ce3d020106082a8648ce3d030107034200042c43929137"
         "299e67555a9f947c2f17a6412e8d0ad5a50b8e91475ac49c7861520b0711fa7a"
         "e1ea0194a8f4d31fbcd1d36b940b3a6d66dc34092dac5655ff49c7"},
        // TODO(b/183476655): Remove this once we don't care about FW-upgraded
        // chips.
        {"Infineon OPTIGA(TM) ECC Manufacturing CA 033",
         "3059301306072a8648ce3d020106082a8648ce3d030107034200048e72217be0"
         "16b33242092808a77dc4ec9671ceda85525748d6522455a3c61504afe1a21e12"
         "7876b346b6c89a84f1bd0e0343abcbc1617a1fbe2dbfd0bf18ce3e"},
        {"CROS D2 CIK",
         "3059301306072a8648ce3d020106082a8648ce3d030107034200040f1ad2760b"
         "e780f36e57eee5a942ab5b153513b2117c74bb6e523216fb08afb008a09bdc7e"
         "d59dadb62a2b08322f118245193bb117065c9a77fc732e86846bb3"},
        {"CROS D2 CIK",
         "3059301306072a8648ce3d020106082a8648ce3d03010703420004a011d8302f"
         "e79d51c4a8d30f45411c8b3afe5218e25f0f1efa97e568a6d98b847f3df336bc"
         "3948bb9d584f6c2dd80442b62c9bddece8472d0044b7d5c1083d73"},
};

const CertificateAuthority kKnownCrosCoreEndorsementCA[] = {
    {"IFX TPM EK Intermediate CA 24",
     "9D3F39677EBDB7B95F383021EA6EF90AD2BEA4E38B10CA65DCD84D0B33D400FA"
     "E7E56FC553975FDADD425227F055C029B6544331E3BA50ED33F6CC02D833EA4E"
     "0EECFE9AD1ADD7095F3A804C560F031E8705A3AD5189CBD62678B5B8205C37ED"
     "780A3EDE8DE64A08980C048872E789937A49FC4048EADCAC9B3FD0F0DD085E76"
     "30DDF9C0C31EFF3B77C6C3601AA7C3DCD10F08616C01435697746A61F920335C"
     "0C45A41149F5D22FCD23DBE35003A9AF7FD91C18715E3709F86A38AB149113C4"
     "D5273C3C90599734FF627ACBF408B082C76E486091F27446E175C50D340DA0FE"
     "5C3FE3D590B8729F4E364E5BF7D854D9AE28EFBCD0CE8F19E6462B3A593983DF"},
    {"IFX TPM EK Intermediate CA 50",
     "ACB01856664D0C81B545DB926D25019FC2D06B4A97DFB91FD7A5AB1A803AA6F4"
     "12FEEE5E3DEF3634172F1271E893C6848B4D156485917DF6F0504947B39F0A5A"
     "E14FFBAB9FF00E70448E51F11DEEA1EA16287ABAAE05D3D00FEB1AA064F1CBD9"
     "E1E67C057087110F9D3023BFA0545C97BD51E473C5B183E50C2984BD9A2DA39B"
     "7D028B895BD939FF0822595DDC948640D06E57ED72EF43B8D8071D2C3C0497A0"
     "EC52F682D1637F06979733BAF56DD809D24C20354D73D3849A1C0DAD23AD5CCB"
     "F8C679242D13FFFE055CC2AB2692897F0329EEA55AF3BB10A4EB4E2937601196"
     "90D64FB352E3D34E05AB53BD4E01EFE3EF56F6DBE315B76A31B0100BF7096093"},
};

// Default D-Bus call timeout.
constexpr base::TimeDelta kPcaAgentDBusTimeout = base::Minutes(2);

// Returns a human-readable description for a known 3-byte |mode|.
std::string GetDescriptionForMode(const char* mode) {
  return base::StringPrintf(
      "Developer Mode: %s, Recovery Mode: %s, Firmware Type: %s",
      mode[0] ? "On" : "Off", mode[1] ? "On" : "Off",
      mode[2] ? "Verified" : "Developer");
}

std::string GetHardwareID() {
  char buffer[VB_MAX_STRING_PROPERTY];

  if (VbGetSystemPropertyString("hwid", buffer, std::size(buffer)) == 0) {
    return std::string(buffer);
  }
  LOG(WARNING) << "Could not read hwid property.";
  return std::string();
}

// Finds CA by |issuer_name| and |is_cros_core| flag. On success returns true
// and fills |public_key_hex| with CA public key hex modulus.
bool GetAuthorityPublicKey(const std::string& issuer_name,
                           bool is_cros_core,
                           std::string* public_key_hex) {
  const CertificateAuthority* const kKnownCA =
      is_cros_core ? kKnownCrosCoreEndorsementCA : kKnownEndorsementCA;
  const int kNumIssuers = is_cros_core ? std::size(kKnownCrosCoreEndorsementCA)
                                       : std::size(kKnownEndorsementCA);
  for (int i = 0; i < kNumIssuers; ++i) {
    if (issuer_name == kKnownCA[i].issuer) {
      public_key_hex->assign(kKnownCA[i].modulus);
      return true;
    }
  }
  return false;
}

std::string GetACAName(attestation::ACAType aca_type) {
  switch (aca_type) {
    case attestation::DEFAULT_ACA:
      return "the default ACA";
    case attestation::TEST_ACA:
      return "the test ACA";
    default:
      return "ACA " + base::NumberToString(static_cast<uint32_t>(aca_type));
  }
}

std::string GetIdentityFeaturesString(int identity_features) {
  std::string feature_str;
  switch (identity_features) {
    case attestation::NO_IDENTITY_FEATURES:
      return "NO_IDENTITY_FEATURES";
    case attestation::IDENTITY_FEATURE_ENTERPRISE_ENROLLMENT_ID:
      return "IDENTITY_FEATURE_ENTERPRISE_ENROLLMENT_ID";
    default:
      LOG(WARNING) << __func__
                   << ":Unexpected feature code: " << identity_features;
      return "(" + base::NumberToString(identity_features) + ")";
  }
}

std::string GetKeyTypeName(attestation::KeyType key_type) {
  switch (key_type) {
    case attestation::KEY_TYPE_ECC:
      return "ECC";
    case attestation::KEY_TYPE_RSA:
      return "RSA";
  }
  return "unknown";
}

void LogErrorFromCA(const std::string& func,
                    const std::string& details,
                    const std::string& extra_details) {
  std::ostringstream stream;
  stream << func << ": Received error from Attestation CA";
  if (!details.empty()) {
    stream << ": " << details;
    if (!extra_details.empty()) {
      stream << ". Extra details: " << extra_details;
    }
  }
  LOG(ERROR) << stream.str() << ".";
}

template <typename RequestType>
std::optional<attestation::DeviceSetupCertificateRequestMetadata>
GetDeviceSetupCertificateRequestMetadataIfPresent(const RequestType& request) {
  if (request.metadata_case() !=
      RequestType::MetadataCase::kDeviceSetupCertificateRequestMetadata) {
    return std::nullopt;
  }

  return std::optional(request.device_setup_certificate_request_metadata());
}

}  // namespace

namespace attestation {

namespace {

DeviceConfig kDeviceConfigsToQuote[] = {
    DeviceConfig::kBootMode,
    DeviceConfig::kDeviceModel,
};

pca_agent::EnrollRequest ToPcaAgentEnrollRequest(
    const AttestationFlowData& data) {
  pca_agent::EnrollRequest ret;
  ret.set_aca_type(data.aca_type());
  ret.set_request(data.result_request());
  return ret;
}

pca_agent::GetCertificateRequest ToPcaAgentCertRequest(
    const AttestationFlowData& data) {
  pca_agent::GetCertificateRequest ret;
  ret.set_aca_type(data.aca_type());
  ret.set_request(data.result_request());
  return ret;
}

constexpr KeyUsage GetKeyUsageByProfile(CertificateProfile profile) {
  return profile == ENTERPRISE_VTPM_EK_CERTIFICATE ? KEY_USAGE_DECRYPT
                                                   : KEY_USAGE_SIGN;
}

constexpr KeyRestriction GetKeyRestrictionByProfile(
    CertificateProfile profile) {
  return profile == ENTERPRISE_VTPM_EK_CERTIFICATE
             ? KeyRestriction::kRestricted
             : KeyRestriction::kUnrestricted;
}

}  // namespace
using QuoteMap = google::protobuf::Map<int, Quote>;

const size_t kChallengeSignatureNonceSize = 20;  // For all TPMs.

AttestationService::AttestationService(brillo::SecureBlob* abe_data,
                                       const std::string& attested_device_id)
    : abe_data_(abe_data),
      attested_device_id_(attested_device_id),
      weak_factory_(this) {}

AttestationService::~AttestationService() {
  // Stop the worker thread before we destruct it.
  if (worker_thread_) {
    worker_thread_->Stop();
  }
}

bool AttestationService::Initialize() {
  return InitializeWithCallback(base::DoNothing());
}

bool AttestationService::InitializeWithCallback(
    InitializeCompleteCallback callback) {
  if (!worker_thread_) {
    worker_thread_.reset(new ServiceWorkerThread(this));
    worker_thread_->StartWithOptions(
        base::Thread::Options(base::MessagePumpType::IO, 0));
    LOG(INFO) << "Attestation service started.";
  }
  // Creates |default_pca_agent_proxy_| here if needed; unlike other objects,
  // |default_pca_agent_proxy_| is used in the origin thread instead of worker
  // thread.
  if (!pca_agent_proxy_) {
    if (!bus_) {
      dbus::Bus::Options options;
      options.bus_type = dbus::Bus::SYSTEM;
      options.dbus_task_runner = worker_thread_->task_runner();
      bus_ = base::MakeRefCounted<dbus::Bus>(options);
    }
    default_pca_agent_proxy_ =
        std::make_unique<org::chromium::PcaAgentProxy>(bus_);
    pca_agent_proxy_ = default_pca_agent_proxy_.get();
  }
  worker_thread_->task_runner()->PostTask(
      FROM_HERE, base::BindOnce(&AttestationService::InitializeTask,
                                base::Unretained(this), std::move(callback)));
  return true;
}

void AttestationService::InitializeTask(InitializeCompleteCallback callback) {
  if (!tpm_utility_) {
    default_tpm_utility_.reset(TpmUtilityFactory::New());
    CHECK(default_tpm_utility_->Initialize());
    tpm_utility_ = default_tpm_utility_.get();
  }
  if (!hwsec_factory_) {
    default_hwsec_factory_ = std::make_unique<hwsec::FactoryImpl>();
    hwsec_factory_ = default_hwsec_factory_.get();
  }
  if (!hwsec_) {
    default_hwsec_ = hwsec_factory_->GetAttestationFrontend();
    hwsec_ = default_hwsec_.get();
  }
  if (!nvram_quoter_) {
    default_nvram_quoter_.reset(NvramQuoterFactory::New(*tpm_utility_));
    nvram_quoter_ = default_nvram_quoter_.get();
  }
  if (!crypto_utility_) {
    default_crypto_utility_.reset(new CryptoUtilityImpl(tpm_utility_, hwsec_));
    crypto_utility_ = default_crypto_utility_.get();
  }

  bool existing_database;
  if (database_) {
    existing_database = true;
  } else {
    default_database_.reset(new DatabaseImpl(crypto_utility_, hwsec_));
    existing_database = default_database_->Initialize();
    database_ = default_database_.get();
  }
  if (existing_database && MigrateAttestationDatabase()) {
    if (!database_->SaveChanges()) {
      LOG(WARNING) << "Attestation: Failed to persist database changes.";
    }
  }
  if (!key_store_) {
    pkcs11_token_manager_.reset(new chaps::TokenManagerClient());
    default_key_store_.reset(new Pkcs11KeyStore(pkcs11_token_manager_.get()));
    key_store_ = default_key_store_.get();
  }
  if (hwid_.empty()) {
    hwid_ = GetHardwareID();
  }
  if (!IsPreparedForEnrollment()) {
    worker_thread_->task_runner()->PostTask(
        FROM_HERE, base::BindOnce(&AttestationService::PrepareForEnrollment,
                                  base::Unretained(this), std::move(callback)));
  } else {
    // Ignore errors. If failed this time, will be re-attempted on next boot.
    tpm_utility_->RemoveOwnerDependency();
    std::move(callback).Run(true);
  }
}

bool AttestationService::MigrateAttestationDatabase() {
  bool migrated = false;

  auto* database_pb = database_->GetMutableProtobuf();
  if (database_pb->has_credentials()) {
    if (!database_pb->credentials().encrypted_endorsement_credentials().count(
            DEFAULT_ACA) &&
        database_pb->credentials()
            .has_default_encrypted_endorsement_credential()) {
      LOG(INFO) << "Attestation: Migrating endorsement credential for "
                << GetACAName(DEFAULT_ACA) << ".";
      (*database_pb->mutable_credentials()
            ->mutable_encrypted_endorsement_credentials())[DEFAULT_ACA] =
          database_pb->credentials().default_encrypted_endorsement_credential();
      migrated = true;
    }
    if (!database_pb->credentials().encrypted_endorsement_credentials().count(
            TEST_ACA) &&
        database_pb->credentials()
            .has_test_encrypted_endorsement_credential()) {
      LOG(INFO) << "Attestation: Migrating endorsement credential for "
                << GetACAName(TEST_ACA) << ".";
      (*database_pb->mutable_credentials()
            ->mutable_encrypted_endorsement_credentials())[TEST_ACA] =
          database_pb->credentials().test_encrypted_endorsement_credential();
      migrated = true;
    }
  }

  // Migrate identity data if needed.
  migrated |= MigrateIdentityData();

  if (migrated) {
    EncryptAllEndorsementCredentials();
    LOG(INFO) << "Attestation: Migrated attestation database.";
  }

  // Migrate Rsa PublicKey Format to SubjectPublicKeyInfo
  if (database_pb->credentials().has_legacy_endorsement_public_key()) {
    std::string public_key_info;
    if (GetSubjectPublicKeyInfo(
            database_pb->credentials().endorsement_key_type(),
            database_pb->credentials().legacy_endorsement_public_key(),
            &public_key_info)) {
      database_pb->mutable_credentials()->set_endorsement_public_key(
          public_key_info);
    } else {
      // If the format conversion fails, that means the EK public key is broken
      // somehow, which should not happen. If it does, that means EK data
      // becomes invalid. Clean up all EK metadata to resolve this problem.
      LOG(ERROR) << __func__ << ": Migrate public format fail.";
      database_pb->mutable_credentials()->clear_endorsement_key_type();
      database_pb->mutable_credentials()->clear_endorsement_credential();
    }
    database_pb->mutable_credentials()->clear_legacy_endorsement_public_key();
    migrated |= true;
  }

  return migrated;
}

bool AttestationService::MigrateIdentityData() {
  auto* database_pb = database_->GetMutableProtobuf();
  if (database_pb->identities().size() > 0) {
    // We already migrated identity data.
    return false;
  }

  bool error = false;

  // The identity we're creating will have the next index in identities.
  LOG(INFO) << "Attestation: Migrating existing identity into identity "
            << database_pb->identities().size() << ".";
  CHECK(database_pb->identities().size() == kFirstIdentity);
  AttestationDatabase::Identity* identity_data =
      database_pb->mutable_identities()->Add();
  identity_data->set_features(IDENTITY_FEATURE_ENTERPRISE_ENROLLMENT_ID);
  if (database_pb->has_identity_binding()) {
    identity_data->mutable_identity_binding()->CopyFrom(
        database_pb->identity_binding());
  }
  if (database_pb->has_identity_key()) {
    identity_data->mutable_identity_key()->CopyFrom(
        database_pb->identity_key());
    identity_data->mutable_identity_key()->clear_identity_credential();
    if (database_pb->identity_key().has_identity_credential()) {
      // Create an identity certificate for this identity and the default ACA.
      AttestationDatabase::IdentityCertificate identity_certificate;
      identity_certificate.set_identity(kFirstIdentity);
      identity_certificate.set_aca(DEFAULT_ACA);
      identity_certificate.set_identity_credential(
          database_pb->identity_key().identity_credential());
      auto* map = database_pb->mutable_identity_certificates();
      auto in = map->insert(IdentityCertificateMap::value_type(
          DEFAULT_ACA, identity_certificate));
      if (!in.second) {
        LOG(ERROR) << "Attestation: Could not migrate existing identity.";
        error = true;
      }
    }
    if (database_pb->identity_key().has_enrollment_id()) {
      database_->GetMutableProtobuf()->set_enrollment_id(
          database_pb->identity_key().enrollment_id());
    }
  }

  if (database_pb->has_pcr0_quote()) {
    auto in = identity_data->mutable_pcr_quotes()->insert(
        QuoteMap::value_type(0, database_pb->pcr0_quote()));
    if (!in.second) {
      LOG(ERROR) << "Attestation: Could not migrate existing identity.";
      error = true;
    }
  } else {
    LOG(ERROR) << "Attestation: Missing PCR0 quote in existing database.";
    error = true;
  }
  if (database_pb->has_pcr1_quote()) {
    auto in = identity_data->mutable_pcr_quotes()->insert(
        QuoteMap::value_type(1, database_pb->pcr1_quote()));
    if (!in.second) {
      LOG(ERROR) << "Attestation: Could not migrate existing identity.";
      error = true;
    }
  } else {
    LOG(ERROR) << "Attestation: Missing PCR1 quote in existing database.";
    error = true;
  }

  if (error) {
    database_pb->mutable_identities()->RemoveLast();
    database_pb->mutable_identity_certificates()->erase(DEFAULT_ACA);
  }

  return !error;
}

void AttestationService::ShutdownTask() {
  database_ = nullptr;
  default_database_.reset(nullptr);
  crypto_utility_ = nullptr;
  default_crypto_utility_.reset(nullptr);
  tpm_utility_ = nullptr;
  default_tpm_utility_.reset(nullptr);
  if (bus_) {
    bus_->ShutdownAndBlock();
  }
}

void AttestationService::GetFeatures(const GetFeaturesRequest& request,
                                     GetFeaturesCallback callback) {
  auto result = std::make_shared<GetFeaturesReply>();
  base::OnceClosure task =
      base::BindOnce(&AttestationService::GetFeaturesTask,
                     base::Unretained(this), request, result);
  base::OnceClosure reply =
      base::BindOnce(&AttestationService::TaskRelayCallback<GetFeaturesReply>,
                     GetWeakPtr(), std::move(callback), result);
  worker_thread_->task_runner()->PostTaskAndReply(FROM_HERE, std::move(task),
                                                  std::move(reply));
}

void AttestationService::GetFeaturesTask(
    const GetFeaturesRequest& request,
    const std::shared_ptr<GetFeaturesReply>& result) {
  result->set_is_available(false);
  for (const KeyType key_type : tpm_utility_->GetSupportedKeyTypes()) {
    result->set_is_available(true);
    *(result->mutable_supported_key_types()->Add()) = key_type;
  }
  result->set_status(STATUS_SUCCESS);
}

void AttestationService::GetKeyInfo(const GetKeyInfoRequest& request,
                                    GetKeyInfoCallback callback) {
  auto result = std::make_shared<GetKeyInfoReply>();
  base::OnceClosure task =
      base::BindOnce(&AttestationService::GetKeyInfoTask,
                     base::Unretained(this), request, result);
  base::OnceClosure reply =
      base::BindOnce(&AttestationService::TaskRelayCallback<GetKeyInfoReply>,
                     GetWeakPtr(), std::move(callback), result);
  worker_thread_->task_runner()->PostTaskAndReply(FROM_HERE, std::move(task),
                                                  std::move(reply));
}

void AttestationService::GetKeyInfoTask(
    const GetKeyInfoRequest& request,
    const std::shared_ptr<GetKeyInfoReply>& result) {
  CertifiedKey key;
  if (!FindKeyByLabel(request.username(), request.key_label(), &key)) {
    result->set_status(STATUS_INVALID_PARAMETER);
    return;
  }
  std::string public_key_info;
  if (!GetSubjectPublicKeyInfo(key.key_type(), key.public_key(),
                               &public_key_info)) {
    LOG(ERROR) << __func__ << ": Bad public key.";
    result->set_status(STATUS_UNEXPECTED_DEVICE_ERROR);
    return;
  }
  result->set_key_type(key.key_type());
  result->set_key_usage(key.key_usage());
  result->set_public_key(public_key_info);
  result->set_certify_info(key.certified_key_info());
  result->set_certify_info_signature(key.certified_key_proof());
  result->set_certified_key_credential(key.certified_key_credential());
  if (key.has_intermediate_ca_cert()) {
    result->set_certificate(CreatePEMCertificateChain(key));
  } else {
    result->set_certificate(key.certified_key_credential());
  }
  result->set_payload(key.payload());
}

void AttestationService::GetEndorsementInfo(
    const GetEndorsementInfoRequest& request,
    GetEndorsementInfoCallback callback) {
  auto result = std::make_shared<GetEndorsementInfoReply>();
  base::OnceClosure task =
      base::BindOnce(&AttestationService::GetEndorsementInfoTask,
                     base::Unretained(this), request, result);
  base::OnceClosure reply = base::BindOnce(
      &AttestationService::TaskRelayCallback<GetEndorsementInfoReply>,
      GetWeakPtr(), std::move(callback), result);
  worker_thread_->task_runner()->PostTaskAndReply(FROM_HERE, std::move(task),
                                                  std::move(reply));
}

std::optional<std::string> AttestationService::GetEndorsementPublicKey() const {
  const auto& database_pb = database_->GetProtobuf();
  if (database_pb.has_credentials() &&
      database_pb.credentials().has_endorsement_public_key()) {
    return database_pb.credentials().endorsement_public_key();
  }

  // Try to read the public key directly.
  std::string public_key;
  if (!tpm_utility_->GetEndorsementPublicKey(GetEndorsementKeyType(),
                                             &public_key)) {
    return std::nullopt;
  }
  return public_key;
}

std::optional<std::string> AttestationService::GetEndorsementCertificate()
    const {
  const auto& database_pb = database_->GetProtobuf();
  if (database_pb.has_credentials() &&
      database_pb.credentials().has_endorsement_credential()) {
    return database_pb.credentials().endorsement_credential();
  }

  // Try to read the certificate directly.
  std::string certificate;
  if (!tpm_utility_->GetEndorsementCertificate(GetEndorsementKeyType(),
                                               &certificate)) {
    return std::nullopt;
  }
  return certificate;
}

void AttestationService::GetEndorsementInfoTask(
    const GetEndorsementInfoRequest& request,
    const std::shared_ptr<GetEndorsementInfoReply>& result) {
  KeyType key_type = GetEndorsementKeyType();

  if (key_type != KEY_TYPE_RSA && key_type != KEY_TYPE_ECC) {
    result->set_status(STATUS_INVALID_PARAMETER);
    return;
  }

  std::optional<std::string> public_key = GetEndorsementPublicKey();
  if (!public_key.has_value()) {
    LOG(ERROR) << __func__ << ": Endorsement public key not available.";
    result->set_status(STATUS_NOT_AVAILABLE);
    return;
  }

  std::optional<std::string> certificate = GetEndorsementCertificate();
  if (!certificate.has_value()) {
    LOG(ERROR) << __func__ << ": Endorsement cert not available.";
    result->set_status(STATUS_UNEXPECTED_DEVICE_ERROR);
    return;
  }

  result->set_ek_public_key(public_key.value());
  result->set_ek_certificate(certificate.value());
  std::string hash = crypto::SHA256HashString(certificate.value());
  result->set_ek_info(
      base::StringPrintf("EK Certificate:\n%s\nHash:\n%s\n",
                         CreatePEMCertificate(certificate.value()).c_str(),
                         base::HexEncode(hash.data(), hash.size()).c_str()));
}

void AttestationService::GetAttestationKeyInfo(
    const GetAttestationKeyInfoRequest& request,
    GetAttestationKeyInfoCallback callback) {
  auto result = std::make_shared<GetAttestationKeyInfoReply>();
  base::OnceClosure task =
      base::BindOnce(&AttestationService::GetAttestationKeyInfoTask,
                     base::Unretained(this), request, result);
  base::OnceClosure reply = base::BindOnce(
      &AttestationService::TaskRelayCallback<GetAttestationKeyInfoReply>,
      GetWeakPtr(), std::move(callback), result);
  worker_thread_->task_runner()->PostTaskAndReply(FROM_HERE, std::move(task),
                                                  std::move(reply));
}

void AttestationService::GetAttestationKeyInfoTask(
    const GetAttestationKeyInfoRequest& request,
    const std::shared_ptr<GetAttestationKeyInfoReply>& result) {
  const int identity = kFirstIdentity;
  auto aca_type = request.aca_type();
  auto found = FindIdentityCertificate(identity, aca_type);
  if (found ==
      database_->GetMutableProtobuf()->mutable_identity_certificates()->end()) {
    LOG(ERROR) << __func__ << ": Identity " << identity
               << " is not enrolled for attestation with "
               << GetACAName(aca_type) << ".";
    result->set_status(STATUS_INVALID_PARAMETER);
    return;
  }
  const auto& identity_certificate = found->second;
  if (!IsPreparedForEnrollment() ||
      identity_certificate.identity() >=
          database_->GetProtobuf().identities().size()) {
    result->set_status(STATUS_NOT_AVAILABLE);
    return;
  }
  const auto& identity_pb = database_->GetProtobuf().identities().Get(
      identity_certificate.identity());
  if (!identity_pb.has_identity_key()) {
    result->set_status(STATUS_NOT_AVAILABLE);
    return;
  }
  if (identity_pb.identity_key().has_identity_public_key_der()) {
    // TODO(crbug/942487): Use SubjectPublicKeyInfo for identity_public_key_der
    std::string public_key_info;
    if (!GetSubjectPublicKeyInfo(
            identity_pb.identity_key().identity_key_type(),
            identity_pb.identity_key().identity_public_key_der(),
            &public_key_info)) {
      LOG(ERROR) << __func__ << ": Bad public key.";
      result->set_status(STATUS_UNEXPECTED_DEVICE_ERROR);
      return;
    }
    result->set_public_key(public_key_info);
  }
  if (identity_pb.has_identity_binding() &&
      identity_pb.identity_binding().has_identity_public_key_tpm_format()) {
    result->set_public_key_tpm_format(
        identity_pb.identity_binding().identity_public_key_tpm_format());
  }
  if (identity_certificate.has_identity_credential()) {
    result->set_certificate(identity_certificate.identity_credential());
  }
  if (identity_pb.pcr_quotes().count(0)) {
    *result->mutable_pcr0_quote() = identity_pb.pcr_quotes().at(0);
  }
  if (identity_pb.pcr_quotes().count(1)) {
    *result->mutable_pcr1_quote() = identity_pb.pcr_quotes().at(1);
  }
}

void AttestationService::ActivateAttestationKey(
    const ActivateAttestationKeyRequest& request,
    ActivateAttestationKeyCallback callback) {
  auto result = std::make_shared<ActivateAttestationKeyReply>();
  base::OnceClosure task =
      base::BindOnce(&AttestationService::ActivateAttestationKeyTask,
                     base::Unretained(this), request, result);
  base::OnceClosure reply = base::BindOnce(
      &AttestationService::TaskRelayCallback<ActivateAttestationKeyReply>,
      GetWeakPtr(), std::move(callback), result);
  worker_thread_->task_runner()->PostTaskAndReply(FROM_HERE, std::move(task),
                                                  std::move(reply));
}

void AttestationService::ActivateAttestationKeyTask(
    const ActivateAttestationKeyRequest& request,
    const std::shared_ptr<ActivateAttestationKeyReply>& result) {
  if (request.encrypted_certificate().tpm_version() !=
      tpm_utility_->GetVersion()) {
    result->set_status(STATUS_INVALID_PARAMETER);
    LOG(ERROR) << __func__ << ": TPM version mismatch.";
    return;
  }
  std::string certificate;
  if (!ActivateAttestationKeyInternal(
          kFirstIdentity, request.aca_type(), GetEndorsementKeyType(),
          request.encrypted_certificate(), request.save_certificate(),
          &certificate, nullptr /* certificate_index */)) {
    result->set_status(STATUS_UNEXPECTED_DEVICE_ERROR);
    return;
  }
  result->set_certificate(certificate);
}

void AttestationService::CreateCertifiableKey(
    const CreateCertifiableKeyRequest& request,
    CreateCertifiableKeyCallback callback) {
  auto result = std::make_shared<CreateCertifiableKeyReply>();
  base::OnceClosure task =
      base::BindOnce(&AttestationService::CreateCertifiableKeyTask,
                     base::Unretained(this), request, result);
  base::OnceClosure reply = base::BindOnce(
      &AttestationService::TaskRelayCallback<CreateCertifiableKeyReply>,
      GetWeakPtr(), std::move(callback), result);
  worker_thread_->task_runner()->PostTaskAndReply(FROM_HERE, std::move(task),
                                                  std::move(reply));
}

void AttestationService::CreateCertifiableKeyTask(
    const CreateCertifiableKeyRequest& request,
    const std::shared_ptr<CreateCertifiableKeyReply>& result) {
  CertifiedKey key;
  if (!CreateKey(request.username(), request.key_label(), request.key_type(),
                 request.key_usage(), KeyRestriction::kUnrestricted, &key)) {
    result->set_status(STATUS_UNEXPECTED_DEVICE_ERROR);
    return;
  }
  std::string public_key_info;
  if (!GetSubjectPublicKeyInfo(key.key_type(), key.public_key(),
                               &public_key_info)) {
    LOG(ERROR) << __func__ << ": Bad public key.";
    result->set_status(STATUS_UNEXPECTED_DEVICE_ERROR);
    return;
  }
  result->set_public_key(public_key_info);
  result->set_certify_info(key.certified_key_info());
  result->set_certify_info_signature(key.certified_key_proof());
}

void AttestationService::Decrypt(const DecryptRequest& request,
                                 DecryptCallback callback) {
  auto result = std::make_shared<DecryptReply>();
  base::OnceClosure task =
      base::BindOnce(&AttestationService::DecryptTask, base::Unretained(this),
                     request, result);
  base::OnceClosure reply =
      base::BindOnce(&AttestationService::TaskRelayCallback<DecryptReply>,
                     GetWeakPtr(), std::move(callback), result);
  worker_thread_->task_runner()->PostTaskAndReply(FROM_HERE, std::move(task),
                                                  std::move(reply));
}

void AttestationService::DecryptTask(
    const DecryptRequest& request,
    const std::shared_ptr<DecryptReply>& result) {
  CertifiedKey key;
  if (!FindKeyByLabel(request.username(), request.key_label(), &key)) {
    result->set_status(STATUS_INVALID_PARAMETER);
    return;
  }
  std::string data;
  if (!tpm_utility_->Unbind(key.key_blob(), request.encrypted_data(), &data)) {
    result->set_status(STATUS_UNEXPECTED_DEVICE_ERROR);
    return;
  }
  result->set_decrypted_data(data);
}

void AttestationService::Sign(const SignRequest& request,
                              SignCallback callback) {
  auto result = std::make_shared<SignReply>();
  base::OnceClosure task = base::BindOnce(
      &AttestationService::SignTask, base::Unretained(this), request, result);
  base::OnceClosure reply =
      base::BindOnce(&AttestationService::TaskRelayCallback<SignReply>,
                     GetWeakPtr(), std::move(callback), result);
  worker_thread_->task_runner()->PostTaskAndReply(FROM_HERE, std::move(task),
                                                  std::move(reply));
}

void AttestationService::SignTask(const SignRequest& request,
                                  const std::shared_ptr<SignReply>& result) {
  CertifiedKey key;
  if (!FindKeyByLabel(request.username(), request.key_label(), &key)) {
    result->set_status(STATUS_INVALID_PARAMETER);
    return;
  }
  std::string signature;
  if (!tpm_utility_->Sign(key.key_blob(), request.data_to_sign(), &signature)) {
    result->set_status(STATUS_UNEXPECTED_DEVICE_ERROR);
    return;
  }
  result->set_signature(signature);
}

void AttestationService::RegisterKeyWithChapsToken(
    const RegisterKeyWithChapsTokenRequest& request,
    RegisterKeyWithChapsTokenCallback callback) {
  auto result = std::make_shared<RegisterKeyWithChapsTokenReply>();
  base::OnceClosure task =
      base::BindOnce(&AttestationService::RegisterKeyWithChapsTokenTask,
                     base::Unretained(this), request, result);
  base::OnceClosure reply = base::BindOnce(
      &AttestationService::TaskRelayCallback<RegisterKeyWithChapsTokenReply>,
      GetWeakPtr(), std::move(callback), result);
  worker_thread_->task_runner()->PostTaskAndReply(FROM_HERE, std::move(task),
                                                  std::move(reply));
}

void AttestationService::RegisterKeyWithChapsTokenTask(
    const RegisterKeyWithChapsTokenRequest& request,
    const std::shared_ptr<RegisterKeyWithChapsTokenReply>& result) {
  CertifiedKey key;
  if (!FindKeyByLabel(request.username(), request.key_label(), &key)) {
    result->set_status(STATUS_INVALID_PARAMETER);
    return;
  }
  std::string certificate;
  if (request.include_certificates()) {
    certificate = key.certified_key_credential();
  }
  if (!key_store_->Register(request.username(), request.key_label(),
                            key.key_type(), key.key_usage(), key.key_blob(),
                            key.public_key(), certificate)) {
    result->set_status(STATUS_UNEXPECTED_DEVICE_ERROR);
    return;
  }
  if (request.include_certificates()) {
    if (key.has_intermediate_ca_cert() &&
        !key_store_->RegisterCertificate(request.username(),
                                         key.intermediate_ca_cert())) {
      result->set_status(STATUS_UNEXPECTED_DEVICE_ERROR);
      return;
    }
    for (int i = 0; i < key.additional_intermediate_ca_cert_size(); ++i) {
      if (!key_store_->RegisterCertificate(
              request.username(), key.additional_intermediate_ca_cert(i))) {
        result->set_status(STATUS_UNEXPECTED_DEVICE_ERROR);
        return;
      }
    }
  }
  DeleteKey(request.username(), request.key_label());
}

bool AttestationService::IsPreparedForEnrollment() {
  if (!tpm_utility_->IsTpmReady()) {
    return false;
  }
  const auto& database_pb = database_->GetProtobuf();
  // Note that this function only checks for the existence of endorsement
  // credentials, but the identity key, identity key binding and pcr quotes
  // signed by the identity key are also required for enrollment.
  // In normal circumstances, existence of the endorsement credentials implies
  // the existence of the other identity key related pieces, but it is
  // possible for that not to be true, for instance, see crbug.com/899932
  return database_pb.credentials().has_endorsement_credential() ||
         database_pb.credentials().encrypted_endorsement_credentials().size() >
             TEST_ACA;
}

bool AttestationService::IsPreparedForEnrollmentWithACA(ACAType aca_type) {
  const auto& database_pb = database_->GetProtobuf();
  return database_pb.credentials().encrypted_endorsement_credentials().count(
      aca_type);
}
bool AttestationService::IsEnrolled() {
  return IsEnrolledWithACA(DEFAULT_ACA) || IsEnrolledWithACA(TEST_ACA);
}

bool AttestationService::IsEnrolledWithACA(ACAType aca_type) {
  return HasIdentityCertificate(kFirstIdentity, aca_type);
}

AttestationService::IdentityCertificateMap::iterator
AttestationService::FindIdentityCertificate(int identity, ACAType aca_type) {
  auto* database_pb = database_->GetMutableProtobuf();
  auto end = database_pb->mutable_identity_certificates()->end();
  for (auto it = database_pb->mutable_identity_certificates()->begin();
       it != end; ++it) {
    if (it->second.identity() == identity && it->second.aca() == aca_type) {
      return it;
    }
  }
  return end;
}

AttestationDatabase_IdentityCertificate*
AttestationService::FindOrCreateIdentityCertificate(int identity,
                                                    ACAType aca_type,
                                                    int* cert_index) {
  // Find an identity certificate to reuse or create a new one.
  int index;
  auto* database_pb = database_->GetMutableProtobuf();
  auto found = FindIdentityCertificate(identity, aca_type);
  if (found == database_pb->mutable_identity_certificates()->end()) {
    index = identity == kFirstIdentity
                ? aca_type
                : std::max(static_cast<size_t>(kMaxACATypeInternal),
                           database_pb->identity_certificates().size());
    AttestationDatabase::IdentityCertificate new_identity_certificate;
    new_identity_certificate.set_identity(identity);
    new_identity_certificate.set_aca(aca_type);
    auto* map = database_pb->mutable_identity_certificates();
    auto in = map->insert(
        IdentityCertificateMap::value_type(index, new_identity_certificate));
    if (!in.second) {
      LOG(ERROR) << __func__ << ": Failed to create identity certificate "
                 << index << " for identity " << identity << " and "
                 << GetACAName(aca_type) << ".";
      if (cert_index) {
        *cert_index = -1;
      }
      return nullptr;
    }
    found = in.first;
    LOG(INFO) << "Attestation: Creating identity certificate " << index
              << " for identity " << identity << " enrolled with "
              << GetACAName(aca_type);
  } else {
    index = found->first;
  }
  if (cert_index) {
    *cert_index = index;
  }
  return &found->second;
}

bool AttestationService::HasIdentityCertificate(int identity,
                                                ACAType aca_type) {
  return FindIdentityCertificate(identity, aca_type) !=
         database_->GetMutableProtobuf()
             ->mutable_identity_certificates()
             ->end();
}

bool AttestationService::CreateEnrollRequestInternal(
    ACAType aca_type, std::string* enroll_request) {
  const int identity = kFirstIdentity;
  if (!IsPreparedForEnrollmentWithACA(aca_type)) {
    LOG(ERROR) << __func__ << ": Enrollment with " << GetACAName(aca_type)
               << " is not possible, attestation data does not exist.";
    return false;
  }
  const auto& database_pb = database_->GetProtobuf();
  if (database_pb.identities().size() <= identity) {
    LOG(ERROR) << __func__ << ": Enrollment with " << GetACAName(aca_type)
               << " is not possible, identity " << identity
               << " does not exist.";
    return false;
  }
  AttestationEnrollmentRequest request_pb;
  request_pb.set_tpm_version(tpm_utility_->GetVersion());
  *request_pb.mutable_encrypted_endorsement_credential() =
      database_pb.credentials().encrypted_endorsement_credentials().at(
          aca_type);
  const AttestationDatabase::Identity& identity_data =
      database_pb.identities().Get(identity);
  request_pb.set_identity_public_key(
      identity_data.identity_binding().identity_public_key_tpm_format());
  *request_pb.mutable_pcr0_quote() = identity_data.pcr_quotes().at(0);
  *request_pb.mutable_pcr1_quote() = identity_data.pcr_quotes().at(1);

  if (identity_data.features() & IDENTITY_FEATURE_ENTERPRISE_ENROLLMENT_ID) {
    std::string enterprise_enrollment_nonce =
        ComputeEnterpriseEnrollmentNonce();
    if (!enterprise_enrollment_nonce.empty()) {
      request_pb.set_enterprise_enrollment_nonce(
          enterprise_enrollment_nonce.data(),
          enterprise_enrollment_nonce.size());
    }

    if (ShallQuoteRsaEkCertificate()) {
      // Include an encrypted quote of the RSA pub EK certificate so that
      // an EID can be computed during enrollment.

      auto found = identity_data.nvram_quotes().find(RSA_PUB_EK_CERT);
      if (found == identity_data.nvram_quotes().end()) {
        LOG(ERROR) << __func__
                   << ": Cannot find RSA pub EK certificate quote in identity "
                   << identity << ".";
        return false;
      }

      std::string serialized_quote;
      if (!found->second.SerializeToString(&serialized_quote)) {
        LOG(ERROR) << __func__
                   << ": Failed to serialize RSA pub EK quote protobuf.";
        return false;
      }
      if (!EncryptDataForAttestationCA(
              aca_type, serialized_quote,
              request_pb.mutable_encrypted_rsa_endorsement_quote())) {
        LOG(ERROR)
            << "Attestation: Failed to encrypt RSA pub EK certificate for "
            << GetACAName(aca_type) << ".";
        return false;
      }
    }
  }

  if (!request_pb.SerializeToString(enroll_request)) {
    LOG(ERROR) << __func__ << ": Failed to serialize protobuf.";
    return false;
  }
  return true;
}

bool AttestationService::FinishEnrollInternal(
    ACAType aca_type,
    const std::string& enroll_response,
    std::string* server_error) {
  const int identity = kFirstIdentity;
  if (!tpm_utility_->IsTpmReady()) {
    LOG(ERROR) << __func__
               << ": Cannot finish enrollment as the TPM is not ready.";
    return false;
  }
  AttestationEnrollmentResponse response_pb;
  if (!response_pb.ParseFromString(enroll_response)) {
    LOG(ERROR) << __func__ << ": Failed to parse response from CA.";
    return false;
  }
  if (response_pb.status() != OK) {
    *server_error = response_pb.detail();
    LogErrorFromCA(__func__, response_pb.detail(), response_pb.extra_details());
    return false;
  }
  if (response_pb.encrypted_identity_credential().tpm_version() !=
      tpm_utility_->GetVersion()) {
    LOG(ERROR) << __func__ << ": TPM version mismatch.";
    return false;
  }
  int certificate_index;
  if (!ActivateAttestationKeyInternal(
          identity, aca_type, GetEndorsementKeyType(),
          response_pb.encrypted_identity_credential(),
          true /* save_certificate */, nullptr /* certificate */,
          &certificate_index)) {
    return false;
  }
  LOG(INFO) << __func__ << ": Enrollment of identity " << identity << " with "
            << GetACAName(aca_type) << " complete. Certificate #"
            << certificate_index << ".";
  return true;
}

bool AttestationService::CreateCertificateRequestInternal(
    ACAType aca_type,
    const std::string& username,
    const CertifiedKey& key,
    CertificateProfile profile,
    const std::string& origin,
    std::string* certificate_request,
    std::string* message_id,
    std::optional<DeviceSetupCertificateRequestMetadata>
        device_setup_certificate_request_metadata) {
  if (!tpm_utility_->IsTpmReady()) {
    return false;
  }
  if (!IsEnrolledWithACA(aca_type)) {
    LOG(ERROR) << __func__ << ": Device is not enrolled for attestation with "
               << GetACAName(aca_type) << ".";
    return false;
  }
  if (profile == ENTERPRISE_VTPM_EK_CERTIFICATE && !does_support_vtpm_ek_) {
    LOG(ERROR) << __func__ << ": VTPM EK not supported on non-GSC device.";
    return false;
  }
  auto found = FindIdentityCertificate(kFirstIdentity, aca_type);
  if (found ==
      database_->GetMutableProtobuf()->mutable_identity_certificates()->end()) {
    LOG(ERROR) << __func__ << ": Identity " << kFirstIdentity
               << " is not enrolled for attestation with "
               << GetACAName(aca_type) << ".";
    return false;
  }
  const auto& identity_certificate = found->second;
  if (!crypto_utility_->GetRandom(kNonceSize, message_id)) {
    LOG(ERROR) << __func__ << ": GetRandom(message_id) failed.";
    return false;
  }
  AttestationCertificateRequest request_pb;
  request_pb.set_tpm_version(tpm_utility_->GetVersion());
  request_pb.set_message_id(*message_id);
  request_pb.set_identity_credential(
      identity_certificate.identity_credential());
  request_pb.set_profile(profile);

  // TODO(b/286838595): Remove the profile switch once PCA supports
  // DEVICE_TRUST_USER_CERTIFICATE.
  if (profile == DEVICE_TRUST_USER_CERTIFICATE) {
    // Reuse the ENTERPRISE_USER_CERTIFICATE from PCA when requesting a
    // DEVICE_TRUST_USER_CERTIFICATE as they provide a similar functionality.
    request_pb.set_profile(ENTERPRISE_USER_CERTIFICATE);
  }

  if (profile == ENTERPRISE_ENROLLMENT_CERTIFICATE) {
    // Send the attested device ID, if we have one.
    if (!attested_device_id_.empty()) {
      request_pb.set_attested_device_id(attested_device_id_);
    }

    const int identity = identity_certificate.identity();
    const AttestationDatabase::Identity& identity_data =
        database_->GetProtobuf().identities().Get(identity);
    // Copy NVRAM quotes to include in an enrollment certificate from the
    // identity if possible.
    std::set<NVRAMQuoteType> not_in_identity;
    for (NVRAMQuoteType quote_type :
         nvram_quoter_->GetListForEnrollmentCertificate()) {
      const auto found = identity_data.nvram_quotes().find(quote_type);
      if (found != identity_data.nvram_quotes().cend()) {
        (*request_pb.mutable_nvram_quotes())[quote_type] = found->second;
      } else {
        not_in_identity.insert(quote_type);
      }
    }
    // Data that is supposed to be in the identity but is missing won't be
    // quoted now, as we want to drive everything from the identity.
    for (NVRAMQuoteType quote_type : nvram_quoter_->GetListForIdentity()) {
      if (not_in_identity.erase(quote_type)) {
        LOG(WARNING) << "Could not find quote of type " << quote_type
                     << " in identity " << identity
                     << " to provide in enrollment cert request.";
      }
    }
    // Quote the other data now.
    for (auto it = not_in_identity.cbegin(), end = not_in_identity.cend();
         it != end; ++it) {
      Quote quote;
      if (nvram_quoter_->Certify(
              *it, identity_data.identity_key().identity_key_blob(), quote)) {
        (*request_pb.mutable_nvram_quotes())[*it] = quote;
      } else {
        LOG(WARNING) << "Could not provide quote for enrollment cert request.";
      }
    }
  }

  if (profile == ENTERPRISE_VTPM_EK_CERTIFICATE) {
    // VTPM EK certificate requires `attested_device_id_` to be presented.
    if (attested_device_id_.empty()) {
      LOG(ERROR) << __func__ << ": VTPM EK certificate request requires ADID.";
      return false;
    }
    request_pb.set_attested_device_id(attested_device_id_);

    const int identity = identity_certificate.identity();
    const AttestationDatabase::Identity& identity_data =
        database_->GetProtobuf().identities().Get(identity);
    for (NVRAMQuoteType quote_type :
         nvram_quoter_->GetListForVtpmEkCertificate()) {
      const auto found = identity_data.nvram_quotes().find(quote_type);
      if (found != identity_data.nvram_quotes().cend()) {
        (*request_pb.mutable_nvram_quotes())[quote_type] = found->second;
        continue;
      }
      Quote quote;
      if (nvram_quoter_->Certify(
              quote_type, identity_data.identity_key().identity_key_blob(),
              quote)) {
        (*request_pb.mutable_nvram_quotes())[quote_type] = quote;
        continue;
      }
      // For VTPM EK certificate, all the quotes are mandatory.
      LOG(ERROR) << "Could not provide quote for VTPM EK cert request.";
      return false;
    }
  }

  if (profile == DEVICE_SETUP_CERTIFICATE) {
    if (!device_setup_certificate_request_metadata) {
      LOG(ERROR) << __func__
                 << ": Empty DEVICE_SETUP_CERTIFICATE request metadata";
      return false;
    }

    if (!device_setup_certificate_request_metadata->has_id() ||
        device_setup_certificate_request_metadata->id().empty()) {
      LOG(ERROR) << __func__
                 << ": DEVICE_SETUP_CERTIFICATE requires an id to be passed";
      return false;
    }

    if (!device_setup_certificate_request_metadata->has_content_binding() ||
        device_setup_certificate_request_metadata->content_binding().empty()) {
      LOG(ERROR)
          << __func__
          << ": DEVICE_SETUP_CERTIFICATE requires content_binding to be passed";
      return false;
    }

    request_pb.mutable_device_setup_certificate_metadata()->set_id(
        device_setup_certificate_request_metadata->id());
    request_pb.mutable_device_setup_certificate_metadata()
        ->set_timestamp_seconds(
            (base::Time::Now() - base::Time::UnixEpoch()).InSeconds());
    request_pb.mutable_device_setup_certificate_metadata()->set_content_binding(
        device_setup_certificate_request_metadata->content_binding());
  }

  if (!origin.empty() &&
      (profile == CONTENT_PROTECTION_CERTIFICATE_WITH_STABLE_ID)) {
    request_pb.set_origin(origin);
    request_pb.set_temporal_index(ChooseTemporalIndex(username, origin));
  }
  request_pb.set_certified_public_key(key.public_key_tpm_format());
  request_pb.set_certified_key_info(key.certified_key_info());
  request_pb.set_certified_key_proof(key.certified_key_proof());
  if (!request_pb.SerializeToString(certificate_request)) {
    LOG(ERROR) << __func__ << ": Failed to serialize protobuf.";
    return false;
  }
  return true;
}

bool AttestationService::PopulateAndStoreCertifiedKey(
    const AttestationCertificateResponse& response_pb,
    const std::string& username,
    const std::string& key_label,
    CertifiedKey* key) {
  // Finish populating the CertifiedKey protobuf and store it.
  key->set_key_name(key_label);
  key->set_certified_key_credential(response_pb.certified_key_credential());
  key->set_intermediate_ca_cert(response_pb.intermediate_ca_cert());
  key->mutable_additional_intermediate_ca_cert()->MergeFrom(
      response_pb.additional_intermediate_ca_cert());
  if (!SaveKey(username, key_label, *key)) {
    LOG(ERROR) << "Attestation: Failed to save key.";
    return false;
  }
  return true;
}

bool AttestationService::FindKeyByLabel(const std::string& username,
                                        const std::string& key_label,
                                        CertifiedKey* key) {
  if (!username.empty()) {
    std::string key_data;
    if (!key_store_->Read(username, key_label, &key_data)) {
      LOG(INFO) << "Key not found: " << key_label;
      return false;
    }
    if (key && !key->ParseFromString(key_data)) {
      LOG(ERROR) << "Failed to parse key: " << key_label;
      return false;
    }
    return true;
  }
  auto database_pb = database_->GetProtobuf();
  for (int i = 0; i < database_pb.device_keys_size(); ++i) {
    if (database_pb.device_keys(i).key_name() == key_label) {
      *key = database_pb.device_keys(i);
      return true;
    }
  }
  LOG(INFO) << "Key not found: " << key_label;
  return false;
}

bool AttestationService::CreateKey(const std::string& username,
                                   const std::string& key_label,
                                   KeyType key_type,
                                   KeyUsage key_usage,
                                   KeyRestriction key_restriction,
                                   CertifiedKey* key) {
  auto database_pb = database_->GetProtobuf();
  const int identity = kFirstIdentity;
  if (database_pb.identities().size() <= identity) {
    LOG(ERROR) << __func__ << ": Cannot create a certificate request, identity "
               << identity << " does not exist.";
    return false;
  }

  std::string nonce;
  if (!crypto_utility_->GetRandom(kNonceSize, &nonce)) {
    LOG(ERROR) << __func__ << ": GetRandom(nonce) failed.";
    return false;
  }
  std::string key_blob;
  std::string public_key;
  std::string public_key_tpm_format;
  std::string key_info;
  std::string proof;
  const auto& identity_data = database_pb.identities().Get(identity);
  if (!tpm_utility_->CreateCertifiedKey(
          key_type, key_usage, key_restriction, std::nullopt,
          identity_data.identity_key().identity_key_blob(), nonce, &key_blob,
          &public_key, &public_key_tpm_format, &key_info, &proof)) {
    return false;
  }
  key->set_key_blob(key_blob);
  key->set_public_key(public_key);
  key->set_key_name(key_label);
  key->set_public_key_tpm_format(public_key_tpm_format);
  key->set_certified_key_info(key_info);
  key->set_certified_key_proof(proof);
  key->set_key_type(key_type);
  key->set_key_usage(key_usage);
  return SaveKey(username, key_label, *key);
}

bool AttestationService::SaveKey(const std::string& username,
                                 const std::string& key_label,
                                 const CertifiedKey& key) {
  if (!username.empty()) {
    std::string key_data;
    if (!key.SerializeToString(&key_data)) {
      LOG(ERROR) << __func__ << ": Failed to serialize protobuf.";
      return false;
    }
    if (!key_store_->Write(username, key_label, key_data)) {
      LOG(ERROR) << __func__ << ": Failed to store certified key for user.";
      return false;
    }
  } else {
    if (!AddDeviceKey(key_label, key)) {
      LOG(ERROR) << __func__ << ": Failed to store certified key for device.";
      return false;
    }
  }
  return true;
}

bool AttestationService::DeleteKey(const std::string& username,
                                   const std::string& key_label) {
  if (!username.empty()) {
    return key_store_->Delete(username, key_label);
  } else {
    return RemoveDeviceKey(key_label);
  }
}

bool AttestationService::DeleteKeysByPrefix(const std::string& username,
                                            const std::string& key_prefix) {
  if (!username.empty()) {
    return key_store_->DeleteByPrefix(username, key_prefix);
  }
  return RemoveDeviceKeysByPrefix(key_prefix);
}

bool AttestationService::AddDeviceKey(const std::string& key_label,
                                      const CertifiedKey& key) {
  // If a key by this name already exists, reuse the field.
  auto* database_pb = database_->GetMutableProtobuf();
  bool found = false;
  for (int i = 0; i < database_pb->device_keys_size(); ++i) {
    if (database_pb->device_keys(i).key_name() == key_label) {
      found = true;
      *database_pb->mutable_device_keys(i) = key;
      break;
    }
  }
  if (!found)
    *database_pb->add_device_keys() = key;
  return database_->SaveChanges();
}

bool AttestationService::RemoveDeviceKey(const std::string& key_label) {
  auto* database_pb = database_->GetMutableProtobuf();
  bool found = false;
  for (int i = 0; i < database_pb->device_keys_size(); ++i) {
    if (database_pb->device_keys(i).key_name() == key_label) {
      found = true;
      int last = database_pb->device_keys_size() - 1;
      if (i < last) {
        database_pb->mutable_device_keys()->SwapElements(i, last);
      }
      database_pb->mutable_device_keys()->RemoveLast();
      break;
    }
  }
  if (found) {
    if (!database_->SaveChanges()) {
      LOG(WARNING) << __func__ << ": Failed to persist key deletion.";
      return false;
    }
  }
  return true;
}

bool AttestationService::RemoveDeviceKeysByPrefix(
    const std::string& key_prefix) {
  // Manipulate the device keys protobuf field.  Linear time strategy is to swap
  // all elements we want to keep to the front and then truncate.
  auto* device_keys = database_->GetMutableProtobuf()->mutable_device_keys();
  int next_keep_index = 0;
  for (int i = 0; i < device_keys->size(); ++i) {
    if (device_keys->Get(i).key_name().find(key_prefix) != 0) {
      // Prefix doesn't match -> keep.
      if (i != next_keep_index)
        device_keys->SwapElements(next_keep_index, i);
      ++next_keep_index;
    }
  }
  // If no matching keys, do nothing and return success.
  if (next_keep_index == device_keys->size()) {
    return true;
  }
  while (next_keep_index < device_keys->size()) {
    device_keys->RemoveLast();
  }
  return database_->SaveChanges();
}

std::string AttestationService::CreatePEMCertificateChain(
    const CertifiedKey& key) {
  if (key.certified_key_credential().empty()) {
    LOG(WARNING) << "Certificate is empty.";
    return std::string();
  }
  std::string pem = CreatePEMCertificate(key.certified_key_credential());
  if (!key.intermediate_ca_cert().empty()) {
    pem += "\n";
    pem += CreatePEMCertificate(key.intermediate_ca_cert());
  }
  for (int i = 0; i < key.additional_intermediate_ca_cert_size(); ++i) {
    pem += "\n";
    pem += CreatePEMCertificate(key.additional_intermediate_ca_cert(i));
  }
  return pem;
}

std::string AttestationService::CreatePEMCertificate(
    const std::string& certificate) {
  const char kBeginCertificate[] = "-----BEGIN CERTIFICATE-----\n";
  const char kEndCertificate[] = "-----END CERTIFICATE-----";

  std::string pem = kBeginCertificate;
  pem += brillo::data_encoding::Base64EncodeWrapLines(certificate);
  pem += kEndCertificate;
  return pem;
}

int AttestationService::ChooseTemporalIndex(const std::string& user,
                                            const std::string& origin) {
  std::string user_hash = crypto::SHA256HashString(user);
  std::string origin_hash = crypto::SHA256HashString(origin);
  int histogram[kNumTemporalValues] = {};
  auto database_pb = database_->GetProtobuf();
  for (int i = 0; i < database_pb.temporal_index_record_size(); ++i) {
    const AttestationDatabase::TemporalIndexRecord& record =
        database_pb.temporal_index_record(i);
    // Ignore out-of-range index values.
    if (record.temporal_index() < 0 ||
        record.temporal_index() >= kNumTemporalValues)
      continue;
    if (record.origin_hash() == origin_hash) {
      if (record.user_hash() == user_hash) {
        // We've previously chosen this index for this user, reuse it.
        return record.temporal_index();
      } else {
        // We've previously chosen this index for another user.
        ++histogram[record.temporal_index()];
      }
    }
  }
  int least_used_index = 0;
  for (int i = 1; i < kNumTemporalValues; ++i) {
    if (histogram[i] < histogram[least_used_index])
      least_used_index = i;
  }
  if (histogram[least_used_index] > 0) {
    LOG(WARNING) << "Unique origin-specific identifiers have been exhausted.";
  }
  // Record our choice for later reference.
  AttestationDatabase::TemporalIndexRecord* new_record =
      database_pb.add_temporal_index_record();
  new_record->set_origin_hash(origin_hash);
  new_record->set_user_hash(user_hash);
  new_record->set_temporal_index(least_used_index);
  if (!database_->SaveChanges()) {
    LOG(ERROR) << "Failed to save attestation db when choosing temporal index";
    // TODO(louiscollard): Check if any further actions are necessary.
  }
  return least_used_index;
}

bool AttestationService::GetSubjectPublicKeyInfo(
    KeyType key_type,
    const std::string& public_key,
    std::string* public_key_info) const {
  if (key_type == KEY_TYPE_RSA) {
    return crypto_utility_->GetRSASubjectPublicKeyInfo(public_key,
                                                       public_key_info);
  } else if (key_type == KEY_TYPE_ECC) {
    // Do nothing, since we always store SubjectPublicKeyInfo in |public_key|
    // field and will pass it this utility
    *public_key_info = public_key;
    return true;
  } else {
    LOG(ERROR) << __func__ << ": key_type " << key_type << " isn't supported.";
    return false;
  }
}

void AttestationService::PrepareForEnrollment(
    InitializeCompleteCallback callback) {
  if (IsPreparedForEnrollment()) {
    std::move(callback).Run(true);
    return;
  }
  if (!tpm_utility_->IsTpmReady()) {
    // Try again later.
    worker_thread_->task_runner()->PostDelayedTask(
        FROM_HERE,
        base::BindOnce(&AttestationService::PrepareForEnrollment,
                       base::Unretained(this), std::move(callback)),
        base::Seconds(3));
    return;
  }
  base::TimeTicks start = base::TimeTicks::Now();
  LOG(INFO) << "Attestation: Preparing for enrollment...";

  if (auto result = hwsec_->GetCurrentBootMode(); !result.ok()) {
    LOG(ERROR) << __func__
               << "Invalid boot mode, aborting: " << result.status();
    metrics_.ReportAttestationOpsStatus(
        kAttestationPrepareForEnrollment,
        AttestationOpsStatus::kInvalidPcr0Value);
    return;
  }

  KeyType key_type = GetEndorsementKeyType();

  // Gather information about the endorsement key.
  std::string ek_public_key;
  if (!tpm_utility_->GetEndorsementPublicKey(key_type, &ek_public_key)) {
    LOG(ERROR) << __func__ << ": Failed to get EK public key with key_type "
               << key_type;
    std::move(callback).Run(false);
    return;
  }
  LOG(INFO) << "GetEndorsementPublicKey done. (from start: "
            << (base::TimeTicks::Now() - start).InMilliseconds() << "ms.)";

  std::string ek_certificate;
  if (!tpm_utility_->GetEndorsementCertificate(key_type, &ek_certificate)) {
    LOG(ERROR) << __func__ << ": Failed to get " << GetKeyTypeName(key_type)
               << " EK certificate.";
    std::move(callback).Run(false);
    return;
  }
  LOG(INFO) << "GetEndorsementCertificate done. (from start: "
            << (base::TimeTicks::Now() - start).InMilliseconds() << "ms.)";

  // Create a new AIK and PCR quotes for the first identity with default
  // identity features.
  if (!CreateIdentity(kDefaultIdentityFeatures)) {
    LOG(ERROR) << __func__ << ": Failed to create identity.";
    std::move(callback).Run(false);
    return;
  }
  LOG(INFO) << "CreateIdentity done. (from start: "
            << (base::TimeTicks::Now() - start).InMilliseconds() << "ms.)";

  // Store all this in the attestation database.
  auto* database_pb = database_->GetMutableProtobuf();
  TPMCredentials* credentials_pb = database_pb->mutable_credentials();
  credentials_pb->set_endorsement_key_type(key_type);
  credentials_pb->set_endorsement_public_key(ek_public_key);
  credentials_pb->set_endorsement_credential(ek_certificate);

  // Encrypt the endorsement credential for all the ACAs we know of.
  EncryptAllEndorsementCredentials();

  if (!database_->SaveChanges()) {
    LOG(ERROR) << "Attestation: Failed to write database.";
    std::move(callback).Run(false);
    return;
  }

  // Ignore errors when removing dependency. If failed this time, will be
  // re-attempted on next boot.
  tpm_utility_->RemoveOwnerDependency();

  base::TimeDelta delta = (base::TimeTicks::Now() - start);
  LOG(INFO) << "Attestation: Prepared successfully (" << delta.InMilliseconds()
            << "ms) with " << GetKeyTypeName(key_type) << " EK.";
  metrics_.ReportAttestationPrepareDuration(delta);
  metrics_.ReportAttestationOpsStatus(kAttestationPrepareForEnrollment,
                                      AttestationOpsStatus::kSuccess);
  std::move(callback).Run(true);
}

bool AttestationService::CreateIdentity(int identity_features) {
  // The identity we're creating will have the next index in identities.
  auto* database_pb = database_->GetMutableProtobuf();
  const int identity = database_pb->identities().size();
  KeyType identity_key_type = GetAttestationIdentityKeyType();
  LOG(INFO) << "Attestation: Creating identity " << identity << " with "
            << GetIdentityFeaturesString(identity_features) << " and "
            << GetKeyTypeName(identity_key_type) << " AIK.";
  AttestationDatabase::Identity new_identity_pb;

  new_identity_pb.set_features(identity_features);
  if (identity_features & IDENTITY_FEATURE_ENTERPRISE_ENROLLMENT_ID) {
    auto* identity_key = new_identity_pb.mutable_identity_key();
    identity_key->set_enrollment_id(database_pb->enrollment_id());
  }
  if (!tpm_utility_->CreateIdentity(identity_key_type, &new_identity_pb)) {
    LOG(ERROR) << __func__ << " failed to make a new identity.";
    return false;
  }
  std::string identity_key_blob_for_quote =
      new_identity_pb.identity_key().identity_key_blob();

  // Quote PCRs and store them in the identity. These quotes are intended to
  // be valid for the lifetime of the identity key so they do not need
  // external data. This only works when firmware ensures that these PCRs
  // will not change unless the TPM owner is cleared.
  auto* pcr_quote_map = new_identity_pb.mutable_pcr_quotes();

  for (DeviceConfig device_config : kDeviceConfigsToQuote) {
    ASSIGN_OR_RETURN(
        const Quote& quote_pb,
        hwsec_->Quote(device_config,
                      brillo::BlobFromString(identity_key_blob_for_quote)),
        _.WithStatus<TPMError>("Failed to quote").LogError().As(false));

    // TODO(b/278988714): refactor the PCR-related function/protobuf so that we
    // don't need this conversion.
    // Converts device config to corresponding index in Identity::pcr_quotes.
    int pcr = 0;
    switch (device_config) {
      case DeviceConfig::kBootMode:
        pcr = 0;
        break;
      case DeviceConfig::kDeviceModel:
        pcr = 1;
        break;
      default:
        LOG(ERROR) << __func__ << ": Unsupported Device Config";
        return false;
    }
    auto in = pcr_quote_map->insert(QuoteMap::value_type(pcr, quote_pb));
    if (!in.second) {
      LOG(ERROR) << "Attestation: Failed to store PCR" << pcr
                 << " quote for identity " << identity << ".";
      return false;
    }
  }

  for (NVRAMQuoteType data : nvram_quoter_->GetListForIdentity()) {
    if (!InsertCertifiedNvramData(data, false /* must_be_present */,
                                  &new_identity_pb)) {
      return false;
    }
  }

  // Certify the RSA EK cert only when we are using non-RSA EK. In this case,
  // we don't provide the RSA EK cert which originally is used for calculating
  // the Enrollment ID.
  if ((identity_features & IDENTITY_FEATURE_ENTERPRISE_ENROLLMENT_ID) &&
      ShallQuoteRsaEkCertificate()) {
    if (!InsertCertifiedNvramData(RSA_PUB_EK_CERT, true /* must_be_present */,
                                  &new_identity_pb)) {
      return false;
    }
  }

  database_pb->add_identities()->CopyFrom(new_identity_pb);
  return true;
}

bool AttestationService::InsertCertifiedNvramData(
    NVRAMQuoteType quote_type,
    bool must_be_present,
    AttestationDatabase::Identity* identity) {
  TPM_SELECT_BEGIN;
  TPM2_SECTION();
  OTHER_TPM_SECTION({
    LOG(WARNING) << __func__ << ": Should not be called for TPM 1.2 devices.";
  });
  TPM_SELECT_END;
  Quote quote;
  if (!nvram_quoter_->Certify(
          quote_type, identity->identity_key().identity_key_blob(), quote)) {
    return !must_be_present;
  }

  auto* nv_quote_map = identity->mutable_nvram_quotes();
  auto in_bid = nv_quote_map->insert(QuoteMap::value_type(quote_type, quote));
  if (in_bid.second) {
    return true;
  } else {
    LOG(ERROR) << "Attestation: Failed to store quote of type " << quote_type
               << " for identity " << identity << ".";
  }
  return false;
}

int AttestationService::GetIdentitiesCount() const {
  return database_->GetProtobuf().identities().size();
}

int AttestationService::GetIdentityFeatures(int identity) const {
  return database_->GetProtobuf().identities().Get(identity).features();
}

AttestationService::IdentityCertificateMap
AttestationService::GetIdentityCertificateMap() const {
  return database_->GetProtobuf().identity_certificates();
}

bool AttestationService::EncryptAllEndorsementCredentials() {
  auto* database_pb = database_->GetMutableProtobuf();
  std::optional<std::string> ek_certificate = GetEndorsementCertificate();
  if (!ek_certificate.has_value()) {
    LOG(ERROR) << "Attestation: Failed to obtain endorsement certificate.";
    return false;
  }

  TPMCredentials* credentials_pb = database_pb->mutable_credentials();
  for (int aca = kDefaultACA; aca < kMaxACATypeInternal; ++aca) {
    if (credentials_pb->encrypted_endorsement_credentials().count(aca)) {
      continue;
    }
    ACAType aca_type = GetACAType(static_cast<ACATypeInternal>(aca));
    LOG(INFO) << "Attestation: Encrypting endorsement credential for "
              << GetACAName(aca_type) << ".";
    if (!EncryptDataForAttestationCA(
            aca_type, ek_certificate.value(),
            &(*credentials_pb
                   ->mutable_encrypted_endorsement_credentials())[aca])) {
      LOG(ERROR) << "Attestation: Failed to encrypt EK certificate for "
                 << GetACAName(static_cast<ACAType>(aca)) << ".";
      return false;
    }
  }
  return true;
}

bool AttestationService::EncryptDataForAttestationCA(
    ACAType aca_type, const std::string& data, EncryptedData* encrypted_data) {
  const GoogleRsaPublicKey& key = google_keys_.ca_encryption_key(aca_type);
  if (!crypto_utility_->EncryptDataForGoogle(data, key.modulus_in_hex(),
                                             key.key_id(), encrypted_data)) {
    return false;
  }
  return true;
}

bool AttestationService::ActivateAttestationKeyInternal(
    int identity,
    ACAType aca_type,
    KeyType ek_key_type,
    const EncryptedIdentityCredential& encrypted_certificate,
    bool save_certificate,
    std::string* certificate,
    int* certificate_index) {
  const auto& database_pb = database_->GetProtobuf();
  if (database_pb.identities().size() <= identity) {
    LOG(ERROR) << __func__ << ": Enrollment is not possible, identity "
               << identity << " does not exist.";
    return false;
  }
  const auto& identity_data = database_pb.identities().Get(identity);
  std::string certificate_local;
  if (encrypted_certificate.tpm_version() == TPM_1_2) {
    // TPM 1.2 style activate.
    if (!tpm_utility_->ActivateIdentity(
            identity_data.identity_key().identity_key_blob(),
            encrypted_certificate.asym_ca_contents(),
            encrypted_certificate.sym_ca_attestation(), &certificate_local)) {
      LOG(ERROR) << __func__ << ": Failed to activate identity " << identity
                 << ".";
      return false;
    }
  } else {
    // TPM 2.0 style activate.
    std::string credential;
    if (!tpm_utility_->ActivateIdentityForTpm2(
            ek_key_type, identity_data.identity_key().identity_key_blob(),
            encrypted_certificate.encrypted_seed(),
            encrypted_certificate.credential_mac(),
            encrypted_certificate.wrapped_certificate().wrapped_key(),
            &credential)) {
      LOG(ERROR) << __func__ << ": Failed to activate identity " << identity
                 << ".";
      return false;
    }
    if (!crypto_utility_->DecryptIdentityCertificateForTpm2(
            credential, encrypted_certificate.wrapped_certificate(),
            &certificate_local)) {
      LOG(ERROR) << __func__ << ": Failed to decrypt certificate for identity "
                 << identity << ".";
      return false;
    }
  }
  if (save_certificate) {
    if (auto result = hwsec_->GetCurrentBootMode(); !result.ok()) {
      LOG(ERROR) << __func__
                 << "Invalid boot mode, aborting: " << result.status();
      metrics_.ReportAttestationOpsStatus(
          kAttestationActivateAttestationKey,
          AttestationOpsStatus::kInvalidPcr0Value);
      return false;
    }

    int index;
    AttestationDatabase_IdentityCertificate* identity_certificate =
        FindOrCreateIdentityCertificate(identity, aca_type, &index);
    if (!identity_certificate) {
      LOG(ERROR) << __func__ << ": Failed to find or create an identity"
                 << " certificate for identity " << identity << " with "
                 << GetACAName(aca_type) << ".";
      return false;
    }
    // Set the credential obtained when activating the identity with the
    // response.
    identity_certificate->set_identity_credential(certificate_local);
    if (!database_->SaveChanges()) {
      LOG(ERROR) << __func__ << ": Failed to persist database changes.";
      return false;
    }
    if (certificate_index) {
      *certificate_index = index;
    }
  }
  if (certificate) {
    *certificate = certificate_local;
  }
  return true;
}

void AttestationService::GetEnrollmentPreparations(
    const GetEnrollmentPreparationsRequest& request,
    GetEnrollmentPreparationsCallback callback) {
  auto result = std::make_shared<GetEnrollmentPreparationsReply>();
  base::OnceClosure task =
      base::BindOnce(&AttestationService::GetEnrollmentPreparationsTask,
                     base::Unretained(this), request, result);
  base::OnceClosure reply = base::BindOnce(
      &AttestationService::TaskRelayCallback<GetEnrollmentPreparationsReply>,
      GetWeakPtr(), std::move(callback), result);
  worker_thread_->task_runner()->PostTaskAndReply(FROM_HERE, std::move(task),
                                                  std::move(reply));
}

void AttestationService::GetEnrollmentPreparationsTask(
    const GetEnrollmentPreparationsRequest& request,
    const std::shared_ptr<GetEnrollmentPreparationsReply>& result) {
  for (int aca = kDefaultACA; aca < kMaxACATypeInternal; ++aca) {
    ACAType aca_type = GetACAType(static_cast<ACATypeInternal>(aca));
    if (!request.has_aca_type() || aca_type == request.aca_type()) {
      (*result->mutable_enrollment_preparations())[aca_type] =
          IsPreparedForEnrollmentWithACA(aca_type);
    }
  }
}

void AttestationService::GetStatus(const GetStatusRequest& request,
                                   GetStatusCallback callback) {
  auto result = std::make_shared<GetStatusReply>();
  base::OnceClosure task =
      base::BindOnce(&AttestationService::GetStatusTask, base::Unretained(this),
                     request, result);
  base::OnceClosure reply =
      base::BindOnce(&AttestationService::TaskRelayCallback<GetStatusReply>,
                     GetWeakPtr(), std::move(callback), result);
  worker_thread_->task_runner()->PostTaskAndReply(FROM_HERE, std::move(task),
                                                  std::move(reply));
}

bool AttestationService::IsVerifiedMode() const {
  if (!tpm_utility_->IsTpmReady()) {
    VLOG(2) << __func__ << ": Tpm is not ready.";
    return false;
  }
  std::string pcr_value;
  if (!tpm_utility_->ReadPCR(0, &pcr_value)) {
    LOG(WARNING) << __func__ << ": Failed to read PCR0.";
    return false;
  }
  return (pcr_value == GetPCRValueForMode(kVerifiedBootMode));
}

void AttestationService::GetStatusTask(
    const GetStatusRequest& request,
    const std::shared_ptr<GetStatusReply>& result) {
  result->set_prepared_for_enrollment(IsPreparedForEnrollment());
  result->set_enrolled(IsEnrolled());
  for (int i = 0, count = GetIdentitiesCount(); i < count; ++i) {
    GetStatusReply::Identity* identity = result->mutable_identities()->Add();
    identity->set_features(GetIdentityFeatures(i));
  }
  AttestationService::IdentityCertificateMap map = GetIdentityCertificateMap();
  for (auto it = map.cbegin(), end = map.cend(); it != end; ++it) {
    GetStatusReply::IdentityCertificate identity_certificate;
    identity_certificate.set_identity(it->second.identity());
    identity_certificate.set_aca(it->second.aca());
    result->mutable_identity_certificates()->insert(
        google::protobuf::Map<int, GetStatusReply::IdentityCertificate>::
            value_type(it->first, identity_certificate));
  }
  for (int aca = kDefaultACA; aca < kMaxACATypeInternal; ++aca) {
    ACAType aca_type = GetACAType(static_cast<ACATypeInternal>(aca));
    (*result->mutable_enrollment_preparations())[aca_type] =
        IsPreparedForEnrollmentWithACA(aca_type);
  }
  if (request.extended_status()) {
    result->set_verified_boot(IsVerifiedMode());
  }
}

void AttestationService::Verify(const VerifyRequest& request,
                                VerifyCallback callback) {
  auto result = std::make_shared<VerifyReply>();
  base::OnceClosure task = base::BindOnce(
      &AttestationService::VerifyTask, base::Unretained(this), request, result);
  base::OnceClosure reply =
      base::BindOnce(&AttestationService::TaskRelayCallback<VerifyReply>,
                     GetWeakPtr(), std::move(callback), result);
  worker_thread_->task_runner()->PostTaskAndReply(FROM_HERE, std::move(task),
                                                  std::move(reply));
}

bool AttestationService::VerifyIdentityBinding(const IdentityBinding& binding) {
  if (tpm_utility_->GetVersion() == TPM_1_2) {
    // Reconstruct and hash a serialized TPM_IDENTITY_CONTENTS structure.
    const std::string header("\x01\x01\x00\x00\x00\x00\x00\x79", 8);
    std::string digest = base::SHA1HashString(binding.identity_label() +
                                              binding.pca_public_key());
    std::string identity_public_key_info;
    if (!GetSubjectPublicKeyInfo(KEY_TYPE_RSA,
                                 binding.identity_public_key_der(),
                                 &identity_public_key_info)) {
      LOG(ERROR) << __func__ << ": Failed to get identity public key info.";
      return false;
    }
    if (!crypto_utility_->VerifySignature(
            crypto_utility_->DefaultDigestAlgoForSignature(),
            identity_public_key_info,
            header + digest + binding.identity_public_key_tpm_format(),
            binding.identity_binding())) {
      LOG(ERROR) << __func__
                 << ": Failed to verify identity binding signature.";
      return false;
    }
  } else if (tpm_utility_->GetVersion() == TPM_2_0) {
    VLOG(1) << __func__ << ": Nothing to do for TPM 2.0.";
  } else {
    LOG(ERROR) << __func__ << ": Unsupported TPM version.";
    return false;
  }
  return true;
}

bool AttestationService::VerifyQuoteSignature(
    const std::string& aik_public_key_info,
    const Quote& quote,
    uint32_t pcr_index) {
  if (!crypto_utility_->VerifySignature(
          crypto_utility_->DefaultDigestAlgoForSignature(), aik_public_key_info,
          quote.quoted_data(), quote.quote())) {
    LOG(ERROR) << __func__ << ": Signature mismatch.";
    return false;
  }
  // TODO(b/278988714): refactor the PCR-related function so that we don't need
  // this conversion.
  DeviceConfig device_config;
  switch (pcr_index) {
    case 0:
      device_config = DeviceConfig::kBootMode;
      break;
    case 1:
      device_config = DeviceConfig::kDeviceModel;
      break;
    default:
      LOG(ERROR) << __func__ << ": Unknown device config for pcr " << pcr_index;
      return false;
  }

  ASSIGN_OR_RETURN(
      bool is_quoted, hwsec_->IsQuoted(device_config, quote),
      _.WithStatus<TPMError>("Failed to verify quote").LogError().As(false));
  if (!is_quoted) {
    LOG(ERROR) << __func__ << ": Invalid quote.";
    return false;
  }
  return true;
}

std::string AttestationService::GetPCRValueForMode(const char* mode) const {
  std::string mode_str(mode, 3);
  std::string mode_digest = base::SHA1HashString(mode_str);
  std::string pcr_value;
  if (tpm_utility_->GetVersion() == TPM_1_2) {
    // Use SHA-1 digests for TPM 1.2.
    std::string initial(base::kSHA1Length, 0);
    pcr_value = base::SHA1HashString(initial + mode_digest);
  } else if (tpm_utility_->GetVersion() == TPM_2_0) {
    // Use SHA-256 digests for TPM 2.0.
    std::string initial(crypto::kSHA256Length, 0);
    mode_digest.resize(crypto::kSHA256Length);
    pcr_value = crypto::SHA256HashString(initial + mode_digest);
  } else {
    LOG(ERROR) << __func__ << ": Unsupported TPM version.";
  }
  return pcr_value;
}

bool AttestationService::VerifyPCR0Quote(const std::string& aik_public_key_info,
                                         const Quote& pcr0_quote) {
  if (!VerifyQuoteSignature(aik_public_key_info, pcr0_quote, 0)) {
    return false;
  }

  // Check if the PCR0 value represents a known mode.
  for (const auto& mode : kKnownBootModes) {
    std::string pcr_value = GetPCRValueForMode(mode);
    if (pcr0_quote.quoted_pcr_value() == pcr_value) {
      LOG(INFO) << "PCR0: " << GetDescriptionForMode(mode);
      return true;
    }
  }
  LOG(WARNING) << "PCR0 value not recognized.";
  return true;
}

bool AttestationService::VerifyPCR1Quote(const std::string& aik_public_key_info,
                                         const Quote& pcr1_quote) {
  if (!VerifyQuoteSignature(aik_public_key_info, pcr1_quote, 1)) {
    return false;
  }

  // Check that the source hint is correctly populated.
  if (hwid_ != pcr1_quote.pcr_source_hint()) {
    LOG(ERROR) << "PCR1 source hint does not match HWID: " << hwid_;
    return false;
  }

  LOG(INFO) << "PCR1 verified as " << hwid_;
  return true;
}

bool AttestationService::GetCertifiedKeyDigest(
    const std::string& public_key_info,
    const std::string& public_key_tpm_format,
    std::string* key_digest) {
  if (tpm_utility_->GetVersion() == TPM_1_2) {
    return crypto_utility_->GetKeyDigest(public_key_info, key_digest);
  } else if (tpm_utility_->GetVersion() == TPM_2_0) {
    // TPM_ALG_SHA256 = 0x000B, here in big-endian order.
    std::string prefix("\x00\x0B", 2);
    key_digest->assign(prefix +
                       crypto::SHA256HashString(public_key_tpm_format));
    return true;
  }
  LOG(ERROR) << __func__ << ": Unsupported TPM version.";
  return false;
}

bool AttestationService::VerifyCertifiedKey(
    const std::string& aik_public_key_info,
    const std::string& public_key_info,
    const std::string& public_key_tpm_format,
    const std::string& key_info,
    const std::string& proof) {
  if (!crypto_utility_->VerifySignature(
          crypto_utility_->DefaultDigestAlgoForSignature(), aik_public_key_info,
          key_info, proof)) {
    LOG(ERROR) << __func__ << ": Bad key signature.";
    return false;
  }
  std::string key_digest;
  if (!GetCertifiedKeyDigest(public_key_info, public_key_tpm_format,
                             &key_digest)) {
    LOG(ERROR) << __func__ << ": Failed to get key digest.";
    return false;
  }
  if (key_info.find(key_digest) == std::string::npos) {
    LOG(ERROR) << __func__ << ": Public key mismatch.";
    return false;
  }
  return true;
}

bool AttestationService::VerifyCertifiedKeyGeneration(
    const std::string& aik_key_blob, const std::string& aik_public_key_info) {
  std::string nonce;
  if (!crypto_utility_->GetRandom(kNonceSize, &nonce)) {
    LOG(ERROR) << __func__ << ": GetRandom(nonce) failed.";
    return false;
  }

  for (KeyType key_type : tpm_utility_->GetSupportedKeyTypes()) {
    std::string key_blob;
    std::string public_key_der;
    std::string public_key_tpm_format;
    std::string key_info;
    std::string proof;
    if (!tpm_utility_->CreateCertifiedKey(
            key_type, KEY_USAGE_SIGN, KeyRestriction::kUnrestricted,
            std::nullopt, aik_key_blob, nonce, &key_blob, &public_key_der,
            &public_key_tpm_format, &key_info, &proof)) {
      LOG(ERROR) << __func__
                 << ": Failed to create certified key for key_type: "
                 << key_type;
      return false;
    }
    std::string public_key_info;
    if (!GetSubjectPublicKeyInfo(key_type, public_key_der, &public_key_info)) {
      LOG(ERROR) << __func__ << ": Failed to get public key info for key_type: "
                 << key_type;
      return false;
    }
    if (!VerifyCertifiedKey(aik_public_key_info, public_key_info,
                            public_key_tpm_format, key_info, proof)) {
      LOG(ERROR) << __func__
                 << ": Bad certified key for key_type: " << key_type;
      return false;
    }
  }
  return true;
}

bool AttestationService::VerifyActivateIdentity(
    const std::string& aik_public_key_tpm_format) {
  std::string rsa_ek_public_key;
  if (!tpm_utility_->GetEndorsementPublicKey(KEY_TYPE_RSA,
                                             &rsa_ek_public_key)) {
    LOG(ERROR) << __func__
               << ": Can't get RSA EK public key for VerifyActivateIdentity.";
    return false;
  }
  std::string test_credential = "test credential";
  EncryptedIdentityCredential encrypted_credential;
  if (!crypto_utility_->EncryptIdentityCredential(
          tpm_utility_->GetVersion(), test_credential, rsa_ek_public_key,
          aik_public_key_tpm_format, &encrypted_credential)) {
    LOG(ERROR) << __func__ << ": Failed to encrypt identity credential";
    return false;
  }
  if (!ActivateAttestationKeyInternal(kFirstIdentity, DEFAULT_ACA, KEY_TYPE_RSA,
                                      encrypted_credential, false, nullptr,
                                      nullptr)) {
    LOG(ERROR) << __func__ << ": Failed to activate identity";
    return false;
  }
  return true;
}

void AttestationService::VerifyTask(
    const VerifyRequest& request, const std::shared_ptr<VerifyReply>& result) {
  result->set_verified(false);

  std::optional<std::string> ek_public_key = GetEndorsementPublicKey();
  if (!ek_public_key.has_value()) {
    LOG(ERROR) << __func__ << ": Endorsement key not available.";
    return;
  }

  std::optional<std::string> ek_cert = GetEndorsementCertificate();
  if (!ek_cert.has_value()) {
    LOG(ERROR) << __func__ << ": Endorsement cert not available.";
    return;
  }

  std::string issuer;
  if (!crypto_utility_->GetCertificateIssuerName(ek_cert.value(), &issuer)) {
    LOG(ERROR) << __func__ << ": Failed to get certificate issuer.";
    return;
  }
  std::string ca_public_key;
  bool has_found_ca_public_key =
      GetAuthorityPublicKey(issuer, request.cros_core(), &ca_public_key);
  if (has_found_ca_public_key) {
    if (!crypto_utility_->VerifyCertificate(ek_cert.value(), ca_public_key)) {
      LOG(WARNING) << __func__ << ": Bad endorsement credential.";
      return;
    }
  } else {
    if (!VerifyCertificateWithSubjectPublicKeyInfo(issuer, request.cros_core(),
                                                   ek_cert.value())) {
      LOG(ERROR)
          << __func__
          << ": Failed to verify the certificate with subject public key info.";
      return;
    }
  }

  // Verifies that the given public key matches the one in the credential.

  // Gets the public key by GetCertificatePublicKey and
  // GetCertificateSubjectPublicKeyInfo for TPM1.2 and TPM2.0 respectively.
  // TODO(crbug/942487): Only use GetCertificateSubjectPublicKeyInfo after the
  // bug is resolved.
  std::string cert_public_key_info;
  switch (tpm_utility_->GetVersion()) {
    case TPM_1_2:
      if (!crypto_utility_->GetCertificatePublicKey(ek_cert.value(),
                                                    &cert_public_key_info)) {
        LOG(ERROR) << __func__ << ": Failed to call GetCertificatePublicKey.";
        return;
      }
      break;
    case TPM_2_0:
      if (!crypto_utility_->GetCertificateSubjectPublicKeyInfo(
              ek_cert.value(), &cert_public_key_info)) {
        LOG(ERROR) << __func__
                   << ": Failed to call GetCertificateSubjectPublicKeyInfo.";
        return;
      }
      break;
    default:
      NOTREACHED() << "Unexpected TPM version.";
  }

  // Note: Do not use any openssl functions that attempt to decode the public
  // key. These will fail because openssl does not recognize the OAEP key type,
  // which could happen for some TPM1.2 chips.
  if (cert_public_key_info != ek_public_key.value()) {
    LOG(ERROR) << __func__ << ": Bad certificate public key.";
    return;
  }

  // All done if we only needed to verify EK. Otherwise, continue with full
  // verification.
  if (request.ek_only()) {
    result->set_verified(true);
    return;
  }

  auto database_pb = database_->GetProtobuf();
  const auto& identity_data = database_pb.identities().Get(kFirstIdentity);
  std::string identity_public_key_info;
  if (!GetSubjectPublicKeyInfo(
          identity_data.identity_key().identity_key_type(),
          identity_data.identity_key().identity_public_key_der(),
          &identity_public_key_info)) {
    LOG(ERROR) << __func__ << ": Failed to get identity public key info.";
    return;
  }
  if (!VerifyIdentityBinding(identity_data.identity_binding())) {
    LOG(ERROR) << __func__ << ": Bad identity binding.";
    return;
  }
  if (auto result = hwsec_->GetCurrentBootMode(); !result.ok()) {
    LOG(ERROR) << __func__ << "Invalid boot mode: " << result.status();
    metrics_.ReportAttestationOpsStatus(
        kAttestationVerify, AttestationOpsStatus::kInvalidPcr0Value);
  }
  if (!VerifyPCR0Quote(identity_public_key_info,
                       identity_data.pcr_quotes().at(0))) {
    LOG(ERROR) << __func__ << ": Bad PCR0 quote.";
    return;
  }
  if (!VerifyPCR1Quote(identity_public_key_info,
                       identity_data.pcr_quotes().at(1))) {
    // Don't fail because many devices don't use PCR1.
    LOG(WARNING) << __func__ << ": Bad PCR1 quote.";
  }
  if (!VerifyCertifiedKeyGeneration(
          identity_data.identity_key().identity_key_blob(),
          identity_public_key_info)) {
    LOG(ERROR) << __func__ << ": Failed to verify certified key generation.";
    return;
  }

  // Originally, we use VerifyActivateIdentity to test ActivateIdentity TPM
  // command works in TPM 1.2, but we don't really need it for TPM 2.0. Because
  // we have more complete tests in Cr50, we are planning to obsolete the tests
  // in the service daemon. Moreover, supporting this would require simulating
  // the entire attestation flow but pointless. We decide to not to support this
  // test for ECC EK.
  if (!VerifyActivateIdentity(
          identity_data.identity_binding().identity_public_key_tpm_format())) {
    LOG(ERROR) << __func__ << ": Failed to verify identity activation.";
    return;
  }
  LOG(INFO) << "Attestation: Verified OK.";
  result->set_verified(true);
}

void AttestationService::CreateEnrollRequest(
    const CreateEnrollRequestRequest& request,
    CreateEnrollRequestCallback callback) {
  auto result = std::make_shared<CreateEnrollRequestReply>();
  base::OnceClosure task = base::BindOnce(
      &AttestationService::CreateEnrollRequestTask<CreateEnrollRequestRequest>,
      base::Unretained(this), request, result);
  base::OnceClosure reply = base::BindOnce(
      &AttestationService::TaskRelayCallback<CreateEnrollRequestReply>,
      GetWeakPtr(), std::move(callback), result);
  worker_thread_->task_runner()->PostTaskAndReply(FROM_HERE, std::move(task),
                                                  std::move(reply));
}

template <typename RequestType>
void AttestationService::CreateEnrollRequestTask(
    const RequestType& request,
    const std::shared_ptr<CreateEnrollRequestReply>& result) {
  if (!CreateEnrollRequestInternal(request.aca_type(),
                                   result->mutable_pca_request())) {
    result->clear_pca_request();
    result->set_status(STATUS_UNEXPECTED_DEVICE_ERROR);
  }
}

void AttestationService::FinishEnroll(const FinishEnrollRequest& request,
                                      FinishEnrollCallback callback) {
  auto result = std::make_shared<FinishEnrollReply>();
  base::OnceClosure task =
      base::BindOnce(&AttestationService::FinishEnrollTask<FinishEnrollReply>,
                     base::Unretained(this), request, result);
  base::OnceClosure reply =
      base::BindOnce(&AttestationService::TaskRelayCallback<FinishEnrollReply>,
                     GetWeakPtr(), std::move(callback), result);
  worker_thread_->task_runner()->PostTaskAndReply(FROM_HERE, std::move(task),
                                                  std::move(reply));
}

template <typename ReplyType>
void AttestationService::FinishEnrollTask(
    const FinishEnrollRequest& request,
    const std::shared_ptr<ReplyType>& result) {
  std::string server_error;
  if (!FinishEnrollInternal(request.aca_type(), request.pca_response(),
                            &server_error)) {
    if (server_error.empty()) {
      result->set_status(STATUS_UNEXPECTED_DEVICE_ERROR);
    } else {
      result->set_status(STATUS_REQUEST_DENIED_BY_CA);
    }
  }
}

void AttestationService::PostStartEnrollTask(
    const std::shared_ptr<AttestationFlowData>& data) {
  base::OnceClosure task = base::BindOnce(&AttestationService::StartEnrollTask,
                                          base::Unretained(this), data);
  base::OnceClosure reply =
      base::BindOnce(&AttestationService::OnEnrollAction, GetWeakPtr(), data);
  worker_thread_->task_runner()->PostTaskAndReply(FROM_HERE, std::move(task),
                                                  std::move(reply));
}

void AttestationService::Enroll(const EnrollRequest& request,
                                EnrollCallback callback) {
  PostStartEnrollTask(
      std::make_shared<AttestationFlowData>(request, std::move(callback)));
}

void AttestationService::SendEnrollRequest(
    const std::shared_ptr<AttestationFlowData>& data) {
  auto pca_request = ToPcaAgentEnrollRequest(*data);
  auto on_success = base::BindOnce(
      &AttestationService::HandlePcaAgentEnrollReply, GetWeakPtr(), data);
  auto on_error =
      base::BindOnce(&AttestationService::HandlePcaAgentEnrollRequestError,
                     GetWeakPtr(), data);
  pca_agent_proxy_->EnrollAsync(pca_request, std::move(on_success),
                                std::move(on_error),
                                kPcaAgentDBusTimeout.InMilliseconds());
}

void AttestationService::HandlePcaAgentEnrollRequestError(
    const std::shared_ptr<AttestationFlowData>& data, brillo::Error*) {
  LOG(ERROR) << __func__ << ": Error sending enroll request to |pca_agent|";
  data->set_status(STATUS_UNEXPECTED_DEVICE_ERROR);
  enrollment_statuses_[data->aca_type()] = EnrollmentStatus::kNotEnrolled;
  data->set_action(AttestationFlowAction::kAbort);
  OnEnrollAction(data);
}

void AttestationService::OnEnrollAction(
    const std::shared_ptr<AttestationFlowData>& data) {
  VLOG(1) << __func__ << ": action is : " << static_cast<int>(data->action());
  switch (data->action()) {
    default:
    case AttestationFlowAction::kUnknown:
      LOG(DFATAL) << "Unexpected action code: "
                  << static_cast<int>(data->action());
      data->set_status(STATUS_NOT_SUPPORTED);
      data->ReturnStatus();
      return;
    case AttestationFlowAction::kAbort:
      data->ReturnStatus();
      for (const auto& alias : enrollment_queue_.PopAll(data->aca_type())) {
        alias->set_status(data->status());
        alias->ReturnStatus();
      }
      return;
    case AttestationFlowAction::kProcessRequest:
      SendEnrollRequest(data);
      return;
    case AttestationFlowAction::kEnqueue:
      // If in the dbus calling thread the status has changed, re-posts the
      // task.
      if (enrollment_statuses_[data->aca_type()] !=
          EnrollmentStatus::kInProgress) {
        PostStartEnrollTask(data);
      } else {
        if (!enrollment_queue_.Push(data)) {
          data->set_status(STATUS_UNEXPECTED_DEVICE_ERROR);
          data->ReturnStatus();
        }
      }
      return;
    case AttestationFlowAction::kNoop:
      PostStartCertificateTaskOrReturn(data);
      for (const auto& alias : enrollment_queue_.PopAll(data->aca_type())) {
        PostStartCertificateTaskOrReturn(alias);
      }
      return;
  }
}

void AttestationService::OnGetCertificateAction(
    const std::shared_ptr<AttestationFlowData>& data) {
  VLOG(1) << __func__ << ": action is : " << static_cast<int>(data->action());
  switch (data->action()) {
    default:
    case AttestationFlowAction::kUnknown:
      LOG(DFATAL) << "Unexpected action code: "
                  << static_cast<int>(data->action());
      data->set_status(STATUS_NOT_SUPPORTED);
      data->ReturnStatus();
      return;
    case AttestationFlowAction::kProcessRequest:
      SendGetCertificateRequest(data);
      return;
    case AttestationFlowAction::kEnqueue:
      // If no alias found, re-posts the task. Sadly the task will check the key
      // store again. The good news is, this case should be rare in practice.
      if (!certificate_queue_.HasAnyAlias(data)) {
        // Despite of the callee name, it always posts the task here since we
        // shall get certificate.
        PostStartCertificateTaskOrReturn(data);
      } else {
        // TODO(b/149723745): UMA for respective failure cases.
        CertificateQueue::PushResult result = certificate_queue_.Push(data);
        if (result != CertificateQueue::PushResult::kSuccess) {
          data->set_status(STATUS_UNEXPECTED_DEVICE_ERROR);
          data->ReturnStatus();
        }
      }
      return;
    case AttestationFlowAction::kAbort:
    case AttestationFlowAction::kNoop:
      ReturnForAllCertificateRequestAliases(data);
      return;
  }
}

void AttestationService::ReturnForAllCertificateRequestAliases(
    const std::shared_ptr<AttestationFlowData>& data) {
  if (data->status() == STATUS_SUCCESS) {
    data->ReturnCertificate();
    std::string certificate = data->certificate();
    for (const auto& alias : certificate_queue_.PopAllAliases(data)) {
      if (data != alias) {
        alias->set_certificate(data->certificate());
        alias->set_key_blob(data->key_blob());
        alias->set_certified_key_credential(data->certified_key_credential());
        alias->ReturnCertificate();
      }
    }
  } else {
    data->ReturnStatus();
    for (const auto& alias : certificate_queue_.PopAllAliases(data)) {
      if (data != alias) {
        alias->set_status(data->status());
        alias->ReturnStatus();
      }
    }
  }
}

void AttestationService::StartEnrollTask(
    const std::shared_ptr<AttestationFlowData>& data) {
  // When the enrollment is in progress, all the attestation flow entries listen
  // to the same response.
  if (enrollment_statuses_[data->aca_type()] == EnrollmentStatus::kInProgress) {
    data->set_action(AttestationFlowAction::kEnqueue);
    return;
  }
  // This is the place we initialize the enrollment statuses; at this moment
  // there is no write operation in other threads, so we don't bother using
  // compare_and_exchange atomic operation.
  if (enrollment_statuses_[data->aca_type()] == EnrollmentStatus::kUnknown) {
    enrollment_statuses_[data->aca_type()] =
        IsEnrolledWithACA(data->aca_type()) ? EnrollmentStatus::kEnrolled
                                            : EnrollmentStatus::kNotEnrolled;
  }
  // At this point, possible statuses are : kEnrolled and kNotEnrolled.
  const bool is_enrolled =
      enrollment_statuses_[data->aca_type()] == EnrollmentStatus::kEnrolled;
  if (is_enrolled && !data->forced_enrollment()) {
    data->set_action(AttestationFlowAction::kNoop);
    return;
  }
  if (!is_enrolled && !data->shall_enroll()) {
    data->set_action(AttestationFlowAction::kAbort);
    data->set_status(STATUS_UNEXPECTED_DEVICE_ERROR);
    return;
  }
  std::string result_request;
  if (!CreateEnrollRequestInternal(data->aca_type(), &result_request)) {
    data->set_action(AttestationFlowAction::kAbort);
    data->set_status(STATUS_UNEXPECTED_DEVICE_ERROR);
    return;
  }
  enrollment_statuses_[data->aca_type()] = EnrollmentStatus::kInProgress;
  data->emplace_result_request(std::move(result_request));
  data->set_action(AttestationFlowAction::kProcessRequest);
}

void AttestationService::FinishEnrollTaskV2(
    const std::shared_ptr<AttestationFlowData>& data) {
  std::string server_error;
  if (!FinishEnrollInternal(data->aca_type(), data->result_response(),
                            &server_error)) {
    if (server_error.empty()) {
      data->set_status(STATUS_UNEXPECTED_DEVICE_ERROR);
    } else {
      data->set_status(STATUS_REQUEST_DENIED_BY_CA);
    }
    data->set_action(AttestationFlowAction::kAbort);
    enrollment_statuses_[data->aca_type()] = EnrollmentStatus::kNotEnrolled;
  } else {
    data->set_action(AttestationFlowAction::kNoop);
    enrollment_statuses_[data->aca_type()] = EnrollmentStatus::kEnrolled;
  }
}

void AttestationService::PostStartCertificateTaskOrReturn(
    const std::shared_ptr<AttestationFlowData>& data) {
  if (!data->shall_get_certificate()) {
    data->ReturnStatus();
    return;
  }
  base::OnceClosure task = base::BindOnce(
      &AttestationService::StartCertificateTask, base::Unretained(this), data);
  base::OnceClosure reply = base::BindOnce(
      &AttestationService::OnGetCertificateAction, GetWeakPtr(), data);
  worker_thread_->task_runner()->PostTaskAndReply(FROM_HERE, std::move(task),
                                                  std::move(reply));
}

void AttestationService::StartCertificateTask(
    const std::shared_ptr<AttestationFlowData>& data) {
  DCHECK(data->shall_get_certificate());

  if (certificate_queue_.HasAnyAlias(data)) {
    data->set_action(AttestationFlowAction::kEnqueue);
    return;
  }

  CertifiedKey key;
  if (!data->forced_get_certificate() &&
      FindKeyByLabel(data->username(), data->key_label(), &key)) {
    std::string public_key_info;
    if (!GetSubjectPublicKeyInfo(key.key_type(), key.public_key(),
                                 &public_key_info)) {
      LOG(ERROR) << __func__ << ": Failed to call `GetSubjectPublicKeyInfo()`.";
      data->set_status(STATUS_UNEXPECTED_DEVICE_ERROR);
      data->set_action(AttestationFlowAction::kAbort);
      return;
    }
    data->set_public_key(std::move(public_key_info));
    data->set_certificate(CreatePEMCertificateChain(key));
    data->set_certified_key_credential(key.certified_key_credential());
    data->set_key_blob(key.key_blob());
    data->set_action(AttestationFlowAction::kNoop);
    return;
  }
  // Indirects to the existing logic; by doing this we don't have to worry about
  // changing the current behavior.
  const GetCertificateRequest& request = data->get_certificate_request();
  auto reply = std::make_shared<CreateCertificateRequestReply>();
  CreateCertificateRequestTask(request, reply);
  if (reply->status() != STATUS_SUCCESS) {
    data->set_status(reply->status());
    data->set_action(AttestationFlowAction::kAbort);
    return;
  }
  data->emplace_result_request(std::move(*(reply->mutable_pca_request())));
  data->set_action(AttestationFlowAction::kProcessRequest);
  // Different from the way we handle enrollment, enqueues |data| right here so
  // we can check the existence of aliases to tell if the certification in
  // progress.
  CertificateQueue::PushResult push_result = certificate_queue_.Push(data);
  // the certificate queue is in a broken state since we already ensure
  // |HasAnyAlias| to be |false|; crashes |attestationd| to bring it back to
  // initial state in any case.
  CHECK_EQ(push_result, CertificateQueue::PushResult::kSuccess)
      << "Unexpected error during pushing the first alias to certificate "
         "queue.";
}

void AttestationService::FinishCertificateTask(
    const std::shared_ptr<AttestationFlowData>& data) {
  // Indirects to the existing logic; by doing this we don't have to worry about
  // changing the current behavior.
  FinishCertificateRequestRequest request;
  request.set_pca_response(data->result_response());
  request.set_username(data->username());
  request.set_key_label(data->key_label());
  auto reply = std::make_shared<FinishCertificateRequestReply>();
  FinishCertificateRequestTask(request, reply);
  if (reply->status() != STATUS_SUCCESS) {
    data->set_status(reply->status());
    data->set_action(AttestationFlowAction::kAbort);
    return;
  }
  data->set_public_key(std::move(*(reply->mutable_public_key())));
  data->set_certificate(std::move(*(reply->mutable_certificate())));
  data->set_certified_key_credential(
      std::move(*(reply->mutable_certified_key_credential())));
  data->set_key_blob((std::move(*(reply->mutable_key_blob()))));
  data->set_action(AttestationFlowAction::kNoop);
}

void AttestationService::HandlePcaAgentEnrollReply(
    const std::shared_ptr<AttestationFlowData>& data,
    const pca_agent::EnrollReply& pca_reply) {
  if (pca_reply.status() != STATUS_SUCCESS) {
    enrollment_statuses_[data->aca_type()] = EnrollmentStatus::kNotEnrolled;
    data->set_status(pca_reply.status());
    data->set_action(AttestationFlowAction::kAbort);
    OnEnrollAction(data);
    return;
  }
  data->set_result_response(pca_reply.response());
  base::OnceClosure task = base::BindOnce(
      &AttestationService::FinishEnrollTaskV2, base::Unretained(this), data);
  base::OnceClosure reply =
      base::BindOnce(&AttestationService::OnEnrollAction, GetWeakPtr(), data);
  worker_thread_->task_runner()->PostTaskAndReply(FROM_HERE, std::move(task),
                                                  std::move(reply));
}

void AttestationService::CreateCertificateRequest(
    const CreateCertificateRequestRequest& request,
    CreateCertificateRequestCallback callback) {
  auto result = std::make_shared<CreateCertificateRequestReply>();
  base::OnceClosure task =
      base::BindOnce(&AttestationService::CreateCertificateRequestTask<
                         CreateCertificateRequestRequest>,
                     base::Unretained(this), request, result);
  base::OnceClosure reply = base::BindOnce(
      &AttestationService::TaskRelayCallback<CreateCertificateRequestReply>,
      GetWeakPtr(), std::move(callback), result);
  worker_thread_->task_runner()->PostTaskAndReply(FROM_HERE, std::move(task),
                                                  std::move(reply));
}

template <typename RequestType>
void AttestationService::CreateCertificateRequestTask(
    const RequestType& request,
    const std::shared_ptr<CreateCertificateRequestReply>& result) {
  const int identity = kFirstIdentity;
  auto database_pb = database_->GetProtobuf();
  if (database_pb.identities().size() <= identity) {
    LOG(ERROR) << __func__ << ": Cannot create a certificate request, identity "
               << identity << " does not exist.";
    result->set_status(STATUS_UNEXPECTED_DEVICE_ERROR);
    return;
  }

  std::string nonce;
  if (!crypto_utility_->GetRandom(kNonceSize, &nonce)) {
    LOG(ERROR) << __func__ << ": GetRandom(nonce) failed.";
    result->set_status(STATUS_UNEXPECTED_DEVICE_ERROR);
    return;
  }
  KeyType key_type = request.key_type();
  std::string key_blob;
  std::string public_key_der;
  std::string public_key_tpm_format;
  std::string key_info;
  std::string proof;
  CertifiedKey key;

  const KeyUsage key_usage =
      GetKeyUsageByProfile(request.certificate_profile());
  const KeyRestriction key_restriction =
      GetKeyRestrictionByProfile(request.certificate_profile());

  const auto& identity_data = database_pb.identities().Get(identity);
  if (!tpm_utility_->CreateCertifiedKey(
          key_type, key_usage, key_restriction, request.certificate_profile(),
          identity_data.identity_key().identity_key_blob(), nonce, &key_blob,
          &public_key_der, &public_key_tpm_format, &key_info, &proof)) {
    LOG(ERROR) << __func__ << ": Failed to create a key.";
    result->set_status(STATUS_UNEXPECTED_DEVICE_ERROR);
    return;
  }
  key.set_key_blob(key_blob);
  key.set_public_key(public_key_der);
  key.set_public_key_tpm_format(public_key_tpm_format);
  key.set_certified_key_info(key_info);
  key.set_certified_key_proof(proof);
  key.set_key_type(key_type);
  key.set_key_usage(key_usage);
  std::string message_id;
  if (!CreateCertificateRequestInternal(
          request.aca_type(), request.username(), key,
          request.certificate_profile(), request.request_origin(),
          result->mutable_pca_request(), &message_id,
          GetDeviceSetupCertificateRequestMetadataIfPresent(request))) {
    result->clear_pca_request();
    result->set_status(STATUS_UNEXPECTED_DEVICE_ERROR);
    return;
  }
  std::string serialized_key;
  if (!key.SerializeToString(&serialized_key)) {
    LOG(ERROR) << __func__ << ": Failed to serialize key protobuf.";
    result->clear_pca_request();
    result->set_status(STATUS_UNEXPECTED_DEVICE_ERROR);
    return;
  }
  pending_cert_requests_[message_id] = serialized_key;
}

void AttestationService::FinishCertificateRequest(
    const FinishCertificateRequestRequest& request,
    FinishCertificateRequestCallback callback) {
  auto result = std::make_shared<FinishCertificateRequestReply>();
  base::OnceClosure task =
      base::BindOnce(&AttestationService::FinishCertificateRequestTask<
                         FinishCertificateRequestReply>,
                     base::Unretained(this), request, result);
  base::OnceClosure reply = base::BindOnce(
      &AttestationService::TaskRelayCallback<FinishCertificateRequestReply>,
      GetWeakPtr(), std::move(callback), result);
  worker_thread_->task_runner()->PostTaskAndReply(FROM_HERE, std::move(task),
                                                  std::move(reply));
}

template <typename ReplyType>
void AttestationService::FinishCertificateRequestTask(
    const FinishCertificateRequestRequest& request,
    const std::shared_ptr<ReplyType>& result) {
  AttestationCertificateResponse response_pb;
  if (!response_pb.ParseFromString(request.pca_response())) {
    LOG(ERROR) << __func__ << ": Failed to parse response from Attestation CA.";
    result->set_status(STATUS_UNEXPECTED_DEVICE_ERROR);
    return;
  }
  CertRequestMap::iterator iter =
      pending_cert_requests_.find(response_pb.message_id());
  if (iter == pending_cert_requests_.end()) {
    LOG(ERROR) << __func__ << ": Pending request not found.";
    result->set_status(STATUS_UNEXPECTED_DEVICE_ERROR);
    return;
  }
  if (response_pb.status() != OK) {
    LogErrorFromCA(__func__, response_pb.detail(), response_pb.extra_details());
    pending_cert_requests_.erase(iter);
    result->set_status(STATUS_REQUEST_DENIED_BY_CA);
    return;
  }
  CertifiedKey key;
  if (!key.ParseFromArray(iter->second.data(), iter->second.size())) {
    LOG(ERROR) << __func__ << ": Failed to parse pending request key.";
    pending_cert_requests_.erase(iter);
    result->set_status(STATUS_UNEXPECTED_DEVICE_ERROR);
    return;
  }
  if (!GetSubjectPublicKeyInfo(key.key_type(), key.public_key(),
                               result->mutable_public_key())) {
    LOG(ERROR) << __func__ << ": Failed to call `GetSubjectPublicKeyInfo()`.";
    pending_cert_requests_.erase(iter);
    result->set_status(STATUS_UNEXPECTED_DEVICE_ERROR);
    return;
  }
  pending_cert_requests_.erase(iter);
  if (!PopulateAndStoreCertifiedKey(response_pb, request.username(),
                                    request.key_label(), &key)) {
    result->set_status(STATUS_UNEXPECTED_DEVICE_ERROR);
    return;
  }
  LOG(INFO) << "Attestation: Certified key credential received and stored.";
  result->set_status(STATUS_SUCCESS);
  result->set_certificate(CreatePEMCertificateChain(key));
  result->set_certified_key_credential(key.certified_key_credential());
  result->set_key_blob(key.key_blob());
}

void AttestationService::GetCertificate(const GetCertificateRequest& request,
                                        GetCertificateCallback callback) {
  PostStartEnrollTask(
      std::make_shared<AttestationFlowData>(request, std::move(callback)));
}

void AttestationService::SendGetCertificateRequest(
    const std::shared_ptr<AttestationFlowData>& data) {
  auto pca_request = ToPcaAgentCertRequest(*data);
  auto on_success =
      base::BindOnce(&AttestationService::HandlePcaAgentGetCertificateReply,
                     GetWeakPtr(), data);
  auto on_error = base::BindOnce(
      &AttestationService::HandlePcaAgentGetCertificateRequestError,
      GetWeakPtr(), data);
  pca_agent_proxy_->GetCertificateAsync(pca_request, std::move(on_success),
                                        std::move(on_error),
                                        kPcaAgentDBusTimeout.InMilliseconds());
}

void AttestationService::HandlePcaAgentGetCertificateRequestError(
    const std::shared_ptr<AttestationFlowData>& data, brillo::Error*) {
  LOG(ERROR) << __func__
             << ": Error sending certificate request to |pca_agent|";
  data->set_status(STATUS_UNEXPECTED_DEVICE_ERROR);
  data->set_action(AttestationFlowAction::kAbort);
  OnGetCertificateAction(data);
  return;
}

void AttestationService::HandlePcaAgentGetCertificateReply(
    const std::shared_ptr<AttestationFlowData>& data,
    const pca_agent::GetCertificateReply& pca_reply) {
  if (pca_reply.status() != STATUS_SUCCESS) {
    data->set_status(pca_reply.status());
    data->set_action(AttestationFlowAction::kAbort);
    OnGetCertificateAction(data);
    return;
  }
  data->set_result_response(pca_reply.response());
  base::OnceClosure task = base::BindOnce(
      &AttestationService::FinishCertificateTask, base::Unretained(this), data);
  base::OnceClosure reply = base::BindOnce(
      &AttestationService::OnGetCertificateAction, GetWeakPtr(), data);
  worker_thread_->task_runner()->PostTaskAndReply(FROM_HERE, std::move(task),
                                                  std::move(reply));
}

bool AttestationService::ValidateEnterpriseChallenge(
    VAType va_type, const SignedData& signed_challenge) {
  const char kExpectedChallengePrefix[] = "EnterpriseKeyChallenge";
  // VA server always use SHA256 as digest algorithm for signature.
  if (!crypto_utility_->VerifySignatureUsingHexKey(
          NID_sha256, google_keys_.va_signing_key(va_type).modulus_in_hex(),
          signed_challenge.data(), signed_challenge.signature())) {
    LOG(ERROR) << __func__ << ": Failed to verify challenge signature.";
    return false;
  }
  Challenge challenge;
  if (!challenge.ParseFromString(signed_challenge.data())) {
    LOG(ERROR) << __func__ << ": Failed to parse challenge protobuf.";
    return false;
  }
  if (challenge.prefix() != kExpectedChallengePrefix) {
    LOG(ERROR) << __func__ << ": Unexpected challenge prefix.";
    return false;
  }
  return true;
}

bool AttestationService::EncryptEnterpriseKeyInfo(
    VAType va_type, const KeyInfo& key_info, EncryptedData* encrypted_data) {
  std::string serialized;
  if (!key_info.SerializeToString(&serialized)) {
    LOG(ERROR) << "Failed to serialize key info.";
    return false;
  }
  return crypto_utility_->EncryptDataForGoogle(
      serialized, google_keys_.va_encryption_key(va_type).modulus_in_hex(),
      google_keys_.va_encryption_key(va_type).key_id(), encrypted_data);
}

void AttestationService::SignEnterpriseChallenge(
    const SignEnterpriseChallengeRequest& request,
    SignEnterpriseChallengeCallback callback) {
  auto result = std::make_shared<SignEnterpriseChallengeReply>();
  base::OnceClosure task =
      base::BindOnce(&AttestationService::SignEnterpriseChallengeTask,
                     base::Unretained(this), request, result);
  base::OnceClosure reply = base::BindOnce(
      &AttestationService::TaskRelayCallback<SignEnterpriseChallengeReply>,
      GetWeakPtr(), std::move(callback), result);
  worker_thread_->task_runner()->PostTaskAndReply(FROM_HERE, std::move(task),
                                                  std::move(reply));
}

void AttestationService::SignEnterpriseChallengeTask(
    const SignEnterpriseChallengeRequest& request,
    const std::shared_ptr<SignEnterpriseChallengeReply>& result) {
  CertifiedKey key;
  if (!FindKeyByLabel(request.username(), request.key_label(), &key)) {
    result->set_status(STATUS_INVALID_PARAMETER);
    return;
  }

  // Validate that the challenge is coming from the expected source.
  SignedData signed_challenge;
  if (!signed_challenge.ParseFromString(request.challenge())) {
    LOG(ERROR) << __func__ << ": Failed to parse signed challenge.";
    result->set_status(STATUS_INVALID_PARAMETER);
    return;
  }
  if (!ValidateEnterpriseChallenge(request.va_type(), signed_challenge)) {
    LOG(ERROR) << __func__ << ": Invalid challenge.";
    result->set_status(STATUS_INVALID_PARAMETER);
    return;
  }
  // Add a nonce to ensure this service cannot be used to sign arbitrary data.
  std::string nonce;
  if (!crypto_utility_->GetRandom(kChallengeSignatureNonceSize, &nonce)) {
    LOG(ERROR) << __func__ << ": Failed to generate nonce.";
    result->set_status(STATUS_UNEXPECTED_DEVICE_ERROR);
    return;
  }

  const bool is_user_specific = !request.username().empty();
  KeyInfo key_info;
  // EUK -> Enterprise User Key
  // EMK -> Enterprise Machine Key
  if (is_user_specific) {
    key_info.set_flow_type(ENTERPRISE_USER);
    key_info.set_domain(request.domain());
  } else {
    // For machine key the domain name should not be include.
    key_info.set_flow_type(ENTERPRISE_MACHINE);
  }
  if (request.include_customer_id() && !PopulateCustomerId(&key_info)) {
    result->set_status(STATUS_UNEXPECTED_DEVICE_ERROR);
    return;
  }
  key_info.set_device_id(request.device_id());

  if (request.has_device_trust_signals_json())
    *key_info.mutable_device_trust_signals_json() =
        request.device_trust_signals_json();

  std::optional<CertifiedKey> key_for_certificate_and_spkac;
  if (is_user_specific) {
    // Always include the EUK certificate if an EUK is being challenged.
    // Note that if including SPKAC has been requested when challenging an EUK,
    // the SPKAC will also be created for the EUK. In other words,
    // |key_name_for_spkac| is currently ignored for EUKs.
    key_for_certificate_and_spkac = key;
  } else if (request.include_signed_public_key() &&
             !request.key_name_for_spkac().empty()) {
    // If a specific key name for SPKAC has been requested when challenging an
    // EMK, include the certificate for that key.
    CertifiedKey key_for_spkac;
    if (!FindKeyByLabel(std::string() /* username */,
                        request.key_name_for_spkac(), &key_for_spkac)) {
      result->set_status(STATUS_INVALID_PARAMETER);
      return;
    }
    key_for_certificate_and_spkac = key_for_spkac;
  }
  if (key_for_certificate_and_spkac) {
    key_info.set_certificate(
        CreatePEMCertificateChain(key_for_certificate_and_spkac.value()));
    if (request.include_signed_public_key()) {
      std::string spkac;
      if (!crypto_utility_->CreateSPKAC(
              key_for_certificate_and_spkac.value().key_blob(),
              key_for_certificate_and_spkac.value().public_key(),
              key_for_certificate_and_spkac.value().key_type(), &spkac)) {
        LOG(ERROR) << __func__ << ": Failed to create signed public key.";
        result->set_status(STATUS_UNEXPECTED_DEVICE_ERROR);
        return;
      }
      key_info.set_signed_public_key_and_challenge(spkac);
    }
  }

  ChallengeResponse response_pb;
  *response_pb.mutable_challenge() = signed_challenge;
  response_pb.set_nonce(nonce);
  if (!EncryptEnterpriseKeyInfo(request.va_type(), key_info,
                                response_pb.mutable_encrypted_key_info())) {
    LOG(ERROR) << __func__ << ": Failed to encrypt KeyInfo.";
    result->set_status(STATUS_UNEXPECTED_DEVICE_ERROR);
    return;
  }

  // Serialize and sign the response protobuf.
  std::string serialized;
  if (!response_pb.SerializeToString(&serialized)) {
    LOG(ERROR) << __func__ << ": Failed to serialize response protobuf.";
    result->set_status(STATUS_UNEXPECTED_DEVICE_ERROR);
    return;
  }
  if (!SignChallengeData(key, serialized,
                         result->mutable_challenge_response())) {
    result->clear_challenge_response();
    result->set_status(STATUS_UNEXPECTED_DEVICE_ERROR);
    return;
  }
}

void AttestationService::SignSimpleChallenge(
    const SignSimpleChallengeRequest& request,
    SignSimpleChallengeCallback callback) {
  auto result = std::make_shared<SignSimpleChallengeReply>();
  base::OnceClosure task =
      base::BindOnce(&AttestationService::SignSimpleChallengeTask,
                     base::Unretained(this), request, result);
  base::OnceClosure reply = base::BindOnce(
      &AttestationService::TaskRelayCallback<SignSimpleChallengeReply>,
      GetWeakPtr(), std::move(callback), result);
  worker_thread_->task_runner()->PostTaskAndReply(FROM_HERE, std::move(task),
                                                  std::move(reply));
}

void AttestationService::SignSimpleChallengeTask(
    const SignSimpleChallengeRequest& request,
    const std::shared_ptr<SignSimpleChallengeReply>& result) {
  CertifiedKey key;
  if (!FindKeyByLabel(request.username(), request.key_label(), &key)) {
    result->set_status(STATUS_INVALID_PARAMETER);
    return;
  }
  // Add a nonce to ensure this service cannot be used to sign arbitrary data.
  std::string nonce;
  if (!crypto_utility_->GetRandom(kChallengeSignatureNonceSize, &nonce)) {
    LOG(ERROR) << __func__ << ": Failed to generate nonce.";
    result->set_status(STATUS_UNEXPECTED_DEVICE_ERROR);
    return;
  }
  if (!SignChallengeData(key, request.challenge() + nonce,
                         result->mutable_challenge_response())) {
    result->clear_challenge_response();
    result->set_status(STATUS_UNEXPECTED_DEVICE_ERROR);
    return;
  }
}

bool AttestationService::SignChallengeData(const CertifiedKey& key,
                                           const std::string& data_to_sign,
                                           std::string* response) {
  std::string signature;
  if (!tpm_utility_->Sign(key.key_blob(), data_to_sign, &signature)) {
    LOG(ERROR) << __func__ << ": Failed to sign data.";
    return false;
  }
  SignedData signed_data;
  signed_data.set_data(data_to_sign);
  signed_data.set_signature(signature);
  if (!signed_data.SerializeToString(response)) {
    LOG(ERROR) << __func__ << ": Failed to serialize signed data.";
    return false;
  }
  return true;
}

void AttestationService::SetKeyPayload(const SetKeyPayloadRequest& request,
                                       SetKeyPayloadCallback callback) {
  auto result = std::make_shared<SetKeyPayloadReply>();
  base::OnceClosure task =
      base::BindOnce(&AttestationService::SetKeyPayloadTask,
                     base::Unretained(this), request, result);
  base::OnceClosure reply =
      base::BindOnce(&AttestationService::TaskRelayCallback<SetKeyPayloadReply>,
                     GetWeakPtr(), std::move(callback), result);
  worker_thread_->task_runner()->PostTaskAndReply(FROM_HERE, std::move(task),
                                                  std::move(reply));
}

void AttestationService::SetKeyPayloadTask(
    const SetKeyPayloadRequest& request,
    const std::shared_ptr<SetKeyPayloadReply>& result) {
  CertifiedKey key;
  if (!FindKeyByLabel(request.username(), request.key_label(), &key)) {
    result->set_status(STATUS_INVALID_PARAMETER);
    return;
  }
  key.set_payload(request.payload());
  if (!SaveKey(request.username(), request.key_label(), key)) {
    result->set_status(STATUS_UNEXPECTED_DEVICE_ERROR);
    return;
  }
}

void AttestationService::DeleteKeys(const DeleteKeysRequest& request,
                                    DeleteKeysCallback callback) {
  auto result = std::make_shared<DeleteKeysReply>();
  base::OnceClosure task =
      base::BindOnce(&AttestationService::DeleteKeysTask,
                     base::Unretained(this), request, result);
  base::OnceClosure reply =
      base::BindOnce(&AttestationService::TaskRelayCallback<DeleteKeysReply>,
                     GetWeakPtr(), std::move(callback), result);
  worker_thread_->task_runner()->PostTaskAndReply(FROM_HERE, std::move(task),
                                                  std::move(reply));
}

void AttestationService::DeleteKeysTask(
    const DeleteKeysRequest& request,
    const std::shared_ptr<DeleteKeysReply>& result) {
  if (request.has_match_behavior() &&
      request.match_behavior() == DeleteKeysRequest::MATCH_BEHAVIOR_EXACT) {
    if (!DeleteKey(request.username(), request.key_label_match())) {
      result->set_status(STATUS_UNEXPECTED_DEVICE_ERROR);
    }
    return;
  }
  if (!DeleteKeysByPrefix(request.username(), request.key_label_match())) {
    LOG(ERROR) << __func__ << ": Failed to delete keys with prefix: "
               << request.key_label_match();
    result->set_status(STATUS_UNEXPECTED_DEVICE_ERROR);
  }
}

void AttestationService::ResetIdentity(const ResetIdentityRequest& request,
                                       ResetIdentityCallback callback) {
  auto result = std::make_shared<ResetIdentityReply>();
  base::OnceClosure task =
      base::BindOnce(&AttestationService::ResetIdentityTask,
                     base::Unretained(this), request, result);
  base::OnceClosure reply =
      base::BindOnce(&AttestationService::TaskRelayCallback<ResetIdentityReply>,
                     GetWeakPtr(), std::move(callback), result);
  worker_thread_->task_runner()->PostTaskAndReply(FROM_HERE, std::move(task),
                                                  std::move(reply));
}

void AttestationService::ResetIdentityTask(
    const ResetIdentityRequest& request,
    const std::shared_ptr<ResetIdentityReply>& result) {
  LOG(ERROR) << __func__ << ": Not implemented.";
  result->set_status(STATUS_NOT_SUPPORTED);
}

void AttestationService::GetEnrollmentId(const GetEnrollmentIdRequest& request,
                                         GetEnrollmentIdCallback callback) {
  auto result = std::make_shared<GetEnrollmentIdReply>();
  base::OnceClosure task =
      base::BindOnce(&AttestationService::GetEnrollmentIdTask,
                     base::Unretained(this), request, result);

  base::OnceClosure reply = base::BindOnce(
      &AttestationService::TaskRelayCallback<GetEnrollmentIdReply>,
      GetWeakPtr(), std::move(callback), result);
  worker_thread_->task_runner()->PostTaskAndReply(FROM_HERE, std::move(task),
                                                  std::move(reply));
}

void AttestationService::GetEnrollmentIdTask(
    const GetEnrollmentIdRequest& request,
    const std::shared_ptr<GetEnrollmentIdReply>& result) {
  std::string enrollment_id;
  if (request.ignore_cache()) {
    enrollment_id = ComputeEnterpriseEnrollmentId();
  } else {
    const auto& database_pb = database_->GetProtobuf();
    if (database_pb.has_enrollment_id()) {
      enrollment_id = std::string(database_pb.enrollment_id());
    } else {
      enrollment_id = ComputeEnterpriseEnrollmentId();
      if (!enrollment_id.empty()) {
        database_->GetMutableProtobuf()->set_enrollment_id(enrollment_id);
        if (!database_->SaveChanges()) {
          LOG(WARNING) << __func__ << "Failed to save attestation db.";
        }
      }
    }
  }
  if (enrollment_id.empty()) {
    result->set_status(STATUS_NOT_AVAILABLE);
  }
  result->set_enrollment_id(enrollment_id);
}

void AttestationService::GetCertifiedNvIndex(
    const GetCertifiedNvIndexRequest& request,
    GetCertifiedNvIndexCallback callback) {
  auto result = std::make_shared<GetCertifiedNvIndexReply>();
  base::OnceClosure task =
      base::BindOnce(&AttestationService::GetCertifiedNvIndexTask,
                     base::Unretained(this), request, result);

  base::OnceClosure reply = base::BindOnce(
      &AttestationService::TaskRelayCallback<GetCertifiedNvIndexReply>,
      GetWeakPtr(), std::move(callback), result);
  worker_thread_->task_runner()->PostTaskAndReply(FROM_HERE, std::move(task),
                                                  std::move(reply));
}

void AttestationService::GetCertifiedNvIndexTask(
    const GetCertifiedNvIndexRequest& request,
    const std::shared_ptr<GetCertifiedNvIndexReply>& result) {
  result->set_status(STATUS_NOT_AVAILABLE);

  CertifiedKey key;
  if (!FindKeyByLabel(std::string(), request.key_label(), &key)) {
    LOG(WARNING) << "Attempted to certify NV space with missing key, label: "
                 << request.key_label();
    result->set_status(STATUS_INVALID_PARAMETER);
    return;
  }

  std::string certified_value;
  std::string signature;

  if (!tpm_utility_->CertifyNV(request.nv_index(), request.nv_size(),
                               key.key_blob(), &certified_value, &signature)) {
    LOG(WARNING) << "Attestation: Failed to certify NV data of size "
                 << request.nv_size() << " at index " << std::hex
                 << std::showbase << request.nv_index()
                 << ", using key with label: " << request.key_label();
    result->set_status(STATUS_INVALID_PARAMETER);
    return;
  }

  result->set_certified_data(certified_value);
  result->set_signature(signature);
  result->set_key_certificate(key.certified_key_credential());
  result->set_status(STATUS_SUCCESS);
}

std::string AttestationService::ComputeEnterpriseEnrollmentNonce() {
  if (!abe_data_ || abe_data_->empty()) {
    // If there was no device secret we cannot compute the DEN.
    // We do not want to fail attestation for those devices.
    return "";
  }

  std::string data(abe_data_->char_data(), abe_data_->size());
  std::string key(kAttestationBasedEnterpriseEnrollmentContextName);
  return crypto_utility_->HmacSha256(key, data);
}

std::string AttestationService::ComputeEnterpriseEnrollmentId() {
  std::string den = ComputeEnterpriseEnrollmentNonce();
  if (den.empty()) {
    LOG(ERROR) << __func__ << ": Failed to compute DEN.";
    return "";
  }

  std::string ek_bytes;
  if (!tpm_utility_->GetEndorsementPublicKeyBytes(
          endorsement_key_type_for_enrollment_id_, &ek_bytes)) {
    LOG(ERROR) << __func__ << ": Failed to key EK bytes.";
    return "";
  }

  // Compute the EID based on DEN and EK bytes.
  return crypto_utility_->HmacSha256(den, ek_bytes);
}

KeyType AttestationService::GetEndorsementKeyType() const {
  // If some EK information already exists in the database, we need to keep the
  // key type consistent.
  const auto& database_pb = database_->GetProtobuf();
  if (database_pb.credentials().has_endorsement_public_key() ||
      database_pb.credentials().has_endorsement_credential()) {
    // We use the default value of key_type for backward compatibility, no need
    // to check if endorsement_key_type is set.
    return database_pb.credentials().endorsement_key_type();
  }

  // We didn't generate any data yet. Use the suggested key type.
  return default_endorsement_key_type_;
}

KeyType AttestationService::GetAttestationIdentityKeyType() const {
  return default_identity_key_type_;
}

bool AttestationService::PopulateCustomerId(KeyInfo* key_info) {
  if (!policy_provider_.get())
    policy_provider_ = std::make_unique<policy::PolicyProvider>();
  policy_provider_->Reload();

  // If device_policy is still not loaded, return an error.
  if (!policy_provider_->device_policy_is_loaded()) {
    LOG(ERROR) << __func__ << ": Failed to get device policy.";
    return false;
  }
  std::string customer_id;
  if (!policy_provider_->GetDevicePolicy().GetCustomerId(&customer_id) ||
      customer_id.empty()) {
    LOG(ERROR) << __func__ << ": Failed to get customer ID.";
    return false;
  }
  key_info->set_customer_id(customer_id);
  return true;
}

base::WeakPtr<AttestationService> AttestationService::GetWeakPtr() {
  return weak_factory_.GetWeakPtr();
}

ACAType AttestationService::GetACAType(ACATypeInternal aca_type_internal) {
  switch (aca_type_internal) {
    case kDefaultACA:
      return DEFAULT_ACA;
    case kTestACA:
      return TEST_ACA;
    default:
      return DEFAULT_ACA;
  }
}

bool AttestationService::VerifyCertificateWithSubjectPublicKeyInfo(
    const std::string& issuer_name,
    bool is_cros_core,
    const std::string& ek_cert) {
  if (is_cros_core) {
    return false;
  }
  bool has_subject_public_key_info = false;
  for (const auto& info : kKnownEndorsementCASubjectKeyInfo) {
    if (issuer_name == info.issuer) {
      if (crypto_utility_->VerifyCertificateWithSubjectPublicKey(
              ek_cert, info.subject_public_key_info)) {
        return true;
      }
      has_subject_public_key_info = true;
    }
  }
  if (has_subject_public_key_info) {
    LOG(WARNING) << __func__
                 << ": Failed to verify the certificate with CA public keys";
  } else {
    LOG(WARNING) << __func__ << ": Failed to get CA public key.";
  }
  return false;
}

bool AttestationService::ShallQuoteRsaEkCertificate() const {
  // The EK type is RSA; PCA server doesn't need the certificate to compute EID.
  if (GetEndorsementKeyType() == KEY_TYPE_RSA) {
    CHECK_EQ(endorsement_key_type_for_enrollment_id_, KEY_TYPE_RSA)
        << "Attesation support don't support ECC-based EID computation with "
           "RSA EK.";
    return false;
  }
  return endorsement_key_type_for_enrollment_id_ == KEY_TYPE_RSA;
}

}  // namespace attestation
