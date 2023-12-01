/* Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <optional>

#include <base/files/file.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/posix/eintr_wrapper.h>
#include <brillo/file_utils.h>
#include <brillo/secure_blob.h>
#include <fcntl.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>
#include <sys/sysinfo.h>
#include <tpm2/BaseTypes.h>
#include <tpm2/Capabilities.h>
#include <tpm2/Implementation.h>
#include <tpm2/tpm_types.h>
#include <unistd.h>

#include <libhwsec-foundation/crypto/big_num_util.h>
#include <libhwsec-foundation/crypto/ecdh_hkdf.h>
#include <pinweaver/pinweaver_eal.h>

#define DEVICE_KEY_SIZE 32
#define PW_OBJ_CONST_SIZE 8
#define PW_NONCE_SIZE (128 / 8)
#define PINWEAVER_EAL_CONST 2
#define RESTART_TIMER_THRESHOLD 10

using hwsec_foundation::EllipticCurve;

namespace {
constexpr char kLogPath[] = "log";
constexpr char kTreeDataPath[] = "tree_data";
}  // namespace

extern "C" {

int pinweaver_eal_sha256_init(pinweaver_eal_sha256_ctx_t* ctx) {
  int rv = SHA256_Init(ctx);
  if (rv != 1) {
    PINWEAVER_EAL_INFO("SHA256_Init failed: %d", rv);
  }
  return rv == 1 ? 0 : -1;
}

int pinweaver_eal_sha256_update(pinweaver_eal_sha256_ctx_t* ctx,
                                const void* data,
                                size_t size) {
  int rv = SHA256_Update(ctx, reinterpret_cast<const uint8_t*>(data), size);
  if (rv != 1) {
    PINWEAVER_EAL_INFO("SHA256_Update failed: %d", rv);
  }
  return rv == 1 ? 0 : -1;
}

int pinweaver_eal_sha256_final(pinweaver_eal_sha256_ctx_t* ctx, void* res) {
  int rv = SHA256_Final(reinterpret_cast<uint8_t*>(res), ctx);
  if (rv != 1) {
    PINWEAVER_EAL_INFO("SHA256_Final failed: %d", rv);
  }
  return rv == 1 ? 0 : -1;
}

int pinweaver_eal_hmac_sha256_init(pinweaver_eal_hmac_sha256_ctx_t* ctx,
                                   const void* key,
                                   size_t key_size /* in bytes */) {
  *ctx = HMAC_CTX_new();
  if (!*ctx) {
    PINWEAVER_EAL_INFO("HMAC_CTX_new failed");
    return -1;
  }
  int rv = HMAC_Init_ex(*ctx, reinterpret_cast<const uint8_t*>(key), key_size,
                        EVP_sha256(), NULL);
  if (rv != 1) {
    PINWEAVER_EAL_INFO("HMAC_Init_ex failed: %d", rv);
  }
  return rv == 1 ? 0 : -1;
}
int pinweaver_eal_hmac_sha256_update(pinweaver_eal_hmac_sha256_ctx_t* ctx,
                                     const void* data,
                                     size_t size) {
  int rv = HMAC_Update(*ctx, reinterpret_cast<const uint8_t*>(data), size);
  if (rv != 1) {
    PINWEAVER_EAL_INFO("HMAC_Update failed: %d", rv);
  }
  return rv == 1 ? 0 : -1;
}

int pinweaver_eal_hmac_sha256_final(pinweaver_eal_hmac_sha256_ctx_t* ctx,
                                    void* res) {
  unsigned int len;
  int rv = HMAC_Final(*ctx, reinterpret_cast<uint8_t*>(res), &len);
  HMAC_CTX_free(*ctx);
  *ctx = NULL;
  if (rv != 1) {
    PINWEAVER_EAL_INFO("HMAC_Final failed: %d", rv);
  }
  return rv == 1 ? 0 : -1;
}

int pinweaver_eal_aes256_ctr(const void* key,
                             size_t key_size, /* in bytes */
                             const void* iv,
                             const void* data,
                             size_t size,
                             void* res) {
  EVP_CIPHER_CTX* ctx;
  int rv;
  int len, len_final;

  if (key_size != 256 / 8)
    return -1;
  ctx = EVP_CIPHER_CTX_new();
  if (!ctx)
    return -1;
  rv = EVP_EncryptInit(ctx, EVP_aes_256_ctr(),
                       reinterpret_cast<const uint8_t*>(key),
                       reinterpret_cast<const uint8_t*>(iv));
  if (rv != 1)
    goto out;
  rv = EVP_EncryptUpdate(ctx, reinterpret_cast<uint8_t*>(res), &len,
                         reinterpret_cast<const uint8_t*>(data), size);
  if (rv != 1)
    goto out;
  rv = EVP_EncryptFinal(ctx, reinterpret_cast<uint8_t*>(res) + len, &len_final);
out:
  EVP_CIPHER_CTX_free(ctx);
  return rv == 1 ? 0 : -1;
}

int pinweaver_eal_aes256_ctr_custom(const void* key,
                                    size_t key_size, /* in bytes */
                                    const void* iv,
                                    const void* data,
                                    size_t size,
                                    void* res) {
  return pinweaver_eal_aes256_ctr(key, key_size, iv, data, size, res);
}

int pinweaver_eal_safe_memcmp(const void* s1, const void* s2, size_t len) {
  const uint8_t* us1 = reinterpret_cast<const uint8_t*>(s1);
  const uint8_t* us2 = reinterpret_cast<const uint8_t*>(s2);
  int result = 0;

  while (len--)
    result |= *us1++ ^ *us2++;

  return result != 0;
}

int pinweaver_eal_rand_bytes(void* buf, size_t size) {
  return RAND_bytes(reinterpret_cast<uint8_t*>(buf), size) == 1 ? 0 : -1;
}

uint64_t pinweaver_eal_seconds_since_boot() {
  struct sysinfo si;
  if (sysinfo(&si))
    return 0;

  return (uint64_t)si.uptime;
}

int pinweaver_eal_memcpy_s(void* dest,
                           size_t destsz,
                           const void* src,
                           size_t count) {
  if (count == 0)
    return 0;

  if (dest == NULL)
    return EINVAL;

  if (src == NULL) {
    memset(dest, 0, destsz);
    return EINVAL;
  }

  if (destsz < count) {
    memset(dest, 0, destsz);
    return ERANGE;
  }

  memcpy(dest, src, count);
  return 0;
}

static int g_device_key_fill[3] = {0x01, 0x00, 0xFF};

static int pinweaver_eal_get_device_key(int kind, void* key /* 256-bit */) {
  if (kind < 0 || kind >= 3)
    return -1;
  memset(key, g_device_key_fill[kind], 256 / 8);
  return 0;
}

static void* secure_memset(void* ptr, int value, size_t num) {
  volatile uint8_t* v_ptr = reinterpret_cast<uint8_t*>(ptr);
  while (num--)
    *(v_ptr++) = value;
  return ptr;
}

static int derive_pw_key(
    const uint8_t* device_key /* DEVICE_KEY_SIZE=256-bit */,
    const uint8_t* object_const /* PW_OBJ_CONST_SIZE */,
    const uint8_t* nonce /* PW_NONCE_SIZE */,
    uint8_t* result /* SHA256_DIGEST_SIZE */) {
  pinweaver_eal_hmac_sha256_ctx_t hash;
  if (pinweaver_eal_hmac_sha256_init(&hash, device_key, DEVICE_KEY_SIZE))
    return -1;
  if (pinweaver_eal_hmac_sha256_update(&hash, object_const,
                                       PW_OBJ_CONST_SIZE)) {
    pinweaver_eal_hmac_sha256_final(&hash, result);
    return -1;
  }
  if (pinweaver_eal_hmac_sha256_update(&hash, nonce, PW_NONCE_SIZE)) {
    pinweaver_eal_hmac_sha256_final(&hash, result);
    return -1;
  }
  return pinweaver_eal_hmac_sha256_final(&hash, result);
}

int pinweaver_eal_derive_keys(struct merkle_tree_t* merkle_tree) {
  const uint8_t kWrapKeyConst[PW_OBJ_CONST_SIZE] = {'W', 'R', 'A', 'P',
                                                    'W', 'R', 'A', 'P'};
  const uint8_t kHmacKeyConst[PW_OBJ_CONST_SIZE] = {'H', 'M', 'A', 'C',
                                                    'H', 'M', 'A', 'C'};
  uint8_t device_key[DEVICE_KEY_SIZE];
  if (pinweaver_eal_get_device_key(PINWEAVER_EAL_CONST, device_key))
    return -1;

  if (derive_pw_key(device_key, kWrapKeyConst,
                    merkle_tree->key_derivation_nonce, merkle_tree->wrap_key))
    return -1;

  if (derive_pw_key(device_key, kHmacKeyConst,
                    merkle_tree->key_derivation_nonce, merkle_tree->hmac_key))
    return -1;

  // Do not leave the content of the device key on the stack.
  secure_memset(device_key, 0, sizeof(device_key));

  return 0;
}

int pinweaver_eal_storage_init_state(uint8_t root_hash[PW_HASH_SIZE],
                                     uint32_t* restart_count) {
  struct pw_log_storage_t log;
  int ret = pinweaver_eal_storage_get_log(&log);
  if (ret != 0)
    return ret;

  memcpy(root_hash, log.entries[0].root, PW_HASH_SIZE);

  /* This forces an NVRAM write for hard reboots for which the
   * timer value gets reset. The TPM restart and reset counters
   * were not used because they do not track the state of the
   * counter.
   *
   * Pinweaver uses the restart_count to know when the time since
   * boot can be used as the elapsed time for the delay schedule,
   * versus when the elapsed time starts from a timestamp.
   */
  if (pinweaver_eal_seconds_since_boot() < RESTART_TIMER_THRESHOLD) {
    ++log.restart_count;
    int ret = pinweaver_eal_storage_set_log(&log);
    if (ret != 0)
      return ret;
  }
  *restart_count = log.restart_count;
  return 0;
}

int pinweaver_eal_storage_set_log(const struct pw_log_storage_t* log) {
  if (!brillo::WriteStringToFile(
          base::FilePath(kLogPath),
          std::string(reinterpret_cast<const char*>(log),
                      sizeof(struct pw_log_storage_t)))) {
    LOG(ERROR) << "Failed to write pinweaver log file.";
    return -1;
  }
  return 0;
}

int pinweaver_eal_storage_get_log(struct pw_log_storage_t* dest) {
  std::string contents;
  if (!base::ReadFileToString(base::FilePath(kLogPath), &contents)) {
    LOG(ERROR) << "Failed to read pinweaver log file.";
    return -1;
  }
  if (contents.size() != sizeof(struct pw_log_storage_t)) {
    LOG(ERROR) << "Mismatched pinweaver log file size.";
    return -1;
  }
  memcpy(dest, contents.data(), sizeof(struct pw_log_storage_t));
  return 0;
}

int pinweaver_eal_storage_set_tree_data(
    const struct pw_long_term_storage_t* data) {
  if (!brillo::WriteStringToFile(
          base::FilePath(kTreeDataPath),
          std::string(reinterpret_cast<const char*>(data),
                      sizeof(struct pw_long_term_storage_t)))) {
    LOG(ERROR) << "Failed to write pinweaver tree data file.";
    return -1;
  }
  return 0;
}

int pinweaver_eal_storage_get_tree_data(struct pw_long_term_storage_t* dest) {
  std::string contents;
  if (!base::ReadFileToString(base::FilePath(kTreeDataPath), &contents)) {
    LOG(ERROR) << "Failed to read pinweaver tree data file.";
    return -1;
  }
  if (contents.size() != sizeof(struct pw_long_term_storage_t)) {
    LOG(ERROR) << "Mismatched pinweaver tree data file size.";
    return -1;
  }
  memcpy(dest, contents.data(), sizeof(struct pw_long_term_storage_t));
  return 0;
}

// Defined in tpm2 library.
void PCRComputeCurrentDigest(TPMI_ALG_HASH, TPML_PCR_SELECTION*, TPM2B_DIGEST*);

uint8_t get_current_pcr_digest(const uint8_t bitmask[2],
                               uint8_t sha256_of_selected_pcr[32]) {
  TPM2B_DIGEST pcr_digest;
  TPML_PCR_SELECTION selection;

  selection.count = 1;
  selection.pcrSelections[0].hash = TPM_ALG_SHA256;
  selection.pcrSelections[0].sizeofSelect = PCR_SELECT_MIN;
  memset(&selection.pcrSelections[0].pcrSelect, 0, PCR_SELECT_MIN);
  memcpy(&selection.pcrSelections[0].pcrSelect, bitmask, 2);

  PCRComputeCurrentDigest(TPM_ALG_SHA256, &selection, &pcr_digest);
  if (memcmp(&selection.pcrSelections[0].pcrSelect, bitmask, 2) != 0)
    return 1;

  memcpy(sha256_of_selected_pcr, &pcr_digest.b.buffer, 32);
  return 0;
}

uint8_t pinweaver_eal_get_current_pcr_digest(
    const uint8_t bitmask[2], uint8_t sha256_of_selected_pcr[32]) {
  return get_current_pcr_digest(bitmask, sha256_of_selected_pcr);
}

namespace {
constexpr char kPkPathPrefix[] = "pk";
}

int pinweaver_eal_storage_get_ba_pk(uint8_t auth_channel,
                                    struct pw_ba_pk_t* pk) {
  base::FilePath path =
      base::FilePath(std::string(kPkPathPrefix) + std::to_string(auth_channel));
  std::string contents;
  if (!base::ReadFileToString(path, &contents)) {
    return PW_ERR_BIO_AUTH_PK_NOT_ESTABLISHED;
  }
  if (contents.size() != sizeof(struct pw_ba_pk_t)) {
    PINWEAVER_EAL_INFO("Error: Mismatched Pk file size.");
    return -1;
  }
  memcpy(pk, contents.data(), sizeof(struct pw_ba_pk_t));
  return 0;
}

int pinweaver_eal_storage_set_ba_pk(uint8_t auth_channel,
                                    const struct pw_ba_pk_t* pk) {
  base::FilePath path =
      base::FilePath(std::string(kPkPathPrefix) + std::to_string(auth_channel));
  if (!brillo::WriteStringToFile(path,
                                 std::string(reinterpret_cast<const char*>(pk),
                                             sizeof(struct pw_ba_pk_t)))) {
    PINWEAVER_EAL_INFO("Error: Failed to write Pk file.");
    return -1;
  }
  return 0;
}

int pinweaver_eal_ecdh_derive(const struct pw_ba_ecc_pt_t* ecc_pt_in,
                              void* secret,
                              size_t* secret_size,
                              struct pw_ba_ecc_pt_t* ecc_pt_out) {
  hwsec_foundation::ScopedBN_CTX context =
      hwsec_foundation::CreateBigNumContext();
  if (!context) {
    PINWEAVER_EAL_INFO("Error: Failed to create bignum context.");
    return -1;
  }
  std::optional<EllipticCurve> ec =
      EllipticCurve::Create(EllipticCurve::CurveType::kPrime256, context.get());
  if (!ec.has_value()) {
    PINWEAVER_EAL_INFO("Error: Failed to create EllipticCurve.");
    return -1;
  }

  const crypto::ScopedEC_KEY out_key_pair = ec->GenerateKey(context.get());
  if (!out_key_pair) {
    PINWEAVER_EAL_INFO("Error: Failed to generate EC key.");
    return -1;
  }
  const EC_POINT* out_point = EC_KEY_get0_public_key(out_key_pair.get());
  const BIGNUM* out_priv_key = EC_KEY_get0_private_key(out_key_pair.get());

  crypto::ScopedEC_POINT in_point = ec->CreatePoint();
  if (!in_point) {
    PINWEAVER_EAL_INFO("Error: Failed to create EC point.");
    return -1;
  }
  brillo::SecureBlob in_x_blob(ecc_pt_in->x,
                               ecc_pt_in->x + PW_BA_ECC_CORD_SIZE),
      in_y_blob(ecc_pt_in->y, ecc_pt_in->y + PW_BA_ECC_CORD_SIZE);
  const crypto::ScopedBIGNUM in_x =
      hwsec_foundation::SecureBlobToBigNum(in_x_blob);
  const crypto::ScopedBIGNUM in_y =
      hwsec_foundation::SecureBlobToBigNum(in_y_blob);
  if (!in_x || !in_y) {
    PINWEAVER_EAL_INFO("Error: Failed to transform secure blobs to bignums.");
    return -1;
  }
  if (!EC_POINT_set_affine_coordinates(ec->GetGroup(), in_point.get(),
                                       in_x.get(), in_y.get(), context.get())) {
    PINWEAVER_EAL_INFO("Error: Failed to set affine coords for input point");
    return -1;
  }

  const crypto::ScopedEC_POINT shared_point =
      hwsec_foundation::ComputeEcdhSharedSecretPoint(*ec, *in_point,
                                                     *out_priv_key);
  if (!shared_point) {
    PINWEAVER_EAL_INFO("Error: Failed to compute shared secret point.");
    return -1;
  }
  brillo::SecureBlob shared_secret;
  if (!hwsec_foundation::ComputeEcdhSharedSecret(*ec, *shared_point,
                                                 &shared_secret)) {
    PINWEAVER_EAL_INFO("Error: Failed to compute shared secret.");
    return -1;
  }

  if (*secret_size < shared_secret.size()) {
    PINWEAVER_EAL_INFO("Error: Input secret size is smaller than %zu",
                       shared_secret.size());
    return -1;
  }
  memcpy(secret, shared_secret.data(), shared_secret.size());
  *secret_size = shared_secret.size();
  crypto::ScopedBIGNUM out_x = hwsec_foundation::CreateBigNum(),
                       out_y = hwsec_foundation::CreateBigNum();
  if (!out_x || !out_y) {
    PINWEAVER_EAL_INFO("Error: Failed to create bignums.");
    return -1;
  }
  if (!EC_POINT_get_affine_coordinates(ec->GetGroup(), out_point, out_x.get(),
                                       out_y.get(), context.get())) {
    PINWEAVER_EAL_INFO("Error: Failed to get affine coords for output point");
    return -1;
  }
  brillo::SecureBlob out_x_blob, out_y_blob;
  if (!hwsec_foundation::BigNumToSecureBlob(*out_x, PW_BA_ECC_CORD_SIZE,
                                            &out_x_blob) ||
      !hwsec_foundation::BigNumToSecureBlob(*out_y, PW_BA_ECC_CORD_SIZE,
                                            &out_y_blob)) {
    PINWEAVER_EAL_INFO("Error: Failed to transform bignums to secure blobs.");
    return -1;
  }
  memcpy(ecc_pt_out->x, out_x_blob.data(), out_x_blob.size());
  memcpy(ecc_pt_out->y, out_y_blob.data(), out_y_blob.size());
  return 0;
}
}
