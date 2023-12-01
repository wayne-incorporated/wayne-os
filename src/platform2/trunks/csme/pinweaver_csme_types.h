// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TRUNKS_CSME_PINWEAVER_CSME_TYPES_H_
#define TRUNKS_CSME_PINWEAVER_CSME_TYPES_H_

#include <stdint.h>

// == definitions (defined in CSE...)

#ifndef BITS_TO_BYTES
#define BITS_TO_BYTES(_bits) (((_bits) + 7) >> 3)
#endif
#ifndef MAX
#define MAX(A, B) (((A) > (B)) ? (A) : (B))
#endif

// Size of allocated buffer per client.
#define PW_MAX_HECI_BUF_SIZE 4096
#define PW_MAX_HECI_HEADER_SIZE \
  MAX(sizeof(struct pw_heci_header_req), sizeof(struct pw_heci_header_res))
#define PW_SHA_256_DIGEST_SIZE BITS_TO_BYTES(256)
#define PW_MAX_DIGEST_SIZE PW_SHA_256_DIGEST_SIZE
#define PW_MAX_HECI_PAYLOAD_SIZE \
  (PW_MAX_HECI_BUF_SIZE - PW_MAX_HECI_HEADER_SIZE)

#pragma pack(push, 1)

// == common enums
enum pcr_alg_t {
  PW_PCR_ALG_SHA_256 = 0xb,  // TPM_ALG_SHA256
};

// Currently largest command/response is pw_prov_salting_key_hash_get_response.
#define PW_MAX_HECI_BUFFER_PROV_CLIENT 100

/*
4 clients:
        1. fixed coreboot client
            HECI1 Id6 FIXED client
            supporting pcr_extend and pcr_read
        2. dynamic tpm provisioning client
            <Guid("168DBC9C-F757-4EED-A2D8-94A3B70F26C2")>
            suppoting salting_key_hash_set, salting_key_get, salting_key_commit
and initialize_owner
        3. dynamic tpm tunnel client
            <Guid("A6103662-23A6-4315-A53B-749D91CAEE17")>
            *sends to host* tpm_command
        4. dynamic core pinweaver client
            <Guid("989E0B6F-DA76-45D7-9299-A4079D7E22B1")>
            supports core_pinweaver_command
*/

// Commands supported by tpm prov client
enum pw_tpm_prov_cmd_t {
  PW_SALTING_KEY_HASH_SET = 0,
  PW_SALTING_KEY_HASH_GET = 1,
  PW_SALTING_KEY_HASH_COMMIT = 2,
  PW_PROV_INITIALIZE_OWNER = 3,
};

// Commands supported by core pinweaver clients
// (fixed that serves coreboot or dynamic that serves crypthome)
enum pw_core_pinweaver_cmd_t {
  PW_PCR_EXTEND = 0,
  PW_PCR_READ = 1,
  PW_CORE_PINWEAVER_CMD = 2,  // supported after tpm_tunnel connected
};

// Commands supported by tpm tunnel client
enum pw_tpm_tunnel_cmd_t {
  PW_TPM_TUNNEL_CMD = 0,
};

// == common header
struct pw_heci_header_req {
  // One of pw_tpm_tunnel_cmd_t, pw_dyn_core_cmd_t, pw_dyn_core_cmd_t,
  // pw_tpm_prov_cmd_t.
  uint8_t pw_heci_cmd;
  // Sequential counter to be copied from command to response by the
  // processing entity.
  uint8_t pw_heci_seq;
  // Total length of following message not including header.
  uint16_t total_length;
};
struct pw_heci_header_res {
  // One of pw_tpm_tunnel_cmd_t, pw_dyn_core_cmd_t, pw_dyn_core_cmd_t,
  // pw_tpm_prov_cmd_t.
  uint8_t pw_heci_cmd;
  // Sequential counter to be copied from command to response by the
  // processing entity.
  uint8_t pw_heci_seq;
  // Total length of following message not including header.
  uint16_t total_length;
  // Protocol / operation response code.
  uint32_t pw_heci_rc;
};

// == HECI command and response structs

// dynamic tpm provisioning client
// PW_PROV_SALTING_KEY_HASH_SET
struct pw_prov_salting_key_hash_set_request {
  struct pw_heci_header_req header;
  uint8_t buffer[PW_SHA_256_DIGEST_SIZE];
};
static_assert(sizeof(struct pw_prov_salting_key_hash_set_request) <=
              PW_MAX_HECI_BUFFER_PROV_CLIENT);

struct pw_prov_salting_key_hash_set_response {
  struct pw_heci_header_res header;
};
static_assert(sizeof(struct pw_prov_salting_key_hash_set_response) <=
              PW_MAX_HECI_BUFFER_PROV_CLIENT);

// dynamic tpm provisioning client
// PW_PROV_SALTING_KEY_HASH_GET
struct pw_prov_salting_key_hash_get_request {
  struct pw_heci_header_req header;
};
static_assert(sizeof(struct pw_prov_salting_key_hash_get_request) <=
              PW_MAX_HECI_BUFFER_PROV_CLIENT);

struct pw_prov_salting_key_hash_get_response {
  struct pw_heci_header_res header;
  uint8_t committed;
  uint8_t buffer[PW_SHA_256_DIGEST_SIZE];
};
static_assert(sizeof(struct pw_prov_salting_key_hash_get_response) <=
              PW_MAX_HECI_BUFFER_PROV_CLIENT);

// dynamic tpm provisioning client
// PW_PROV_PW_SALTING_KEY_HASH_COMMIT
struct pw_prov_salting_key_hash_commit_request {
  struct pw_heci_header_req header;
};
static_assert(sizeof(struct pw_prov_salting_key_hash_commit_request) <=
              PW_MAX_HECI_BUFFER_PROV_CLIENT);

struct pw_prov_salting_key_hash_commit_response {
  struct pw_heci_header_res header;
};
static_assert(sizeof(struct pw_prov_salting_key_hash_commit_response) <=
              PW_MAX_HECI_BUFFER_PROV_CLIENT);

// dynamic tpm provisioning client
// PW_PROV_INITIALIZE_OWNER
struct pw_prov_initialize_owner_request {
  struct pw_heci_header_req header;
};
static_assert(sizeof(struct pw_prov_initialize_owner_request) <=
              PW_MAX_HECI_BUFFER_PROV_CLIENT);

struct pw_prov_initialize_owner_response {
  struct pw_heci_header_res header;
};
static_assert(sizeof(struct pw_prov_initialize_owner_response) <=
              PW_MAX_HECI_BUFFER_PROV_CLIENT);

// Fixed Coreboot client AND
// dynamic core pinweaver client
// PW_PCR_EXTEND
struct pw_pcr_extend_request {
  struct pw_heci_header_req header;
  uint32_t pcr_index;  // 0 to 23
  uint32_t hash_alg;   // support only 0xb == TPM_ALG_SHA256
  uint8_t buffer[PW_MAX_DIGEST_SIZE];
};

struct pw_pcr_extend_response {
  struct pw_heci_header_res header;
};

// Fixed Coreboot client AND
// dynamic core pinweaver client
// PW_PCR_READ
struct pw_pcr_read_request {
  struct pw_heci_header_req header;
  uint32_t pcr_index;  // 0 to 23
  uint32_t hash_alg;   // support only 0xb == TPM_ALG_SHA256
};

struct pw_pcr_read_response {
  struct pw_heci_header_res header;
  uint32_t pcr_index;
  uint32_t hash_alg;  // support only 0xb == TPM_ALG_SHA256
  uint8_t digest[PW_MAX_DIGEST_SIZE];
};

// dynamic core pinweaver client
// PW_CORE_PINWEAVER_CMD
struct pw_core_pinweaver_command_request {
  struct pw_heci_header_req header;
  uint8_t pinweaver_request_blob[PW_MAX_HECI_PAYLOAD_SIZE];
};

struct pw_core_pinweaver_command_response {
  struct pw_heci_header_res header;
  uint8_t pinweaver_response_blob[PW_MAX_HECI_PAYLOAD_SIZE];
};

// dynamic TPM_Tunnel client
// PW_TPM_TUNNEL
struct pw_tpm_command_request {
  struct pw_heci_header_req header;
  uint8_t tpm_request_blob[PW_MAX_HECI_PAYLOAD_SIZE];
};

struct pw_tpm_command_response {
  struct pw_heci_header_res header;
  uint8_t tpm_response_blob[PW_MAX_HECI_PAYLOAD_SIZE];
};
#pragma pack(pop)

#endif  // TRUNKS_CSME_PINWEAVER_CSME_TYPES_H_
