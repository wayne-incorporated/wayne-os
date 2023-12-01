/*
 * Copyright 2010 The ChromiumOS Authors <chromium-os-dev@chromium.org>
 *
 * Device-Mapper block hash tree interface.
 * See Documentation/device-mapper/dm-bht.txt for details.
 *
 * This file is released under the GPL.
 */

#include <limits.h>
#include <string.h>

#include <algorithm>
#include <memory>
#include <string>

#include <base/bits.h>
#include <base/check.h>
#include <base/check_op.h>
#include <base/logging.h>
#include <crypto/secure_hash.h>
#include <crypto/sha2.h>

#include <asm-generic/bitops/fls.h>
#include <linux/errno.h>

#include "verity/dm-bht.h"

#define DM_MSG_PREFIX "dm bht"

/* For sector formatting. */
#if defined(_LP64) || defined(__LP64__) || __BITS_PER_LONG == 64
#define __PRIS_PREFIX "z"
#else
#define __PRIS_PREFIX "ll"
#endif
#define PRIu64 __PRIS_PREFIX "u"

#define DIV_ROUND_UP(n, d) (((n) + (d)-1) / (d))

/*-----------------------------------------------
 * Utilities
 *-----------------------------------------------*/

/* We assume we only have one CPU in userland. */
#define nr_cpu_ids 1
#define smp_processor_id(_x) 0

#define VERBOSE_DEBUG 0

namespace verity {
namespace {

inline void* alloc_page(void) {
  void* memptr;

  if (posix_memalign(static_cast<void**>(&memptr), PAGE_SIZE, PAGE_SIZE))
    return NULL;
  return memptr;
}

uint8_t from_hex(uint8_t ch) {
  if ((ch >= '0') && (ch <= '9'))
    return ch - '0';
  if ((ch >= 'a') && (ch <= 'f'))
    return ch - 'a' + 10;
  if ((ch >= 'A') && (ch <= 'F'))
    return ch - 'A' + 10;
  return -1;
}

/**
 * dm_bht_bin_to_hex - converts a binary stream to human-readable hex
 * @binary: a byte array of length @binary_len
 * @hex: a byte array of length @binary_len * 2 + 1
 */
void dm_bht_bin_to_hex(uint8_t* binary, uint8_t* hex, unsigned int binary_len) {
  while (binary_len-- > 0) {
    // NOLINTNEXTLINE(runtime/printf)
    sprintf((char* __restrict__)hex, "%02hhx", (unsigned char)*binary);
    hex += 2;
    binary++;
  }
}

/**
 * dm_bht_hex_to_bin - converts a hex stream to binary
 * @binary: a byte array of length @binary_len
 * @hex: a byte array of length @binary_len * 2 + 1
 */
void dm_bht_hex_to_bin(uint8_t* binary,
                       const uint8_t* hex,
                       unsigned int binary_len) {
  while (binary_len-- > 0) {
    *binary = from_hex(*(hex++));
    *binary *= 16;
    *binary += from_hex(*(hex++));
    binary++;
  }
}

void dm_bht_log_mismatch(struct dm_bht* bht,
                         uint8_t* given,
                         uint8_t* computed) {
  uint8_t given_hex[DM_BHT_MAX_DIGEST_SIZE * 2 + 1];
  uint8_t computed_hex[DM_BHT_MAX_DIGEST_SIZE * 2 + 1];
  dm_bht_bin_to_hex(given, given_hex, bht->digest_size);
  dm_bht_bin_to_hex(computed, computed_hex, bht->digest_size);
  DLOG(ERROR) << given_hex << " != " << computed_hex;
}

/*-----------------------------------------------
 * Implementation functions
 *-----------------------------------------------*/

int dm_bht_initialize_entries(struct dm_bht* bht);

int dm_bht_read_callback_stub(void* ctx,
                              sector_t start,
                              uint8_t* dst,
                              sector_t count,
                              struct dm_bht_entry* entry);
}  // namespace

/**
 * dm_bht_compute_hash: hashes a page of data
 */
int dm_bht_compute_hash(struct dm_bht* bht,
                        const uint8_t* buffer,
                        uint8_t* digest) {
  std::unique_ptr<crypto::SecureHash> hash(
      crypto::SecureHash::Create(crypto::SecureHash::SHA256));
  hash->Update(buffer, PAGE_SIZE);
  if (bht->have_salt) {
    hash->Update(bht->salt, sizeof(bht->salt));
  }
  hash->Finish(digest, DM_BHT_MAX_DIGEST_SIZE);
  return 0;
}

const char kSha256HashName[] = "sha256";

/**
 * dm_bht_create - prepares @bht for us
 * @bht: pointer to a dm_bht_create()d bht
 * @depth: tree depth without the root; including block hashes
 * @block_count:the number of block hashes / tree leaves
 * @alg_name: crypto hash algorithm name
 *
 * Returns 0 on success.
 *
 * Callers can offset into devices by storing the data in the io callbacks.
 * TODO(wad) bust up into smaller helpers
 */
int dm_bht_create(struct dm_bht* bht,
                  unsigned int block_count,
                  const char* alg_name) {
  int status = 0;

  if (std::string(alg_name) != kSha256HashName) {
    status = -EINVAL;
    goto bad_hash_alg;
  }

  bht->have_salt = false;
  bht->externally_allocated = false;

  bht->digest_size = crypto::kSHA256Length;
  /* We expect to be able to pack >=2 hashes into a page */
  if (PAGE_SIZE / bht->digest_size < 2) {
    DLOG(ERROR) << "too few hashes fit in a page";
    status = -EINVAL;
    goto bad_digest_len;
  }

  if (bht->digest_size > DM_BHT_MAX_DIGEST_SIZE) {
    DLOG(ERROR) << "DM_BHT_MAX_DIGEST_SIZE too small for chosen digest";
    status = -EINVAL;
    goto bad_digest_len;
  }

  /* Configure the tree */
  bht->block_count = block_count;
  DLOG(INFO) << "Setting block_count " << block_count;
  if (block_count == 0) {
    DLOG(ERROR) << "block_count must be non-zero";
    status = -EINVAL;
    goto bad_block_count;
  }

  /* Each dm_bht_entry->nodes is one page.  The node code tracks
   * how many nodes fit into one entry where a node is a single
   * hash (message digest).
   */
  bht->node_count_shift = fls(PAGE_SIZE / bht->digest_size) - 1;
  /* Round down to the nearest power of two.  This makes indexing
   * into the tree much less painful.
   */
  bht->node_count = 1 << bht->node_count_shift;

  /* This is unlikely to happen, but with 64k pages, who knows. */
  if (bht->node_count > UINT_MAX / bht->digest_size) {
    DLOG(ERROR) << "node_count * hash_len exceeds UINT_MAX!";
    status = -EINVAL;
    goto bad_node_count;
  }

  bht->depth = DIV_ROUND_UP(fls(block_count - 1), bht->node_count_shift);
  DLOG(INFO) << "Setting depth to " << bht->depth;

  /* Ensure that we can safely shift by this value. */
  if (bht->depth * bht->node_count_shift >= sizeof(unsigned int) * 8) {
    DLOG(ERROR) << "specified depth and node_count_shift is too large";
    status = -EINVAL;
    goto bad_node_count;
  }

  /* Allocate levels. Each level of the tree may have an arbitrary number
   * of dm_bht_entry structs.  Each entry contains node_count nodes.
   * Each node in the tree is a cryptographic digest of either node_count
   * nodes on the subsequent level or of a specific block on disk.
   */
  bht->levels =
      (struct dm_bht_level*)calloc(bht->depth, sizeof(struct dm_bht_level));
  if (!bht->levels) {
    DLOG(ERROR) << "failed to allocate tree levels";
    status = -ENOMEM;
    goto bad_level_alloc;
  }

  /* Setup read callback stub */
  bht->read_cb = &dm_bht_read_callback_stub;

  status = dm_bht_initialize_entries(bht);
  if (status)
    goto bad_entries_alloc;

  /* We compute depth such that there is only be 1 block at level 0. */
  CHECK_EQ(bht->levels[0].count, 1);

  return 0;

bad_entries_alloc:
  while (bht->depth-- > 0)
    free(bht->levels[bht->depth].entries);
  free(bht->levels);
bad_node_count:
bad_level_alloc:
bad_block_count:
bad_digest_len:
bad_hash_alg:
  return status;
}

namespace {

int dm_bht_initialize_entries(struct dm_bht* bht) {
  /* The last_index represents the index into the last
   * block digest that will be stored in the tree.  By walking the
   * tree with that index, it is possible to compute the total number
   * of entries needed at each level in the tree.
   *
   * Since each entry will contain up to |node_count| nodes of the tree,
   * it is possible that the last index may not be at the end of a given
   * entry->nodes.  In that case, it is assumed the value is padded.
   *
   * Note, we treat both the tree root (1 hash) and the tree leaves
   * independently from the bht data structures.  Logically, the root is
   * depth=-1 and the block layer level is depth=bht->depth
   */
  uint64_t last_index =
      base::bits::AlignUp(bht->block_count, bht->node_count) - 1;
  struct dm_bht_level* level = NULL;
  int depth;

  /* check that the largest level->count can't result in an int overflow
   * on allocation or sector calculation.
   */
  if (((last_index >> bht->node_count_shift) + 1) >
      UINT_MAX / std::max((uint64_t)sizeof(struct dm_bht_entry),
                          (uint64_t)to_sector(PAGE_SIZE))) {
    LOG(ERROR) << "required entries " << last_index + 1 << " is too large.";
    return -EINVAL;
  }

  /* Track the current sector location for each level so we don't have to
   * compute it during traversals.
   */
  bht->sectors = 0;
  for (depth = 0; depth < bht->depth; ++depth) {
    level = dm_bht_get_level(bht, depth);
    level->count = dm_bht_index_at_level(bht, depth, last_index) + 1;
    DLOG(INFO) << "depth: " << depth << " entries: " << level->count;
    /* TODO(wad) consider the case where the data stored for each
     * level is done with contiguous pages (instead of using
     * entry->nodes) and the level just contains two bitmaps:
     * (a) which pages have been loaded from disk
     * (b) which specific nodes have been verified.
     */
    level->entries =
        (struct dm_bht_entry*)calloc(level->count, sizeof(struct dm_bht_entry));
    if (!level->entries) {
      DLOG(ERROR) << "failed to allocate entries for depth " << bht->depth;
      /* let the caller clean up the mess */
      return -ENOMEM;
    }
    level->sector = bht->sectors;
    /* number of sectors per entry * entries at this level */
    bht->sectors += level->count * to_sector(PAGE_SIZE);
    /* not ideal, but since unsigned overflow behavior is defined */
    if (bht->sectors < level->sector) {
      LOG(ERROR) << "level sector calculation overflowed.";
      return -EINVAL;
    }
  }

  return 0;
}

int dm_bht_read_callback_stub(void* ctx,
                              sector_t start,
                              uint8_t* dst,
                              sector_t count,
                              struct dm_bht_entry* entry) {
  LOG(ERROR) << "dm_bht_read_callback_stub called!";
  dm_bht_read_completed(entry, -EIO);
  return -EIO;
}

}  // namespace

/**
 * dm_bht_read_completed
 * @entry: pointer to the entry that's been loaded
 * @status: I/O status. Non-zero is failure.
 * MUST always be called after a read_cb completes.
 */
void dm_bht_read_completed(struct dm_bht_entry* entry, int status) {
  if (status) {
    /* TODO(wad) add retry support */
    LOG(ERROR) << "an I/O error occurred while reading entry.";
    entry->state = DM_BHT_ENTRY_ERROR_IO;
    /* entry->nodes will be freed later */
    return;
  }
  CHECK_EQ(entry->state, DM_BHT_ENTRY_PENDING);
  entry->state = DM_BHT_ENTRY_READY;
}

namespace {

/* dm_bht_verify_path
 * Verifies the path. Returns 0 on ok.
 */
int dm_bht_verify_path(struct dm_bht* bht,
                       unsigned int block,
                       const uint8_t* buffer) {
  int depth = bht->depth;
  uint8_t digest[DM_BHT_MAX_DIGEST_SIZE];
  struct dm_bht_entry* entry;
  uint8_t* node;
  int state;

  do {
    /* Need to check that the hash of the current block is accurate
     * in its parent.
     */
    entry = dm_bht_get_entry(bht, depth - 1, block);
    state = entry->state;
    /* This call is only safe if all nodes along the path
     * are already populated (i.e. READY) via dm_bht_populate.
     */
    CHECK_GE(state, DM_BHT_ENTRY_READY);
    node = dm_bht_get_node(bht, entry, depth, block);

    if (dm_bht_compute_hash(bht, buffer, digest) ||
        memcmp(digest, node, bht->digest_size))
      goto mismatch;

    /* Keep the containing block of hashes to be verified in the
     * next pass.
     */
    buffer = entry->nodes;
  } while (--depth > 0 && state != DM_BHT_ENTRY_VERIFIED);

  if (depth == 0 && state != DM_BHT_ENTRY_VERIFIED) {
    if (dm_bht_compute_hash(bht, buffer, digest) ||
        memcmp(digest, bht->root_digest, bht->digest_size))
      goto mismatch;
    entry->state = DM_BHT_ENTRY_VERIFIED;
  }

  /* Mark path to leaf as verified. */
  for (depth++; depth < bht->depth; depth++) {
    entry = dm_bht_get_entry(bht, depth, block);
    /* At this point, entry can only be in VERIFIED or READY state.
     */
    entry->state = DM_BHT_ENTRY_VERIFIED;
  }

#if VERBOSE_DEBUG
  DLOG(INFO) << "verify_path: node " << block << " is verified to root";
#endif
  return 0;

mismatch:
  DLOG(ERROR) << "verify_path: failed to verify hash (d=" << depth
              << ",bi=" << block << ")";
  dm_bht_log_mismatch(bht, node, digest);
  return DM_BHT_ENTRY_ERROR_MISMATCH;
}

}  // namespace

/**
 * dm_bht_zeroread_callback - read callback which always returns 0s
 * @ctx: ignored
 * @start: ignored
 * @data: buffer to write 0s to
 * @count: number of sectors worth of data to write
 * @complete_ctx: opaque context for @completed
 * @completed: callback to confirm end of data read
 *
 * Always returns 0.
 *
 * Meant for use by dm_compute() callers.  It allows dm_populate to
 * be used to pre-fill a tree with zeroed out entry nodes.
 */
int dm_bht_zeroread_callback(void* ctx,
                             sector_t start,
                             uint8_t* dst,
                             sector_t count,
                             struct dm_bht_entry* entry) {
  memset(dst, 0, verity_to_bytes(count));
  dm_bht_read_completed(entry, 0);
  return 0;
}

/**
 * dm_bht_is_populated - check that entries from disk needed to verify a given
 *                       block are all ready
 * @bht: pointer to a dm_bht_create()d bht
 * @block: specific block data is expected from
 *
 * Callers may wish to call dm_bht_is_populated() when checking an io
 * for which entries were already pending.
 */
bool dm_bht_is_populated(struct dm_bht* bht, unsigned int block) {
  int depth;

  for (depth = bht->depth - 1; depth >= 0; depth--) {
    struct dm_bht_entry* entry = dm_bht_get_entry(bht, depth, block);
    if (entry->state < DM_BHT_ENTRY_READY)
      return false;
  }

  return true;
}

/**
 * dm_bht_populate - reads entries from disk needed to verify a given block
 * @bht: pointer to a dm_bht_create()d bht
 * @ctx: context used for all read_cb calls on this request
 * @block: specific block data is expected from
 *
 * Returns negative value on error. Returns 0 on success.
 */
int dm_bht_populate(struct dm_bht* bht, void* ctx, unsigned int block) {
  int depth;
  int state = 0;

  CHECK_LT(block, bht->block_count);
  bht->externally_allocated = false;

#if VERBOSE_DEBUG
  DLOG(INFO) << "dm_bht_populate %u" << block;
#endif

  for (depth = bht->depth - 1; depth >= 0; --depth) {
    struct dm_bht_level* level;
    struct dm_bht_entry* entry;
    unsigned int index;
    uint8_t* buffer;

    entry = dm_bht_get_entry(bht, depth, block);
    state = entry->state;
    if (state == DM_BHT_ENTRY_UNALLOCATED)
      entry->state = DM_BHT_ENTRY_PENDING;

    if (state == DM_BHT_ENTRY_VERIFIED)
      break;
    if (state <= DM_BHT_ENTRY_ERROR)
      goto error_state;
    if (state != DM_BHT_ENTRY_UNALLOCATED)
      continue;

    /* Current entry is claimed for allocation and loading */
    buffer = static_cast<uint8_t*>(alloc_page());
    if (!buffer)
      goto nomem;

    /* dm-bht guarantees page-aligned memory for callbacks. */
    entry->nodes = buffer;

    /* TODO(wad) error check callback here too */

    level = &bht->levels[depth];
    index = dm_bht_index_at_level(bht, depth, block);
    bht->read_cb(ctx, level->sector + to_sector(index * PAGE_SIZE),
                 entry->nodes, to_sector(PAGE_SIZE), entry);
  }

  return 0;

error_state:
  LOG(ERROR) << "block " << block << " at depth " << depth
             << " is in an error state";
  return state;

nomem:
  LOG(ERROR) << "failed to allocate memory for entry->nodes";
  return -ENOMEM;
}

/**
 * dm_bht_verify_block - checks that all nodes in the path for @block are valid
 * @bht: pointer to a dm_bht_create()d bht
 * @block: specific block data is expected from
 * @buffer: page holding the block data
 * @offset: offset into the page
 *
 * Returns 0 on success, 1 on missing data, and a negative error
 * code on verification failure. All supporting functions called
 * should return similarly.
 */
int dm_bht_verify_block(struct dm_bht* bht,
                        unsigned int block,
                        const uint8_t* buffer,
                        unsigned int offset) {
  CHECK_EQ(offset, 0);

  return dm_bht_verify_path(bht, block, buffer);
}

/**
 * dm_bht_destroy - cleans up all memory used by @bht
 * @bht: pointer to a dm_bht_create()d bht
 *
 * Returns 0 on success. Does not free @bht itself.
 */
int dm_bht_destroy(struct dm_bht* bht) {
  int depth;

  depth = bht->depth;
  while (depth-- != 0) {
    struct dm_bht_entry* entry = bht->levels[depth].entries;
    struct dm_bht_entry* entry_end = entry + bht->levels[depth].count;
    if (!bht->externally_allocated) {
      for (; entry < entry_end; ++entry) {
        switch (entry->state) {
          /* At present, no other states free memory,
           * but that will change.
           */
          case DM_BHT_ENTRY_UNALLOCATED:
            /* Allocated with improper state */
            CHECK(!entry->nodes);
            continue;
          default:
            CHECK(entry->nodes);
            free(entry->nodes);
            break;
        }
      }
    }
    free(bht->levels[depth].entries);
    bht->levels[depth].entries = NULL;
  }
  free(bht->levels);
  return 0;
}

void dm_bht_set_buffer(struct dm_bht* bht, void* buffer) {
  int depth;
  /* Buffers are externally allocated, so mark them as such. */
  bht->externally_allocated = true;

  auto buffer_p = static_cast<uint8_t*>(buffer);
  for (depth = 0; depth < bht->depth; ++depth) {
    struct dm_bht_level* level = dm_bht_get_level(bht, depth);
    struct dm_bht_entry* entry_end = level->entries + level->count;
    struct dm_bht_entry* entry;

    for (entry = level->entries; entry < entry_end; ++entry) {
      entry->nodes = buffer_p;
      memset(buffer_p, 0, PAGE_SIZE);
      buffer_p += PAGE_SIZE;
    }
  }
}

/**
 * dm_bht_compute - computes and updates all non-block-level hashes in a tree
 * @bht: pointer to a dm_bht_create()d bht
 *
 * Returns 0 on success, >0 when data is pending, and <0 when a IO or other
 * error has occurred.
 *
 * Walks the tree and computes the hashes at each level from the
 * hashes below.
 */
int dm_bht_compute(struct dm_bht* bht) {
  int depth, r = 0;

  for (depth = bht->depth - 2; depth >= 0; depth--) {
    struct dm_bht_level* level = dm_bht_get_level(bht, depth);
    struct dm_bht_level* child_level = level + 1;
    struct dm_bht_entry* entry = level->entries;
    struct dm_bht_entry* child = child_level->entries;
    unsigned int i, j;

    for (i = 0; i < level->count; i++, entry++) {
      unsigned int count = bht->node_count;

      memset(entry->nodes, 0, PAGE_SIZE);
      entry->state = DM_BHT_ENTRY_READY;

      if (i == (level->count - 1))
        count = child_level->count % bht->node_count;
      if (count == 0)
        count = bht->node_count;
      for (j = 0; j < count; j++, child++) {
        uint8_t* digest = dm_bht_node(bht, entry, j);

        r = dm_bht_compute_hash(bht, child->nodes, digest);
        if (r) {
          DLOG(ERROR) << "Failed to update (d=" << depth << ",i=" << i << ")";
          goto out;
        }
      }
    }
  }
  r = dm_bht_compute_hash(bht, bht->levels[0].entries->nodes, bht->root_digest);
  if (r)
    DLOG(ERROR) << "Failed to update root hash";

out:
  return r;
}

/**
 * dm_bht_store_block - sets a given block's hash in the tree
 * @bht: pointer to a dm_bht_create()d bht
 * @block: numeric index of the block in the tree
 * @block_data: array of uint8_ts containing the block of data to hash
 *
 * Returns 0 on success.
 *
 * If the containing entry in the tree is unallocated, it will allocate memory
 * and mark the entry as ready.  All other block entries will be 0s.
 *
 * It is up to the users of the update interface to ensure the entry data is
 * fully populated prior to use. The number of updated entries is NOT tracked.
 */
int dm_bht_store_block(struct dm_bht* bht,
                       unsigned int block,
                       uint8_t* block_data) {
  int depth = bht->depth;
  struct dm_bht_entry* entry = dm_bht_get_entry(bht, depth - 1, block);
  uint8_t* node = dm_bht_get_node(bht, entry, depth, block);

  return dm_bht_compute_hash(bht, block_data, node);
}

/*-----------------------------------------------
 * Accessors
 *-----------------------------------------------*/

/**
 * dm_bht_sectors - return the sectors required on disk
 * @bht: pointer to a dm_bht_create()d bht
 */
sector_t dm_bht_sectors(const struct dm_bht* bht) {
  return bht->sectors;
}

/**
 * dm_bht_set_read_cb - set read callback
 * @bht: pointer to a dm_bht_create()d bht
 * @read_cb: callback function used for all read requests by @bht
 */
void dm_bht_set_read_cb(struct dm_bht* bht, dm_bht_callback read_cb) {
  bht->read_cb = read_cb;
}

/**
 * dm_bht_set_root_hexdigest - sets an unverified root digest hash from hex
 * @bht: pointer to a dm_bht_create()d bht
 * @hexdigest: array of uint8_ts containing the new digest in binary
 * Returns non-zero on error.  hexdigest should be NUL terminated.
 */
int dm_bht_set_root_hexdigest(struct dm_bht* bht, const uint8_t* hexdigest) {
  /* Make sure we have at least the bytes expected */
  if (strnlen(reinterpret_cast<const char*>(hexdigest), bht->digest_size * 2) !=
      bht->digest_size * 2) {
    DLOG(ERROR) << "root digest length does not match hash algorithm";
    return -1;
  }
  dm_bht_hex_to_bin(bht->root_digest, hexdigest, bht->digest_size);
#ifdef CONFIG_DM_DEBUG
  DLOG(INFO) << "Set root digest to " << hexdigest << ". Parsed as -> ";
  dm_bht_log_mismatch(bht, bht->root_digest, bht->root_digest);
#endif
  return 0;
}

/**
 * dm_bht_root_hexdigest - returns root digest in hex
 * @bht: pointer to a dm_bht_create()d bht
 * @hexdigest: uint8_t array of size @available
 * @available: must be bht->digest_size * 2 + 1
 */
int dm_bht_root_hexdigest(struct dm_bht* bht,
                          uint8_t* hexdigest,
                          int available) {
  if (available < 0 || ((unsigned int)available) < bht->digest_size * 2 + 1) {
    DLOG(ERROR) << "hexdigest has too few bytes available";
    return -EINVAL;
  }
  dm_bht_bin_to_hex(bht->root_digest, hexdigest, bht->digest_size);
  return 0;
}

/**
 * dm_bht_set_salt - sets the salt used, in hex
 * @bht: pointer to a dm_bht_create()d bht
 * @hexsalt: salt string, as hex; will be zero-padded or truncated to
 *            DM_BHT_SALT_SIZE * 2 hex digits.
 */
void dm_bht_set_salt(struct dm_bht* bht, const char* hexsalt) {
  size_t saltlen = std::min(strlen(hexsalt) / 2, sizeof(bht->salt));
  bht->have_salt = true;
  memset(bht->salt, 0, sizeof(bht->salt));
  dm_bht_hex_to_bin(bht->salt, (const uint8_t*)hexsalt, saltlen);
}

/**
 * dm_bht_salt - returns the salt used, in hex
 * @bht: pointer to a dm_bht_create()d bht
 * @hexsalt: buffer to put salt into, of length DM_BHT_SALT_SIZE * 2 + 1.
 */
int dm_bht_salt(struct dm_bht* bht, char* hexsalt) {
  if (!bht->have_salt)
    return -EINVAL;
  dm_bht_bin_to_hex(bht->salt, reinterpret_cast<uint8_t*>(hexsalt),
                    sizeof(bht->salt));
  return 0;
}

DmBht::~DmBht() {
  if (dm_bht_ptr_) {
    dm_bht_destroy(dm_bht_ptr_.get());
  }
}

int DmBht::Create(unsigned int blocksize, std::string alg) {
  dm_bht_ptr_ = std::make_unique<struct dm_bht>();
  return dm_bht_create(dm_bht_ptr_.get(), blocksize, alg.c_str());
}

void DmBht::SetReadCallback(dm_bht_callback callback) {
  dm_bht_set_read_cb(dm_bht_ptr_.get(), callback);
}

void DmBht::SetSalt(std::string hexsalt) {
  dm_bht_set_salt(dm_bht_ptr_.get(), hexsalt.c_str());
}

void DmBht::SetBuffer(void* buffer) {
  dm_bht_set_buffer(dm_bht_ptr_.get(), buffer);
}

sector_t DmBht::Sectors() {
  return dm_bht_sectors(dm_bht_ptr_.get());
}

unsigned int DmBht::DigestSize() {
  return dm_bht_ptr_->digest_size;
}

int DmBht::StoreBlock(unsigned int block, uint8_t* block_data) {
  return dm_bht_store_block(dm_bht_ptr_.get(), block, block_data);
}

int DmBht::Compute() {
  return dm_bht_compute(dm_bht_ptr_.get());
}

void DmBht::HexDigest(uint8_t* hexdigest, int available) {
  dm_bht_root_hexdigest(dm_bht_ptr_.get(), hexdigest, available);
}

}  // namespace verity
