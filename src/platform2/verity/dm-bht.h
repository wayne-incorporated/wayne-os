/*
 * Copyright 2010 The ChromiumOS Authors <chromium-os-dev@chromium.org>
 *
 * Device-Mapper block hash tree interface.
 * See Documentation/device-mapper/dm-bht.txt for details.
 *
 * This file is released under the GPLv2.
 */
#ifndef VERITY_DM_BHT_H_
#define VERITY_DM_BHT_H_

#include <cstdint>
#include <memory>
#include <string>

#include <brillo/brillo_export.h>

/* To avoid allocating memory for digest tests, we just setup a
 * max to use for now.
 */
#define DM_BHT_MAX_DIGEST_SIZE 128 /* 1k hashes are unlikely for now */
#define DM_BHT_SALT_SIZE 32        /* 256 bits of salt is a lot */

/* UNALLOCATED, PENDING, READY, and VERIFIED are valid states. All other
 * values are entry-related return codes.
 */
#define DM_BHT_ENTRY_VERIFIED 8    /* 'nodes' has been checked against parent */
#define DM_BHT_ENTRY_READY 4       /* 'nodes' is loaded and available */
#define DM_BHT_ENTRY_PENDING 2     /* 'nodes' is being loaded */
#define DM_BHT_ENTRY_UNALLOCATED 0 /* untouched */
#define DM_BHT_ENTRY_ERROR -1      /* entry is unsuitable for use */
#define DM_BHT_ENTRY_ERROR_IO -2   /* I/O error on load */

/* Additional possible return codes */
#define DM_BHT_ENTRY_ERROR_MISMATCH -3 /* Digest mismatch */

#define PAGE_SIZE 4096ul
#define PAGE_SHIFT 12ul

typedef uint64_t sector_t;

/* The value is 9 because the sector size is 512 bytes. */
#define SECTOR_SHIFT 9ul
#define to_sector(x) ((x) >> SECTOR_SHIFT)
#define verity_to_bytes(x) ((x) << SECTOR_SHIFT)

namespace verity {

BRILLO_EXPORT
extern const char kSha256HashName[];

/* dm_bht_entry
 * Contains dm_bht->node_count tree nodes at a given tree depth.
 * state is used to transactionally assure that data is paged in
 * from disk.  Unless dm_bht kept running crypto contexts for each
 * level, we need to load in the data for on-demand verification.
 */
struct dm_bht_entry {
  volatile int state; /* see defines */
  /* Keeping an extra pointer per entry wastes up to ~33k of
   * memory if a 1m blocks are used (or 66 on 64-bit arch)
   */
  void* io_context; /* Reserve a pointer for use during io */
  /* data should only be non-NULL if fully populated. */
  // NOLINTNEXTLINE(readability/multiline_comment)
  uint8_t* nodes; /* The hash data used to verify the children.
                   * Guaranteed to be page-aligned. */
};

/* dm_bht_level
 * Contains an array of entries which represent a page of hashes where
 * each hash is a node in the tree at the given tree depth/level.
 */
struct dm_bht_level {
  struct dm_bht_entry* entries; /* array of entries of tree nodes */
  unsigned int count;           /* number of entries at this level */
  sector_t sector;              /* starting sector for this level */
};

/* opaque context, start, databuf, sector_count */
typedef int (*dm_bht_callback)(void*,    /* external context */
                               sector_t, /* start sector */
                               uint8_t*, /* destination page */
                               sector_t, /* num sectors */
                               struct dm_bht_entry*);
/* dm_bht - Device mapper block hash tree
 * dm_bht provides a fixed interface for comparing data blocks
 * against a cryptographic hashes stored in a hash tree. It
 * optimizes the tree structure for storage on disk.
 *
 * The tree is built from the bottom up.  A collection of data,
 * external to the tree, is hashed and these hashes are stored
 * as the blocks in the tree.  For some number of these hashes,
 * a parent node is created by hashing them.  These steps are
 * repeated.
 *
 * TODO(wad): All hash storage memory is pre-allocated and freed once an
 * entire branch has been verified.
 */
struct dm_bht {
  /* Configured values */
  int depth;                /* Depth of the tree including the root */
  unsigned int block_count; /* Number of blocks hashed */
  unsigned char salt[DM_BHT_SALT_SIZE];

  /* This is a temporary hack to ease the transition to salting. It will
   * be removed once salting is supported both in kernel and userspace,
   * and the salt will default to all zeroes instead. */
  bool have_salt;

  /* Computed values */
  unsigned int node_count;       /* Data size (in hashes) for each entry */
  unsigned int node_count_shift; /* first bit set - 1 */
  /* There is one per CPU so that verified can be simultaneous. */
  /* We assume we only have one CPU in userland. */
  unsigned int digest_size;
  sector_t sectors; /* Number of disk sectors used */

  /* bool verified;  Full tree is verified */
  uint8_t root_digest[DM_BHT_MAX_DIGEST_SIZE];
  struct dm_bht_level* levels; /* in reverse order */
  /* Callback for reading from the hash device */
  dm_bht_callback read_cb;
  /* True if the buffers are externally allocated. */
  bool externally_allocated;
};

/* Constructor for struct dm_bht instances. */
BRILLO_EXPORT
int dm_bht_create(struct dm_bht* bht,
                  unsigned int block_count,
                  const char* alg_name);
/* Destructor for struct dm_bht instances.  Does not free @bht */
BRILLO_EXPORT
int dm_bht_destroy(struct dm_bht* bht);

/* Basic accessors for struct dm_bht */
BRILLO_EXPORT
sector_t dm_bht_sectors(const struct dm_bht* bht);
BRILLO_EXPORT
void dm_bht_set_read_cb(struct dm_bht* bht, dm_bht_callback read_cb);
BRILLO_EXPORT
int dm_bht_set_root_hexdigest(struct dm_bht* bht, const uint8_t* hexdigest);
BRILLO_EXPORT
int dm_bht_root_hexdigest(struct dm_bht* bht,
                          uint8_t* hexdigest,
                          int available);
BRILLO_EXPORT
void dm_bht_set_salt(struct dm_bht* bht, const char* hexsalt);
int dm_bht_salt(struct dm_bht* bht, char* hexsalt);

/* Functions for loading in data from disk for verification */
bool dm_bht_is_populated(struct dm_bht* bht, unsigned int block);
BRILLO_EXPORT
int dm_bht_populate(struct dm_bht* bht, void* read_cb_ctx, unsigned int block);
BRILLO_EXPORT
int dm_bht_verify_block(struct dm_bht* bht,
                        unsigned int block,
                        const uint8_t* buffer,
                        unsigned int offset);
BRILLO_EXPORT
int dm_bht_zeroread_callback(void* ctx,
                             sector_t start,
                             uint8_t* dst,
                             sector_t count,
                             struct dm_bht_entry* entry);
BRILLO_EXPORT
void dm_bht_read_completed(struct dm_bht_entry* entry, int status);

int dm_bht_compute_hash(struct dm_bht* bht,
                        const uint8_t* buffer,
                        uint8_t* digest);

/* Functions for creating struct dm_bhts on disk.  A newly created dm_bht
 * should not be directly used for verification. (It should be repopulated.)
 * In addition, these functions aren't meant to be called in parallel.
 */
BRILLO_EXPORT
int dm_bht_compute(struct dm_bht* bht);
BRILLO_EXPORT
void dm_bht_set_buffer(struct dm_bht* bht, void* buffer);
BRILLO_EXPORT
int dm_bht_store_block(struct dm_bht* bht,
                       unsigned int block,
                       uint8_t* block_data);

/* Functions for converting indices to nodes. */

inline struct dm_bht_level* dm_bht_get_level(struct dm_bht* bht, int depth) {
  return &bht->levels[depth];
}

inline unsigned int dm_bht_get_level_shift(struct dm_bht* bht, int depth) {
  return (bht->depth - depth) * bht->node_count_shift;
}

/* For the given depth, this is the entry index.  At depth+1 it is the node
 * index for depth.
 */
inline unsigned int dm_bht_index_at_level(struct dm_bht* bht,
                                          int depth,
                                          unsigned int leaf) {
  return leaf >> dm_bht_get_level_shift(bht, depth);
}

inline uint8_t* dm_bht_node(struct dm_bht* bht,
                            struct dm_bht_entry* entry,
                            unsigned int node_index) {
  return &entry->nodes[node_index * bht->digest_size];
}

inline struct dm_bht_entry* dm_bht_get_entry(struct dm_bht* bht,
                                             int depth,
                                             unsigned int block) {
  unsigned int index = dm_bht_index_at_level(bht, depth, block);
  struct dm_bht_level* level = dm_bht_get_level(bht, depth);

  return &level->entries[index];
}

inline uint8_t* dm_bht_get_node(struct dm_bht* bht,
                                struct dm_bht_entry* entry,
                                int depth,
                                unsigned int block) {
  unsigned int index = dm_bht_index_at_level(bht, depth, block);

  return dm_bht_node(bht, entry, index % bht->node_count);
}

class DmBhtInterface {
 public:
  virtual ~DmBhtInterface() = default;

  virtual int Create(unsigned int blocksize, std::string alg) = 0;
  virtual void SetReadCallback(dm_bht_callback callback) = 0;
  virtual void SetSalt(std::string hexsalt) = 0;
  virtual void SetBuffer(void* buffer) = 0;
  virtual sector_t Sectors() = 0;
  virtual unsigned int DigestSize() = 0;
  virtual int StoreBlock(unsigned int block, uint8_t* block_data) = 0;
  virtual int Compute() = 0;
  virtual void HexDigest(uint8_t* hexdigest, int available) = 0;
};

// Class wrapping C dm_bht functions.
class BRILLO_EXPORT DmBht : public DmBhtInterface {
 public:
  DmBht() {}
  ~DmBht() override;

  // Disallow copying.
  DmBht(const DmBht&) = delete;
  DmBht& operator=(const DmBht&) = delete;

  // `DmBhtInterface` overrides.
  int Create(unsigned int blocksize, std::string alg) override;
  void SetReadCallback(dm_bht_callback callback) override;
  void SetSalt(std::string hexsalt) override;
  void SetBuffer(void* buffer) override;
  sector_t Sectors() override;
  unsigned int DigestSize() override;
  int StoreBlock(unsigned int block, uint8_t* block_data) override;
  int Compute() override;
  void HexDigest(uint8_t* hexdigest, int available) override;

 private:
  std::unique_ptr<struct dm_bht> dm_bht_ptr_;
};

}  // namespace verity

#endif  // VERITY_DM_BHT_H_
