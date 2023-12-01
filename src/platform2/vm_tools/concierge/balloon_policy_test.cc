// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/concierge/balloon_policy.h"
#include "vm_tools/concierge/vm_util.h"

#include <string>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/json/json_reader.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace vm_tools {
namespace concierge {

// Test that shared and unevictable memory is subtracted from disk caches when
// checking if the guest has low caches.
TEST(BalloonPolocyTest, Unreclaimable) {
  // Values are roughly what a 4GB ARCVM would get (but rounded)
  const int64_t host_lwm = 200 * MIB;
  ZoneInfoStats guest_stats = {.sum_low = 200 * MIB, .totalreserve = 300 * MIB};
  MemoryMargins margins = {.critical = 400 * MIB, .moderate = 2000 * MIB};
  const LimitCacheBalloonPolicy::Params params = {
      .reclaim_target_cache = 0,
      .critical_target_cache = 0,
      .moderate_target_cache = 200 * MIB};
  LimitCacheBalloonPolicy policy(margins, host_lwm, guest_stats, params,
                                 "test");

  // Test that when, because of unevictable memory, there is less cache left
  // than the cache limit, that we keep free_memory at MaxFree.
  {
    BalloonStats stats = {{.free_memory = policy.MaxFree(),
                           .disk_caches = 300 * MIB,
                           .unevictable_memory = 101 * MIB}};
    EXPECT_EQ(
        0, policy.ComputeBalloonDeltaImpl(0 /* host_free */, stats,
                                          margins.moderate /* host_available */,
                                          false, "test", 0, {}));
  }

  // Test that when, because of shared memory, there is less cache left than the
  // cache limit, that we keep free_memory at MaxFree.
  {
    BalloonStats stats = {{.free_memory = policy.MaxFree(),
                           .disk_caches = 300 * MIB,

                           .shared_memory = 101 * MIB}};
    EXPECT_EQ(
        0, policy.ComputeBalloonDeltaImpl(0 /* host_free */, stats,
                                          margins.moderate /* host_available */,
                                          false, "test", 0, {}));
  }
}

// Test that having no limits still inflates the balloon to reduce excess free.
TEST(BalloonPolicyTest, LimitCacheNoLimit) {
  const int64_t host_lwm = 200 * MIB;
  ZoneInfoStats guest_stats = {.sum_low = 200 * MIB, .totalreserve = 300 * MIB};
  const MemoryMargins margins = {.critical = 400 * MIB, .moderate = 2000 * MIB};
  const LimitCacheBalloonPolicy::Params params = {.reclaim_target_cache = 0,
                                                  .critical_target_cache = 0,
                                                  .moderate_target_cache = 0};
  LimitCacheBalloonPolicy policy(margins, host_lwm, guest_stats, params,
                                 "test");

  // NB: Because there are no cache limits, target_free will always be
  // MaxFree().

  // Test that we don't inflate the balloon if it's just a little bit.
  {
    const BalloonStats stats = {
        {.free_memory = policy.MaxFree() + MIB, .disk_caches = 0}};
    EXPECT_EQ(0, policy.ComputeBalloonDeltaImpl(0 /* host_free */, stats,
                                                0 /* host_available */, false,
                                                "test", 0, {}));
  }

  // Test that we do inflate the balloon if it's a lot (twice MaxFree()).
  {
    const BalloonStats stats = {
        {.free_memory = policy.MaxFree() * 2, .disk_caches = 0}};
    EXPECT_EQ(policy.MaxFree(),
              policy.ComputeBalloonDeltaImpl(0 /* host_free */, stats,
                                             0 /* host_available */, false,
                                             "test", 0, {}));
  }

  // Test that we deflate the balloon even if we just need a small piece.
  {
    const BalloonStats stats = {
        {.free_memory = policy.MaxFree() * 3 / 4, .disk_caches = 0}};
    EXPECT_EQ(-(policy.MaxFree() / 4),
              policy.ComputeBalloonDeltaImpl(0 /* host_free */, stats,
                                             0 /* host_available */, false,
                                             "test", 0, {}));
  }
}

// Tests that moderate_target_cache works as expected.
TEST(BalloonPolicyTest, LimitCacheModerate) {
  // Values are roughly what a 4GB ARCVM would get (but rounded)
  const int64_t host_lwm = 200 * MIB;
  ZoneInfoStats guest_stats = {.sum_low = 200 * MIB, .totalreserve = 300 * MIB};
  MemoryMargins margins = {.critical = 400 * MIB, .moderate = 2000 * MIB};
  const LimitCacheBalloonPolicy::Params params = {
      .reclaim_target_cache = 0,
      .critical_target_cache = 0,
      .moderate_target_cache = 200 * MIB};
  LimitCacheBalloonPolicy policy(margins, host_lwm, guest_stats, params,
                                 "test");

  // limit_start is the host_available level below which we start limiting
  // guest memory.
  const uint64_t limit_start =
      margins.moderate + policy.MaxFree() - guest_stats.sum_low;

  // Test that we inflate the balloon a bit when we start getting a bit close
  // to the moderate margin.
  {
    BalloonStats stats = {{
        .free_memory = policy.MaxFree(),
        .disk_caches = 1000 * MIB,
    }};
    EXPECT_EQ(
        MIB, policy.ComputeBalloonDeltaImpl(
                 0 /* host_free */, stats,
                 limit_start - MIB /* host_available */, false, "test", 0, {}));
  }

  // Test that when there is less cache left than the distance to target free,
  // we only inflate the balloon enough to reclaim that cache.
  {
    BalloonStats stats = {
        {.free_memory = policy.MaxFree(), .disk_caches = 300 * MIB}};
    const int64_t cache_above_limit =
        stats.stats_ffi.disk_caches - params.moderate_target_cache;
    EXPECT_EQ(cache_above_limit,
              policy.ComputeBalloonDeltaImpl(
                  0 /* host_free */, stats,
                  margins.moderate /* host_available */, false, "test", 0, {}));
  }

  // Test that when we are way below the moderate margin, we still give the
  // guest MinFree() memory.
  {
    BalloonStats stats = {
        {.free_memory = policy.MaxFree(), .disk_caches = 2000 * MIB}};
    const int64_t free_above_min =
        stats.stats_ffi.free_memory - policy.MinFree();
    EXPECT_EQ(free_above_min,
              policy.ComputeBalloonDeltaImpl(0 /* host_free */, stats,
                                             0 /* host_available */, false,
                                             "test", 0, {}));
  }
}

// Tests that critical_target_cache works as expected.
TEST(BalloonPolicyTest, LimitCacheCritical) {
  // Values are roughly what a 4GB ARCVM would get (but rounded)
  const int64_t host_lwm = 200 * MIB;
  ZoneInfoStats guest_stats = {.sum_low = 200 * MIB, .totalreserve = 300 * MIB};
  MemoryMargins margins = {.critical = 400 * MIB, .moderate = 2000 * MIB};
  const LimitCacheBalloonPolicy::Params params = {
      .reclaim_target_cache = 0,
      .critical_target_cache = 100 * MIB,
      .moderate_target_cache = 0};
  LimitCacheBalloonPolicy policy(margins, host_lwm, guest_stats, params,
                                 "test");

  // limit_start is the host_available level below which we start limiting
  // guest memory.
  const uint64_t limit_start =
      margins.critical + policy.MaxFree() - guest_stats.sum_low;

  // Test that we inflate the balloon a bit when we start getting a bit close
  // to the critical margin.
  {
    BalloonStats stats = {
        {.free_memory = policy.MaxFree(), .disk_caches = 1000 * MIB}};
    EXPECT_EQ(
        MIB, policy.ComputeBalloonDeltaImpl(
                 0 /* host_free */, stats,
                 limit_start - MIB /* host_available */, false, "test", 0, {}));
  }

  // Test that when there is less cache left than the distance to target free,
  // we only inflate the balloon enough to reclaim that cache.
  {
    BalloonStats stats = {
        {.free_memory = policy.MaxFree(), .disk_caches = 150 * MIB}};
    const int64_t cache_above_limit =
        stats.stats_ffi.disk_caches - params.critical_target_cache;
    EXPECT_EQ(cache_above_limit,
              policy.ComputeBalloonDeltaImpl(
                  0 /* host_free */, stats,
                  margins.critical /* host_available */, false, "test", 0, {}));
  }

  // Test that when we are way below the critical margin, we still give the
  // guest MinFree() memory.
  {
    BalloonStats stats = {
        {.free_memory = policy.MaxFree(), .disk_caches = 1000 * MIB}};
    const int64_t free_above_min =
        stats.stats_ffi.free_memory - policy.MinFree();
    EXPECT_EQ(free_above_min,
              policy.ComputeBalloonDeltaImpl(0 /* host_free */, stats,
                                             0 /* host_available */, false,
                                             "test", 0, {}));
  }
}

// Tests that reclaim_target_cache works as expected.
TEST(BalloonPolicyTest, LimitCacheReclaim) {
  // Values are roughly what a 4GB ARCVM would get (but rounded)
  const int64_t host_lwm = 200 * MIB;
  ZoneInfoStats guest_stats = {.sum_low = 200 * MIB, .totalreserve = 300 * MIB};
  MemoryMargins margins = {.critical = 400 * MIB, .moderate = 2000 * MIB};
  const LimitCacheBalloonPolicy::Params params = {
      .reclaim_target_cache = 100 * MIB,
      .critical_target_cache = 0,
      .moderate_target_cache = 0};
  LimitCacheBalloonPolicy policy(margins, host_lwm, guest_stats, params,
                                 "test");

  // limit_start is the host_free level below which we start limiting
  // guest memory.
  const uint64_t limit_start =
      host_lwm + policy.MaxFree() - guest_stats.sum_low;

  // Test that we inflate the balloon a bit when we start getting a bit close
  // to reclaiming in the host.
  {
    BalloonStats stats = {
        {.free_memory = policy.MaxFree(), .disk_caches = 1000 * MIB}};
    EXPECT_EQ(MIB, policy.ComputeBalloonDeltaImpl(
                       limit_start - MIB /* host_free */, stats,
                       0 /* host_available */, false, "test", 0, {}));
  }

  // Test that when there is less cache left than the distance to target free,
  // we only inflate the balloon enough to reclaim that cache.
  {
    BalloonStats stats = {
        {.free_memory = policy.MaxFree(), .disk_caches = 150 * MIB}};
    const int64_t cache_above_limit =
        stats.stats_ffi.disk_caches - params.reclaim_target_cache;
    EXPECT_EQ(cache_above_limit,
              policy.ComputeBalloonDeltaImpl(host_lwm /* host_free */, stats,
                                             0 /* host_available */, false,
                                             "test", 0, {}));
  }

  // Test that when we are way past reclaiming in the host, we still give the
  // guest MinFree() memory.
  {
    BalloonStats stats = {
        {.free_memory = policy.MaxFree(), .disk_caches = 1000 * MIB}};
    const int64_t free_above_min =
        stats.stats_ffi.free_memory - policy.MinFree();
    EXPECT_EQ(free_above_min,
              policy.ComputeBalloonDeltaImpl(0 /* host_free */, stats,
                                             0 /* host_available */, false,
                                             "test", 0, {}));
  }
}

// Tests that critical_target_cache and moderate_target_cache work together as
// expected.
TEST(BalloonPolicyTest, LimitCacheModerateAndCritical) {
  // Values are roughly what a 4GB ARCVM would get (but rounded)
  const int64_t host_lwm = 200 * MIB;
  ZoneInfoStats guest_stats = {.sum_low = 200 * MIB, .totalreserve = 300 * MIB};
  MemoryMargins margins = {.critical = 400 * MIB, .moderate = 2000 * MIB};
  const LimitCacheBalloonPolicy::Params params = {
      .reclaim_target_cache = 0,
      .critical_target_cache = 100 * MIB,
      .moderate_target_cache = 200 * MIB};
  LimitCacheBalloonPolicy policy(margins, host_lwm, guest_stats, params,
                                 "test");

  // Test that when we are limited by both moderate and critical available cache
  // limits, the smaller of the two is used.
  BalloonStats stats = {
      {.free_memory = policy.MaxFree(), .disk_caches = 150 * MIB}};
  const int64_t cache_above_limit =
      stats.stats_ffi.disk_caches - params.critical_target_cache;
  EXPECT_EQ(cache_above_limit,
            policy.ComputeBalloonDeltaImpl(
                0 /* host_free */, stats, margins.critical /* host_available */,
                false, "test", 0, {}));
}

// Tests that the guest gets MinFree memory even if the host is very low.
TEST(BalloonPolicyTest, LimitCacheGuestFreeLow) {
  // Values are roughly what a 4GB ARCVM would get (but rounded)
  const int64_t host_lwm = 200 * MIB;
  ZoneInfoStats guest_stats = {.sum_low = 200 * MIB, .totalreserve = 300 * MIB};
  MemoryMargins margins = {.critical = 400 * MIB, .moderate = 2000 * MIB};
  const LimitCacheBalloonPolicy::Params params = {
      .reclaim_target_cache = 0,
      .critical_target_cache = 100 * MIB,
      .moderate_target_cache = 200 * MIB};
  LimitCacheBalloonPolicy policy(margins, host_lwm, guest_stats, params,
                                 "test");

  BalloonStats stats = {{.free_memory = 0, .disk_caches = 150 * MIB}};
  EXPECT_EQ(-policy.MinFree(),
            policy.ComputeBalloonDeltaImpl(0 /* host_free */, stats,
                                           0 /* host_available */, false,
                                           "test", 0, {}));
}

// Tests that ParseZoneInfoStats works on real input.
TEST(BalloonPolicyTest, ParseZoneInfoStatsSnapshot) {
  auto stats = ParseZoneInfoStats(
      "Node 0, zone      DMA\n"
      "  per-node stats\n"
      "      nr_inactive_anon 364023\n"
      "      nr_active_anon 97740\n"
      "      nr_inactive_file 20238\n"
      "      nr_active_file 95809\n"
      "      nr_unevictable 24263\n"
      "      nr_slab_reclaimable 7997\n"
      "      nr_slab_unreclaimable 18546\n"
      "      nr_isolated_anon 0\n"
      "      nr_isolated_file 0\n"
      "      workingset_nodes 1789\n"
      "      workingset_refault_anon 0\n"
      "      workingset_refault_file 86864\n"
      "      workingset_activate_anon 0\n"
      "      workingset_activate_file 13430\n"
      "      workingset_restore_anon 0\n"
      "      workingset_restore_file 72672\n"
      "      workingset_nodereclaim 0\n"
      "      nr_anon_pages 450240\n"
      "      nr_mapped    48448\n"
      "      nr_file_pages 140275\n"
      "      nr_dirty     0\n"
      "      nr_writeback 0\n"
      "      nr_writeback_temp 0\n"
      "      nr_shmem     23504\n"
      "      nr_shmem_hugepages 0\n"
      "      nr_shmem_pmdmapped 0\n"
      "      nr_file_hugepages 0\n"
      "      nr_file_pmdmapped 0\n"
      "      nr_anon_transparent_hugepages 123\n"
      "      nr_vmscan_write 0\n"
      "      nr_vmscan_immediate_reclaim 0\n"
      "      nr_dirtied   95963\n"
      "      nr_written   95960\n"
      "      nr_kernel_misc_reclaimable 0\n"
      "      nr_foll_pin_acquired 392\n"
      "      nr_foll_pin_released 392\n"
      "      nr_kernel_stack 17440\n"
      "  pages free     3208\n"
      "        min      113\n"
      "        low      151\n"
      "        high     179\n"
      "        spanned  4095\n"
      "        present  3742\n"
      "        managed  3208\n"
      "        cma      0\n"
      "        protection: (0, 3248, 3700, 3700, 3700)\n"
      "      nr_free_pages 3208\n"
      "      nr_zone_inactive_anon 0\n"
      "      nr_zone_active_anon 0\n"
      "      nr_zone_inactive_file 0\n"
      "      nr_zone_active_file 0\n"
      "      nr_zone_unevictable 0\n"
      "      nr_zone_write_pending 0\n"
      "      nr_mlock     0\n"
      "      nr_page_table_pages 0\n"
      "      nr_bounce    0\n"
      "      nr_zspages   0\n"
      "      nr_free_cma  0\n"
      "  pagesets\n"
      "    cpu: 0\n"
      "              count: 0\n"
      "              high:  0\n"
      "              batch: 1\n"
      "  vm stats threshold: 4\n"
      "    cpu: 1\n"
      "              count: 0\n"
      "              high:  0\n"
      "              batch: 1\n"
      "  vm stats threshold: 4\n"
      "    cpu: 2\n"
      "              count: 0\n"
      "              high:  0\n"
      "              batch: 1\n"
      "  vm stats threshold: 4\n"
      "  node_unreclaimable:  0\n"
      "  start_pfn:           1\n"
      "Node 0, zone    DMA32\n"
      "  pages free     55144\n"
      "        min      29527\n"
      "        low      39744\n"
      "        high     47125\n"
      "        spanned  1044480\n"
      "        present  847872\n"
      "        managed  831488\n"
      "        cma      0\n"
      "        protection: (0, 0, 452, 452, 452)\n"
      "      nr_free_pages 55144\n"
      "      nr_zone_inactive_anon 299032\n"
      "      nr_zone_active_anon 87931\n"
      "      nr_zone_inactive_file 19179\n"
      "      nr_zone_active_file 86754\n"
      "      nr_zone_unevictable 20737\n"
      "      nr_zone_write_pending 0\n"
      "      nr_mlock     21\n"
      "      nr_page_table_pages 7964\n"
      "      nr_bounce    0\n"
      "      nr_zspages   0\n"
      "      nr_free_cma  0\n"
      "  pagesets\n"
      "    cpu: 0\n"
      "              count: 58\n"
      "              high:  378\n"
      "              batch: 63\n"
      "  vm stats threshold: 24\n"
      "    cpu: 1\n"
      "              count: 95\n"
      "              high:  378\n"
      "              batch: 63\n"
      "  vm stats threshold: 24\n"
      "    cpu: 2\n"
      "              count: 0\n"
      "              high:  378\n"
      "              batch: 63\n"
      "  vm stats threshold: 24\n"
      "  node_unreclaimable:  0\n"
      "  start_pfn:           4096\n"
      "Node 0, zone   Normal\n"
      "  pages free     7002\n"
      "        min      4150\n"
      "        low      5586\n"
      "        high     6623\n"
      "        spanned  141824\n"
      "        present  141824\n"
      "        managed  116890\n"
      "        cma      0\n"
      "        protection: (0, 0, 0, 0, 0)\n"
      "      nr_free_pages 7002\n"
      "      nr_zone_inactive_anon 64991\n"
      "      nr_zone_active_anon 9801\n"
      "      nr_zone_inactive_file 1059\n"
      "      nr_zone_active_file 9055\n"
      "      nr_zone_unevictable 3526\n"
      "      nr_zone_write_pending 0\n"
      "      nr_mlock     1892\n"
      "      nr_page_table_pages 839\n"
      "      nr_bounce    0\n"
      "      nr_zspages   0\n"
      "      nr_free_cma  0\n"
      "  pagesets\n"
      "    cpu: 0\n"
      "              count: 41\n"
      "              high:  186\n"
      "              batch: 31\n"
      "  vm stats threshold: 12\n"
      "    cpu: 1\n"
      "              count: 7\n"
      "              high:  186\n"
      "              batch: 31\n"
      "  vm stats threshold: 12\n"
      "    cpu: 2\n"
      "              count: 0\n"
      "              high:  186\n"
      "              batch: 31\n"
      "  vm stats threshold: 12\n"
      "  node_unreclaimable:  0\n"
      "  start_pfn:           1048576\n"
      "Node 0, zone  Movable\n"
      "  pages free     0\n"
      "        min      0\n"
      "        low      0\n"
      "        high     0\n"
      "        spanned  0\n"
      "        present  0\n"
      "        managed  0\n"
      "        cma      0\n"
      "        protection: (0, 0, 0, 0, 0)\n"
      "Node 0, zone   Device\n"
      "  pages free     0\n"
      "        min      0\n"
      "        low      0\n"
      "        high     0\n"
      "        spanned  0\n"
      "        present  0\n"
      "        managed  0\n"
      "        cma      0\n"
      "        protection: (0, 0, 0, 0, 0)\n");

  EXPECT_TRUE(stats);
  EXPECT_EQ(stats->sum_low, 45481 * PAGE_BYTES);
  EXPECT_EQ(stats->totalreserve, 85041 * PAGE_BYTES);
}

// Tests that ParseZoneInfoStats works on real input.
TEST(BalloonPolicyTest, ParseZoneInfoStatsFailures) {
  EXPECT_FALSE(ParseZoneInfoStats(""));

  // Missing non-zero high and protection.
  EXPECT_FALSE(ParseZoneInfoStats("low 1"));

  // Missing protection.
  EXPECT_FALSE(ParseZoneInfoStats("low 1\nhigh 1"));

  // Bad low watermark.
  EXPECT_FALSE(ParseZoneInfoStats("low 1a\nhigh 1\nprotection(1)"));

  // Bad low watermark.
  EXPECT_FALSE(ParseZoneInfoStats("low 1 1\nhigh 1\nprotection(1)"));

  // Bad high watermark.
  EXPECT_FALSE(ParseZoneInfoStats("low 1\nhigh a1\nprotection(1)"));

  // Bad high watermark.
  EXPECT_FALSE(ParseZoneInfoStats("low 1\nhigh 2 2\nprotection(1)"));

  // Missing low.
  EXPECT_FALSE(ParseZoneInfoStats("high 1\nprotection: (1)"));

  // Missing high before protection.
  EXPECT_FALSE(ParseZoneInfoStats("low 1\nprotection: (1)"));

  // Missing high before protection.
  EXPECT_FALSE(
      ParseZoneInfoStats("low 1\nhigh 1\nprotection: (1)\nprotection: (1)"));

  // No protection line between two high lines.
  EXPECT_FALSE(ParseZoneInfoStats("low 1\nhigh 1\nhigh: 1"));
}

TEST(BalloonPolicyTest, LimitCacheBalloonDeflationLimits) {
  LimitCacheBalloonPolicy policy(
      {}, 0, {}, {.responsive_max_deflate_bytes = 200 * 4096}, "test");
  ComponentMemoryMargins margins{
      .chrome_critical = 0,
      .chrome_moderate = 0,
      .arcvm_foreground = 300 * 4096,
      .arcvm_perceptible = 600 * 4096,
      .arcvm_cached = 800 * 4096,
  };
  policy.UpdateBalloonDeflationLimits(margins,
                                      /* total_available */ 1000 * 4096,
                                      /* balloon_size */ 800 * 4096);

  // Should result in limits of:
  // foreground, 100 * 4096
  // perceptible, 400 * 4096
  // cached, 600 * 4096

  uint64_t new_balloon_size = 0;
  uint64_t freed_space = 0;

  ASSERT_TRUE(policy.DeflateBalloonToSaveProcess(
      700 * 4096, kAppAdjForegroundMax, new_balloon_size, freed_space));
  // Should be deflated by max_deflate_bytes
  ASSERT_EQ(new_balloon_size, 600 * 4096);
  ASSERT_EQ(freed_space, 200 * 4096);

  // Should not be deflated for oom score of cached since the
  // new size is already at the limit for cached
  ASSERT_FALSE(policy.DeflateBalloonToSaveProcess(
      1, kAppAdjPerceptibleMax + 1, new_balloon_size, freed_space));
  ASSERT_FALSE(policy.DeflateBalloonToSaveProcess(
      1, kAppAdjCachedMax, new_balloon_size, freed_space));

  // Should be deflated for perceptible by max_deflate down to the limit for
  // perceptible
  ASSERT_TRUE(policy.DeflateBalloonToSaveProcess(
      500 * 4096, kAppAdjPerceptibleMax, new_balloon_size, freed_space));
  ASSERT_EQ(new_balloon_size, 400 * 4096);
  ASSERT_EQ(freed_space, 200 * 4096);

  // Should no longer be deflated for perceptible since the limit has been
  // reached
  ASSERT_FALSE(policy.DeflateBalloonToSaveProcess(
      1, kAppAdjPerceptibleMax, new_balloon_size, freed_space));
  ASSERT_FALSE(policy.DeflateBalloonToSaveProcess(
      1, kAppAdjForegroundMax + 1, new_balloon_size, freed_space));

  // Should still be deflated for foreground
  ASSERT_TRUE(policy.DeflateBalloonToSaveProcess(
      150 * 4096, kAppAdjForegroundMax, new_balloon_size, freed_space));
  ASSERT_EQ(new_balloon_size, 250 * 4096);
  ASSERT_EQ(freed_space, 150 * 4096);

  // Should not be deflated for foreground if the app and max deflate are both
  // too large
  ASSERT_FALSE(policy.DeflateBalloonToSaveProcess(
      300 * 4096, kAppAdjForegroundMax - 1, new_balloon_size, freed_space));
  ASSERT_FALSE(policy.DeflateBalloonToSaveProcess(
      151 * 4096, kAppAdjForegroundMax - 1, new_balloon_size, freed_space));

  // Should still be deflated for foreground if the app is small enough
  ASSERT_TRUE(policy.DeflateBalloonToSaveProcess(
      150 * 4096, kAppAdjForegroundMax, new_balloon_size, freed_space));
  ASSERT_EQ(new_balloon_size, 100 * 4096);
  ASSERT_EQ(freed_space, 150 * 4096);

  // At the lowest limit, should not be deflated for anything
  ASSERT_FALSE(policy.DeflateBalloonToSaveProcess(
      1, kAppAdjForegroundMax - 1, new_balloon_size, freed_space));
}

}  // namespace concierge
}  // namespace vm_tools
