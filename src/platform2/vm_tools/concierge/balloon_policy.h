// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#ifndef VM_TOOLS_CONCIERGE_BALLOON_POLICY_H_
#define VM_TOOLS_CONCIERGE_BALLOON_POLICY_H_

#include <crosvm/crosvm_control.h>

#include <limits>
#include <optional>
#include <stdint.h>
#include <string>

namespace vm_tools {
namespace concierge {

constexpr int64_t KIB = 1024;
constexpr int64_t MIB = 1024 * 1024;
constexpr int64_t PAGE_BYTES = 4096;

struct BalloonStats {
  BalloonStatsFfi stats_ffi;
  uint64_t balloon_actual;
};

struct MemoryMargins {
  uint64_t critical;
  uint64_t moderate;
};

struct ComponentMemoryMargins {
  uint64_t chrome_critical;
  uint64_t chrome_moderate;
  uint64_t arcvm_foreground;
  uint64_t arcvm_perceptible;
  uint64_t arcvm_cached;
};

struct BalloonDeflationLimit {
  uint64_t min_balloon_size = std::numeric_limits<uint64_t>::max();
  int32_t oom_score_adj = std::numeric_limits<int32_t>::max();
};

// Re-defined from Android KillEventsMonitor.java. Must be kept in sync.
static constexpr int32_t kAppAdjForegroundMax = 0;
static constexpr int32_t kAppAdjPerceptibleMax = 900 - 1;
static constexpr int32_t kAppAdjCachedMax = 999;

// The max oom score for perceptible processes. This is from Android
// ProcessList.java.
static constexpr int32_t kPlatformPerceptibleMaxOmmScoreAdjValue = 250;

class BalloonPolicyInterface {
 public:
  virtual ~BalloonPolicyInterface() {}

  // Calculates the amount of memory to be shifted between a VM and the host.
  // Positive value means that the policy wants to move that amount of memory
  // from the guest to the host.
  virtual int64_t ComputeBalloonDelta(
      const BalloonStats& stats,
      uint64_t host_available,
      bool game_mode,
      const std::string& vm,
      int64_t total_available_memory,
      ComponentMemoryMargins component_margins) = 0;

  virtual bool DeflateBalloonToSaveProcess(int proc_size,
                                           int proc_oom_score,
                                           uint64_t& new_balloon_size,
                                           uint64_t& freed_space) = 0;

  // Update the current balloon size. This method is supposed to be called when
  // the balloon size has been changed by someone outside of the balloon policy
  // (e.g., aggressive balloon).
  virtual void UpdateCurrentBalloonSize(uint64_t size) = 0;
};

class BalanceAvailableBalloonPolicy : public BalloonPolicyInterface {
 public:
  BalanceAvailableBalloonPolicy(int64_t critical_host_available,
                                int64_t guest_available_bias,
                                const std::string& vm);

  int64_t ComputeBalloonDelta(
      const BalloonStats& stats,
      uint64_t host_available,
      bool game_mode,
      const std::string& vm,
      int64_t total_available_memory,
      ComponentMemoryMargins component_margins) override;

  bool DeflateBalloonToSaveProcess(int proc_size,
                                   int proc_oom_score,
                                   uint64_t& new_balloon_size,
                                   uint64_t& freed_space) override;

  // Ignore this because BalanceAvailableBalloonPolicy does not cache the
  // balloon size.
  void UpdateCurrentBalloonSize(uint64_t size) override {}

 private:
  // ChromeOS's critical margin.
  const int64_t critical_host_available_;

  // How much to bias the balance of available memory, depending on how full
  // the balloon is.
  const int64_t guest_available_bias_;

  // The max actual balloon size observed.
  int64_t max_balloon_actual_;

  // This is a guessed value of guest's critical available
  // size. If free memory is smaller than this, guest memory
  // managers (OOM, Android LMKD) will start killing apps.
  int64_t critical_guest_available_;

  // for calculating critical_guest_available
  int64_t prev_guest_available_;
  int64_t prev_balloon_full_percent_;

  // This class keeps the state of a balloon and modified only via
  // ComputeBalloonDelta() so no copy/assign operations are needed.
  BalanceAvailableBalloonPolicy(const BalanceAvailableBalloonPolicy&) = delete;
  BalanceAvailableBalloonPolicy& operator=(
      const BalanceAvailableBalloonPolicy&) = delete;
};

struct ZoneInfoStats {
  int64_t sum_low;
  int64_t totalreserve;
};

class LimitCacheBalloonPolicy : public BalloonPolicyInterface {
 public:
  struct Params {
    // The maximum amount of page cache the guest should have if ChromeOS is
    // reclaiming.
    int64_t reclaim_target_cache;

    // The maximum amount of page cache the guest should have if ChromeOS has
    // critical memory pressure.
    int64_t critical_target_cache;

    // The maximum amount of page cache the guest should have if ChromeOS has
    // moderate memory pressure.
    int64_t moderate_target_cache;

    // If >0, enable responsive balloon sizing. Concierge will listen on a VSOCK
    // for connections from LMKD in Android. When LMKD is about to kill an App,
    // it will signal the balloon sizing code, which may deflate the balloon
    // instead of killing the app.
    int64_t responsive_max_deflate_bytes;
  };
  LimitCacheBalloonPolicy(const MemoryMargins& margins,
                          int64_t host_lwm,
                          ZoneInfoStats guest_zoneinfo,
                          const Params& params,
                          const std::string& vm);

  int64_t ComputeBalloonDelta(
      const BalloonStats& stats,
      uint64_t host_available,
      bool game_mode,
      const std::string& vm,
      int64_t total_available_memory,
      ComponentMemoryMargins component_margins) override;

  int64_t ComputeBalloonDeltaImpl(int64_t host_free,
                                  const BalloonStats& stats,
                                  int64_t host_available,
                                  bool game_mode,
                                  const std::string& vm,
                                  int64_t total_available_memory,
                                  ComponentMemoryMargins component_margins);

  bool DeflateBalloonToSaveProcess(int proc_size,
                                   int proc_oom_score,
                                   uint64_t& new_balloon_size,
                                   uint64_t& freed_space) override;

  void UpdateCurrentBalloonSize(uint64_t size) override;

  // Updates the deflation limits when the balloon policy is refreshed
  void UpdateBalloonDeflationLimits(ComponentMemoryMargins component_margins,
                                    int64_t total_available_mem,
                                    int64_t balloon_size);

  // Expose the minimum target for guest free memory for testing. The balloon
  // will be sized so that guest free memory is not below this amount.
  int64_t MinFree() { return guest_zoneinfo_.sum_low - MIB; }

  // Expose the maximum target for guest free memory for testing. The balloon
  // will be sized so that guest free memory is not above this amount.
  int64_t MaxFree();

 private:
  // ChromeOS's memory margins.
  const MemoryMargins margins_;

  // The sum of all the host's zone's low memory watermarks.
  const int64_t host_lwm_;

  // Stats from the guest's zoneinfo.
  const ZoneInfoStats guest_zoneinfo_;

  // Tunable parameters of the policy.
  const Params params_;

  // The current balloon size in bytes
  uint64_t current_balloon_size_ = 0;

  // Number of deflation limits. Currently 3 (foreground, perceptible,
  // cached).
  static constexpr size_t kDeflationLimitCount = 3;
  BalloonDeflationLimit balloon_deflation_limits_[kDeflationLimitCount]{};

  LimitCacheBalloonPolicy(const LimitCacheBalloonPolicy&) = delete;
  LimitCacheBalloonPolicy& operator=(const LimitCacheBalloonPolicy&) = delete;

  // Calculates the balloon size limit given the specified margin
  static uint64_t GetBalloonSizeLimitForMargin(int64_t total_available_mem,
                                               int64_t balloon_size,
                                               int64_t margin);
};

// Computes the sum of all of ChromeOS's zone's low watermarks. To help
// initialize LimitCacheBalloonPolicy. Returns std::nullopt on error.
std::optional<uint64_t> HostZoneLowSum(bool log_on_error);

// Computes the sum of all the zone low watermarks from the contents of
// /proc/zoneinfo.
uint64_t ZoneLowSumFromZoneInfo(const std::string& zoneinfo);

// Computes statistics so that a balloon policy can know when Linux is close to
// reclaiming memory, or Android's LMKD is close to killing Apps.
std::optional<ZoneInfoStats> ParseZoneInfoStats(const std::string& zoneinfo);

}  // namespace concierge
}  // namespace vm_tools

#endif  // VM_TOOLS_CONCIERGE_BALLOON_POLICY_H_
