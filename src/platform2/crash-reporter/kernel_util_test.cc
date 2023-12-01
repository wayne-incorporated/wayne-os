// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/kernel_util.h"

#include <gtest/gtest.h>

#include "crash-reporter/test_util.h"

namespace {

// Perform tests which are common across architectures
void ComputeKernelStackSignatureCommon(kernel_util::ArchKind arch) {
  const char kStackButNoPC[] =
      "<4>[ 6066.829029]  [<790340af>] __do_softirq+0xa6/0x143\n";
  EXPECT_EQ("kernel--83615F0A",
            kernel_util::ComputeKernelStackSignature(kStackButNoPC, arch));

  const char kMissingEverything[] =
      "<4>[ 6066.829029]  [<790340af>] ? __do_softirq+0xa6/0x143\n";
  EXPECT_EQ("kernel-UnspecifiedStackSignature",
            kernel_util::ComputeKernelStackSignature(kMissingEverything, arch));

  // Long message.
  const char kTruncatedMessage[] =
      "<0>[   87.485611] Kernel panic - not syncing: 01234567890123456789"
      "01234567890123456789X\n";
  EXPECT_EQ("kernel-0123456789012345678901234567890123456789-00000000",
            kernel_util::ComputeKernelStackSignature(kTruncatedMessage, arch));
}

}  // namespace

TEST(KernelUtilTest, GetCompilerArch) {
  kernel_util::ArchKind arch = kernel_util::GetCompilerArch();
  EXPECT_LT(kernel_util::kArchUnknown, arch);
  EXPECT_GT(kernel_util::kArchCount, arch);
}

TEST(KernelUtilTest, ComputeKernelStackSignatureARM) {
  const char kBugToPanic[] =
      "<5>[  123.412524] Modules linked in:\n"
      "<5>[  123.412534] CPU: 0    Tainted: G        W    "
      "(2.6.37-01030-g51cee64 #153)\n"
      "<5>[  123.412552] PC is at write_breakme+0xd0/0x1b4\n"
      "<5>[  123.412560] LR is at write_breakme+0xc8/0x1b4\n"
      "<5>[  123.412569] pc : [<c0058220>]    lr : [<c005821c>]    "
      "psr: 60000013\n"
      "<5>[  123.412574] sp : f4e0ded8  ip : c04d104c  fp : 000e45e0\n"
      "<5>[  123.412581] r10: 400ff000  r9 : f4e0c000  r8 : 00000004\n"
      "<5>[  123.412589] r7 : f4e0df80  r6 : f4820c80  r5 : 00000004  "
      "r4 : f4e0dee8\n"
      "<5>[  123.412598] r3 : 00000000  r2 : f4e0decc  r1 : c05f88a9  "
      "r0 : 00000039\n"
      "<5>[  123.412608] Flags: nZCv  IRQs on  FIQs on  Mode SVC_32  ISA "
      "ARM  Segment user\n"
      "<5>[  123.412617] Control: 10c53c7d  Table: 34dcc04a  DAC: 00000015\n"
      "<0>[  123.412626] Process bash (pid: 1014, stack limit = 0xf4e0c2f8)\n"
      "<0>[  123.412634] Stack: (0xf4e0ded8 to 0xf4e0e000)\n"
      "<0>[  123.412641] dec0:                                              "
      "         f4e0dee8 c0183678\n"
      "<0>[  123.412654] dee0: 00000000 00000000 00677562 0000081f c06a6a78 "
      "400ff000 f4e0dfb0 00000000\n"
      "<0>[  123.412666] df00: bec7ab44 000b1719 bec7ab0c c004f498 bec7a314 "
      "c024acc8 00000001 c018359c\n"
      "<0>[  123.412679] df20: f4e0df34 c04d10fc f5803c80 271beb39 000e45e0 "
      "f5803c80 c018359c c017bfe0\n"
      "<0>[  123.412691] df40: 00000004 f4820c80 400ff000 f4e0df80 00000004 "
      "f4e0c000 00000000 c01383e4\n"
      "<0>[  123.412703] df60: f4820c80 400ff000 f4820c80 400ff000 00000000 "
      "00000000 00000004 c0138578\n"
      "<0>[  123.412715] df80: 00000000 00000000 00000004 00000000 00000004 "
      "402f95d0 00000004 00000004\n"
      "<0>[  123.412727] dfa0: c0054984 c00547c0 00000004 402f95d0 00000001 "
      "400ff000 00000004 00000000\n"
      "<0>[  123.412739] dfc0: 00000004 402f95d0 00000004 00000004 400ff000 "
      "000c194c bec7ab58 000e45e0\n"
      "<0>[  123.412751] dfe0: 00000000 bec7aad8 40232520 40284e9c 60000010 "
      "00000001 00000000 00000000\n"
      "<5>[   39.496577] Backtrace:\n"
      "<5>[  123.412782] [<c0058220>] (__bug+0x20/0x2c) from [<c0183678>] "
      "(write_breakme+0xdc/0x1bc)\n"
      "<5>[  123.412798] [<c0183678>] (write_breakme+0xdc/0x1bc) from "
      "[<c017bfe0>] (proc_reg_write+0x88/0x9c)\n";

  EXPECT_EQ("kernel-write_breakme-97D3E92F",
            kernel_util::ComputeKernelStackSignature(kBugToPanic,
                                                     kernel_util::kArchArm));
}

TEST(KernelUtilTest, ComputeKernelStackSignatureARM64SoftwarePAN) {
  // "NULL pointer dereference" takes a different exception path on some ARM64,
  // so include a separate case for it.
  const char kBugToPanic[] =
      "<6>[  103.654739] lkdtm: Performing direct entry EXCEPTION\n"
      "<1>[  103.654769] Unable to handle kernel access to user memory outside "
      "uaccess routines at virtual address 0000000000000000\n"
      "<1>[  103.654776] Mem abort info:\n"
      "<1>[  103.654782]   ESR = 0x96000045\n"
      "<1>[  103.654790]   EC = 0x25: DABT (current EL), IL = 32 bits\n"
      "<1>[  103.654796]   SET = 0, FnV = 0\n"
      "<1>[  103.654802]   EA = 0, S1PTW = 0\n"
      "<1>[  103.654807] Data abort info:\n"
      "<1>[  103.654813]   ISV = 0, ISS = 0x00000045\n"
      "<1>[  103.654819]   CM = 0, WnR = 1\n"
      "<1>[  103.654826] user pgtable: 4k pages, 39-bit VAs, "
      "pgdp=000000005e07f000\n"
      "<1>[  103.654833] [0000000000000000] pgd=0000000060b5d003, "
      "p4d=0000000060b5d003, pud=0000000060b5d003, pmd=0000000000000000\n"
      "<0>[  103.654854] Internal error: Oops: 96000045 [#1] PREEMPT SMP\n"
      "<4>[  103.654862] Modules linked in: veth rfcomm algif_hash "
      "algif_skcipher af_alg uinput xt_cgroup uvcvideo videobuf2_vmalloc "
      "videobuf2_memops videobuf2_v4l2 videobuf2_common ntc_thermistor "
      "xt_MASQUERADE rockchip_saradc ip6table_nat fuse btusb btrtl btintel "
      "btbcm bluetooth ecdh_generic ecc iio_trig_sysfs cros_ec_sensors "
      "cros_ec_sensors_core industrialio_triggered_buffer kfifo_buf "
      "cros_ec_sensorhub lzo_rle mwifiex_pcie lzo_compress mwifiex zram "
      "cfg80211 asix usbnet mii joydev\n"
      "<4>[  103.654996] CPU: 1 PID: 4582 Comm: sh Not tainted 5.10.57 #100 "
      "9711356a0d4e7b4f4bd6fa297fb43c393b08616a\n"
      "<4>[  103.655002] Hardware name: Google Kevin (DT)\n"
      "<4>[  103.655011] pstate: 60400005 (nZCv daif +PAN -UAO -TCO BTYPE=--)\n"
      "<4>[  103.655027] pc : lkdtm_EXCEPTION+0x10/0x1c\n"
      "<4>[  103.655037] lr : lkdtm_do_action+0x24/0x38\n"
      "<4>[  103.655042] sp : ffffffc0171ebca0\n"
      "<4>[  103.655049] x29: ffffffc0171ebca0 x28: ffffff802cc41e80 \n"
      "<4>[  103.655060] x27: 0000000000000000 x26: 0000000000000000 \n"
      "<4>[  103.655071] x25: 0000000000000000 x24: ffffffc010b46738 \n"
      "<4>[  103.655082] x23: 0000000000000040 x22: ffffffc010d49e4d \n"
      "<4>[  103.655093] x21: ffffffc010b46778 x20: ffffffc0171ebde0 \n"
      "<4>[  103.655103] x19: 000000000000000a x18: 00000000ffff0a10 \n"
      "<4>[  103.655114] x17: 0000000000000000 x16: 00000000000000ec \n"
      "<4>[  103.655125] x15: ffffffc0104c54ec x14: 0000000000000003 \n"
      "<4>[  103.655135] x13: 0000000000000004 x12: 0000000000000000 \n"
      "<4>[  103.655146] x11: 0000000000000000 x10: 0000000000000000 \n"
      "<4>[  103.655157] x9 : ffffffc01066fe40 x8 : 0000000000000000 \n"
      "<4>[  103.655168] x7 : 0000000000000000 x6 : ffffffc0111b7f0c \n"
      "<4>[  103.655178] x5 : 0100000000000000 x4 : 0000000000000000 \n"
      "<4>[  103.655189] x3 : ffffffc0171eb958 x2 : ffffff80f755aa70 \n"
      "<4>[  103.655200] x1 : ffffff80f754a788 x0 : ffffffc010b46778 \n"
      "<4>[  103.655211] Call trace:\n"
      "<4>[  103.655221]  lkdtm_EXCEPTION+0x10/0x1c\n"
      "<4>[  103.655229]  direct_entry+0x120/0x130\n"
      "<4>[  103.655241]  full_proxy_write+0x74/0xa4\n"
      "<4>[  103.655251]  vfs_write+0xec/0x2e4\n"
      "<4>[  103.655259]  ksys_write+0x80/0xec\n"
      "<4>[  103.655267]  __arm64_sys_write+0x24/0x30\n"
      "<4>[  103.655278]  el0_svc_common+0xcc/0x1b4\n"
      "<4>[  103.655286]  do_el0_svc_compat+0x28/0x3c\n"
      "<4>[  103.655296]  el0_svc_compat+0x10/0x1c\n"
      "<4>[  103.655305]  el0_sync_compat_handler+0xa8/0xcc\n"
      "<4>[  103.655313]  el0_sync_compat+0x188/0x1c0\n"
      "<0>[  103.655325] Code: aa1e03e9 d503201f d503233f aa1f03e8 (b900011f) "
      "\n"
      "<4>[  103.655334] ---[ end trace be4db89f163f6e56 ]---\n"
      "<0>[  103.668172] Kernel panic - not syncing: Oops: Fatal exception\n"
      "<2>[  103.668194] SMP: stopping secondary CPUs\n"
      "<0>[  103.668207] Kernel Offset: disabled\n"
      "<0>[  103.668216] CPU features: 0x0240022,6100600c\n"
      "<0>[  103.668221] Memory Limit: none\n";

  EXPECT_EQ("kernel-lkdtm_EXCEPTION-124321EE",
            kernel_util::ComputeKernelStackSignature(kBugToPanic,
                                                     kernel_util::kArchArm));
}

TEST(KernelUtilTest, ComputeKernelStackSignatureARM64) {
  const char kBugToPanic[] =
      "<4>[  263.786327] Modules linked in:\n"
      "<4>[  263.841132] CPU: 2 PID: 1303 Comm: bash Not tainted 5.4.57 #355\n"
      "<4>[  263.847229] Hardware name: Google Lazor (rev1, rev3+) (DT)\n"
      "<4>[  263.852883] pstate: 60400009 (nZCv daif +PAN -UAO)\n"
      "<4>[  263.857834] pc : lkdtm_BUG+0xc/0x10\n"
      "<4>[  263.861436] lr : lkdtm_do_action+0x24/0x40\n"
      "<4>[  263.865662] sp : ffffff80b2b47c60\n"
      "<4>[  263.869086] x29: ffffff80b2b47c60 x28: ffffff80c29799c0\n"
      "<4>[  263.874558] x27: 0000000000000000 x26: 0000000000000000\n"
      "<4>[  263.880031] x25: 0000000044000000 x24: ffffffd05a0af040\n"
      "<4>[  263.885501] x23: 0000000000000010 x22: ffffffd05a3c41ce\n"
      "<4>[  263.890968] x21: ffffffd05a0af050 x20: ffffff80b2b47df0\n"
      "<4>[  263.896439] x19: ffffffd05a0af050 x18: ffffffd05ae33000\n"
      "<4>[  263.901916] x17: 0000000000008000 x16: 00000000000000b0\n"
      "<4>[  263.907387] x15: ffffffd05abe1e08 x14: 0000000000000001\n"
      "<4>[  263.912860] x13: 0000000000000000 x12: 0000000000000000\n"
      "<4>[  263.918327] x11: 0000000000000000 x10: dfffffd000000001\n"
      "<4>[  263.923794] x9 : a1be91ac2dd38f00 x8 : ffffffd059af1cdc\n"
      "<4>[  263.929270] x7 : ffffffd0595712e4 x6 : 0000000000000000\n"
      "<4>[  263.934736] x5 : 0000000000000080 x4 : 0000000000000001\n"
      "<4>[  263.940204] x3 : ffffffd059911eb8 x2 : 0000000000000001\n"
      "<4>[  263.945678] x1 : 0000000000000008 x0 : ffffffd05a0af050\n"
      "<4>[  263.951156] Call trace:\n"
      "<4>[  263.953694]  lkdtm_BUG+0xc/0x10\n"
      "<4>[  263.956936]  lkdtm_do_action+0x24/0x40\n"
      "<4>[  263.960805]  direct_entry+0x16c/0x1b4\n"
      "<4>[  263.964590]  full_proxy_write+0x6c/0xa8\n"
      "<4>[  263.968555]  __vfs_write+0x54/0x1a0\n"
      "<4>[  263.972153]  vfs_write+0xe4/0x1a4\n"
      "<4>[  263.975573]  ksys_write+0x84/0xec\n"
      "<4>[  263.978992]  __arm64_sys_write+0x20/0x2c\n"
      "<4>[  263.983045]  el0_svc_common+0xa8/0x178\n"
      "<4>[  263.986910]  el0_svc_compat_handler+0x2c/0x40\n"
      "<4>[  263.991403]  el0_svc_compat+0x8/0x10\n"
      "<0>[  263.995097] Code: 97e80634 a9bf7bfd 910003fd d503201f (d4210000)\n"
      "<4>[  264.001374] ---[ end trace 46a2784a72b8824d ]---\n";

  EXPECT_EQ("kernel-lkdtm_BUG-1E904F37",
            kernel_util::ComputeKernelStackSignature(kBugToPanic,
                                                     kernel_util::kArchArm));
}

TEST(KernelUtilTest, ComputeKernelStackSignatureMIPS) {
  const char kBugToPanic[] =
      "<5>[ 3378.472000] lkdtm: Performing direct entry BUG\n"
      "<5>[ 3378.476000] Kernel bug detected[#1]:\n"
      "<5>[ 3378.484000] CPU: 0 PID: 185 Comm: dash Not tainted 3.14.0 #1\n"
      "<5>[ 3378.488000] task: 8fed5220 ti: 8ec4a000 task.ti: 8ec4a000\n"
      "<5>[ 3378.496000] $ 0   : 00000000 804018b8 804010f0 7785b507\n"
      "<5>[ 3378.500000] $ 4   : 8061ab64 81204478 81205b20 00000000\n"
      "<5>[ 3378.508000] $ 8   : 80830000 20746365 72746e65 55422079\n"
      "<5>[ 3378.512000] $12   : 8ec4be94 000000fc 00000000 00000048\n"
      "<5>[ 3378.520000] $16   : 00000004 8ef54000 80710000 00000002\n"
      "<5>[ 3378.528000] $20   : 7765b6d4 00000004 7fffffff 00000002\n"
      "<5>[ 3378.532000] $24   : 00000001 803dc0dc                  \n"
      "<5>[ 3378.540000] $28   : 8ec4a000 8ec4be20 7775438d 804018b8\n"
      "<5>[ 3378.544000] Hi    : 00000000\n"
      "<5>[ 3378.548000] Lo    : 49bf8080\n"
      "<5>[ 3378.552000] epc   : 804010f0 lkdtm_do_action+0x68/0x3f8\n"
      "<5>[ 3378.560000]     Not tainted\n"
      "<5>[ 3378.564000] ra    : 804018b8 direct_entry+0x110/0x154\n"
      "<5>[ 3378.568000] Status: 3100dc03 KERNEL EXL IE \n"
      "<5>[ 3378.572000] Cause : 10800024\n"
      "<5>[ 3378.576000] PrId  : 0001a120 (MIPS interAptiv (multi))\n"
      "<5>[ 3378.580000] Modules linked in: uinput cfg80211 nf_conntrack_ipv6 "
      "nf_defrag_ipv6 ip6table_filter ip6_tables pcnet32 mii fuse "
      "ppp_async ppp_generic slhc tun\n"
      "<5>[ 3378.600000] Process dash (pid: 185, threadinfo=8ec4a000, "
      "task=8fed5220, tls=77632490)\n"
      "<5>[ 3378.608000] Stack : 00000006 ffffff9c 00000000 00000000 00000000 "
      "00000000 8083454a 00000022\n"
      "<5>          7765baa1 00001fee 80710000 8ef54000 8ec4bf08 00000002 "
      "7765b6d4 00000004\n"
      "<5>          7fffffff 00000002 7775438d 805e5158 7fffffff 00000002 "
      "00000000 7785b507\n"
      "<5>          806a96bc 00000004 8ef54000 8ec4bf08 00000002 804018b8 "
      "80710000 806a98bc\n"
      "<5>          00000002 00000020 00000004 8d515600 77756450 00000004 "
      "8ec4bf08 802377e4\n"
      "<5>          ...\n"
      "<5>[ 3378.652000] Call Trace:\n"
      "<5>[ 3378.656000] [<804010f0>] lkdtm_do_action+0x68/0x3f8\n"
      "<5>[ 3378.660000] [<804018b8>] direct_entry+0x110/0x154\n"
      "<5>[ 3378.664000] [<802377e4>] vfs_write+0xe0/0x1bc\n"
      "<5>[ 3378.672000] [<80237f90>] SyS_write+0x78/0xf8\n"
      "<5>[ 3378.676000] [<80111888>] handle_sys+0x128/0x14c\n"
      "<5>[ 3378.680000] \n"
      "<5>[ 3378.684000] \n"
      "<5>Code: 3c04806b  0c1793aa  248494f0 <000c000d> 3c04806b  248494fc  "
      "0c04cc7f  2405017a  08100514 \n"
      "<5>[ 3378.696000] ---[ end trace 75067432f24bbc93 ]---\n";

  EXPECT_EQ("kernel-lkdtm_do_action-5E600A6B",
            kernel_util::ComputeKernelStackSignature(kBugToPanic,
                                                     kernel_util::kArchMips));
}

TEST(KernelUtilTest, ComputeKernelStackSignatureX86) {
  const char kBugToPanic[] =
      "<4>[ 6066.829029]  [<79039d16>] ? run_timer_softirq+0x165/0x1e6\n"
      "<4>[ 6066.829029]  [<790340af>] ignore_old_stack+0xa6/0x143\n"
      "<0>[ 6066.829029] EIP: [<b82d7c15>] ieee80211_stop_tx_ba_session+"
      "0xa3/0xb5 [mac80211] SS:ESP 0068:7951febc\n"
      "<0>[ 6066.829029] CR2: 00000000323038a7\n"
      "<4>[ 6066.845422] ---[ end trace 12b058bb46c43500 ]---\n"
      "<0>[ 6066.845747] Kernel panic - not syncing: Fatal exception "
      "in interrupt\n"
      "<0>[ 6066.846902] Call Trace:\n"
      "<4>[ 6066.846902]  [<7937a07b>] ? printk+0x14/0x19\n"
      "<4>[ 6066.949779]  [<79379fc1>] panic+0x3e/0xe4\n"
      "<4>[ 6066.949971]  [<7937c5c5>] oops_end+0x73/0x81\n"
      "<4>[ 6066.950208]  [<7901b260>] no_context+0x10d/0x117\n";

  const kernel_util::ArchKind arch = kernel_util::kArchX86;
  EXPECT_EQ("kernel-ieee80211_stop_tx_ba_session-DE253569",
            kernel_util::ComputeKernelStackSignature(kBugToPanic, arch));

  const char kPCButNoStack[] =
      "<0>[ 6066.829029] EIP: [<b82d7c15>] ieee80211_stop_tx_ba_session+";
  EXPECT_EQ("kernel-ieee80211_stop_tx_ba_session-00000000",
            kernel_util::ComputeKernelStackSignature(kPCButNoStack, arch));

  const char kBreakmeBug[] =
      "<4>[  180.492137]  [<790970c6>] ? handle_mm_fault+0x67f/0x96d\n"
      "<4>[  180.492137]  [<790dcdfe>] ? proc_reg_write+0x5f/0x73\n"
      "<4>[  180.492137]  [<790e2224>] ? write_breakme+0x0/0x108\n"
      "<4>[  180.492137]  [<790dcd9f>] ? proc_reg_write+0x0/0x73\n"
      "<4>[  180.492137]  [<790ac0aa>] vfs_write+0x85/0xe4\n"
      "<0>[  180.492137] Code: c6 44 05 b2 00 89 d8 e8 0c ef 09 00 85 c0 75 "
      "0b c7 00 00 00 00 00 e9 8e 00 00 00 ba e6 75 4b 79 89 d8 e8 f1 ee 09 "
      "00 85 c0 75 04 <0f> 0b eb fe ba 58 47 49 79 89 d8 e8 dd ee 09 00 85 "
      "c0 75 0a 68\n"
      "<0>[  180.492137] EIP: [<790e22a4>] write_breakme+0x80/0x108 SS:ESP "
      "0068:aa3e9efc\n"
      "<4>[  180.501800] ---[ end trace 2a6b72965e1b1523 ]---\n"
      "<0>[  180.502026] Kernel panic - not syncing: Fatal exception\n"
      "<4>[  180.502026] Call Trace:\n"
      "<4>[  180.502806]  [<79379aba>] ? printk+0x14/0x1a\n"
      "<4>[  180.503033]  [<79379a00>] panic+0x3e/0xe4\n"
      "<4>[  180.503287]  [<7937c005>] oops_end+0x73/0x81\n"
      "<4>[  180.503520]  [<790055dd>] die+0x58/0x5e\n"
      "<4>[  180.503538]  [<7937b96c>] do_trap+0x8e/0xa7\n"
      "<4>[  180.503555]  [<79003d70>] ? do_invalid_op+0x0/0x80\n";
  EXPECT_EQ("kernel-write_breakme-122AB3CD",
            kernel_util::ComputeKernelStackSignature(kBreakmeBug, arch));

  const char kPCLineTooOld[] =
      "<4>[  174.492137]  [<790970c6>] ignored_function+0x67f/0x96d\n"
      "<4>[  175.492137]  [<790970c6>] ignored_function2+0x67f/0x96d\n"
      "<0>[  174.492137] EIP: [<790e22a4>] write_breakme+0x80/0x108 SS:ESP "
      "0068:aa3e9efc\n"
      "<4>[  180.501800] ---[ end trace 2a6b72965e1b1523 ]---\n"
      "<4>[  180.502026] Call Trace:\n"
      "<0>[  180.502026] Kernel panic - not syncing: Fatal exception\n"
      "<4>[  180.502806]  [<79379aba>] printk+0x14/0x1a\n";
  EXPECT_EQ("kernel-Fatal exception-ED4C84FE",
            kernel_util::ComputeKernelStackSignature(kPCLineTooOld, arch));

  // Panic without EIP line.
  const char kExamplePanicOnly[] =
      "<0>[   87.485611] Kernel panic - not syncing: Testing panic\n"
      "<4>[   87.485630] Pid: 2825, comm: bash Tainted: G         "
      "C 2.6.32.23+drm33.10 #1\n"
      "<4>[   87.485639] Call Trace:\n"
      "<4>[   87.485660]  [<8133f71d>] ? printk+0x14/0x17\n"
      "<4>[   87.485674]  [<8133f663>] panic+0x3e/0xe4\n"
      "<4>[   87.485689]  [<810d062e>] write_breakme+0xaa/0x124\n";
  EXPECT_EQ("kernel-Testing panic-E0FC3552",
            kernel_util::ComputeKernelStackSignature(kExamplePanicOnly, arch));

  // Panic from hung task.
  const char kHungTaskBreakMe[] =
      "<3>[  720.459157] INFO: task bash:2287 blocked blah blah\n"
      "<5>[  720.459282] Call Trace:\n"
      "<5>[  720.459307]  [<810a457b>] ? __dentry_open+0x186/0x23e\n"
      "<5>[  720.459323]  [<810b9c71>] ? mntput_no_expire+0x29/0xe2\n"
      "<5>[  720.459336]  [<810b9d48>] ? mntput+0x1e/0x20\n"
      "<5>[  720.459350]  [<810ad135>] ? path_put+0x1a/0x1d\n"
      "<5>[  720.459366]  [<8137cacc>] schedule+0x4d/0x4f\n"
      "<5>[  720.459379]  [<8137ccfb>] schedule_timeout+0x26/0xaf\n"
      "<5>[  720.459394]  [<8102127e>] ? should_resched+0xd/0x27\n"
      "<5>[  720.459409]  [<81174d1f>] ? _copy_from_user+0x3c/0x50\n"
      "<5>[  720.459423]  [<8137cd9e>] "
      "schedule_timeout_uninterruptible+0x1a/0x1c\n"
      "<5>[  720.459438]  [<810dee63>] write_breakme+0xb3/0x178\n"
      "<5>[  720.459453]  [<810dedb0>] ? meminfo_proc_show+0x2f2/0x2f2\n"
      "<5>[  720.459467]  [<810d94ae>] proc_reg_write+0x6d/0x87\n"
      "<5>[  720.459481]  [<810d9441>] ? proc_reg_poll+0x76/0x76\n"
      "<5>[  720.459493]  [<810a5e9e>] vfs_write+0x79/0xa5\n"
      "<5>[  720.459505]  [<810a6011>] sys_write+0x40/0x65\n"
      "<5>[  720.459519]  [<8137e677>] sysenter_do_call+0x12/0x26\n"
      "<0>[  720.459530] Kernel panic - not syncing: hung_task: blocked tasks\n"
      "<5>[  720.459768] Pid: 31, comm: khungtaskd Tainted: "
      "G         C  3.0.8 #1\n"
      "<5>[  720.459998] Call Trace:\n"
      "<5>[  720.460140]  [<81378a35>] panic+0x53/0x14a\n"
      "<5>[  720.460312]  [<8105f875>] watchdog+0x15b/0x1a0\n"
      "<5>[  720.460495]  [<8105f71a>] ? hung_task_panic+0x16/0x16\n"
      "<5>[  720.460693]  [<81043af3>] kthread+0x67/0x6c\n"
      "<5>[  720.460862]  [<81043a8c>] ? __init_kthread_worker+0x2d/0x2d\n"
      "<5>[  720.461106]  [<8137eb9e>] kernel_thread_helper+0x6/0x10\n";
  EXPECT_EQ("kernel-(HANG)-hung_task: blocked tasks-600B37EA",
            kernel_util::ComputeKernelStackSignature(kHungTaskBreakMe, arch));

  // Panic with all question marks in the last stack trace.
  const char kUncertainStackTrace[] =
      "<0>[56279.689669] ------------[ cut here ]------------\n"
      "<2>[56279.689677] kernel BUG at /build/x86-alex/tmp/portage/"
      "sys-kernel/chromeos-kernel-0.0.1-r516/work/chromeos-kernel-0.0.1/"
      "kernel/timer.c:844!\n"
      "<0>[56279.689683] invalid opcode: 0000 [#1] SMP \n"
      "<0>[56279.689688] last sysfs file: /sys/power/state\n"
      "<5>[56279.689692] Modules linked in: nls_iso8859_1 nls_cp437 vfat fat "
      "gobi usbnet tsl2583(C) industrialio(C) snd_hda_codec_realtek "
      "snd_hda_intel i2c_dev snd_hda_codec snd_hwdep qcserial snd_pcm usb_wwan "
      "i2c_i801 snd_timer nm10_gpio snd_page_alloc rtc_cmos fuse "
      "nf_conntrack_ipv6 nf_defrag_ipv6 uvcvideo videodev ip6table_filter "
      "ath9k ip6_tables ipv6 mac80211 ath9k_common ath9k_hw ath cfg80211 "
      "xt_mark\n"
      "<5>[56279.689731] \n"
      "<5>[56279.689738] Pid: 24607, comm: powerd_suspend Tainted: G        "
      "WC  2.6.38.3+ #1 SAMSUNG ELECTRONICS CO., LTD. Alex/G100          \n"
      "<5>[56279.689748] EIP: 0060:[<8103e3ea>] EFLAGS: 00210286 CPU: 3\n"
      "<5>[56279.689758] EIP is at add_timer+0xd/0x1b\n"
      "<5>[56279.689762] EAX: f5e00684 EBX: f5e003c0 ECX: 00000002 EDX: "
      "00200246\n"
      "<5>[56279.689767] ESI: f5e003c0 EDI: d28bc03c EBP: d2be5e40 ESP: "
      "d2be5e40\n"
      "<5>[56279.689772]  DS: 007b ES: 007b FS: 00d8 GS: 00e0 SS: 0068\n"
      "<0>[56279.689778] Process powerd_suspend (pid: 24607, ti=d2be4000 "
      "task=f5dc9b60 task.ti=d2be4000)\n"
      "<0>[56279.689782] Stack:\n"
      "<5>[56279.689785]  d2be5e4c f8dccced f4ac02c0 d2be5e70 f8ddc752 "
      "f5e003c0 f4ac0458 f4ac092c\n"
      "<5>[56279.689797]  f4ac043c f4ac02c0 f4ac0000 f4ac007c d2be5e7c "
      "f8dd4a33 f4ac0164 d2be5e94\n"
      "<5>[56279.689809]  f87e0304 f69ff0cc f4ac0164 f87e02a4 f4ac0164 "
      "d2be5eb0 81248968 00000000\n"
      "<0>[56279.689821] Call Trace:\n"
      "<5>[56279.689840]  [<f8dccced>] ieee80211_sta_restart+0x25/0x8c "
      "[mac80211]\n"
      "<5>[56279.689854]  [<f8ddc752>] ieee80211_reconfig+0x2e9/0x339 "
      "[mac80211]\n"
      "<5>[56279.689869]  [<f8dd4a33>] ieee80211_aes_cmac+0x182d/0x184e "
      "[mac80211]\n"
      "<5>[56279.689883]  [<f87e0304>] cfg80211_get_dev_from_info+0x29b/0x2c0 "
      "[cfg80211]\n"
      "<5>[56279.689895]  [<f87e02a4>] ? "
      "cfg80211_get_dev_from_info+0x23b/0x2c0 [cfg80211]\n"
      "<5>[56279.689904]  [<81248968>] legacy_resume+0x25/0x5d\n"
      "<5>[56279.689910]  [<812490ae>] device_resume+0xdd/0x110\n"
      "<5>[56279.689917]  [<812491c2>] dpm_resume_end+0xe1/0x271\n"
      "<5>[56279.689925]  [<81060481>] suspend_devices_and_enter+0x18b/0x1de\n"
      "<5>[56279.689932]  [<810605ba>] enter_state+0xe6/0x132\n"
      "<5>[56279.689939]  [<8105fd4b>] state_store+0x91/0x9d\n"
      "<5>[56279.689945]  [<8105fcba>] ? state_store+0x0/0x9d\n"
      "<5>[56279.689953]  [<81178fb1>] kobj_attr_store+0x16/0x22\n"
      "<5>[56279.689961]  [<810eea5e>] sysfs_write_file+0xc1/0xec\n"
      "<5>[56279.689969]  [<810af443>] vfs_write+0x8f/0x101\n"
      "<5>[56279.689975]  [<810ee99d>] ? sysfs_write_file+0x0/0xec\n"
      "<5>[56279.689982]  [<810af556>] sys_write+0x40/0x65\n"
      "<5>[56279.689989]  [<81002d57>] sysenter_do_call+0x12/0x26\n"
      "<0>[56279.689993] Code: c1 d3 e2 4a 89 55 f4 f7 d2 21 f2 6a 00 31 c9 89 "
      "d8 e8 6e fd ff ff 5a 8d 65 f8 5b 5e 5d c3 55 89 e5 3e 8d 74 26 00 83 38 "
      "00 74 04 <0f> 0b eb fe 8b 50 08 e8 6f ff ff ff 5d c3 55 89 e5 3e 8d 74 "
      "26 \n"
      "<0>[56279.690009] EIP: [<8103e3ea>] add_timer+0xd/0x1b SS:ESP "
      "0068:d2be5e40\n"
      "<4>[56279.690113] ---[ end trace b71141bb67c6032a ]---\n"
      "<7>[56279.694069] wlan0: deauthenticated from 00:00:00:00:00:01 "
      "(Reason: 6)\n"
      "<0>[56279.703465] Kernel panic - not syncing: Fatal exception\n"
      "<5>[56279.703471] Pid: 24607, comm: powerd_suspend Tainted: G      D "
      "WC  2.6.38.3+ #1\n"
      "<5>[56279.703475] Call Trace:\n"
      "<5>[56279.703483]  [<8136648c>] ? panic+0x55/0x152\n"
      "<5>[56279.703491]  [<810057fa>] ? oops_end+0x73/0x81\n"
      "<5>[56279.703497]  [<81005a44>] ? die+0xed/0xf5\n"
      "<5>[56279.703503]  [<810033cb>] ? do_trap+0x7a/0x80\n"
      "<5>[56279.703509]  [<8100369b>] ? do_invalid_op+0x0/0x80\n"
      "<5>[56279.703515]  [<81003711>] ? do_invalid_op+0x76/0x80\n"
      "<5>[56279.703522]  [<8103e3ea>] ? add_timer+0xd/0x1b\n"
      "<5>[56279.703529]  [<81025e23>] ? check_preempt_curr+0x2e/0x69\n"
      "<5>[56279.703536]  [<8102ef28>] ? ttwu_post_activation+0x5a/0x11b\n"
      "<5>[56279.703543]  [<8102fa8d>] ? try_to_wake_up+0x213/0x21d\n"
      "<5>[56279.703550]  [<81368b7f>] ? error_code+0x67/0x6c\n"
      "<5>[56279.703557]  [<8103e3ea>] ? add_timer+0xd/0x1b\n"
      "<5>[56279.703577]  [<f8dccced>] ? ieee80211_sta_restart+0x25/0x8c "
      "[mac80211]\n"
      "<5>[56279.703591]  [<f8ddc752>] ? ieee80211_reconfig+0x2e9/0x339 "
      "[mac80211]\n"
      "<5>[56279.703605]  [<f8dd4a33>] ? ieee80211_aes_cmac+0x182d/0x184e "
      "[mac80211]\n"
      "<5>[56279.703618]  [<f87e0304>] ? "
      "cfg80211_get_dev_from_info+0x29b/0x2c0 [cfg80211]\n"
      "<5>[56279.703630]  [<f87e02a4>] ? "
      "cfg80211_get_dev_from_info+0x23b/0x2c0 [cfg80211]\n"
      "<5>[56279.703637]  [<81248968>] ? legacy_resume+0x25/0x5d\n"
      "<5>[56279.703643]  [<812490ae>] ? device_resume+0xdd/0x110\n"
      "<5>[56279.703649]  [<812491c2>] ? dpm_resume_end+0xe1/0x271\n"
      "<5>[56279.703657]  [<81060481>] ? "
      "suspend_devices_and_enter+0x18b/0x1de\n"
      "<5>[56279.703663]  [<810605ba>] ? enter_state+0xe6/0x132\n"
      "<5>[56279.703670]  [<8105fd4b>] ? state_store+0x91/0x9d\n"
      "<5>[56279.703676]  [<8105fcba>] ? state_store+0x0/0x9d\n"
      "<5>[56279.703683]  [<81178fb1>] ? kobj_attr_store+0x16/0x22\n"
      "<5>[56279.703690]  [<810eea5e>] ? sysfs_write_file+0xc1/0xec\n"
      "<5>[56279.703697]  [<810af443>] ? vfs_write+0x8f/0x101\n"
      "<5>[56279.703703]  [<810ee99d>] ? sysfs_write_file+0x0/0xec\n"
      "<5>[56279.703709]  [<810af556>] ? sys_write+0x40/0x65\n"
      "<5>[56279.703716]  [<81002d57>] ? sysenter_do_call+0x12/0x26\n";
  // The first trace contains only uncertain entries and its hash is 00000000,
  // so, if we used that, the signature would be kernel-add_timer-00000000.
  // Instead we use the second-to-last trace for the hash.
  EXPECT_EQ(
      "kernel-add_timer-B5178878",
      kernel_util::ComputeKernelStackSignature(kUncertainStackTrace, arch));
}

TEST(KernelUtilTest, ComputeKernelStackSignatureX86_64) {
  const kernel_util::ArchKind arch = kernel_util::kArchX86_64;
  const char kStackTraceWithRIP[] =
      "<6>[ 1504.062071] tpm_tis tpm_tis: command 0x65 (size 18) returned code "
      "0x0\n"
      "<6>[ 1504.489032] tpm_tis tpm_tis: command 0x1e (size 274) returned "
      "code 0x0\n"
      "<1>[ 1505.850798] BUG: unable to handle kernel NULL pointer dereference "
      "at 0000000000000008\n"
      "<1>[ 1505.850823] IP: [<ffffffff94fb0c27>] list_del_init+0x8/0x1b\n"
      "<5>[ 1505.850843] PGD 0\n"
      "<5>[ 1505.850854] Oops: 0002 [#1] SMP\n"
      "<0>[ 1505.853049] gsmi: Log Shutdown Reason 0x03\n"
      "<5>[ 1505.853059] Modules linked in: ip6t_REJECT rfcomm i2c_dev uinput "
      "zram(C) memconsole zsmalloc(C) snd_hda_codec_realtek snd_hda_codec_hdmi "
      "snd_hda_intel snd_hda_codec snd_hwdep snd_pcm snd_page_alloc fuse "
      "nf_conntrack_ipv6 nf_defrag_ipv6 ip6table_filter ip6_tables "
      "snd_seq_midi snd_seq_midi_event snd_rawmidi snd_seq snd_seq_device "
      "snd_timer r8169 ath9k_btcoex ath9k_common_btcoex ath9k_hw_btcoex ath "
      "mac80211 cfg80211 ath3k btusb btrtl btbcm btintel bluetooth\n"
      "<5>[ 1505.853231] CPU 1\n"
      "<5>[ 1505.853240] Pid: 2663, comm: quipper Tainted: G WC 3.8.11 #1\n"
      "<5>[ 1505.853254] RIP: 0010:[<ffffffff94fb0c27>] [<ffffffff94fb0c27>] "
      "list_del_init+0x8/0x1b\n"
      "<5>[ 1505.853272] RSP: 0000:ffff880171789dd8 EFLAGS: 00010293\n"
      "<5>[ 1505.853282] RAX: ffff880171789de8 RBX: ffff8801715e6b40 RCX: "
      "000000000000003c\n"
      "<5>[ 1505.853294] RDX: 0000000000000000 RSI: 0000000000000004 RDI: "
      "ffff8801715e6b40\n"
      "<5>[ 1505.853305] RBP: ffff880171789e20 R08: ffffffff956b7ba8 R09: "
      "0000000000000000\n"
      "<5>[ 1505.853317] R10: 0000000000000004 R11: 000000000000000f R12: "
      "ffff880171789de8\n"
      "<5>[ 1505.853329] R13: ffff8801715e6c80 R14: ffff880177c040d8 R15: "
      "ffff880171789f00\n"
      "<5>[ 1505.853341] FS: 00007fd0e720f740(0000) GS:ffff88017cb00000(0000) "
      "knlGS:0000000000000000\n"
      "<5>[ 1505.853353] CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033\n"
      "<5>[ 1505.853364] CR2: 0000000000000008 CR3: 000000016087c000 CR4: "
      "00000000000607e0\n"
      "<5>[ 1505.853375] DR0: 0000000000000000 DR1: 0000000000000000 DR2: "
      "0000000000000000\n"
      "<5>[ 1505.853386] DR3: 0000000000000000 DR6: 00000000ffff0ff0 DR7: "
      "0000000000000400\n"
      "<5>[ 1505.853398] Process quipper (pid: 2663, threadinfo "
      "ffff880171788000, task ffff880174dda580)\n"
      "<5>[ 1505.853409] Stack:\n"
      "<5>[ 1505.853416] ffff880171789e20 ffffffff94fb13c8 ffff8801715e6b40 "
      "ffff8801715e6c80\n"
      "<5>[ 1505.853440] 00000000fc9daf41 ffff880171789e30 ffff880175cfac60 "
      "ffff880171789e30\n"
      "<5>[ 1505.853463] ffff880174dda838 ffff880171789e60 ffffffff94fb36ea "
      "ffff880176bb3dc0\n"
      "<5>[ 1505.853487] Call Trace:\n"
      "<5>[ 1505.853498] [<ffffffff94fb13c8>] ? namespace_unlock+0x98/0x10e\n"
      "<5>[ 1505.853510] [<ffffffff94fb36ea>] put_mnt_ns+0x19d/0x1c4\n"
      "<5>[ 1505.853523] [<ffffffff94f0fb50>] free_nsproxy+0x1d/0x75\n"
      "<5>[ 1505.853535] [<ffffffff94f0fd5c>] "
      "switch_task_namespaces+0x47/0x4e\n"
      "<5>[ 1505.853547] [<ffffffff94f0fd73>] exit_task_namespaces+0x10/0x12\n"
      "<5>[ 1505.853561] [<ffffffff94ef54ea>] do_exit+0x74b/0x8f7\n"
      "<5>[ 1505.853573] [<ffffffff94e84a98>] ? "
      "__percpu_counter_add+0x46/0x51\n"
      "<5>[ 1505.853587] [<ffffffff94f8a0de>] ? do_munmap+0x353/0x364\n"
      "<5>[ 1505.853599] [<ffffffff94ef57fb>] do_group_exit+0x42/0xb0\n"
      "<5>[ 1505.853611] [<ffffffff94ef587d>] sys_exit_group+0x14/0x14\n"
      "<5>[ 1505.853623] [<ffffffff95353928>] system_call_fastpath+0x16/0x1b\n"
      "<5>[ 1505.853633] Code: f1 be 00 00 40 00 48 89 e5 e8 fc fe ff ff 48 3d "
      "00 f0 ff ff 77 0b 48 c7 80 b0 00 00 00 ea ff ff ff 5d c3 48 8b 17 48 8b "
      "47 08 55 <48> 89 42 08 48 89 e5 48 89 10 48 89 3f 48 89 7f 08 5d c3 0f "
      "1f\n"
      "<1>[ 1505.853861] RIP [<ffffffff94fb0c27>] list_del_init+0x8/0x1b\n"
      "<5>[ 1505.853877] RSP <ffff880171789dd8>\n"
      "<5>[ 1505.853885] CR2: 0000000000000008\n"
      "<4>[ 1505.853914] ---[ end trace 6559e9c0a9497905 ]---\n"
      "<0>[ 1505.861341] Kernel panic - not syncing: Fatal exception\n"
      "<0>[ 1505.861358] Kernel Offset: 0x13e00000 from 0xffffffff81000000 "
      "(relocation range: 0xffffffff80000000-0xffffffffbfffffff)\n"
      "<0>[ 1505.861462] gsmi: Log Shutdown Reason 0x02\n"
      "";

  EXPECT_EQ("kernel-list_del_init-590B9789",
            kernel_util::ComputeKernelStackSignature(kStackTraceWithRIP, arch));

  // Panic without function name in RIP line
  const char kExamplePanicRIPAddressOnly[] =
      "<0>[   21.097918] Kernel panic - not syncing: dumptest\n"
      "<4>[   21.097928] CPU: 6 PID: 3006 Comm: bash Not tainted "
      "4.19.113-08544-ge67503bc40df #1\n"
      "<4>[   21.097934] Hardware name: Google Akemi/Akemi, BIOS "
      "Google_Akemi.12672.104.0 02/21/2020\n"
      "<4>[   21.097938] Call Trace:\n"
      "<4>[   21.097956]  dump_stack+0x97/0xdb\n"
      "<4>[   21.097967]  panic+0x100/0x282\n"
      "<4>[   21.097980]  lkdtm_PANIC+0x17/0x17\n"
      "<4>[   21.097988]  direct_entry+0x107/0x113\n"
      "<4>[   21.097998]  full_proxy_write+0x4b/0x7d\n"
      "<4>[   21.098008]  __vfs_write+0x45/0x190\n"
      "<4>[   21.098018]  ? selinux_file_permission+0x7c/0x115\n"
      "<4>[   21.098027]  vfs_write+0xe5/0x195\n"
      "<4>[   21.098034]  ksys_write+0x75/0xce\n"
      "<4>[   21.098042]  do_syscall_64+0x54/0xde\n"
      "<4>[   21.098050]  entry_SYSCALL_64_after_hwframe+0x44/0xa9\n"
      "<4>[   21.098059] RIP: 0033:0x7c527e0982c4\n"
      "<4>[   21.098066] Code: 89 02 48 c7 c0 ff ff ff ff c3 66 2e 0f 1f 84 00 "
      "00 00 00 00 66 90 48 8d 05 c1 99 2c 00 8b 00 85 c0 75 2b b8 01 00 00 00 "
      "0f 05 <48> 3d 00 f0 ff ff 77 04 c3 0f 1f 00 48 8b 15 71 3b 2c 00 f7 d8 "
      "64\n"
      "<4>[   21.098073] RSP: 002b:00007ffe335470e8 EFLAGS: 00000246 ORIG_RAX: "
      "0000000000000001\n"
      "<4>[   21.098080] RAX: ffffffffffffffda RBX: 0000000000000006 RCX: "
      "00007c527e0982c4\n"
      "<4>[   21.098085] RDX: 0000000000000006 RSI: 0000576fc9514fd0 RDI: "
      "0000000000000001\n"
      "<4>[   21.098090] RBP: 00007ffe33547110 R08: 00007c527e358f80 R09: "
      "0000000000000005\n"
      "<4>[   21.098095] R10: 0000000000000073 R11: 0000000000000246 R12: "
      "0000576fc9514fd0\n"
      "<4>[   21.098100] R13: 00007c527e35d700 R14: 0000000000000006 R15: "
      "0000000000000006\n"
      "<0>[   21.098179] Kernel Offset: 0x2400000 from 0xffffffff81000000 "
      "(relocation range: 0xffffffff80000000-0xffffffffbfffffff)\n"
      "<0>[   21.100417] gsmi: Log Shutdown Reason 0x02\n";
  EXPECT_EQ("kernel-dumptest-E0489331",
            kernel_util::ComputeKernelStackSignature(
                kExamplePanicRIPAddressOnly, arch));

  // Bug to panic new RIP line
  const char kExampleBugToPanicNewRIP[] =
      "<1>[  913.688488] BUG: kernel NULL pointer dereference, address: "
      "0000000000000160\n"
      "<1>[  913.688496] #PF: supervisor read access in kernel mode\n"
      "<1>[  913.688500] #PF: error_code(0x0000) - not-present page\n"
      "<6>[  913.688504] PGD 0 P4D 0 \n"
      "<4>[  913.688511] Oops: 0000 [#1] PREEMPT SMP NOPTI\n"
      "<4>[  913.688516] CPU: 3 PID: 381 Comm: kworker/3:2 Not tainted "
      "5.4.57-07393-g3f0082cb2d20 #1\n"
      "<4>[  913.688519] Hardware name: LENOVO Morphius/Morphius, BIOS "
      "Google_Morphius.13360.0.0 07/19/2020\n"
      "<4>[  913.688529] Workqueue:  0x0 (events)\n"
      "<4>[  913.688538] RIP: 0010:pick_task_fair+0x55/0x77\n"
      "<4>[  913.688543] Code: ff 49 89 c6 4d 85 ff 74 21 4d 85 f6 74 19 41 83 "
      "7f 40 00 74 08 48 89 df e8 05 b9 ff ff 49 8b 47 58 49 3b 46 58 79 03 4d "
      "89 fe <49> 8b 9e 60 01 00 00 48 85 db 75 bd 49 81 c6 40 ff ff ff eb 03 "
      "45\n"
      "<4>[  913.688547] RSP: 0018:ffffa94a8043bdd8 EFLAGS: 00010046\n"
      "<4>[  913.688551] RAX: 0000000000000000 RBX: ffffa2fba6193e00 RCX: "
      "0000000000024580\n"
      "<4>[  913.688554] RDX: 0000000000000003 RSI: 0000000000000000 RDI: "
      "ffffa2fba6193e00\n"
      "<4>[  913.688558] RBP: ffffa94a8043bdf0 R08: 000000d4bc9f6f47 R09: "
      "0000000000000002\n"
      "<4>[  913.688561] R10: 0000000000000000 R11: ffffffff908d8c6d R12: "
      "0000000000000000\n"
      "<4>[  913.688564] R13: 0000000000000003 R14: 0000000000000000 R15: "
      "0000000000000000\n"
      "<4>[  913.688568] FS:  0000000000000000(0000) GS:ffffa2fbdeec0000(0000) "
      "knlGS:0000000000000000\n"
      "<4>[  913.688571] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033\n"
      "<4>[  913.688574] CR2: 00000000000000c8 CR3: 00000003c5374000 CR4: "
      "00000000003406e0\n"
      "<4>[  913.688577] Call Trace:\n"
      "<4>[  913.688587]  __schedule+0x83f/0xf92\n"
      "<4>[  913.688594]  schedule+0x75/0x99\n"
      "<4>[  913.688599]  worker_thread+0x2c4/0x375\n"
      "<4>[  913.688605]  kthread+0x138/0x140\n"
      "<4>[  913.688610]  ? pr_cont_work+0x58/0x58\n"
      "<4>[  913.688615]  ? kthread_blkcg+0x2e/0x2e\n"
      "<4>[  913.688619]  ret_from_fork+0x22/0x40\n"
      "<4>[  913.688623] Modules linked in: bridge stp llc veth tun "
      "nf_nat_tftp nf_conntrack_tftp nf_nat_ftp nf_conntrack_ftp esp6 ah6 "
      "ip6t_ipv6header rfcomm cmac algif_hash algif_skcipher af_alg uinput ccm "
      "kvm_amd ccp snd_acp3x_i2s snd_acp3x_pcm_dma ip6t_REJECT "
      "snd_hda_codec_hdmi snd_hda_intel snd_intel_dspcfg snd_hda_codec "
      "snd_hwdep snd_hda_core snd_pci_acp3x i2c_piix4 snd_soc_rt5682 "
      "snd_soc_cros_ec_codec snd_soc_rl6231 snd_soc_acp_rt5682_mach "
      "i2c_cros_ec_tunnel acpi_als snd_soc_max98357a xt_MASQUERADE fuse "
      "iio_trig_sysfs cros_ec_lid_angle cros_ec_sensors cros_ec_sensors_core "
      "cros_ec_sensors_ring industrialio_triggered_buffer kfifo_buf "
      "industrialio cros_ec_sensorhub btusb btrtl btintel btbcm bluetooth "
      "ecdh_generic ecc uvcvideo videobuf2_v4l2 videobuf2_common "
      "videobuf2_vmalloc videobuf2_memops iwlmvm lzo_rle lzo_compress zram "
      "iwl7000_mac80211 r8152 mii iwlwifi cfg80211 joydev\n"
      "<0>[  913.695114] gsmi: Log Shutdown Reason 0x03\n"
      "<4>[  913.695117] CR2: 0000000000000160\n"
      "<4>[  913.695121] ---[ end trace ab83d26c5b621e21 ]---\n"
      "<4>[  913.711109] RIP: 0010:pick_task_fair+0x55/0x77\n"
      "<4>[  913.711115] Code: ff 49 89 c6 4d 85 ff 74 21 4d 85 f6 74 19 41 83 "
      "7f 40 00 74 08 48 89 df e8 05 b9 ff ff 49 8b 47 58 49 3b 46 58 79 03 4d "
      "89 fe <49> 8b 9e 60 01 00 00 48 85 db 75 bd 49 81 c6 40 ff ff ff eb 03 "
      "45\n"
      "<4>[  913.711119] RSP: 0018:ffffa94a8043bdd8 EFLAGS: 00010046\n"
      "<4>[  913.711124] RAX: 0000000000000000 RBX: ffffa2fba6193e00 RCX: "
      "0000000000024580\n"
      "<4>[  913.711127] RDX: 0000000000000003 RSI: 0000000000000000 RDI: "
      "ffffa2fba6193e00\n"
      "<4>[  913.711131] RBP: ffffa94a8043bdf0 R08: 000000d4bc9f6f47 R09: "
      "0000000000000002\n"
      "<4>[  913.711134] R10: 0000000000000000 R11: ffffffff908d8c6d R12: "
      "0000000000000000\n"
      "<4>[  913.711137] R13: 0000000000000003 R14: 0000000000000000 R15: "
      "0000000000000000\n"
      "<4>[  913.711141] FS:  0000000000000000(0000) GS:ffffa2fbdeec0000(0000) "
      "knlGS:0000000000000000\n"
      "<4>[  913.711145] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033\n"
      "<4>[  913.711148] CR2: 00000000000000c8 CR3: 00000003c5374000 CR4: "
      "00000000003406e0\n"
      "<0>[  913.711152] Kernel panic - not syncing: Fatal exception\n"
      "<0>[  915.314269] Shutting down cpus with NMI\n"
      "<0>[  915.314314] Kernel Offset: 0xf800000 from 0xffffffff81000000 "
      "(relocation range: 0xffffffff80000000-0xffffffffbfffffff)\n"
      "<0>[  915.314553] gsmi: Log Shutdown Reason 0x02\n";
  EXPECT_EQ(
      "kernel-pick_task_fair-C3E38321",
      kernel_util::ComputeKernelStackSignature(kExampleBugToPanicNewRIP, arch));

  const char kStackTraceWithNewRIP[] =
      "<1>[ 2358.194168] BUG: kernel NULL pointer dereference, address: "
      "0000000000000160\n"
      "<1>[ 2358.194185] #PF: supervisor read access in kernel mode\n"
      "<1>[ 2358.194193] #PF: error_code(0x0000) - not-present page\n"
      "<6>[ 2358.194200] PGD 0 P4D 0\n"
      "<4>[ 2358.194215] Oops: 0000 [#1] PREEMPT SMP NOPTI\n"
      "<4>[ 2358.194226] CPU: 7 PID: 4983 Comm: ThreadPoolSingl Not tainted "
      "5.4.57-07393-g3f0082cb2d20 #1\n"
      "<4>[ 2358.194234] Hardware name: LENOVO Morphius/Morphius, BIOS "
      "Google_Morphius.13360.0.0 07/19/2020\n"
      "<4>[ 2358.194253] RIP: 0010:pick_task_fair+0x55/0x77\n"
      "<4>[ 2358.194263] Code: ff 49 89 c6 4d 85 ff 74 21 4d 85 f6 74 19 41 83 "
      "7f 40 00 74 08 48 89 df e8 05 b9 ff ff 49 8b 47 58 49 3b 46 58 79 03 4d "
      "89 fe <49> 8b 9e 60 01 00 00 48 85 db 75 bd 49 81 c6 40 ff ff ff eb 03 "
      "45\n"
      "<4>[ 2358.194276] RSP: 0018:ffffb0a2c89efb78 EFLAGS: 00010046\n"
      "<4>[ 2358.194286] RAX: 0000000000000000 RBX: ffff9bff01790800 RCX: "
      "ffff9bff1efe4600\n"
      "<4>[ 2358.194293] RDX: 0000000000000007 RSI: 0000000000000000 RDI: "
      "ffff9bff01790800\n"
      "<4>[ 2358.194302] RBP: ffffb0a2c89efb90 R08: 000002250fea3371 R09: "
      "0000000000000004\n"
      "<4>[ 2358.194309] R10: 0000000000000000 R11: ffffffff8a2d8c6d R12: "
      "0000000000000000\n"
      "<4>[ 2358.194319] R13: 0000000000000007 R14: 0000000000000000 R15: "
      "0000000000000000\n"
      "<4>[ 2358.194329] FS: 00007c9ea7d79700(0000) GS:ffff9bff1efc0000(0000) "
      "knlGS:0000000000000000\n"
      "<4>[ 2358.194338] CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033\n"
      "<4>[ 2358.194345] CR2: 0000000000000160 CR3: 00000003277dc000 CR4: "
      "00000000003406e0\n"
      "<4>[ 2358.194352] Call Trace:\n"
      "<4>[ 2358.194379]  __schedule+0x83f/0xf92\n"
      "<4>[ 2358.194391]  ? __schedule+0x590/0xf92\n"
      "<4>[ 2358.194402]  schedule+0x75/0x99\n"
      "<4>[ 2358.194414]  futex_wait_queue_me+0xd4/0x132\n"
      "<4>[ 2358.194427]  futex_wait+0x115/0x245\n"
      "<4>[ 2358.194442]  do_futex+0x4d6/0x7aa\n"
      "<4>[ 2358.194452]  ? __vfs_write+0x198/0x1c5\n"
      "<4>[ 2358.194462]  ? cpuacct_charge+0x3a/0x71\n"
      "<4>[ 2358.194471]  __se_sys_futex+0x91/0x17c\n"
      "<4>[ 2358.194481]  do_syscall_64+0x54/0x7e\n"
      "<4>[ 2358.194490]  entry_SYSCALL_64_after_hwframe+0x44/0xa9\n"
      "<4>[ 2358.194499] RIP: 0033:0x7c9ebc748a47\n"
      "<4>[ 2358.194506] Code: 89 84 24 80 00 00 00 e8 57 32 00 00 e8 a2 36 00 "
      "00 "
      "44 89 ee 41 89 c0 45 31 d2 31 d2 40 80 f6 80 4c 89 e7 b8 ca 00 00 00 0f "
      "05 "
      "<48> 3d 00 f0 ff ff 0f 87 4d 01 00 00 44 89 c7 e8 d5 36 00 00 31 f6\n"
      "<4>[ 2358.194512] RSP: 002b:00007c9ea7d78660 EFLAGS: 00000282 ORIG_RAX: "
      "00000000000000ca\n"
      "<4>[ 2358.194519] RAX: ffffffffffffffda RBX: 00007c9ea7d78980 RCX: "
      "00007c9ebc748a47\n"
      "<4>[ 2358.194525] RDX: 0000000000000000 RSI: 0000000000000080 RDI: "
      "00007c9ea7d789a8\n"
      "<4>[ 2358.194530] RBP: 00007c9ea7d78730 R08: 0000000000000000 R09: "
      "00007c9ebb04c8d0\n"
      "<4>[ 2358.194535] R10: 0000000000000000 R11: 0000000000000282 R12: "
      "00007c9ea7d789a8\n"
      "<4>[ 2358.194541] R13: 0000000000000000 R14: 00007c9ea7d786b0 R15: "
      "0000000000000000\n"
      "<4>[ 2358.194548] Modules linked in:\n"
      "<0>[ 2358.201575] gsmi: Log Shutdown Reason 0x03\n"
      "<4>[ 2358.201578] CR2: 0000000000000160 \n"
      "";

  EXPECT_EQ(
      "kernel-pick_task_fair-54582FE9",
      kernel_util::ComputeKernelStackSignature(kStackTraceWithNewRIP, arch));
}

TEST(KernelUtilTest, ComputeNoCErrorSignature) {
  const char kNoCError[] =
      "QTISECLIB [1727120e379]MMSS_NOC ERROR: ERRLOG0_LOW = 0x00000105\n"
      "QTISECLIB [1727120e445]MMSS_NOC ERROR: ERRLOG0_HIGH = 0x0000007f\n"
      "QTISECLIB [1727120e49c]MMSS_NOC ERROR: ERRLOG1_LOW = 0x00000019\n"
      "QTISECLIB [1727120e4fa]MMSS_NOC ERROR: ERRLOG1_HIGH = 0x00007300\n"
      "QTISECLIB [1727120e580]MMSS_NOC ERROR: ERRLOG3_LOW = 0x00004008\n"
      "QTISECLIB [1727120e617]MMSS_NOC ERROR: SBM0 FAULTINSTATUS0_LOW = "
      "0x00000001\n"
      "QTISECLIB [17271210311]CONFIG_NOC ERROR: ERRLOG1_LOW = 0x00000003\n"
      "";

  EXPECT_EQ("kernel-(NOC-Error)-MMSS-2CBA847E",
            kernel_util::ComputeNoCErrorSignature(kNoCError));
}

TEST(KernelUtilTest, ComputeKernelStackSignatureCommonAllArches) {
  ComputeKernelStackSignatureCommon(kernel_util::kArchArm);
  ComputeKernelStackSignatureCommon(kernel_util::kArchMips);
  ComputeKernelStackSignatureCommon(kernel_util::kArchX86);
  ComputeKernelStackSignatureCommon(kernel_util::kArchX86_64);
}

TEST(KernelUtilTest, WatchdogSignature) {
  const char kConsoleRamoopsWithLongLastLine[] =
      "<6>[    0.000000] microcode: microcode updated early to revision 0xde, "
      "date = 2020-05-27\n"
      "<6>[    0.000000] Initializing cgroup subsys cpuset\n"
      "<6>[    0.000000] Initializing cgroup subsys cpu\n"
      "<6>[    0.000000] Initializing cgroup subsys cpuacct\n"
      "<5>[    0.000000] Linux version 4.4.252-19740-gcbe014496e37 "
      "(chrome-bot@chromeos-ci-legacy-us-central2-d-x32-38-i0v9) (Chromium OS "
      "12.0_pre408248_p20201125-r9 clang version 12.0.0 "
      "(/var/tmp/portage/sys-devel/llvm-12.0_pre408248_p20201125-r9/work/"
      "llvm-12.0_pre408248_p20201125/clang "
      "f402e682d0ef5598eeffc9a21a691b03e602ff58)) #1 SMP PREEMPT Mon Jan 25 "
      "17:58:05 PST 2021\n"
      "";

  const std::string kWatchdogRebootReason = "-(WATCHDOG)";

  EXPECT_EQ(
      "kernel-(WATCHDOG)-Linux version 4.4.252-19740-gcbe014496e3-082847C6",
      kernel_util::WatchdogSignature(kConsoleRamoopsWithLongLastLine,
                                     kWatchdogRebootReason));

  const char kConsoleRamoopsWithShortLastLine[] =
      "<6>[    0.000000] microcode: microcode updated early to revision 0xde, "
      "date = 2020-05-27\n"
      "<6>[    0.000000] Initializing cgroup subsys cpuset\n"
      "<6>[    0.000000] Initializing cgroup subsys cpu\n"
      "<6>[    0.000000] Initializing cgroup subsys cpuacct\n"
      "<5>[    0.000000] last line\n"
      "";

  EXPECT_EQ("kernel-(WATCHDOG)-last line-3D7C5AEC",
            kernel_util::WatchdogSignature(kConsoleRamoopsWithShortLastLine,
                                           kWatchdogRebootReason));

  const char kBrokenConsoleRamoops[] = "broken";
  EXPECT_EQ("kernel-(WATCHDOG)-broken-28348215",
            kernel_util::WatchdogSignature(kBrokenConsoleRamoops,
                                           kWatchdogRebootReason));
}

TEST(KernelUtilTest, IsHypervisor) {
  const char kHypervisorLog[] =
      "Panic#1 Part1\n"
      "<6>[    0.000000] microcode: microcode updated early to revision 0xa4, "
      "date = 2022-02-01\n"
      "<5>[    0.000000] Linux version 5.10.117-manatee (<redacted email"
      "address>) (Chromium OS 14.0_pre450784_p20220316-r22 clang version 14.0.0"
      " (/var/tmp/portage/sys-devel/llvm-14.0_pre450784_p20220316-r22/work/"
      "llvm-14.0_pre450784_p20220316/clang), LLD 14.0.0) #1 SMP Fri Jun 3 "
      "16:57:19 PDT 2022\n"
      "<6>[    0.000000] x86/split lock detection: warning about user-space "
      "split_locks\n"
      "<6>[    0.000000] x86/fpu: Supporting XSAVE feature 0x001: 'x87 "
      "floating point registers'\n"
      "";
  EXPECT_TRUE(kernel_util::IsHypervisorCrash(kHypervisorLog));

  const char kChromeOsLog[] =
      "Panic#1 Part1\n"
      "<5>[    0.000000] Linux version 5.10.119 (<redacted email address>) "
      "(Chromium OS 14.0_pre450784_p20220316-r22 clang version 14.0.0 "
      "(/var/tmp/portage/sys-devel/llvm-14.0_pre450784_p20220316-r22/work/"
      "llvm-14.0_pre450784_p20220316/clang), LLD 14.0.0) #1 SMP PREEMPT "
      "Fri Jun 10 12:46:22 PDT 2022\n"
      "<6>[    0.000000] x86/fpu: Supporting XSAVE feature 0x001: 'x87 "
      "floating point registers'\n"
      "<6>[    0.000000] x86/fpu: Supporting XSAVE feature 0x002: 'SSE "
      "registers'\n"
      "";
  EXPECT_FALSE(kernel_util::IsHypervisorCrash(kChromeOsLog));
}

TEST(KernelUtilTest, GetHypervisorLog) {
  const char kConsoleLog[] =
      "[15.468853] IPv6: ADDRCONF(NETDEV_CHANGE): arc_ns0: link becomes ready\n"
      "[15.469310] IPv6: ADDRCONF(NETDEV_CHANGE): veth0: link becomes ready\n"
      "[15.505797] IPv6: ADDRCONF(NETDEV_CHANGE): veth1: link becomes ready\n"
      "";
  const char kHypervisorLogHeader[] =
      "\n"
      "--------[ hypervisor log ]--------\n"
      "";
  const char kHypervisorLog[] =
      "[3.553454] vfio-pci-pm 0000:00:15.3: attach allowed to drvr vfio-pci-pm "
      "[internal device]\\n SUBSYSTEM=pci\\n DEVICE=+pci:0000:00:15.3\n"
      "[3.562705] vfio-pci-pm 0000:00:16.0: attach allowed to drvr vfio-pci-pm "
      "[internal device]\\n SUBSYSTEM=pci\\n DEVICE=+pci:0000:00:16.0\n"
      "[3.571948] vfio-pci-pm 0000:00:19.0: attach allowed to drvr vfio-pci-pm "
      "[internal device]\\n SUBSYSTEM=pci\\n DEVICE=+pci:0000:00:19.0\n"
      "[3.581197] vfio-pci-pm 0000:00:19.1: attach allowed to drvr vfio-pci-pm "
      "[internal device]\\n SUBSYSTEM=pci\\n DEVICE=+pci:0000:00:19.1\n"
      "";

  std::string extract;
  std::string logWithoutHypervisor(kConsoleLog);
  EXPECT_FALSE(
      kernel_util::ExtractHypervisorLog(logWithoutHypervisor, extract));
  EXPECT_EQ("", extract);
  EXPECT_EQ(kConsoleLog, logWithoutHypervisor);

  std::string logWithHypervisor(kConsoleLog);
  logWithHypervisor += kHypervisorLogHeader;
  logWithHypervisor += kHypervisorLog;
  EXPECT_TRUE(kernel_util::ExtractHypervisorLog(logWithHypervisor, extract));
  EXPECT_EQ(kHypervisorLog, extract);
  EXPECT_EQ(kConsoleLog, logWithHypervisor);
}
