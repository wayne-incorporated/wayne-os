// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SECAGENTD_BPF_BPF_UTILS_H_
#define SECAGENTD_BPF_BPF_UTILS_H_
#include "secagentd/bpf/bpf_types.h"

#define CROS_ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))
static inline __attribute__((always_inline)) bool is_kthread(
    const struct task_struct* t) {
  // From sched.h:
  // #define PF_KTHREAD  0x00200000
  return (BPF_CORE_READ(t, flags) & 0x00200000);
}

static inline __attribute__((always_inline)) const struct task_struct*
cros_normalize_to_last_exec(const struct task_struct* t) {
  const struct task_struct* ret = t;
  // Arbitrarily selected limit to convince the verifier that the BPF will
  // always halt.
  for (int i = 0; i < 64; ++i) {
    struct task_struct* parent = BPF_CORE_READ(ret, real_parent, group_leader);
    if ((!parent) || (BPF_CORE_READ(ret, self_exec_id) !=
                      BPF_CORE_READ(parent, self_exec_id))) {
      break;
    }
    ret = parent;
  }
  return ret;
}

static inline __attribute__((always_inline)) void cros_fill_task_info(
    struct cros_process_task_info* task_info, const struct task_struct* t) {
  const struct task_struct* parent =
      cros_normalize_to_last_exec(BPF_CORE_READ(t, real_parent, group_leader));
  task_info->ppid = BPF_CORE_READ(parent, tgid);
  task_info->parent_start_time = BPF_CORE_READ(parent, start_boottime);
  task_info->start_time = BPF_CORE_READ(t, group_leader, start_boottime);
  task_info->pid = BPF_CORE_READ(t, tgid);

  task_info->uid = BPF_CORE_READ(t, real_cred, uid.val);
  task_info->gid = BPF_CORE_READ(t, real_cred, gid.val);

  // Read argv from user memory.
  const uintptr_t arg_start = (uintptr_t)BPF_CORE_READ(t, mm, arg_start);
  const uintptr_t arg_end = (uintptr_t)BPF_CORE_READ(t, mm, arg_end);
  if ((arg_end - arg_start) > sizeof(task_info->commandline)) {
    task_info->commandline_len = sizeof(task_info->commandline);
  } else {
    task_info->commandline_len = (uint32_t)(arg_end - arg_start);
  }
  bpf_probe_read_user(task_info->commandline, task_info->commandline_len,
                      (const void*)arg_start);
  if (task_info->commandline_len == sizeof(task_info->commandline)) {
    task_info->commandline[task_info->commandline_len - 1] = '\0';
  }
}

#endif  // SECAGENTD_BPF_BPF_UTILS_H_
