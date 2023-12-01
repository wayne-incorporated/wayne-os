// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SECAGENTD_BPF_BPF_TYPES_H_
#define SECAGENTD_BPF_BPF_TYPES_H_

#ifdef __cplusplus
#include <stdint.h>
#include <sys/socket.h>
#define _Static_assert static_assert
namespace secagentd::bpf {
#else
// Kernels 5.10,5.15 won't have support for fentry/fexit
// hooks. Instead these kernels have downstream tracepoints
// defined and added to areas of interest within the kernel.
// NO_FUNCTION_HOOKS is defined by the BUILD file when a
// 5.15 or 5.10 kernel is detected and when that is the case
// then the NO substitution is used otherwise it is assumed the
// kernel supports fentry/fexit and so the YES substitution is used.
// In short, this allows different hooks to be used based on
// whether the kernel is expected to support fentry/fexit hooks
// or not.
#if defined(NO_FUNCTION_HOOKS) && NO_FUNCTION_HOOKS == 1
#define CROS_IF_FUNCTION_HOOK(YES, NO) SEC(NO)
#else
#define CROS_IF_FUNCTION_HOOK(YES, NO) SEC(YES)
#endif
#endif

// The max arg size set by limits.h is ~128KB. To avoid consuming an absurd
// amount of memory arguments will be truncated to 512 bytes. If all 512
// bytes are used the consuming userspace daemon will scrape procfs for the
// entire command line.
#define CROS_MAX_REDUCED_ARG_SIZE (512)

// Although the maximum path size defined in linux/limits.h is larger we
// truncate path sizes to keep memory usage reasonable. If needed the full path
// name can be regenerated from the inode in image_info.
#define CROS_MAX_PATH_SIZE (512)

// The size of the buffer allocated from the BPF ring buffer. The size must be
// large enough to hold the largest BPF event structure and must also be of
// 2^N size.
#define CROS_MAX_STRUCT_SIZE (2048)

#define CROS_MAX_SOCKET (1024)
#define CROS_AVG_CONN_PER_SOCKET (2)
#define CROS_MAX_FLOW_MAP_ENTRIES (CROS_MAX_SOCKET * CROS_AVG_CONN_PER_SOCKET)

#ifdef __cplusplus
constexpr uint32_t kMaxFlowMapEntries{CROS_MAX_FLOW_MAP_ENTRIES};
#endif
typedef uint64_t time_ns_t;

// TODO(b/243571230): all of these struct fields map to kernel types.
// Since including vmlinux.h directly in this file causes numerous compilation
// errors with a cpp compiler we must instead pick a standard type. There is a
// risk that the kernel types do not map well into these standard types for
// certain architectures; so add static asserts to make sure we detect this
// failure at compile time.

// Fixed width version of timespec.
struct cros_timespec {
  int64_t tv_sec;
  int64_t tv_nsec;
} __attribute__((aligned(8)));

// The image_info struct contains the security metrics
// of interest for an executable file.
struct cros_image_info {
  char pathname[CROS_MAX_PATH_SIZE];
  uint64_t mnt_ns;
  uint32_t inode_device_id;
  uint32_t inode;
  uint32_t uid;
  uint32_t gid;
  uint32_t pid_for_setns;
  uint16_t mode;
  struct cros_timespec mtime;
  struct cros_timespec ctime;
} __attribute__((aligned(8)));

// The namespace_info struct contains the namespace information for a process.
struct cros_namespace_info {
  uint64_t cgroup_ns;
  uint64_t pid_ns;
  uint64_t user_ns;
  uint64_t uts_ns;
  uint64_t mnt_ns;
  uint64_t net_ns;
  uint64_t ipc_ns;
} __attribute__((aligned(8)));

// This is the process information collected when a process starts or exits.
struct cros_process_task_info {
  uint32_t pid;                 // The tgid.
  uint32_t ppid;                // The tgid of parent.
  time_ns_t start_time;         // Nanoseconds since boot.
  time_ns_t parent_start_time;  // Nanoseconds since boot.
  char commandline[CROS_MAX_REDUCED_ARG_SIZE];
  uint32_t commandline_len;  // At most CROS_MAX_REDUCED_ARG_SIZE.
  uint32_t uid;
  uint32_t gid;
} __attribute__((aligned(8)));

// This is the process information collected when a process starts.
struct cros_process_start {
  struct cros_process_task_info task_info;
  struct cros_image_info image_info;
  struct cros_namespace_info spawn_namespace;
} __attribute__((aligned(8)));

// This is the process information collected when a process exits.
struct cros_process_exit {
  struct cros_process_task_info task_info;
  bool is_leaf;  // True if process has no children.
} __attribute__((aligned(8)));

struct cros_process_change_namespace {
  // PID and start_time together will form a unique identifier for a process.
  // This unique identifier can be used to retrieve the rest of the process
  // information from a userspace process cache.
  uint32_t pid;
  time_ns_t start_time;
  struct cros_namespace_info new_ns;  // The new namespace.
} __attribute__((aligned(8)));

// Indicates the type of process event is contained within the
// event structure.
enum cros_process_event_type {
  kProcessStartEvent,
  kProcessExitEvent,
  kProcessChangeNamespaceEvent
};

// Contains information needed to report process security
// event telemetry regarding processes.
struct cros_process_event {
  enum cros_process_event_type type;
  union {
    struct cros_process_start process_start;
    struct cros_process_exit process_exit;
    struct cros_process_change_namespace process_change_namespace;
  } data;
} __attribute__((aligned(8)));

// http://www.iana.org/assignments/protocol-numbers
#define CROS_IANA_HOPOPT (0)
#define CROS_IANA_ICMP (1)
#define CROS_IANA_TCP (6)
#define CROS_IANA_UDP (17)
#define CROS_IANA_ICMP6 (58)

enum cros_network_protocol {
  CROS_PROTOCOL_TCP = CROS_IANA_TCP,
  CROS_PROTOCOL_UDP = CROS_IANA_UDP,
  CROS_PROTOCOL_ICMP = CROS_IANA_ICMP,
  CROS_PROTOCOL_ICMP6 = CROS_IANA_ICMP6,
  CROS_PROTOCOL_RAW = 251,     // Unassigned IANA number. Not a protocol.
  CROS_PROTOCOL_UNKNOWN = 252  // Unassigned IANA number. Not a protocol.
};

// AF_INET, AF_INET6 are not found in vmlinux.h so use our own
// definition here.
// We only care about AF_INET and AF_INET6 (ipv4 and ipv6).
enum cros_network_family { CROS_FAMILY_AF_INET = 2, CROS_FAMILY_AF_INET6 = 10 };

#ifdef __cplusplus
// make sure that the values used for our definition of families matches
// the definition in the system header.
static_assert(CROS_FAMILY_AF_INET == AF_INET);
static_assert(CROS_FAMILY_AF_INET6 == AF_INET6);
#endif

enum cros_network_socket_direction {
  CROS_SOCKET_DIRECTION_IN,      // socket is a result of an accept.
  CROS_SOCKET_DIRECTION_OUT,     // socket had connect called on it.
  CROS_SOCKET_DIRECTION_UNKNOWN  // non-connection based socket.
};

struct cros_network_common {
  int dev_if;  // The device interface index that this socket is bound to.
  enum cros_network_family family;
  enum cros_network_protocol protocol;
  struct cros_process_task_info process;
} __attribute__((aligned(8)));

union cros_ip_addr {
  uint32_t addr4;
  uint8_t addr6[16];
} __attribute__((aligned(8)));

struct cros_network_5_tuple {
  enum cros_network_family family;
  enum cros_network_protocol protocol;
  union cros_ip_addr source_addr;
  uint16_t source_port;
  union cros_ip_addr dest_addr;
  uint16_t dest_port;
} __attribute__((aligned(8)));

/* The design idea behind the flow_map is that the BPF will be responsible for
 * creating and updating entries in the map. Each entry corresponds to a socket
 * identifier and a 5-tuple.
 * Userspace will periodically scan this table and generate reports from it.
 * On the release of a socket, all entries associated with that socket will be
 * marked for garbage cleanup. A socket release can cause multiple entries to be
 * marked for cleanup, this is because a single socket could send datagrams to
 * different IP addresses and ports.
 */
struct cros_flow_map_key {
  struct cros_network_5_tuple five_tuple;
  uint64_t sock;  // Holds struct socket * but force to 64-bit value
  // because on ARM64 we have 64-bit kernel and 32-bit userspace
  // so a pointer in the BPF will be 64-bits while this same pointer would be
  // 32-bits in userspace. This would cause issues.
} __attribute__((aligned(8)));

struct cros_flow_map_value {
  enum cros_network_socket_direction direction;
  uint32_t tx_bytes;
  uint32_t rx_bytes;
  // TODO(b/264550183): add remote_hostname
  // TODO(b/264550183): add application protocol
  // TODO(b/264550183): add http_host
  // TODO(b/264550183): add sni_host
  bool garbage_collect_me;
} __attribute__((aligned(8)));

struct cros_sock_to_process_map_value {
  struct cros_network_common common;
  bool garbage_collect_me;
} __attribute__((aligned(8)));

struct cros_network_socket_listen {
  struct cros_network_common common;
  uint8_t socket_type;  // SOCK_STREAM, SOCK_DGRAM etc..
  uint32_t port;
  uint32_t ipv4_addr;
  uint8_t ipv6_addr[16];
} __attribute__((aligned(8)));

enum cros_network_event_type { kSyntheticNetworkFlow, kNetworkSocketListen };

/* This is not actually generated by BPFs but rather by the userspace
 * BPF skeleton wrapper. The wrapper will scan the BPF maps and then generate
 * events from that. This is done to avoid excessive specialization of the
 * BPF skeleton wrapper generic.
 */
struct cros_synthetic_network_flow {
  // We use the slightly cumbersome map data structures to
  // minimize the amount of copying that is done in userspace.
  struct cros_flow_map_key flow_map_key;
  struct cros_sock_to_process_map_value process_map_value;
  struct cros_flow_map_value flow_map_value;
} __attribute__((aligned(8)));

struct cros_network_event {
  enum cros_network_event_type type;
  union {
    struct cros_network_socket_listen socket_listen;
    struct cros_synthetic_network_flow flow;
  } data;
} __attribute__((aligned(8)));

enum cros_event_type { kProcessEvent, kNetworkEvent };

// The security event structure that contains security event information
// provided by a BPF application.
struct cros_event {
  union {
    struct cros_process_event process_event;
    struct cros_network_event network_event;
  } data;
  enum cros_event_type type;
} __attribute__((aligned(8)));

// Ensure that the ring-buffer sample that is allocated is large enough.
_Static_assert(sizeof(struct cros_event) <= CROS_MAX_STRUCT_SIZE,
               "Event structure exceeds maximum size.");

#ifdef __cplusplus
}  //  namespace secagentd::bpf
#endif

#endif  // SECAGENTD_BPF_BPF_TYPES_H_
