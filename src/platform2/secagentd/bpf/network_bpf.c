// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Include vmlinux.h first to declare all kernel types.
#include "include/secagentd/vmlinux/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// TODO(b/243453873): Workaround to get code completion working in CrosIDE.
#undef __cplusplus
#include "secagentd/bpf/bpf_types.h"
#include "secagentd/bpf/bpf_utils.h"

const char LICENSE[] SEC("license") = "Dual BSD/GPL";
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, CROS_MAX_STRUCT_SIZE * 1024);
} rb SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, CROS_MAX_SOCKET* CROS_AVG_CONN_PER_SOCKET);
  __type(key, struct cros_flow_map_key);
  __type(value, struct cros_flow_map_value);
} cros_network_flow_map SEC(".maps");

/* The process protocol and family information
 * remains the same for a socket for its lifetime.
 * so record it just once.
 */
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, CROS_MAX_SOCKET);
  __type(key, uint64_t);  // A unique ID for a socket.
  __type(value, struct cros_sock_to_process_map_value);
} process_map SEC(".maps");

/* A recording of sockets that have at least one
 * flow map entry associated with it.
 * This should only be used by the BPF to determine
 * if a socket should be added to the socket graveyard
 * at socket release.
 */
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, CROS_MAX_SOCKET);
  __type(key, uint64_t);    // A unique ID for a socket.
  __type(value, uint64_t);  // Also the address of the socket.
} active_socket_map SEC(".maps");

/* BPF Verifier only allows a stack of 512 bytes max.
 * Use this one simple trick that BPF verifiers hate
 * to get around this limitation.
 */
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(key_size, sizeof(uint32_t));
  __uint(value_size, sizeof(struct cros_sock_to_process_map_value));
  __uint(max_entries, 1);
} heap_cros_network_common_map SEC(".maps");

static int __attribute__((always_inline))
determine_protocol(int family, int socket_type, int protocol) {
  if (protocol == CROS_IANA_HOPOPT) {  // generic ip protocol.
    // Determine protocol based on domain(family) and type.
    // SOCK_STREAM protocols under AF_INET , AF_INET6 are TCP/IP
    // SOCK_DGRAM protocols under AF_INET, AF_INET6 are UDP
    if (family == CROS_FAMILY_AF_INET || family == CROS_FAMILY_AF_INET6) {
      if (socket_type == SOCK_STREAM) {
        return CROS_PROTOCOL_TCP;
      } else if (socket_type == SOCK_DGRAM) {
        return CROS_PROTOCOL_UDP;
      } else if (socket_type == SOCK_RAW) {
        return CROS_PROTOCOL_RAW;
      }
    }
  } else if (protocol == CROS_IANA_ICMP) {
    return CROS_PROTOCOL_ICMP;
  } else if (protocol == CROS_IANA_TCP) {
    return CROS_PROTOCOL_TCP;
  } else if (protocol == CROS_IANA_UDP) {
    return CROS_PROTOCOL_UDP;
  } else if (socket_type == SOCK_RAW) {
    return CROS_PROTOCOL_RAW;
  } else if (socket_type == CROS_IANA_ICMP6) {
    return CROS_PROTOCOL_ICMP6;
  }
  // The socket type is dgram or stream but the protocol isn't one we recognize.
  return CROS_PROTOCOL_UNKNOWN;
}

static void __attribute__((always_inline))
cros_fill_common(struct cros_network_common* common,
                 const struct socket* sock) {
  struct task_struct* t = (struct task_struct*)bpf_get_current_task();
  struct sock* sk = BPF_CORE_READ(sock, sk);
  int socket_type = BPF_CORE_READ(sock, type);
  common->family = BPF_CORE_READ(sk, __sk_common).skc_family;
  common->protocol = determine_protocol(common->family, socket_type,
                                        BPF_CORE_READ(sk, sk_protocol));
  cros_fill_task_info(&common->process, t);
}

static inline __attribute__((always_inline)) void cros_fill_network_5_tuple(
    struct cros_network_5_tuple* five_tuple, const struct socket* sock) {
  struct sock_common sk_common = BPF_CORE_READ(sock, sk, __sk_common);
  five_tuple->family = sk_common.skc_family;
  five_tuple->protocol =
      determine_protocol(five_tuple->family, BPF_CORE_READ(sock, type),
                         BPF_CORE_READ(sock, sk, sk_protocol));
  if (five_tuple->family == CROS_FAMILY_AF_INET) {
    five_tuple->dest_addr.addr4 = sk_common.skc_daddr;
    five_tuple->source_addr.addr4 = sk_common.skc_rcv_saddr;
  } else if (five_tuple->family == CROS_FAMILY_AF_INET6) {
    __builtin_memmove(five_tuple->source_addr.addr6,
                      sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8,
                      sizeof(five_tuple->source_addr.addr6));
    __builtin_memmove(five_tuple->dest_addr.addr6,
                      sk_common.skc_v6_daddr.in6_u.u6_addr8,
                      sizeof(five_tuple->dest_addr.addr6));
  }
  five_tuple->dest_port = sk_common.skc_dport;
  five_tuple->source_port = sk_common.skc_num;
}

static inline __attribute__((always_inline)) void cros_new_flow_entry(
    struct cros_flow_map_key* key_ref,
    enum cros_network_socket_direction direction,
    uint32_t tx_bytes,
    uint32_t rx_bytes) {
  struct cros_sock_to_process_map_value* process_value;
  const uint32_t zero = 0;
  struct cros_flow_map_value value;
  __builtin_memset(&value, 0, sizeof(value));
  value.garbage_collect_me = false;
  value.direction = direction;
  value.rx_bytes = rx_bytes;
  value.tx_bytes = tx_bytes;
  bpf_map_update_elem(&active_socket_map, &key_ref->sock, &key_ref->sock,
                      BPF_NOEXIST);
  bpf_map_update_elem(&cros_network_flow_map, key_ref, &value, BPF_ANY);
  /* Use the heap instead of the stack. */
  process_value = bpf_map_lookup_elem(&heap_cros_network_common_map, &zero);
  if (process_value == NULL) {
    return;
  }
  __builtin_memset(process_value, 0,
                   sizeof(struct cros_sock_to_process_map_value));
  cros_fill_common(&process_value->common, (const struct socket*)key_ref->sock);
  process_value->garbage_collect_me = false;
  bpf_map_update_elem(&process_map, &key_ref->sock, process_value, BPF_NOEXIST);
}

CROS_IF_FUNCTION_HOOK("fexit/inet_listen",
                      "raw_tracepoint/cros_inet_listen_exit")
int BPF_PROG(cros_handle_inet_listen,
             struct socket* socket,
             int backlog,
             int rv) {
  if (rv != 0) {
    return 0;
  }
  struct task_struct* t = (struct task_struct*)bpf_get_current_task();
  if (is_kthread(t)) {
    return 0;
  }
  struct cros_event* event =
      (struct cros_event*)(bpf_ringbuf_reserve(&rb, sizeof(*event), 0));
  if (event == NULL) {
    return 0;
  }
  struct sock* sk = BPF_CORE_READ(socket, sk);
  event->type = kNetworkEvent;
  event->data.network_event.type = kNetworkSocketListen;
  struct cros_network_socket_listen* sl =
      &(event->data.network_event.data.socket_listen);
  cros_fill_common(&sl->common, socket);
  sl->socket_type = BPF_CORE_READ(socket, type);
  // Extract out the source port.
  sl->port = BPF_CORE_READ(sk, __sk_common).skc_num;
  // Fill out the IPv4 address.
  sl->ipv4_addr = BPF_CORE_READ(sk, __sk_common).skc_rcv_saddr;
  __builtin_memmove(
      sl->ipv6_addr,
      BPF_CORE_READ(sk, __sk_common).skc_v6_rcv_saddr.in6_u.u6_addr8,
      sizeof(sl->ipv6_addr) / sizeof(uint8_t));
  bpf_ringbuf_submit(event, 0);
  return 0;
}

CROS_IF_FUNCTION_HOOK("fexit/inet_sendmsg",
                      "raw_tracepoint/cros_inet_sendmsg_exit")
int BPF_PROG(cros_handle_inet_sendmsg_exit,
             struct socket* sock,
             struct msghdr* msg,
             size_t size,
             int rv) {
  if (rv <= 0) {
    return 0;
  }
  struct cros_flow_map_value* value_ref;
  struct cros_flow_map_key key;
  // Fun fact: BPF verifier will complain if the key contains
  // any uninitialized values.
  __builtin_memset(&key, 0, sizeof(key));
  key.sock = (uint64_t)sock;
  cros_fill_network_5_tuple(&key.five_tuple, (const struct socket*)key.sock);
  value_ref = bpf_map_lookup_elem(&cros_network_flow_map, &key);
  if (value_ref) {  // entry already exist
    value_ref->tx_bytes = value_ref->tx_bytes + rv;
  } else {
    // The socket was likely in operation before this BPF program was loaded
    // so we can't be sure of the direction.
    enum cros_network_socket_direction dir = CROS_SOCKET_DIRECTION_UNKNOWN;
    cros_new_flow_entry(&key, /*direction*/ dir,
                        /*tx_bytes*/ rv, /*rx_bytes*/ 0);
  }
  return 0;
}

CROS_IF_FUNCTION_HOOK("fexit/inet_recvmsg",
                      "raw_tracepoint/cros_inet_recvmsg_exit")
int BPF_PROG(cros_handle_inet_recvmsg_exit,
             struct socket* sock,
             struct msghdr* msg,
             size_t size,
             int flags,
             int rv) {
  if (rv <= 0) {
    return 0;
  }
  struct cros_flow_map_value* value_ref;
  struct cros_flow_map_key key;
  // Fun fact: BPF verifier will complain if the key contains
  // any uninitialized values.
  __builtin_memset(&key, 0, sizeof(key));
  key.sock = (uint64_t)sock;
  cros_fill_network_5_tuple(&key.five_tuple, (const struct socket*)key.sock);
  value_ref = bpf_map_lookup_elem(&cros_network_flow_map, &key);
  if (value_ref) {  // entry already exist
    value_ref->rx_bytes = value_ref->rx_bytes + rv;
  } else {
    // If the socket is a stream socket then we are likely here because the
    // socket was created then connect/accepted before this BPF program
    // was loaded. We can't say much about the direction of the socket.
    cros_new_flow_entry(&key, /*direction*/ CROS_SOCKET_DIRECTION_UNKNOWN,
                        /*tx_bytes*/ 0, /*rx_bytes*/ rv);
  }
  return 0;
}

CROS_IF_FUNCTION_HOOK("fexit/inet_accept",
                      "raw_tracepoint/cros_inet_accept_exit")
int BPF_PROG(cros_handle_inet_accept_exit,
             struct socket* sock,
             struct socket* newsock,
             int flags,
             bool kern,
             int rv) {
  if (rv < 0) {
    return 0;
  }
  struct cros_flow_map_value* value_ref;
  struct cros_flow_map_key key;
  // Fun fact: BPF verifier will complain if the key contains
  // any uninitialized values.
  __builtin_memset(&key, 0, sizeof(key));
  key.sock = (uint64_t)newsock;
  cros_fill_network_5_tuple(&key.five_tuple, (const struct socket*)key.sock);
  value_ref = bpf_map_lookup_elem(&cros_network_flow_map, &key);
  if (value_ref) {  // entry already exist.. this shouldn't be the case.
    bpf_printk(
        "cros_network_accept_exit encountered a socket with existing flow "
        "entry");
  } else {  // entry does not exist so must be an outbound connection.
    cros_new_flow_entry(&key, /*direction*/ CROS_SOCKET_DIRECTION_IN,
                        /*tx_bytes*/ 0, /*rx_bytes*/ rv);
  }
  return 0;
}

CROS_IF_FUNCTION_HOOK("fexit/inet_stream_connect",
                      "raw_tracepoint/cros_inet_stream_connect_exit")
int BPF_PROG(cros_handle_inet_stream_connect_exit,
             struct socket* sock,
             struct sockaddr* uaddr,
             int addr_lens,
             int flags,
             int is_sendmsg,
             int rv) {
  if (rv < 0) {
    return 0;
  }
  struct cros_flow_map_value* value_ref;
  struct cros_flow_map_key key;
  // Fun fact: BPF verifier will complain if the key contains
  // any uninitialized values.
  __builtin_memset(&key, 0, sizeof(key));
  key.sock = (uint64_t)sock;
  cros_fill_network_5_tuple(&key.five_tuple, (const struct socket*)key.sock);
  value_ref = bpf_map_lookup_elem(&cros_network_flow_map, &key);
  if (value_ref) {
    value_ref->direction = CROS_SOCKET_DIRECTION_OUT;
  } else {  // entry does not exist so must be an outbound connection.
    cros_new_flow_entry(&key, /*direction*/ CROS_SOCKET_DIRECTION_OUT,
                        /*tx_bytes*/ 0, /*rx_bytes*/ rv);
  }
  return 0;
}

CROS_IF_FUNCTION_HOOK("fexit/inet_release",
                      "raw_tracepoint/cros_inet_release_enter")
int BPF_PROG(cros_handle_inet_release_enter, struct socket* sock) {
  uint64_t key = (uint64_t)sock;
  bpf_map_delete_elem(&active_socket_map, &key);
  return 0;
}
