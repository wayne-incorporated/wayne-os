/*
 * Copyright 2013 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

/*
 * WiFi Testbed Regulatory
 *
 * Userspace helper which sends regulatory domains to Linux via nl80211.
 * This code is based on CRDA.  Plese see LICENSE.CRDA for the license
 * associated with the original code.
 */

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#include <linux/nl80211.h>
#include <netlink/attr.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/genl.h>
#include <netlink/msg.h>

/* Constants used for creating a single "allow anything" rule */
#define RULE_FREQ_RANGE_MIN_KHZ 2000000
#define RULE_FREQ_RANGE_MAX_KHZ 6000000
#define RULE_BANDWIDTH_MAX_KHZ 80000
#define RULE_ANTENNA_GAIN_MAX_MBI 300
#define RULE_EIRP_MAX_MBM 2300

struct nl80211_state {
  struct nl_sock *nl_sock;
  struct nl_cache *nl_cache;
  struct genl_family *nl80211;
};

static int nl80211_init(struct nl80211_state *state) {
  int err;

  state->nl_sock = nl_socket_alloc();
  if (!state->nl_sock) {
    fprintf(stderr, "Failed to allocate netlink sock.\n");
    return -ENOMEM;
  }

  if (genl_connect(state->nl_sock)) {
    fprintf(stderr, "Failed to connect to generic netlink.\n");
    err = -ENOLINK;
    goto out_sock_destroy;
  }

  if (genl_ctrl_alloc_cache(state->nl_sock, &state->nl_cache)) {
    fprintf(stderr, "Failed to allocate generic netlink cache.\n");
    err = -ENOMEM;
    goto out_sock_destroy;
  }

  state->nl80211 = genl_ctrl_search_by_name(state->nl_cache, "nl80211");
  if (!state->nl80211) {
    fprintf(stderr, "nl80211 not found.\n");
    err = -ENOENT;
    goto out_cache_free;
  }

  return 0;

 out_cache_free:
  nl_cache_free(state->nl_cache);
 out_sock_destroy:
  nl_socket_free(state->nl_sock);
  return err;
}

static void nl80211_cleanup(struct nl80211_state *state) {
  genl_family_put(state->nl80211);
  nl_cache_free(state->nl_cache);
  nl_socket_free(state->nl_sock);
}

static int reg_handler(struct nl_msg *msg, void *arg) {
  return NL_SKIP;
}

static int wait_handler(struct nl_msg *msg, void *arg) {
  int *finished = arg;
  *finished = 1;
  return NL_STOP;
}

static int error_handler(struct sockaddr_nl *nla,
                         struct nlmsgerr *err,
                         void *arg) {
  fprintf(stderr, "nl80211 error %d\n", err->error);
  exit(err->error);
}

static inline int is_world_regdom(const char *alpha2) {
  if (alpha2[0] == '0' && alpha2[1] == '0')
    return 1;
  return 0;
}

static inline int is_alpha2(const char *alpha2) {
  if (isupper(alpha2[0]) && isupper(alpha2[1]))
    return 1;
  return 0;
}

static inline int is_valid_regdom(const char *alpha2) {
  if (is_alpha2(alpha2) || is_world_regdom(alpha2))
    return 1;
  return 0;
}

int main(int argc, char **argv) {
  int r;
  char alpha2[3] = { '0', '0' };
  char *env_country;
  struct nl80211_state nlstate;
  struct nl_cb *cb = NULL;
  struct nl_msg *msg;
  int finished = 0;

  struct nlattr *nl_reg_rules;
  struct ieee80211_regdomain *rd = NULL;
  struct nlattr *nl_reg_rule;

  if (argc != 1) {
    fprintf(stderr, "Usage: %s\n", argv[0]);
    return 1;
  }

  env_country = getenv("COUNTRY");
  if (env_country) {
    if (!is_valid_regdom(env_country)) {
      fprintf(stderr, "COUNTRY environment variable must be "
              "ISO ISO 3166-1-alpha-2 (uppercase) or 00\n");
      return 1;
    }
    memcpy(alpha2, env_country, 2);
  }

  r = nl80211_init(&nlstate);
  if (r) {
    return 1;
  }

  msg = nlmsg_alloc();
  if (!msg) {
    fprintf(stderr, "Failed to allocate netlink message.\n");
    r = -1;
    goto out;
  }

  genlmsg_put(msg, 0, 0, genl_family_get_id(nlstate.nl80211), 0,
    0, NL80211_CMD_SET_REG, 0);

  NLA_PUT_STRING(msg, NL80211_ATTR_REG_ALPHA2, alpha2);
  NLA_PUT_U8(msg, NL80211_ATTR_DFS_REGION, NL80211_DFS_UNSET);

  nl_reg_rules = nla_nest_start(msg, NL80211_ATTR_REG_RULES);
  if (!nl_reg_rules) {
    r = -1;
    goto nla_put_failure;
  }

  nl_reg_rule = nla_nest_start(msg, 0);
  if (!nl_reg_rule)
    goto nla_put_failure;

  NLA_PUT_U32(msg, NL80211_ATTR_REG_RULE_FLAGS, 0);
  NLA_PUT_U32(msg, NL80211_ATTR_FREQ_RANGE_START,
        RULE_FREQ_RANGE_MIN_KHZ);
  NLA_PUT_U32(msg, NL80211_ATTR_FREQ_RANGE_END,
        RULE_FREQ_RANGE_MAX_KHZ);
  NLA_PUT_U32(msg, NL80211_ATTR_FREQ_RANGE_MAX_BW,
        RULE_BANDWIDTH_MAX_KHZ);
  NLA_PUT_U32(msg, NL80211_ATTR_POWER_RULE_MAX_ANT_GAIN,
        RULE_ANTENNA_GAIN_MAX_MBI);
  NLA_PUT_U32(msg, NL80211_ATTR_POWER_RULE_MAX_EIRP,
        RULE_EIRP_MAX_MBM);

  nla_nest_end(msg, nl_reg_rule);
  nla_nest_end(msg, nl_reg_rules);

  cb = nl_cb_alloc(NL_CB_CUSTOM);
  if (!cb)
    goto out_cb_put;

  r = nl_send_auto_complete(nlstate.nl_sock, msg);

  if (r < 0) {
    fprintf(stderr, "Failed to send regulatory request: %d\n", r);
    goto out_cb_put;
  }

  nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, reg_handler, NULL);
  nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, wait_handler, &finished);
  nl_cb_err(cb, NL_CB_CUSTOM, error_handler, NULL);

  if (!finished) {
    r = nl_wait_for_ack(nlstate.nl_sock);
    if (r < 0) {
      fprintf(stderr, "Failed to set regulatory domain: "
              "%s (%d)\n", nl_geterror(r), r);
      goto out_cb_put;
    }
  }

out_cb_put:
  nl_cb_put(cb);
nla_put_failure:
  nlmsg_free(msg);
out:
  nl80211_cleanup(&nlstate);
  free(rd);

  return r != 0;
}
