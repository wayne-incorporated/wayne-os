// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "p2p/client/service_finder.h"

#include <avahi-client/client.h>
#include <avahi-client/lookup.h>
#include <avahi-common/error.h>
#include <avahi-glib/glib-watch.h>
#include <fcntl.h>
#include <glib.h>
#include <unistd.h>

#include <set>
#include <stdexcept>

#include <base/check.h>
#include <base/check_op.h>
#include <base/logging.h>
#include <base/notreached.h>

#include "p2p/common/util.h"

using std::map;
using std::set;
using std::string;
using std::vector;

namespace p2p {

namespace client {

class ServiceFinderAvahi : public ServiceFinder {
 public:
  ServiceFinderAvahi();
  ServiceFinderAvahi(const ServiceFinderAvahi&) = delete;
  ServiceFinderAvahi& operator=(const ServiceFinderAvahi&) = delete;

  virtual ~ServiceFinderAvahi();

  vector<const Peer*> GetPeersForFile(const string& file) const;

  vector<string> AvailableFiles() const;

  int NumTotalConnections() const;

  int NumTotalPeers() const;

  bool Lookup();

  void Abort();

  static ServiceFinderAvahi* Construct();

 private:
  static gboolean quit_lookup_loop(GIOChannel* channel,
                                   GIOCondition cond,
                                   gpointer user_data);

  static void on_avahi_changed(AvahiClient* client,
                               AvahiClientState state,
                               void* user_data);

  static void service_resolve_cb(AvahiServiceResolver* r,
                                 AvahiIfIndex interface,
                                 AvahiProtocol protocol,
                                 AvahiResolverEvent event,
                                 const char* name,
                                 const char* type,
                                 const char* domain,
                                 const char* host_name,
                                 const AvahiAddress* a,
                                 uint16_t port,
                                 AvahiStringList* txt,
                                 AvahiLookupResultFlags flags,
                                 void* user_data);

  bool IsOwnService(const char* name);

  void HandleResolverEvent(const AvahiAddress* a,
                           uint16_t port,
                           AvahiStringList* txt);

  static void on_service_browser_changed(AvahiServiceBrowser* b,
                                         AvahiIfIndex interface,
                                         AvahiProtocol protocol,
                                         AvahiBrowserEvent event,
                                         const char* name,
                                         const char* type,
                                         const char* domain,
                                         AvahiLookupResultFlags flags,
                                         void* user_data);

  virtual bool Initialize();
  void BrowserCheckIfDone();

  AvahiGLibPoll* poll_;
  AvahiClient* client_;
  bool running_;
  vector<Peer*> peers_;
  map<string, vector<Peer*>> file_to_servers_;
  AvahiServiceBrowser* lookup_browser_;
  bool lookup_all_for_now_;
  set<AvahiServiceResolver*> lookup_pending_resolvers_;
  GMainLoop* lookup_loop_;

  // Flag used to signal the request was canceled.
  volatile bool must_exit_now_;

  // A pipe used to wake up the |lookup_loop_| when Abort() is called.
  int abort_pipe_[2];

  // A GIOChannel on top of |abort_pipe_[0]| in order to watch it from the main
  // loop.
  GIOChannel* abort_io_channel_;

  // The source tag for the |abort_io_channel_| watch on the main loop.
  guint abort_source_;
};

ServiceFinderAvahi::ServiceFinderAvahi()
    : poll_(NULL),
      client_(NULL),
      running_(false),
      lookup_browser_(NULL),
      lookup_all_for_now_(false),
      lookup_loop_(NULL),
      must_exit_now_(false),
      abort_io_channel_(NULL) {
  // Create and attach a pipe used from the signal handler to wake up the
  // glib main loop.
  if (pipe2(abort_pipe_, O_NONBLOCK) != 0) {
    PLOG(ERROR) << "Creating a pipe(). Aborting now.";
    must_exit_now_ = true;
    abort_pipe_[0] = abort_pipe_[1] = -1;
    return;
  }

  abort_io_channel_ = g_io_channel_unix_new(abort_pipe_[0]);
  abort_source_ =
      g_io_add_watch(abort_io_channel_, G_IO_IN, quit_lookup_loop, this);
}

ServiceFinderAvahi::~ServiceFinderAvahi() {
  for (auto const& i : peers_) {
    delete i;
  }

  if (abort_io_channel_) {
    g_source_remove(abort_source_);
    g_io_channel_unref(abort_io_channel_);
  }

  close(abort_pipe_[0]);
  close(abort_pipe_[1]);

  CHECK(lookup_browser_ == NULL);
  CHECK(lookup_loop_ == NULL);

  // If the process was canceled with Abort() there can be some resolvers
  // pending on |lookup_pending_resolvers_|. Release them now.
  if (must_exit_now_) {
    for (auto const resolver : lookup_pending_resolvers_)
      avahi_service_resolver_free(resolver);
    lookup_pending_resolvers_.clear();
  }
  CHECK_EQ(0U, lookup_pending_resolvers_.size());

  if (client_ != NULL)
    avahi_client_free(client_);
  if (poll_ != NULL)
    avahi_glib_poll_free(poll_);
}

vector<string> ServiceFinderAvahi::AvailableFiles() const {
  vector<string> ret;
  for (auto const& i : file_to_servers_)
    ret.push_back(i.first);
  return ret;
}

int ServiceFinderAvahi::NumTotalConnections() const {
  int sum = 0;
  for (auto const& peer : peers_)
    sum += peer->num_connections;
  return sum;
}

int ServiceFinderAvahi::NumTotalPeers() const {
  return peers_.size();
}

vector<const Peer*> ServiceFinderAvahi::GetPeersForFile(
    const string& file) const {
  map<string, vector<Peer*>>::const_iterator it = file_to_servers_.find(file);
  if (it == file_to_servers_.end())
    return vector<const Peer*>();
  return vector<const Peer*>(it->second.begin(), it->second.end());
}

void ServiceFinderAvahi::HandleResolverEvent(const AvahiAddress* a,
                                             uint16_t port,
                                             AvahiStringList* txt) {
  Peer* peer = NULL;
  AvahiStringList* l;
  // 64 bytes is enough to hold any literal IPv4 and IPv6 addresses
  char buf[64];

  avahi_address_snprint(buf, sizeof buf, a);

  peer = new Peer();
  peer->address = string(buf);
  peer->is_ipv6 = (a->proto == AVAHI_PROTO_INET6);
  peer->port = port;

  for (l = txt; l != NULL; l = l->next) {
    string txt((const char*)l->text, l->size);
    const char* s = txt.c_str();
    const char* e = strrchr(s, '=');

    VLOG(1) << " TXT: len=" << l->size << " data=" << txt;

    if (e == NULL || strlen(e + 1) < 1) {
      LOG(WARNING) << "Attribute `" << txt
                   << "` is malformed (malformed value)";
      continue;
    }

    if (strncasecmp(s, "id_", strlen("id_")) == 0) {
      char* endp = NULL;
      size_t file_size = strtol(e + 1, &endp, 10);
      string file_name = txt.substr(strlen("id_"), e - s - strlen("id_"));

      if (*endp != '\0') {
        LOG(WARNING) << "Attribute `" << txt
                     << "` is malformed (value not a decimal number)";
        continue;
      }

      peer->files[file_name] = file_size;

    } else if (strncasecmp(s, "num_connections=", strlen("num_connections=")) ==
               0) {
      char* endp = NULL;
      int parsed_value = strtol(s + strlen("num_connections="), &endp, 10);
      if (endp != NULL) {
        peer->num_connections = parsed_value;
      }
    }
  }

  peers_.push_back(peer);
  for (auto const& file : peer->files) {
    vector<Peer*>& per_file = file_to_servers_[file.first];
    per_file.push_back(peer);
  }
}

void ServiceFinderAvahi::service_resolve_cb(AvahiServiceResolver* r,
                                            AvahiIfIndex interface,
                                            AvahiProtocol protocol,
                                            AvahiResolverEvent event,
                                            const char* name,
                                            const char* type,
                                            const char* domain,
                                            const char* host_name,
                                            const AvahiAddress* a,
                                            uint16_t port,
                                            AvahiStringList* txt,
                                            AvahiLookupResultFlags flags,
                                            void* user_data) {
  ServiceFinderAvahi* finder = reinterpret_cast<ServiceFinderAvahi*>(user_data);

  if (event == AVAHI_RESOLVER_FAILURE) {
    LOG(ERROR) << "Resolver failure: "
               << avahi_strerror(avahi_client_errno(finder->client_));
  } else {
    finder->HandleResolverEvent(a, port, txt);
  }

  if (finder->lookup_pending_resolvers_.erase(r) != 1)
    NOTREACHED();
  avahi_service_resolver_free(r);

  finder->BrowserCheckIfDone();
}

bool ServiceFinderAvahi::IsOwnService(const char* name) {
  return g_strcmp0(name, avahi_client_get_host_name(client_)) == 0;
}

static string ToString(AvahiBrowserEvent event) {
  switch (event) {
    case AVAHI_BROWSER_FAILURE:
      return "AVAHI_BROWSER_FAILURE";
    case AVAHI_BROWSER_NEW:
      return "AVAHI_BROWSER_NEW";
    case AVAHI_BROWSER_REMOVE:
      return "AVAHI_BROWSER_REMOVE";
    case AVAHI_BROWSER_CACHE_EXHAUSTED:
      return "AVAHI_BROWSER_CACHE_EXHAUSTED";
    case AVAHI_BROWSER_ALL_FOR_NOW:
      return "AVAHI_BROWSER_ALL_FOR_NOW";
  }
  return "Unknown";
}

void ServiceFinderAvahi::on_service_browser_changed(
    AvahiServiceBrowser* b,
    AvahiIfIndex interface,
    AvahiProtocol protocol,
    AvahiBrowserEvent event,
    const char* name,
    const char* type,
    const char* domain,
    AvahiLookupResultFlags flags,
    void* user_data) {
  ServiceFinderAvahi* finder = reinterpret_cast<ServiceFinderAvahi*>(user_data);

  // Can be called directly by avahi_service_browser_new() so the browser_
  // member may not be set just yet...
  if (finder->lookup_browser_ == NULL)
    finder->lookup_browser_ = b;

  VLOG(1) << "on_browser_changed: event=" << ToString(event)
          << " name=" << (name != NULL ? name : "(nil)") << " type=" << type
          << " domain=" << (domain != NULL ? domain : "(nil)")
          << " flags=" << flags;

  // Never return results from ourselves
  if (finder->IsOwnService(name)) {
    VLOG(1) << "Ignoring results from ourselves.";
    return;
  }

  switch (event) {
    case AVAHI_BROWSER_FAILURE:
      LOG(ERROR) << "Browser failure: "
                 << avahi_strerror(avahi_client_errno(finder->client_));
      break;

    case AVAHI_BROWSER_NEW: {
      AvahiServiceResolver* resolver = avahi_service_resolver_new(
          finder->client_, interface, protocol, name, type, domain,
          AVAHI_PROTO_UNSPEC, (AvahiLookupFlags)0, service_resolve_cb, finder);
      if (!resolver) {
        LOG(ERROR) << "avahi_service_resolver_new() failed: "
                   << avahi_strerror(avahi_client_errno(finder->client_));
      } else {
        finder->lookup_pending_resolvers_.insert(resolver);
      }
    } break;

    case AVAHI_BROWSER_REMOVE:
      break;

    case AVAHI_BROWSER_CACHE_EXHAUSTED:
      break;

    case AVAHI_BROWSER_ALL_FOR_NOW:
      finder->lookup_all_for_now_ = TRUE;
      finder->BrowserCheckIfDone();
      break;
  }
}

void ServiceFinderAvahi::BrowserCheckIfDone() {
  if (!lookup_all_for_now_)
    return;

  if (lookup_pending_resolvers_.size() > 0)
    return;

  CHECK(lookup_loop_ != NULL);
  g_main_loop_quit(lookup_loop_);
}

bool ServiceFinderAvahi::Lookup() {
  // Prevent new calls to Lookup() once Abort() was called.
  if (must_exit_now_)
    return true;

  CHECK(lookup_loop_ == NULL);

  // Clear existing data, if any.
  peers_.clear();
  file_to_servers_.clear();
  lookup_all_for_now_ = false;

  lookup_loop_ = g_main_loop_new(NULL, FALSE);
  lookup_browser_ = avahi_service_browser_new(
      client_, AVAHI_IF_UNSPEC, AVAHI_PROTO_UNSPEC, "_cros_p2p._tcp",
      NULL, /* domain */
      (AvahiLookupFlags)0, on_service_browser_changed, this);
  if (!lookup_browser_) {
    LOG(ERROR) << "avahi_service_browser_new() failed: "
               << avahi_strerror(avahi_client_errno(client_));
    g_main_loop_unref(lookup_loop_);
    lookup_loop_ = NULL;
    return false;
  }

  g_main_loop_run(lookup_loop_);
  g_main_loop_unref(lookup_loop_);
  lookup_loop_ = NULL;

  avahi_service_browser_free(lookup_browser_);
  lookup_browser_ = NULL;

  // TODO(deymo): Detect if the mDNS is filtered and return false if it is.
  // See crbug.com/267082 for details.
  return true;
}

gboolean ServiceFinderAvahi::quit_lookup_loop(GIOChannel* channel,
                                              GIOCondition cond,
                                              gpointer user_data) {
  LOG(INFO) << "Abort() processed, quiting main loop.";

  ServiceFinderAvahi* finder = reinterpret_cast<ServiceFinderAvahi*>(user_data);
  CHECK(finder->lookup_loop_ != NULL);
  g_main_loop_quit(finder->lookup_loop_);
  return TRUE;
}

void ServiceFinderAvahi::Abort() {
  // Allow several calls to this function.
  if (must_exit_now_)
    return;
  must_exit_now_ = true;

  // Wake up the main loop if we are running it. In case of an error, we
  // can't log the result since this is running in the signal handler. In the
  // case we can't write to this pipe, which should never happen, we abort the
  // process excecution without returning from the handler.
  if (write(abort_pipe_[1], "*", 1) != 1)
    abort();
}

// -----------------------------------------------------------------------------

void ServiceFinderAvahi::on_avahi_changed(AvahiClient* client,
                                          AvahiClientState state,
                                          void* user_data) {
  ServiceFinderAvahi* finder = reinterpret_cast<ServiceFinderAvahi*>(user_data);
  VLOG(1) << "on_avahi_changed, state=" << state;
  if (state == AVAHI_CLIENT_S_RUNNING) {
    finder->running_ = true;
  } else {
    finder->running_ = false;
  }
}

bool ServiceFinderAvahi::Initialize() {
  int error;

  // Note that if Avahi is not running and can't be activated,
  // avahi_client_new() may block for up to 25 seconds because it's
  // doing a sync D-Bus method call... short of fixing libavahi-client
  // there's really no way around this :-/
  poll_ = avahi_glib_poll_new(NULL, G_PRIORITY_DEFAULT);
  client_ = avahi_client_new(avahi_glib_poll_get(poll_), (AvahiClientFlags)0,
                             on_avahi_changed, this, &error);
  if (client_ == NULL) {
    LOG(ERROR) << "Error constructing AvahiClient: " << error;
    return false;
  }

  if (!running_) {
    LOG(ERROR) << "Avahi daemon is not running";
    return false;
  }

  return true;
}

ServiceFinderAvahi* ServiceFinderAvahi::Construct() {
  ServiceFinderAvahi* client = new ServiceFinderAvahi();
  if (!client->Initialize()) {
    delete client;
    return NULL;
  }
  return client;
}

ServiceFinder* ServiceFinder::Construct() {
  return ServiceFinderAvahi::Construct();
}

}  // namespace client

}  // namespace p2p
