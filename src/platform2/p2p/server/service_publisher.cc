// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "p2p/server/service_publisher.h"

#include <avahi-client/client.h>
#include <avahi-client/publish.h>
#include <avahi-common/error.h>
#include <avahi-glib/glib-watch.h>
#include <glib.h>

#include <map>

#include <base/logging.h>
#include <base/strings/stringprintf.h>

#include "p2p/common/util.h"

using std::map;
using std::string;

namespace p2p {

namespace server {

// File sizes can change very quickly and very often so rate-limit
// these kind of changes to once every ten seconds. Otherwise we
// may end up generate a lot of unnecessary traffic.
const int kFileChangedDelayMSec = 10000;

class ServicePublisherAvahi : public ServicePublisher {
 public:
  explicit ServicePublisherAvahi(uint16_t http_port);
  ServicePublisherAvahi(const ServicePublisherAvahi&) = delete;
  ServicePublisherAvahi& operator=(const ServicePublisherAvahi&) = delete;

  ~ServicePublisherAvahi() override;

  void AddFile(const string& file, size_t file_size) override;

  void RemoveFile(const string& file) override;

  void UpdateFileSize(const string& file, size_t file_size) override;

  void SetNumConnections(int num_connections) override;

  map<string, size_t> files() override;

  bool Init();

 private:
  // Callback used for timeout management - see kFileChangedDelayMSec.
  static gboolean OnDelayTimeoutExpired(gpointer user_data);

  // Callback used for when Avahi changes state.
  static void OnAvahiChanged(AvahiClient* client,
                             AvahiClientState state,
                             void* user_data);

  // Helper for calculating the TXT records to publish.
  AvahiStringList* CalculateTXTRecords();

  // Method used to publish the information in files_ to Avahi.
  void Publish(bool may_delay);

  // The TCP port of the HTTP server.
  uint16_t http_port_;

  // The LAN name currently used by Avahi. This is used as the
  // identifier of the DNS-SD service being exported via mDNS.
  string lan_name_;

  // Object used for integrating Avahi with the GLib mainloop.
  AvahiGLibPoll* poll_;

  // The Avahi object.
  AvahiClient* client_;

  // Object used to publish DNS-SD records.
  AvahiEntryGroup* group_;

  // The files (and their sizes) to export. These are exported in TXT
  // records of the DNS-SD service (prefixed with id_).
  map<string, size_t> files_;

  // The current number of HTTP connections. This is exported as a
  // decimal number in the "num-connections" TXT record.
  int num_connections_;

  // GLib source id used for timeout management - see kFileChangedDelayMSec.
  guint delay_timeout_id_;
};

ServicePublisherAvahi::ServicePublisherAvahi(uint16_t http_port)
    : http_port_(http_port),
      poll_(NULL),
      client_(NULL),
      group_(NULL),
      num_connections_(0),
      delay_timeout_id_(0) {}

ServicePublisherAvahi::~ServicePublisherAvahi() {
  if (delay_timeout_id_ != 0)
    g_source_remove(delay_timeout_id_);
  if (group_ != NULL)
    avahi_entry_group_free(group_);
  if (client_ != NULL)
    avahi_client_free(client_);
  if (poll_ != NULL)
    avahi_glib_poll_free(poll_);
}

AvahiStringList* ServicePublisherAvahi::CalculateTXTRecords() {
  AvahiStringList* list;
  string str = base::StringPrintf("num_connections=%d", num_connections_);
  list = avahi_string_list_new(str.c_str(), NULL);
  for (auto& item : files_) {
    string key = string("id_") + item.first;
    string value = std::to_string(item.second);
    // TODO(zeuthen): ensure that len(key+"="+value) <= 255
    list = avahi_string_list_add_pair(list, key.c_str(), value.c_str());
  }
  return list;
}

gboolean ServicePublisherAvahi::OnDelayTimeoutExpired(gpointer user_data) {
  ServicePublisherAvahi* publisher =
      reinterpret_cast<ServicePublisherAvahi*>(user_data);
  VLOG(1) << "Publishing timeout expired";
  publisher->delay_timeout_id_ = 0;
  publisher->Publish(false);
  return FALSE;  // Remove timeout source
}

void ServicePublisherAvahi::Publish(bool may_delay) {
  int rc;
  AvahiStringList* txt;

  if (may_delay) {
    if (delay_timeout_id_ != 0) {
      // Already have a timeout, no need to schedule a new one
      return;
    }
    delay_timeout_id_ =
        g_timeout_add(kFileChangedDelayMSec,
                      static_cast<GSourceFunc>(OnDelayTimeoutExpired), this);
    VLOG(1) << "Scheduling publishing to happen in " << kFileChangedDelayMSec
            << " msec";
    return;
  } else {
    // Not allowed to delay, have to publish immediately .. so if we have
    // a timeout cancel it
    if (delay_timeout_id_ != 0) {
      g_source_remove(delay_timeout_id_);
      delay_timeout_id_ = 0;
      VLOG(1) << "Cancelling already scheduled publishing event";
    }
  }

  VLOG(1) << "Publishing records";

  txt = CalculateTXTRecords();
  if (group_ == NULL) {
    group_ = avahi_entry_group_new(client_, NULL, NULL); /* user_data */
    if (group_ == NULL) {
      LOG(ERROR) << "Error creating AvahiEntryGroup: "
                 << avahi_strerror(avahi_client_errno(client_));
      avahi_string_list_free(txt);
      return;
    }
    rc = avahi_entry_group_add_service_strlst(
        group_, AVAHI_IF_UNSPEC, AVAHI_PROTO_UNSPEC, (AvahiPublishFlags)0,
        lan_name_.c_str(), "_cros_p2p._tcp",
        /* service type */
        NULL,       /* domain */
        NULL,       /* host */
        http_port_, /* IP port */
        txt);
    if (rc != AVAHI_OK) {
      LOG(ERROR) << "Error adding service to AvahiEntryGroup: "
                 << avahi_strerror(avahi_client_errno(client_));
      avahi_string_list_free(txt);
      return;
    }

    rc = avahi_entry_group_commit(group_);
    if (rc != AVAHI_OK) {
      LOG(ERROR) << "Error committing AvahiEntryGroup: "
                 << avahi_strerror(avahi_client_errno(client_));
    }
  } else {
    avahi_entry_group_update_service_txt_strlst(
        group_, AVAHI_IF_UNSPEC, AVAHI_PROTO_UNSPEC, (AvahiPublishFlags)0,
        lan_name_.c_str(), "_cros_p2p._tcp",
        /* service type */
        NULL, /* domain */
        txt);
  }

  avahi_string_list_free(txt);
}

void ServicePublisherAvahi::OnAvahiChanged(AvahiClient* client,
                                           AvahiClientState state,
                                           void* user_data) {
  ServicePublisherAvahi* publisher =
      reinterpret_cast<ServicePublisherAvahi*>(user_data);

  // So, we're called directly by avahi_client_new() - meaning
  // client_ member isn't set yet - thanks :-/
  if (publisher->client_ == NULL)
    publisher->client_ = client;

  VLOG(1) << "OnAvahiChanged, state=" << state;
  if (state == AVAHI_CLIENT_S_RUNNING) {
    // Free the existing group, if there is one. This can happen if
    // e.g. the LAN name used by Avahi changes.
    if (publisher->group_ != NULL) {
      avahi_entry_group_free(publisher->group_);
      publisher->group_ = NULL;
    }
    publisher->lan_name_ = string(avahi_client_get_host_name(client));
    VLOG(1) << "Server running, publishing services using LAN name '"
            << publisher->lan_name_ << "'";
    publisher->Publish(false);
  }
}

bool ServicePublisherAvahi::Init() {
  int error;

  poll_ = avahi_glib_poll_new(NULL, G_PRIORITY_DEFAULT);
  client_ = avahi_client_new(avahi_glib_poll_get(poll_), (AvahiClientFlags)0,
                             OnAvahiChanged, this, &error);
  if (client_ == NULL) {
    LOG(ERROR) << "Error constructing AvahiClient: " << error;
    return false;
  }
  return true;
}

void ServicePublisherAvahi::AddFile(const string& file, size_t file_size) {
  files_[file] = file_size;
  Publish(false);
}

void ServicePublisherAvahi::RemoveFile(const string& file) {
  if (files_.erase(file) != 1) {
    LOG(WARNING) << "Removing file " << file << " not in map";
  }
  Publish(false);
}

void ServicePublisherAvahi::UpdateFileSize(const string& file,
                                           size_t file_size) {
  auto it = files_.find(file);
  if (it == files_.end()) {
    LOG(WARNING) << "Trying to set size for file " << file << " not in map";
    return;
  }
  it->second = file_size;
  Publish(true);
}

void ServicePublisherAvahi::SetNumConnections(int num_connections) {
  if (num_connections_ == num_connections)
    return;
  num_connections_ = num_connections;
  Publish(false);
}

map<string, size_t> ServicePublisherAvahi::files() {
  return files_;
}

// -----------------------------------------------------------------------------

ServicePublisher* ServicePublisher::Construct(uint16_t http_port) {
  ServicePublisherAvahi* instance = new ServicePublisherAvahi(http_port);
  if (!instance->Init()) {
    delete instance;
    return NULL;
  } else {
    return instance;
  }
}

}  // namespace server

}  // namespace p2p
