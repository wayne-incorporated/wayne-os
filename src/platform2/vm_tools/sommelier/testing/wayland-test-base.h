// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VM_TOOLS_SOMMELIER_TESTING_WAYLAND_TEST_BASE_H_
#define VM_TOOLS_SOMMELIER_TESTING_WAYLAND_TEST_BASE_H_

#include <gmock/gmock.h>
#include <sys/socket.h>
#include <vector>

#include "../sommelier.h"                // NOLINT(build/include_directory)
#include "aura-shell-client-protocol.h"  // NOLINT(build/include_directory)
#include "gaming-input-unstable-v2-client-protocol.h"  // NOLINT(build/include_directory)
#include "mock-wayland-channel.h"        // NOLINT(build/include_directory)
#include "sommelier-test-util.h"         // NOLINT(build/include_directory)
#include "viewporter-client-protocol.h"  // NOLINT(build/include_directory)
#include "xdg-output-unstable-v1-client-protocol.h"  // NOLINT(build/include_directory)
#include "xdg-shell-client-protocol.h"  // NOLINT(build/include_directory)

namespace vm_tools {
namespace sommelier {

using ::testing::_;
using ::testing::NiceMock;
using ::testing::Return;

// Create a Wayland client and connect it to Sommelier's Wayland server.
//
// Sets up an actual Wayland client which connects over a Unix socket,
// and can make Wayland requests in the same way as a regular client.
// However, it has no event loop so doesn't process events.
class FakeWaylandClient {
 public:
  explicit FakeWaylandClient(struct sl_context* ctx) {
    // Create a socket pair for libwayland-server and libwayland-client
    // to communicate over.
    int rv = socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv);
    errno_assert(!rv);
    // wl_client takes ownership of its file descriptor
    client = wl_client_create(ctx->host_display, sv[0]);
    errno_assert(!!client);
    sl_set_display_implementation(ctx, client);
    client_display = wl_display_connect_to_fd(sv[1]);
    EXPECT_NE(client_display, nullptr);

    client_registry = wl_display_get_registry(client_display);
    compositor = static_cast<wl_compositor*>(wl_registry_bind(
        client_registry, GlobalName(ctx, &wl_compositor_interface),
        &wl_compositor_interface, WL_COMPOSITOR_CREATE_SURFACE_SINCE_VERSION));
    if (!ctx->xwayland) {
      xdg_wm_base = static_cast<struct xdg_wm_base*>(wl_registry_bind(
          client_registry, GlobalName(ctx, &xdg_wm_base_interface),
          &xdg_wm_base_interface, XDG_WM_BASE_GET_XDG_SURFACE_SINCE_VERSION));
    }
    Flush();
  }

  ~FakeWaylandClient() {
    if (xdg_wm_base != nullptr) {
      xdg_wm_base_destroy(xdg_wm_base);
      xdg_wm_base = nullptr;
    }
    wl_display_disconnect(client_display);
    client_display = nullptr;
    wl_client_destroy(client);
    client = nullptr;
  }

  // Bind to wl_outputs with specified ids and return how many were bound.
  void BindToWlOutputs(struct sl_context* ctx, std::vector<int> ids) {
    unsigned int bound = 0;
    struct sl_global* global;
    wl_list_for_each(global, &ctx->globals, link) {
      // If global name is in list of ids.
      if (std::find(ids.begin(), ids.end(), global->name) != ids.end()) {
        EXPECT_EQ(global->interface, &wl_output_interface);
        outputs.push_back(static_cast<wl_output*>(
            wl_registry_bind(client_registry, global->name, global->interface,
                             WL_OUTPUT_DONE_SINCE_VERSION)));
        bound++;
      }
    }
    EXPECT_EQ(bound, ids.size());
    Flush();
  }

  // Bind to all wl_seats.
  void BindToWlSeats(struct sl_context* ctx) {
    struct sl_global* global;
    wl_list_for_each(global, &ctx->globals, link) {
      if (global->interface == &wl_seat_interface) {
        wl_registry_bind(client_registry, global->name, global->interface,
                         WL_OUTPUT_DONE_SINCE_VERSION);
      }
    }
    Flush();
  }

  // Create a surface.
  struct wl_surface* CreateSurface() {
    struct wl_surface* surface = wl_compositor_create_surface(compositor);
    Flush();
    return surface;
  }

  // Returns the xdg_wm_base object.
  struct xdg_wm_base* GetXdgWmBase() { return xdg_wm_base; }

  // Create an xdg_positioner object.
  struct xdg_positioner* CreatePositioner() {
    struct xdg_positioner* positioner =
        xdg_wm_base_create_positioner(xdg_wm_base);
    Flush();
    return positioner;
  }

  // Create an xdg_surface object.
  struct xdg_surface* CreateXdgSurface() {
    struct xdg_surface* surface =
        xdg_wm_base_get_xdg_surface(xdg_wm_base, CreateSurface());
    Flush();
    return surface;
  }

  void Flush() { wl_display_flush(client_display); }

  // Represents the client from the server's (Sommelier's) end.
  struct wl_client* client = nullptr;

  std::vector<wl_output*> outputs;

 protected:
  // Find the "name" of Sommelier's global for a particular interface,
  // so our fake client can bind to it. This is cheating (normally
  // these names would come from wl_registry.global events) but
  // easier than setting up a proper event loop for this fake client.
  uint32_t GlobalName(struct sl_context* ctx,
                      const struct wl_interface* for_interface) {
    struct sl_global* global;
    wl_list_for_each(global, &ctx->globals, link) {
      if (global->interface == for_interface) {
        return global->name;
      }
    }
    assert(false);
    return 0;
  }

  int sv[2];

  // Represents the server (Sommelier) from the client end.
  struct wl_display* client_display = nullptr;
  struct wl_registry* client_registry = nullptr;
  struct wl_compositor* compositor = nullptr;
  struct xdg_wm_base* xdg_wm_base = nullptr;
};

// Properties of a fake output (monitor) to advertise.
struct OutputConfig {
  int32_t x = 0;
  int32_t y = 0;
  int32_t physical_width_mm = 400;
  int32_t physical_height_mm = 225;
  int32_t width_pixels = 1920;
  int32_t height_pixels = 1080;
  int32_t transform = WL_OUTPUT_TRANSFORM_NORMAL;
  int32_t scale = 1;
  int32_t output_scale = 1000;
  int32_t logical_width = 1920;
  int32_t logical_height = 1080;
};

// Fixture for tests which exercise only Wayland functionality.
class WaylandTestBase : public ::testing::Test {
 public:
  void SetUp() override {
    ON_CALL(mock_wayland_channel_, create_context(_)).WillByDefault(Return(0));
    ON_CALL(mock_wayland_channel_, max_send_size())
        .WillByDefault(Return(DEFAULT_BUFFER_SIZE));
    EXPECT_CALL(mock_wayland_channel_, init).Times(1);
    sl_context_init_default(&ctx);
    ctx.host_display = wl_display_create();
    assert(ctx.host_display);

    ctx.channel = &mock_wayland_channel_;
    EXPECT_TRUE(sl_context_init_wayland_channel(
        &ctx, wl_display_get_event_loop(ctx.host_display), false));

    InitContext();
    Connect();
  }

  void TearDown() override {
    // Process any pending messages before the test exits.
    Pump();

    // TODO(cpelling): Destroy context and any created windows?
  }

  // Flush and dispatch Wayland client calls to the mock host.
  //
  // Called by default in TearDown(), but you can also trigger it midway
  // through the test.
  //
  // If you call `EXPECT_CALL(mock_wayland_channel_, send)` before Pump(), the
  // expectations won't trigger until the Pump() call.
  //
  // Conversely, calling Pump() before
  // `EXPECT_CALL(mock_wayland_channel_, send)` is useful to flush out
  // init messages not relevant to your test case.
  void Pump() {
    wl_display_flush(ctx.display);
    wl_event_loop_dispatch(wl_display_get_event_loop(ctx.host_display), 0);
  }

 protected:
  // Allow subclasses to customize the context prior to Connect().
  virtual void InitContext() {}

  // Set up the Wayland connection, compositor and registry.
  virtual void Connect() {
    ctx.display = wl_display_connect_to_fd(ctx.virtwl_display_fd);
    wl_registry* registry = wl_display_get_registry(ctx.display);

    // Fake the host compositor advertising globals.
    sl_registry_handler(&ctx, registry, next_server_id++, "wl_compositor",
                        kMinHostWlCompositorVersion);
    EXPECT_NE(ctx.compositor, nullptr);
    sl_registry_handler(&ctx, registry, next_server_id++, "xdg_wm_base",
                        XDG_WM_BASE_GET_XDG_SURFACE_SINCE_VERSION);
    sl_registry_handler(&ctx, registry, next_server_id++, "zaura_shell",
                        ZAURA_TOPLEVEL_SET_WINDOW_BOUNDS_SINCE_VERSION);
    sl_registry_handler(&ctx, registry, next_server_id++, "wp_viewporter",
                        WP_VIEWPORTER_DESTROY_SINCE_VERSION);
    sl_registry_handler(&ctx, registry, next_server_id++, "zcr_gaming_input_v2",
                        ZCR_GAMING_INPUT_V2_GET_GAMING_SEAT_SINCE_VERSION);
    sl_registry_handler(&ctx, registry, next_server_id++, "wl_seat",
                        WL_SEAT_RELEASE_SINCE_VERSION);
  }

  // Set up one or more fake outputs for the test.
  void AdvertiseOutputs(FakeWaylandClient* client,
                        std::vector<OutputConfig> outputs) {
    // The host compositor should advertise a wl_output global for each output.
    // Sommelier will handle this by forwarding the globals to its client.
    // global_ids stores the ids of the globals we are advertising so that
    // we can bind to them later.
    std::vector<int> global_ids = {};
    for (const auto& output : outputs) {
      UNUSED(output);  // suppress -Wunused-variable
      global_ids.push_back(ctx.next_global_id);
      uint32_t output_id = next_server_id++;
      sl_registry_handler(&ctx, wl_display_get_registry(ctx.display), output_id,
                          "wl_output", WL_OUTPUT_DONE_SINCE_VERSION);
    }

    // host_outputs populates when Sommelier's client binds to those globals.
    client->BindToWlOutputs(&ctx, global_ids);
    Pump();  // process the bind requests

    // Now the outputs are populated, we can advertise their settings.

    // sl_output_shift_output_x modifies ctx.host_outputs, therefore we are
    // putting them in a separate vector to iterate over. Newly bound outputs
    // are inserted at the end of the list, there should be as many as there
    // are configs.
    std::vector<sl_host_output*> new_outputs = {};
    int configs_left = outputs.size();
    sl_host_output* host_output;
    wl_list_for_each_reverse(host_output, &ctx.host_outputs, link) {
      new_outputs.push_back(host_output);
      if (--configs_left < 1) {
        break;
      }
    }
    // Reversing new_outputs as they were added in reverse.
    std::reverse(new_outputs.begin(), new_outputs.end());
    int i = 0;
    for (sl_host_output* output : new_outputs) {
      ConfigureOutput(output, outputs[i++]);
    }
    // host_outputs should be the requested length.
    EXPECT_EQ(new_outputs.size(), outputs.size());
  }

  void ConfigureOutput(sl_host_output* host_output,
                       const OutputConfig& config) {
    // This is mimicking components/exo/wayland/output_metrics.cc
    uint32_t flags = ZAURA_OUTPUT_SCALE_PROPERTY_CURRENT;
    if (config.output_scale == 1000) {
      flags |= ZAURA_OUTPUT_SCALE_PROPERTY_PREFERRED;
    }
    // zxdg_output is only bound when using direct scale.
    if (ctx.use_direct_scale) {
      HostEventHandler(host_output->zxdg_output)
          ->logical_size(nullptr, host_output->zxdg_output,
                         config.logical_width, config.logical_height);
    }
    HostEventHandler(host_output->aura_output)
        ->scale(nullptr, host_output->aura_output, flags, config.output_scale);
    HostEventHandler(host_output->proxy)
        ->geometry(nullptr, host_output->proxy, config.x, config.y,
                   config.physical_width_mm, config.physical_height_mm,
                   WL_OUTPUT_SUBPIXEL_NONE, "ACME Corp", "Generic Monitor",
                   config.transform);
    HostEventHandler(host_output->proxy)
        ->mode(nullptr, host_output->proxy,
               WL_OUTPUT_MODE_CURRENT | WL_OUTPUT_MODE_PREFERRED,
               config.width_pixels, config.height_pixels, 60);
    HostEventHandler(host_output->proxy)
        ->scale(nullptr, host_output->proxy, config.scale);
    HostEventHandler(host_output->proxy)->done(nullptr, host_output->proxy);
    Pump();
  }

  void RemoveOutput(sl_host_output* output) {
    struct sl_output* sl_output;
    wl_list_for_each(sl_output, &ctx.outputs, link) {
      if (output == sl_output->host_output) {
        sl_registry_remover(&ctx, wl_display_get_registry(ctx.display),
                            sl_output->id);
        break;
      }
    }
  }

  NiceMock<MockWaylandChannel> mock_wayland_channel_;
  sl_context ctx;

  // IDs allocated by the server are in the range [0xff000000, 0xffffffff].
  uint32_t next_server_id = 0xff000000;
};
}  // namespace sommelier
}  // namespace vm_tools

#endif  // VM_TOOLS_SOMMELIER_TESTING_WAYLAND_TEST_BASE_H_
