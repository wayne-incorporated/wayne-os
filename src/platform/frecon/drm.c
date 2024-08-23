/*
 * Copyright 2014 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#include "drm.h"
#include "input.h"
#include "util.h"

static drm_t* g_drm = NULL;

static int32_t atomic_set_prop(drm_t* drm, drmModeAtomicReqPtr pset, uint32_t id,
				drmModeObjectPropertiesPtr props, const char *name, uint64_t value)
{
	uint32_t u;
	int32_t ret;
	drmModePropertyPtr prop;

	for (u = 0; u < props->count_props; u++) {
		prop = drmModeGetProperty(drm->fd, props->props[u]);
		if (!prop)
			continue;
		if (strcmp(prop->name, name)) {
			drmModeFreeProperty(prop);
			continue;
		}
		ret = drmModeAtomicAddProperty(pset, id, prop->prop_id, value);
		if (ret < 0)
			LOG(ERROR, "setting atomic property %s failed with %d\n", name, ret);
		else
			ret = 0;
		drmModeFreeProperty(prop);
		return ret;
	}
	LOG(ERROR, "could not find atomic property %s\n", name);
	return -ENOENT;
}

static int32_t crtc_planes_num(drm_t* drm, int32_t crtc_index)
{
	drmModePlanePtr plane;
	int32_t planes_num = 0;
	drmModePlaneResPtr plane_resources = drmModeGetPlaneResources(drm->fd);

	if (!plane_resources)
		return 1; /* Just pretend there is one plane. */

	for (uint32_t p = 0; p < plane_resources->count_planes; p++) {
		plane = drmModeGetPlane(drm->fd, plane_resources->planes[p]);

		if (plane->possible_crtcs & (1 << crtc_index))
			planes_num++;

		drmModeFreePlane(plane);
	}
	drmModeFreePlaneResources(plane_resources);
	return planes_num;
}

static bool get_connector_path(drm_t* drm, uint32_t connector_id, uint32_t* ret_encoder_id, uint32_t* ret_crtc_id)
{
	drmModeConnector* connector = drmModeGetConnector(drm->fd, connector_id);
	drmModeEncoder* encoder;

	if (!connector)
		return false; /* Error. */

	if (ret_encoder_id)
		*ret_encoder_id = connector->encoder_id;
	if (!connector->encoder_id) {
		drmModeFreeConnector(connector);
		if (ret_crtc_id)
			*ret_crtc_id = 0;
		return true; /* Not connected. */
	}

	encoder = drmModeGetEncoder(drm->fd, connector->encoder_id);
	if (!encoder) {
		if (ret_crtc_id)
			*ret_crtc_id = 0;
		drmModeFreeConnector(connector);
		return false; /* Error. */
	}

	if (ret_crtc_id)
		*ret_crtc_id = encoder->crtc_id;

	drmModeFreeEncoder(encoder);
	drmModeFreeConnector(connector);
	return true; /* Connected. */
}

/* Find CRTC with most planes for given connector_id. */
static bool find_crtc_for_connector(drm_t* drm, uint32_t connector_id, uint32_t* ret_crtc_id)
{
	int enc;
	int32_t crtc_id = -1;
	int32_t max_crtc_planes = -1;
	drmModeConnector* connector = drmModeGetConnector(drm->fd, connector_id);

	if (!connector)
		return false;

	for (enc = 0; enc < connector->count_encoders; enc++) {
		int crtc;
		drmModeEncoder* encoder = drmModeGetEncoder(drm->fd, connector->encoders[enc]);

		if (encoder) {
			for (crtc = 0; crtc < drm->resources->count_crtcs; crtc++) {
				int32_t crtc_planes;

				if (!(encoder->possible_crtcs & (1 << crtc)))
					continue;

				crtc_planes = crtc_planes_num(drm, crtc);
				if (max_crtc_planes < crtc_planes) {
					crtc_id = drm->resources->crtcs[crtc];
					max_crtc_planes = crtc_planes;
				}
			}

			drmModeFreeEncoder(encoder);
			if (crtc_id != -1) {
				if (ret_crtc_id)
					*ret_crtc_id = crtc_id;
				drmModeFreeConnector(connector);
				return true;
			}
		}
	}

	drmModeFreeConnector(connector);
	return false;
}

static int drm_is_primary_plane(drm_t* drm, uint32_t plane_id)
{
	uint32_t p;
	bool found = false;
	int ret = -1;

	drmModeObjectPropertiesPtr props;
	props = drmModeObjectGetProperties(drm->fd,
					   plane_id,
					   DRM_MODE_OBJECT_PLANE);
	if (!props) {
		LOG(ERROR, "Unable to get plane properties: %m");
		return -1;
	}

	for (p = 0; p < props->count_props && !found; p++) {
		drmModePropertyPtr prop;
		prop = drmModeGetProperty(drm->fd, props->props[p]);
		if (prop) {
			if (strcmp("type", prop->name) == 0) {
				found = true;
				ret = (props->prop_values[p] == DRM_PLANE_TYPE_PRIMARY);
			}
			drmModeFreeProperty(prop);
		}
	}

	drmModeFreeObjectProperties(props);

	return ret;
}

/* Disable all planes except for primary on crtc we use. */
static void drm_disable_non_primary_planes(drm_t* drm, uint32_t console_crtc_id)
{
	int ret;

	if (!drm->plane_resources)
		return;

	for (uint32_t p = 0; p < drm->plane_resources->count_planes; p++) {
		drmModePlanePtr plane;
		plane = drmModeGetPlane(drm->fd,
					drm->plane_resources->planes[p]);
		if (plane) {
			int primary = drm_is_primary_plane(drm, plane->plane_id);
			if (!(plane->crtc_id == console_crtc_id && primary != 0)) {
				ret = drmModeSetPlane(drm->fd, plane->plane_id, plane->crtc_id,
						      0, 0,
						      0, 0,
						      0, 0,
						      0, 0,
						      0, 0);
				if (ret) {
					LOG(WARNING, "Unable to disable plane:%d %m", plane->plane_id);
				}
			}
			drmModeFreePlane(plane);
		}
	}
}

static bool drm_is_internal(unsigned type)
{
	unsigned t;
	unsigned kInternalConnectors[] = {
		DRM_MODE_CONNECTOR_LVDS,
		DRM_MODE_CONNECTOR_eDP,
		DRM_MODE_CONNECTOR_DSI,
	};
	for (t = 0; t < ARRAY_SIZE(kInternalConnectors); t++)
		if (type == kInternalConnectors[t])
			return true;
	return false;
}

static drmModeConnector* find_first_connected_connector(drm_t* drm, bool internal, bool external)
{
	for (int i = 0; i < drm->resources->count_connectors; i++) {
		drmModeConnector* connector;

		connector = drmModeGetConnector(drm->fd, drm->resources->connectors[i]);
		if (connector) {
			bool is_internal = drm_is_internal(connector->connector_type);
			if (!internal && is_internal)
				continue;
			if (!external && !is_internal)
				continue;
			if ((connector->count_modes > 0) &&
					(connector->connection == DRM_MODE_CONNECTED))
				return connector;

			drmModeFreeConnector(connector);
		}
	}
	return NULL;
}

static int find_panel_orientation(drm_t *drm)
{
	uint32_t p;
	bool found = false;
	drmModeObjectPropertiesPtr props;

	props = drmModeObjectGetProperties(drm->fd,
					   drm->console_connector_id,
					   DRM_MODE_OBJECT_CONNECTOR);
	if (!props) {
		LOG(ERROR, "Unable to get connector properties: %m");
		return -1;
	}

	for (p = 0; p < props->count_props && !found; p++) {
		drmModePropertyPtr prop;
		prop = drmModeGetProperty(drm->fd, props->props[p]);
		if (prop) {
			if (strcmp("panel orientation", prop->name) == 0) {
				found = true;
				drm->panel_orientation = (int32_t)(props->prop_values[p]);
			}
			drmModeFreeProperty(prop);
		}
	}

	drmModeFreeObjectProperties(props);
	return 0;
}


static bool find_main_monitor(drm_t* drm)
{
	int modes;
	uint32_t console_crtc_id = 0;
	int lid_state = input_check_lid_state();
	drmModeConnector* main_monitor_connector = NULL;

	drm->console_connector_id = 0;

	/*
	 * Find the LVDS/eDP/DSI connectors. Those are the main screens.
	 */
	if (lid_state <= 0)
		main_monitor_connector = find_first_connected_connector(drm, true, false);

	/*
	 * Now try external connectors.
	 */
	if (!main_monitor_connector)
		main_monitor_connector =
				find_first_connected_connector(drm, false, true);

	/*
	 * If we still didn't find a connector, give up and return.
	 */
	if (!main_monitor_connector)
		return false;

	if (!main_monitor_connector->count_modes)
		return false;

	drm->console_connector_id = main_monitor_connector->connector_id;
	drm->console_connector_internal = drm_is_internal(main_monitor_connector->connector_type);
	drm->console_mmWidth = main_monitor_connector->mmWidth;
	drm->console_mmHeight = main_monitor_connector->mmHeight;

	for (modes = 0; modes < main_monitor_connector->count_modes; modes++) {
		if (main_monitor_connector->modes[modes].type &
				DRM_MODE_TYPE_PREFERRED) {
			drm->console_mode_info = main_monitor_connector->modes[modes];
			break;
		}
	}
	/* If there was no preferred mode use first one. */
	if (modes == main_monitor_connector->count_modes)
		drm->console_mode_info = main_monitor_connector->modes[0];

	find_panel_orientation(drm);

	drmModeFreeConnector(main_monitor_connector);

	get_connector_path(drm, drm->console_connector_id, NULL, &console_crtc_id);

	if (!console_crtc_id)
		/* No existing path, find one. */
		find_crtc_for_connector(drm, drm->console_connector_id, &console_crtc_id);

	if (!console_crtc_id)
		/* Cannot find CRTC for connector. We will not be able to use it. */
		return false;

	return true;
}

static void drm_clear_rmfb(drm_t* drm)
{
	if (drm->delayed_rmfb_fb_id) {
		drmModeRmFB(drm->fd, drm->delayed_rmfb_fb_id);
		drm->delayed_rmfb_fb_id = 0;
	}
}

static void drm_fini(drm_t* drm)
{
	if (!drm)
		return;

	if (drm->fd >= 0) {
		drm_clear_rmfb(drm);

		if (drm->plane_resources) {
			drmModeFreePlaneResources(drm->plane_resources);
			drm->plane_resources = NULL;
		}

		if (drm->resources) {
			drmModeFreeResources(drm->resources);
			drm->resources = NULL;
		}

		drmClose(drm->fd);
		drm->fd = -1;
	}

	free(drm);
}

static bool drm_equal(drm_t* l, drm_t* r)
{
	if (!l && !r)
		return true;
	if ((!l && r) || (l && !r))
		return false;

	if (l->console_connector_id != r->console_connector_id)
		return false;
	return true;
}

static int drm_score(drm_t* drm)
{
	drmVersionPtr version;
	int score = 0;

	if (!drm)
		return -1000000000;

	if (!drm->console_connector_id)
		return -1000000000;

	if (drm->console_connector_internal)
		score++;

	version = drmGetVersion(drm->fd);
	if (version) {
		/* We would rather use any driver besides UDL. */
		if (strcmp("udl", version->name) == 0)
			score--;
		if (strcmp("evdi", version->name) == 0)
			score--;
		/* VGEM should be ignored because it has no displays, but lets make sure. */
		if (strcmp("vgem", version->name) == 0)
			score -= 1000000;
		drmFreeVersion(version);
	}
	return score;
}

/*
 * Scan and find best DRM object to display frecon on.
 * This object should be created with DRM master, and we will keep master till
 * first mode set or explicit drop master.
 */
drm_t* drm_scan(void)
{
	unsigned i;
	char* dev_name;
	int ret;
	drm_t *best_drm = NULL;

	for (i = 0; i < DRM_MAX_MINOR; i++) {
		uint64_t atomic = 0;
		drm_t* drm = calloc(1, sizeof(drm_t));

		if (!drm)
			return NULL;

try_open_again:
		ret = asprintf(&dev_name, DRM_DEV_NAME, DRM_DIR_NAME, i);
		if (ret < 0) {
			drm_fini(drm);
			continue;
		}
		drm->fd = open(dev_name, O_RDWR | O_CLOEXEC, 0);
		free(dev_name);
		if (drm->fd < 0) {
			drm_fini(drm);
			continue;
		}
		/* if we have master this should succeed */
		ret = drmSetMaster(drm->fd);
		if (ret != 0) {
			drmClose(drm->fd);
			drm->fd = -1;
			usleep(100*1000);
			goto try_open_again;
		}

		/* Set universal planes cap if possible. Ignore any errors. */
		drmSetClientCap(drm->fd, DRM_CLIENT_CAP_UNIVERSAL_PLANES, 1);

		ret = drmGetCap(drm->fd, DRM_CLIENT_CAP_ATOMIC, &atomic);
		if (!ret && atomic) {
			drm->atomic = true;
			ret = drmSetClientCap(drm->fd, DRM_CLIENT_CAP_ATOMIC, 1);
			if (ret < 0) {
				LOG(ERROR, "Failed to set atomic cap.");
				drm->atomic = false;
			}
		}

		drm->resources = drmModeGetResources(drm->fd);
		if (!drm->resources) {
			drm_fini(drm);
			continue;
		}

		/* Expect at least one crtc so we do not try to run on VGEM. */
		if (drm->resources->count_crtcs == 0 || drm->resources->count_connectors == 0) {
			drm_fini(drm);
			continue;
		}

		drm->plane_resources = drmModeGetPlaneResources(drm->fd);

		if (!find_main_monitor(drm)) {
			drm_fini(drm);
			continue;
		}

		drm->refcount = 1;

		if (drm_score(drm) > drm_score(best_drm)) {
			drm_fini(best_drm);
			best_drm = drm;
		} else {
			drm_fini(drm);
		}
	}

	if (best_drm) {
		drmVersionPtr version;
		version = drmGetVersion(best_drm->fd);
		if (version) {
			LOG(INFO,
			    "Frecon using drm driver %s, version %d.%d, date(%s), desc(%s)%s",
			    version->name,
			    version->version_major,
			    version->version_minor,
			    version->date,
			    version->desc,
			    best_drm->atomic ? " using atomic" : "");
			drmFreeVersion(version);
		}
	}

	return best_drm;
}

void drm_set(drm_t* drm_)
{
	if (g_drm) {
		drm_delref(g_drm);
		g_drm = NULL;
	}
	g_drm = drm_;
}

void drm_close(void)
{
	if (g_drm) {
		drm_delref(g_drm);
		g_drm = NULL;
	}
}

void drm_delref(drm_t* drm)
{
	if (!drm)
		return;
	if (drm->refcount) {
		drm->refcount--;
	} else {
		LOG(ERROR, "Imbalanced drm_close()");
	}
	if (drm->refcount) {
		return;
	}

	drm_fini(drm);
}

drm_t* drm_addref(void)
{
	if (g_drm) {
		g_drm->refcount++;
		return g_drm;
	}

	return NULL;
}

int drm_dropmaster(drm_t* drm)
{
	int ret = 0;

	if (!drm)
		drm = g_drm;
	if (drm)
		ret = drmDropMaster(drm->fd);
	return ret;
}

int drm_setmaster(drm_t* drm)
{
	int ret = 0;

	if (!drm)
		drm = g_drm;
	if (drm)
		ret = drmSetMaster(drm->fd);
	return ret;
}

/*
 * Returns true if connector/crtc/driver have changed and framebuffer object have to be re-created.
 */
bool drm_rescan(void)
{
	drm_t* ndrm;

	/* In case we had master, drop master so the newly created object could have it. */
	drm_dropmaster(g_drm);
	ndrm = drm_scan();
	if (ndrm) {
		if (drm_equal(ndrm, g_drm)) {
			drm_fini(ndrm);
			/* Regain master we dropped. */
			drm_setmaster(g_drm);
		} else {
			drm_delref(g_drm);
			g_drm = ndrm;
			return true;
		}
	} else {
		if (g_drm) {
			drm_delref(g_drm); /* No usable monitor/drm object. */
			g_drm = NULL;
			return true;
		}
	}
	return false;
}

bool drm_valid(drm_t* drm) {
	return drm && drm->fd >= 0 && drm->resources && drm->console_connector_id;
}

static bool is_crtc_possible(drm_t* drm, uint32_t crtc_id, uint32_t mask)
{
	int32_t crtc;
	for (crtc = 0; crtc < drm->resources->count_crtcs; crtc++)
		if (drm->resources->crtcs[crtc] == crtc_id)
			return !!(mask & (1u << crtc));

	return false;

}

#define CHECK(fn) do { ret = fn; if (ret < 0) goto error_mode; } while (0)
static int32_t drm_setmode_atomic(drm_t* drm, uint32_t fb_id)
{
	int32_t ret;
	int32_t crtc, conn;
	uint32_t plane;
	uint32_t console_crtc_id = 0;
	drmModeObjectPropertiesPtr crtc_props = NULL;
	drmModeObjectPropertiesPtr plane_props = NULL;
	drmModeObjectPropertiesPtr conn_props = NULL;
	drmModePlaneResPtr plane_resources;
	drmModeAtomicReqPtr pset = NULL;
	uint32_t mode_id = 0;

	plane_resources = drmModeGetPlaneResources(drm->fd);
	if (!plane_resources)
		return -ENOENT;

	get_connector_path(drm, drm->console_connector_id, NULL, &console_crtc_id);
	if (!console_crtc_id)
		find_crtc_for_connector(drm, drm->console_connector_id, &console_crtc_id);
	if (!console_crtc_id) {
		LOG(ERROR, "Could not get console crtc for connector:%d in modeset.\n", drm->console_connector_id);
		return -ENOENT;
	}

	pset = drmModeAtomicAlloc();
	if (!pset) {
		ret = -ENOMEM;
		goto error_mode;
	}

	for (crtc = 0; crtc < drm->resources->count_crtcs; crtc++) {
		uint32_t crtc_id = drm->resources->crtcs[crtc];

		crtc_props = drmModeObjectGetProperties(drm->fd, crtc_id, DRM_MODE_OBJECT_CRTC);

		if (!crtc_props) {
			LOG(ERROR, "Could not query properties for crtc %d %m.", crtc_id);
			if (crtc_id != console_crtc_id)
				continue;
			ret = -ENOENT;
			goto error_mode;
		}

		if (crtc_id == console_crtc_id) {
			CHECK(drmModeCreatePropertyBlob(drm->fd, &drm->console_mode_info,
							sizeof(drm->console_mode_info),
							&mode_id));
			/* drm->crtc->mode has been set during init */
			CHECK(atomic_set_prop(drm, pset, crtc_id, crtc_props, "MODE_ID", mode_id));
			CHECK(atomic_set_prop(drm, pset, crtc_id, crtc_props, "ACTIVE", 1));
			/* Reset color matrix to identity and gamma/degamma LUTs to pass through,
			 * ignore errors in case they are not supported. */
			atomic_set_prop(drm, pset, crtc_id, crtc_props, "CTM", 0);
			atomic_set_prop(drm, pset, crtc_id, crtc_props, "DEGAMMA_LUT", 0);
			atomic_set_prop(drm, pset, crtc_id, crtc_props, "GAMMA_LUT", 0);
		} else {
			CHECK(atomic_set_prop(drm, pset, crtc_id, crtc_props, "MODE_ID", 0));
			CHECK(atomic_set_prop(drm, pset, crtc_id, crtc_props, "ACTIVE", 0));
		}

		drmModeFreeObjectProperties(crtc_props);
		crtc_props = NULL;
	}

	for (plane = 0; plane < plane_resources->count_planes; plane++) {
		drmModePlanePtr planeobj;
		uint32_t plane_id = plane_resources->planes[plane];
		uint32_t possible_crtcs;
		int primary;

		planeobj = drmModeGetPlane(drm->fd, plane_id);
		if (!planeobj) {
			LOG(ERROR, "Could not query plane object for plane %d %m.", plane_id);
			ret = -ENOENT;
			goto error_mode;
		}

		possible_crtcs = planeobj->possible_crtcs;
		drmModeFreePlane(planeobj);

		primary = drm_is_primary_plane(drm, plane_id);

		plane_props = drmModeObjectGetProperties(drm->fd, plane_id, DRM_MODE_OBJECT_PLANE);
		if (!plane_props) {
			LOG(ERROR, "Could not query properties for plane %d %m.", plane_id);
			ret = -ENOENT;
			goto error_mode;
		}

		if (is_crtc_possible(drm, console_crtc_id, possible_crtcs) && primary) {
			CHECK(atomic_set_prop(drm, pset, plane_id, plane_props, "FB_ID", fb_id));
			CHECK(atomic_set_prop(drm, pset, plane_id, plane_props, "CRTC_ID", console_crtc_id));
			CHECK(atomic_set_prop(drm, pset, plane_id, plane_props, "CRTC_X", 0));
			CHECK(atomic_set_prop(drm, pset, plane_id, plane_props, "CRTC_Y", 0));
			CHECK(atomic_set_prop(drm, pset, plane_id, plane_props, "CRTC_W", drm->console_mode_info.hdisplay));
			CHECK(atomic_set_prop(drm, pset, plane_id, plane_props, "CRTC_H", drm->console_mode_info.vdisplay));
			CHECK(atomic_set_prop(drm, pset, plane_id, plane_props, "SRC_X", 0));
			CHECK(atomic_set_prop(drm, pset, plane_id, plane_props, "SRC_Y", 0));
			CHECK(atomic_set_prop(drm, pset, plane_id, plane_props, "SRC_W", drm->console_mode_info.hdisplay << 16));
			CHECK(atomic_set_prop(drm, pset, plane_id, plane_props, "SRC_H", drm->console_mode_info.vdisplay << 16));
		} else {
			CHECK(atomic_set_prop(drm, pset, plane_id, plane_props, "FB_ID", 0));
			CHECK(atomic_set_prop(drm, pset, plane_id, plane_props, "CRTC_ID", 0));
		}

		drmModeFreeObjectProperties(plane_props);
		plane_props = NULL;
	}

	for (conn = 0; conn < drm->resources->count_connectors; conn++) {
		uint32_t conn_id = drm->resources->connectors[conn];

		conn_props = drmModeObjectGetProperties(drm->fd, conn_id, DRM_MODE_OBJECT_CONNECTOR);
		if (!conn_props) {
			LOG(ERROR, "Could not query properties for connector %d %m.", conn_id);
			if (conn_id != drm->console_connector_id)
				continue;
			ret = -ENOENT;
			goto error_mode;
		}
		if (conn_id == drm->console_connector_id)
			CHECK(atomic_set_prop(drm, pset, conn_id, conn_props, "CRTC_ID", console_crtc_id));
		else
			CHECK(atomic_set_prop(drm, pset, conn_id, conn_props, "CRTC_ID", 0));
		drmModeFreeObjectProperties(conn_props);
		conn_props = NULL;
	}

	ret = drmModeAtomicCommit(drm->fd, pset,
				    DRM_MODE_ATOMIC_ALLOW_MODESET , NULL);
	if (ret < 0) {
		drm_clear_rmfb(drm);
		/* LOG(INFO, "TIMING: Console switch atomic modeset finished."); */
	} else {
		ret = 0;
	}

error_mode:
	if (mode_id)
		drmModeDestroyPropertyBlob(drm->fd, mode_id);

	if (plane_resources)
		drmModeFreePlaneResources(plane_resources);

	if (crtc_props)
		drmModeFreeObjectProperties(crtc_props);

	if (conn_props)
		drmModeFreeObjectProperties(conn_props);

	if (plane_props)
		drmModeFreeObjectProperties(plane_props);

	drmModeAtomicFree(pset);
	return ret;
}
#undef CHECK

static int remove_gamma_properties(drm_t* drm, uint32_t crtc_id) {
	drmModeObjectPropertiesPtr crtc_props = NULL;

	crtc_props = drmModeObjectGetProperties(drm->fd,
						crtc_id,
						DRM_MODE_OBJECT_CRTC);
	if (!crtc_props) {
		LOG(ERROR, "Could not query properties for crtc %d %m.", crtc_id);
		return -ENOENT;
	}

	for (uint32_t i = 0; i < crtc_props->count_props; i++) {
		drmModePropertyPtr prop;
		prop = drmModeGetProperty(drm->fd, crtc_props->props[i]);
		if (!prop)
			continue;

		// Remove the GAMMA_LUT and DEGAMMA_LUT properties.
		if (!strcmp(prop->name, "GAMMA_LUT") ||
		    !strcmp(prop->name, "DEGAMMA_LUT")) {
			// Ignore the return in case it is not supported.
			if (drmModeObjectSetProperty(drm->fd, crtc_id,
						     DRM_MODE_OBJECT_CRTC,
						     crtc_props->props[i],
						     0)) {
				LOG(ERROR, "Unable to remove %s from crtc:%d %m", prop->name, crtc_id);
			}
		}
		drmModeFreeProperty(prop);
	}
	drmModeFreeObjectProperties(crtc_props);
	return 0;
}


int32_t drm_setmode(drm_t* drm, uint32_t fb_id)
{
	int conn;
	int32_t ret;
	uint32_t existing_console_crtc_id = 0;

	if (drm->atomic)
		if (drm_setmode_atomic(drm, fb_id) == 0)
			return 0;
	       	/* Fallback to legacy mode set. */

	get_connector_path(drm, drm->console_connector_id, NULL, &existing_console_crtc_id);

	/* Loop through all the connectors, disable ones that are configured and set video mode on console connector. */
	for (conn = 0; conn < drm->resources->count_connectors; conn++) {
		uint32_t connector_id = drm->resources->connectors[conn];

		if (connector_id == drm->console_connector_id) {
			uint32_t console_crtc_id = 0;

			if (existing_console_crtc_id)
				console_crtc_id = existing_console_crtc_id;
			else {
				find_crtc_for_connector(drm, connector_id, &console_crtc_id);

				if (!console_crtc_id) {
					LOG(ERROR, "Could not get console crtc for connector:%d in modeset.\n", drm->console_connector_id);
					return -ENOENT;
				}
			}

			ret = drmModeSetCrtc(drm->fd, console_crtc_id,
					     fb_id,
					     0, 0,  // x,y
					     &drm->console_connector_id,
					     1,  // connector_count
					     &drm->console_mode_info); // mode

			if (ret) {
				LOG(ERROR, "Unable to set crtc:%d connector:%d %m", console_crtc_id, drm->console_connector_id);
				return ret;
			}

			ret = drmModeSetCursor(drm->fd, console_crtc_id,
						0, 0, 0);

			if (ret)
				LOG(ERROR, "Unable to hide cursor on crtc:%d %m.", console_crtc_id);

			ret = remove_gamma_properties(drm, console_crtc_id);
			if (ret)
				LOG(ERROR, "Unable to remove gamma LUT properties from crtc:%d %m.", console_crtc_id);

			drm_disable_non_primary_planes(drm, console_crtc_id);

		} else {
			uint32_t crtc_id = 0;

			get_connector_path(drm, connector_id, NULL, &crtc_id);
			if (!crtc_id)
				/* This connector is not configured, skip. */
				continue;

			if (existing_console_crtc_id && existing_console_crtc_id == crtc_id)
				/* This connector is mirroring from the same CRTC as console. It will be turned off when console is set. */
				continue;

			ret = drmModeSetCrtc(drm->fd, crtc_id, 0, // buffer_id
					     0, 0,  // x,y
					     NULL,  // connectors
					     0,     // connector_count
					     NULL); // mode
			if (ret)
				LOG(ERROR, "Unable to disable crtc %d: %m", crtc_id);
		}
	}

	drm_clear_rmfb(drm);
	/* LOG(INFO, "TIMING: Console switch modeset finished."); */
	return ret;
}

/*
 * Delayed rmfb(). We want to keep fb at least till after next modeset
 * so our transitions are cleaner (e.g. when recreating term after exitin
 * shell). Also it keeps fb around till Chrome starts.
 */
void drm_rmfb(drm_t* drm, uint32_t fb_id)
{
	drm_clear_rmfb(drm);
	drm->delayed_rmfb_fb_id = fb_id;
}

bool drm_read_edid(drm_t* drm)
{
	drmModeConnector* console_connector;
	if (drm->edid_found) {
		return true;
	}

	console_connector = drmModeGetConnector(drm->fd, drm->console_connector_id);

	if (!console_connector)
		return false;

	for (int i = 0; i < console_connector->count_props; i++) {
		drmModePropertyPtr prop;
		drmModePropertyBlobPtr blob_ptr;
		prop = drmModeGetProperty(drm->fd, console_connector->props[i]);
		if (prop) {
			if (strcmp(prop->name, "EDID") == 0) {
				blob_ptr = drmModeGetPropertyBlob(drm->fd,
					console_connector->prop_values[i]);
				if (blob_ptr) {
					memcpy(&drm->edid, blob_ptr->data, EDID_SIZE);
					drmModeFreePropertyBlob(blob_ptr);
					drmModeFreeConnector(console_connector);
					return (drm->edid_found = true);
				}
			}
		}
	}

	drmModeFreeConnector(console_connector);
	return false;
}

uint32_t drm_gethres(drm_t* drm)
{
	return drm->console_mode_info.hdisplay;
}

uint32_t drm_getvres(drm_t* drm)
{
	return drm->console_mode_info.vdisplay;
}
