/*
 * Copyright 2014 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef DRM_H
#define DRM_H


#include <stdbool.h>
#include <stdio.h>
#include <xf86drm.h>
#include <xf86drmMode.h>

#define EDID_SIZE 0x80

// There are 4 DTD blocks in the EDID
#define EDID_DTD_BASE 0x36
#define EDID_N_DTDS 4

// 18 byte DTD structure
#define DTD_PCLK_LO 0
#define DTD_PCLK_HI 1
#define DTD_HA_LO 2
#define DTD_HBL_LO 3
#define DTD_HABL_HI 4
#define DTD_VA_LO 5
#define DTD_VBL_LO 6
#define DTD_VABL_HI 7
#define DTD_HSO_LO 8
#define DTD_HSW_LO 9
#define DTD_VSX_LO 10
#define DTD_HVSX_HI 11
#define DTD_HSIZE_LO 12
#define DTD_VSIZE_LO 13
#define DTD_HVSIZE_HI 14
#define DTD_HBORDER 15
#define DTD_VBORDER 16
#define DTD_FLAGS 17
#define DTD_SIZE 18

typedef struct _drm_t {
	int refcount;
	int fd;
	drmModeRes* resources;
	drmModePlaneResPtr plane_resources;
	uint32_t console_connector_id;
	uint32_t console_mmWidth;
	uint32_t console_mmHeight;
	bool console_connector_internal;
	drmModeModeInfo console_mode_info;
	bool edid_found;
	char edid[EDID_SIZE];
	uint32_t delayed_rmfb_fb_id;
	bool atomic;
	int32_t panel_orientation; // DRM_PANEL_ORIENTATION_*
} drm_t;

drm_t* drm_scan(void);
void drm_set(drm_t* drm);
void drm_close(void);
drm_t* drm_addref(void);
void drm_delref(drm_t* drm);
int drm_dropmaster(drm_t* drm);
int drm_setmaster(drm_t* drm);
bool drm_rescan(void);
bool drm_valid(drm_t* drm);
int32_t drm_setmode(drm_t* drm, uint32_t fb_id);
void drm_rmfb(drm_t* drm, uint32_t fb_id);
bool drm_read_edid(drm_t* drm);
uint32_t drm_gethres(drm_t* drm);
uint32_t drm_getvres(drm_t* drm);

#endif
