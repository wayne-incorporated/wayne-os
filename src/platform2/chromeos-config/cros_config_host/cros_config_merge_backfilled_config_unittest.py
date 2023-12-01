#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Tests for cros_config_merge_backfilled_config module."""

import unittest

# pylint: disable=import-error
from chromiumos.config.api import component_id_pb2
from chromiumos.config.api import component_pb2
from chromiumos.config.api import design_config_id_pb2
from chromiumos.config.api import design_id_pb2
from chromiumos.config.api import design_pb2
from chromiumos.config.api import device_brand_id_pb2
from chromiumos.config.api import device_brand_pb2
from chromiumos.config.api import partner_id_pb2
from chromiumos.config.api import partner_pb2
from chromiumos.config.api.software import bluetooth_config_pb2
from chromiumos.config.api.software import brand_config_pb2
from chromiumos.config.api.software import software_config_pb2
from chromiumos.config.payload import config_bundle_pb2
import cros_config_merge_backfilled_config


# pylint: enable=import-error


class CrosConfigMergeBackfilledConfigTest(unittest.TestCase):
    """Unit tests for cros_config_merge_backfilled_config"""

    def test_merge_config_bundles(self):
        cb = config_bundle_pb2.ConfigBundle(
            partner_list=[
                partner_pb2.Partner(
                    id=partner_id_pb2.PartnerId(value="partnerA"),
                    name="partnerNameA",
                ),
                partner_pb2.Partner(
                    id=partner_id_pb2.PartnerId(value="partnerC"),
                    name="partnerNameCOrig",
                ),
            ],
            design_list=[
                design_pb2.Design(
                    id=design_id_pb2.DesignId(value="designB"),
                    name="designBName",
                )
            ],
            components=[
                component_pb2.Component(
                    id=component_id_pb2.ComponentId(value="compA"),
                    name="compAName",
                )
            ],
            device_brand_list=[
                device_brand_pb2.DeviceBrand(
                    id=device_brand_id_pb2.DeviceBrandId(value="DeviceBrandA"),
                    brand_name="BrandNameA",
                )
            ],
            brand_configs=[
                brand_config_pb2.BrandConfig(
                    brand_id=device_brand_id_pb2.DeviceBrandId(
                        value="DeviceBrandA"
                    ),
                    wallpaper="DefaultWallpaper",
                ),
            ],
            software_configs=[
                software_config_pb2.SoftwareConfig(
                    design_config_id=design_config_id_pb2.DesignConfigId(
                        value="DesignConfigA"
                    ),
                    bluetooth_config=bluetooth_config_pb2.BluetoothConfig(
                        flags={"flag1": False}
                    ),
                ),
            ],
        )
        backfilled_cb = config_bundle_pb2.ConfigBundle(
            partner_list=[
                partner_pb2.Partner(
                    id=partner_id_pb2.PartnerId(value="partnerB"),
                    name="partnerNameB",
                ),
                partner_pb2.Partner(
                    id=partner_id_pb2.PartnerId(value="partnerC"),
                    name="partnerNameCModified",
                ),
            ],
            design_list=[
                design_pb2.Design(
                    id=design_id_pb2.DesignId(value="DesignB"),
                    name="designBName",
                )
            ],
            device_brand_list=[
                device_brand_pb2.DeviceBrand(
                    id=device_brand_id_pb2.DeviceBrandId(value="DeviceBrandB"),
                    brand_name="BrandNameB",
                )
            ],
        )

        expected_cb = config_bundle_pb2.ConfigBundle(
            partner_list=[
                partner_pb2.Partner(
                    id=partner_id_pb2.PartnerId(value="partnerA"),
                    name="partnerNameA",
                ),
                partner_pb2.Partner(
                    id=partner_id_pb2.PartnerId(value="partnerC"),
                    name="partnerNameCOrig",
                ),
                partner_pb2.Partner(
                    id=partner_id_pb2.PartnerId(value="partnerB"),
                    name="partnerNameB",
                ),
            ],
            components=[
                component_pb2.Component(
                    id=component_id_pb2.ComponentId(value="compA"),
                    name="compAName",
                )
            ],
            design_list=[
                design_pb2.Design(
                    id=design_id_pb2.DesignId(value="designB"),
                    name="designBName",
                )
            ],
            device_brand_list=[
                device_brand_pb2.DeviceBrand(
                    id=device_brand_id_pb2.DeviceBrandId(value="DeviceBrandA"),
                    brand_name="BrandNameA",
                ),
                device_brand_pb2.DeviceBrand(
                    id=device_brand_id_pb2.DeviceBrandId(value="DeviceBrandB"),
                    brand_name="BrandNameB",
                ),
            ],
            brand_configs=[
                brand_config_pb2.BrandConfig(
                    brand_id=device_brand_id_pb2.DeviceBrandId(
                        value="DeviceBrandA"
                    ),
                    wallpaper="DefaultWallpaper",
                ),
            ],
            software_configs=[
                software_config_pb2.SoftwareConfig(
                    design_config_id=design_config_id_pb2.DesignConfigId(
                        value="DesignConfigA"
                    ),
                    bluetooth_config=bluetooth_config_pb2.BluetoothConfig(
                        flags={"flag1": False}
                    ),
                ),
            ],
        )

        cros_config_merge_backfilled_config.merge_config_bundles(
            cb,
            backfilled_cb,
        )

        self.assertEqual(expected_cb, cb)


if __name__ == "__main__":
    unittest.main()
