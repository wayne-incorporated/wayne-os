/*
 * Copyright (C) 2019 MediaTek Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


STATIC_METADATA2_BEGIN(DEVICE, LENS, SENSOR_DRVNAME_OV02A10_MIPI_RAW)
//------------------------------------------------------------------------------
//  android.lens.info
//------------------------------------------------------------------------------
//==========================================================================
CONFIG_METADATA_BEGIN(MTK_LENS_INFO_AVAILABLE_APERTURES)
CONFIG_ENTRY_VALUE(2.0f, MFLOAT)
CONFIG_METADATA_END()

//==========================================================================
CONFIG_METADATA_BEGIN(MTK_LENS_INFO_AVAILABLE_FILTER_DENSITIES)
CONFIG_ENTRY_VALUE(0.0f, MFLOAT)
CONFIG_METADATA_END()
//==========================================================================
CONFIG_METADATA_BEGIN(MTK_LENS_INFO_AVAILABLE_FOCAL_LENGTHS)
CONFIG_ENTRY_VALUE(2.39f, MFLOAT)
CONFIG_METADATA_END()
//==========================================================================
CONFIG_METADATA_BEGIN(MTK_LENS_INFO_AVAILABLE_OPTICAL_STABILIZATION)
CONFIG_ENTRY_VALUE(MTK_LENS_OPTICAL_STABILIZATION_MODE_OFF, MUINT8)
CONFIG_METADATA_END()
//==========================================================================
CONFIG_METADATA_BEGIN(MTK_LENS_INFO_HYPERFOCAL_DISTANCE)
        CONFIG_ENTRY_VALUE(0, MFLOAT)     // fixed focus
CONFIG_METADATA_END()
//==========================================================================
CONFIG_METADATA_BEGIN(MTK_LENS_INFO_MINIMUM_FOCUS_DISTANCE)
        CONFIG_ENTRY_VALUE(0, MFLOAT)    // fixed focus
CONFIG_METADATA_END()
//==========================================================================
CONFIG_METADATA_BEGIN(MTK_LENS_INFO_FOCUS_DISTANCE_CALIBRATION)
CONFIG_ENTRY_VALUE(MTK_LENS_INFO_FOCUS_DISTANCE_CALIBRATION_UNCALIBRATED, MUINT8)
CONFIG_METADATA_END()
//==========================================================================
//    CONFIG_METADATA_BEGIN(MTK_LENS_INFO_SHADING_MAP,
//        1.f, 1.f, 1.f
//    )
//==========================================================================
CONFIG_METADATA_BEGIN(MTK_LENS_INFO_SHADING_MAP_SIZE)
CONFIG_ENTRY_VALUE(MSize(17, 17), MSize)
CONFIG_METADATA_END()
//==========================================================================
//------------------------------------------------------------------------------
STATIC_METADATA_END()

