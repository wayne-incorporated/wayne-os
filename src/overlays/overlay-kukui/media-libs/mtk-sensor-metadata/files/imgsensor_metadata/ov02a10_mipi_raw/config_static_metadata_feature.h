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


STATIC_METADATA2_BEGIN(DEVICE, FEATURE, SENSOR_DRVNAME_OV02A10_MIPI_RAW)
//------------------------------------------------------------------------------
//  android.control
//------------------------------------------------------------------------------
//==========================================================================
CONFIG_METADATA_BEGIN(MTK_CONTROL_AVAILABLE_VIDEO_STABILIZATION_MODES)
CONFIG_ENTRY_VALUE(MTK_CONTROL_VIDEO_STABILIZATION_MODE_OFF, MUINT8)
CONFIG_ENTRY_VALUE(MTK_CONTROL_VIDEO_STABILIZATION_MODE_ON, MUINT8)
CONFIG_METADATA_END()
//==========================================================================
//------------------------------------------------------------------------------
//  android.stats.info
//------------------------------------------------------------------------------
//==========================================================================
CONFIG_METADATA_BEGIN(MTK_STATISTICS_INFO_AVAILABLE_FACE_DETECT_MODES)
CONFIG_ENTRY_VALUE(MTK_STATISTICS_FACE_DETECT_MODE_OFF, MUINT8)
CONFIG_ENTRY_VALUE(MTK_STATISTICS_FACE_DETECT_MODE_SIMPLE, MUINT8)
//        CONFIG_ENTRY_VALUE(MTK_STATISTICS_FACE_DETECT_MODE_FULL,MUINT8)
CONFIG_METADATA_END()
//==========================================================================
CONFIG_METADATA_BEGIN(MTK_STATISTICS_INFO_MAX_FACE_COUNT)
CONFIG_ENTRY_VALUE(15,  MINT32)
CONFIG_METADATA_END()
//==========================================================================
//==========================================================================
CONFIG_METADATA_BEGIN(MTK_FACE_FEATURE_AVAILABLE_GESTURE_MODES)
CONFIG_ENTRY_VALUE(MTK_FACE_FEATURE_GESTURE_MODE_OFF,  MINT32)
//CONFIG_ENTRY_VALUE(MTK_FACE_FEATURE_GESTURE_MODE_SIMPLE,  MINT32)
CONFIG_METADATA_END()
//==========================================================================
//==========================================================================
CONFIG_METADATA_BEGIN(MTK_FACE_FEATURE_AVAILABLE_SMILE_DETECT_MODES)
CONFIG_ENTRY_VALUE(MTK_FACE_FEATURE_SMILE_DETECT_MODE_OFF,  MINT32)
//CONFIG_ENTRY_VALUE(MTK_FACE_FEATURE_SMILE_DETECT_MODE_SIMPLE,  MINT32)
CONFIG_METADATA_END()
//==========================================================================
//==========================================================================
CONFIG_METADATA_BEGIN(MTK_FACE_FEATURE_AVAILABLE_ASD_MODES)
CONFIG_ENTRY_VALUE(MTK_FACE_FEATURE_ASD_MODE_OFF,  MINT32)
CONFIG_ENTRY_VALUE(MTK_FACE_FEATURE_ASD_MODE_SIMPLE,  MINT32)
CONFIG_METADATA_END()
//==========================================================================
//==========================================================================
CONFIG_METADATA_BEGIN(MTK_FACE_FEATURE_AVAILABLE_FORCE_FACE_3A)
CONFIG_ENTRY_VALUE(0,  MINT32)
CONFIG_ENTRY_VALUE(1,  MINT32)
CONFIG_METADATA_END()
//==========================================================================
//==========================================================================
CONFIG_METADATA_BEGIN(MTK_NR_FEATURE_AVAILABLE_3DNR_MODES)
CONFIG_ENTRY_VALUE(MTK_NR_FEATURE_3DNR_MODE_OFF,  MINT32)
CONFIG_ENTRY_VALUE(MTK_NR_FEATURE_3DNR_MODE_ON,  MINT32)
CONFIG_METADATA_END()
//==========================================================================
//==========================================================================
#if (1 == MTKCAM_HAVE_VHDR_SUPPORT)
CONFIG_METADATA_BEGIN(MTK_HDR_FEATURE_AVAILABLE_VHDR_MODES)
CONFIG_ENTRY_VALUE(MTK_HDR_FEATURE_VHDR_MODE_OFF,  MINT32) // MUST Add this mode
CONFIG_METADATA_END()
#endif
//==========================================================================
//------------------------------------------------------------------------------
STATIC_METADATA_END()

