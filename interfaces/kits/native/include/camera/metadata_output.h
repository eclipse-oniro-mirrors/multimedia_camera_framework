/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef NATIVE_INCLUDE_CAMERA_METADATAOUTPUT_H
#define NATIVE_INCLUDE_CAMERA_METADATAOUTPUT_H

#include <stdint.h>
#include <stdio.h>
#include "camera.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @since 11
 * @version 1.0
 */
typedef struct Camera_MetadataOutput Camera_MetadataOutput;

typedef void (*OH_MetadataOutput_OnMetadataObjectAvailable)(Camera_MetadataOutput* metadataOutput,
    Camera_MetadataObject* metadataObject, uint32_t size);

typedef void (*OH_MetadataOutput_OnError)(Camera_MetadataOutput* metadataOutput, Camera_ErrorCode errorCode);

typedef struct MetadataOutput_Callbacks {
    OH_MetadataOutput_OnMetadataObjectAvailable onMetadataObjectAvailable;
    OH_MetadataOutput_OnError onError;
} MetadataOutput_Callbacks;

/**
 * @since 11
 * @version 1.0
 */
Camera_ErrorCode OH_MetadataOutput_RegisterCallback(Camera_MetadataOutput* metadataOutput,
    MetadataOutput_Callbacks* callback);

/**
 * @since 11
 * @version 1.0
 */
Camera_ErrorCode OH_MetadataOutput_UnregisterCallback(Camera_MetadataOutput* metadataOutput,
    MetadataOutput_Callbacks* callback);

/**
 * @since 11
 * @version 1.0
 */
Camera_ErrorCode OH_MetadataOutput_Start(Camera_MetadataOutput* metadataOutput);

/**
 * @since 11
 * @version 1.0
 */
Camera_ErrorCode OH_MetadataOutput_Stop(Camera_MetadataOutput* metadataOutput);

/**
 * @since 11
 * @version 1.0
 */
Camera_ErrorCode OH_MetadataOutput_Release(Camera_MetadataOutput* metadataOutput);

#ifdef __cplusplus
}
#endif

#endif // NATIVE_INCLUDE_CAMERA_METADATAOUTPUT_H