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

#ifndef NATIVE_INCLUDE_CAMERA_PHOTOOUTPUT_H
#define NATIVE_INCLUDE_CAMERA_PHOTOOUTPUT_H

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
typedef struct Camera_PhotoOutput Camera_PhotoOutput;

typedef void (*OH_PhotoOutput_OnFrameStart)(Camera_PhotoOutput* photoOutput);

typedef void (*OH_PhotoOutput_OnFrameShutter)(Camera_PhotoOutput* photoOutput, Camera_FrameShutterInfo* info);

typedef void (*OH_PhotoOutput_OnFrameEnd)(Camera_PhotoOutput* photoOutput, int32_t frameCount);

typedef void (*OH_PhotoOutput_OnError)(Camera_PhotoOutput* photoOutput, Camera_ErrorCode errorCode);

typedef struct PhotoOutput_Callbacks {
    OH_PhotoOutput_OnFrameStart onFrameStart;
    OH_PhotoOutput_OnFrameShutter onFrameShutter;
    OH_PhotoOutput_OnFrameEnd onFrameEnd;
    OH_PhotoOutput_OnError onError;
} PhotoOutput_Callbacks;

/**
 * @since 11
 * @version 1.0
 */
Camera_ErrorCode OH_PhotoOutput_RegisterCallback(Camera_PhotoOutput* photoOutput, PhotoOutput_Callbacks* callback);

/**
 * @since 11
 * @version 1.0
 */
Camera_ErrorCode OH_PhotoOutput_UnregisterCallback(Camera_PhotoOutput* photoOutput, PhotoOutput_Callbacks* callback);

/**
 * @since 11
 * @version 1.0
 */
Camera_ErrorCode OH_PhotoOutput_Capture(Camera_PhotoOutput* photoOutput);

/**
 * @since 11
 * @version 1.0
 */
Camera_ErrorCode OH_PhotoOutput_Capture_WithCaptureSetting(Camera_PhotoOutput* photoOutput,
    Camera_PhotoCaptureSetting setting);

/**
 * @since 11
 * @version 1.0
 */
Camera_ErrorCode OH_PhotoOutput_Release(Camera_PhotoOutput* photoOutput);

/**
 * @since 11
 * @version 1.0
 */
Camera_ErrorCode OH_PhotoOutput_IsMirrorSupported(Camera_PhotoOutput* photoOutput, bool* isSupported);

#ifdef __cplusplus
}
#endif

#endif // NATIVE_INCLUDE_CAMERA_PHOTOOUTPUT_H