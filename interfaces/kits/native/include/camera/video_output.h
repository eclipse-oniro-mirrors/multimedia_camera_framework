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

#ifndef NATIVE_INCLUDE_CAMERA_VIDEOOUTPUT_H
#define NATIVE_INCLUDE_CAMERA_VIDEOOUTPUT_H

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
typedef struct Camera_VideoOutput Camera_VideoOutput;

typedef void (*OH_VideoOutput_OnFrameStart)(Camera_VideoOutput* videoOutput);

typedef void (*OH_VideoOutput_OnFrameEnd)(Camera_VideoOutput* videoOutput, int32_t frameCount);

typedef void (*OH_VideoOutput_OnError)(Camera_VideoOutput* videoOutput, Camera_ErrorCode errorCode);

typedef struct VideoOutput_Callbacks {
    OH_VideoOutput_OnFrameStart onFrameStart;
    OH_VideoOutput_OnFrameEnd onFrameEnd;
    OH_VideoOutput_OnError onError;
} VideoOutput_Callbacks;

/**
 * @since 11
 * @version 1.0
 */
Camera_ErrorCode OH_VideoOutput_RegisterCallback(Camera_VideoOutput* videoOutput, VideoOutput_Callbacks* callback);

/**
 * @since 11
 * @version 1.0
 */
Camera_ErrorCode OH_VideoOutput_UnregisterCallback(Camera_VideoOutput* videoOutput, VideoOutput_Callbacks* callback);

/**
 * @since 11
 * @version 1.0
 */
Camera_ErrorCode OH_VideoOutput_Start(Camera_VideoOutput* videoOutput);

/**
 * @since 11
 * @version 1.0
 */
Camera_ErrorCode OH_VideoOutput_Stop(Camera_VideoOutput* videoOutput);

/**
 * @since 11
 * @version 1.0
 */
Camera_ErrorCode OH_VideoOutput_Release(Camera_VideoOutput* videoOutput);

#ifdef __cplusplus
}
#endif

#endif // NATIVE_INCLUDE_CAMERA_VIDEOOUTPUT_H