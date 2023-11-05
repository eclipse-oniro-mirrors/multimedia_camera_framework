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

/**
 * @file preview_output.h
 * 
 * @brief Declare the preview output concepts.
 *
 * @library libcamera_ndk.so
 * @syscap SystemCapability.Multimedia.Camera.Core
 * @since 11
 * @version 1.0
 */

#ifndef NATIVE_INCLUDE_CAMERA_PREVIEWOUTPUT_H
#define NATIVE_INCLUDE_CAMERA_PREVIEWOUTPUT_H

#include <stdint.h>
#include <stdio.h>
#include "camera.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Preview output object
 *
 * A pointer can be created using {@link Camera_PreviewOutput} method.
 *
 * @since 11
 * @version 1.0
 */
typedef struct Camera_PreviewOutput Camera_PreviewOutput;

/**
 * @brief Preview output frame start callback to be called in {@link PreviewOutput_Callbacks}.
 *
 * @param previewOutput the {@link Camera_PreviewOutput} which deliver the callback.
 * @since 11
 */
typedef void (*OH_PreviewOutput_OnFrameStart)(Camera_PreviewOutput* previewOutput);

/**
 * @brief Preview output frame end callback to be called in {@link PreviewOutput_Callbacks}.
 *
 * @param previewOutput the {@link Camera_PreviewOutput} which deliver the callback.
 * @param frameCount the frame count which delivered by the callback.
 * @since 11
 */
typedef void (*OH_PreviewOutput_OnFrameEnd)(Camera_PreviewOutput* previewOutput, int32_t frameCount);

/**
 * @brief Preview output error callback to be called in {@link PreviewOutput_Callbacks}.
 *
 * @param previewOutput the {@link Camera_PreviewOutput} which deliver the callback.
 * @param errorCode the {@link Camera_ErrorCode} of the preview output.
 *
 * @see CAMERA_SERVICE_FATAL_ERROR
 * @since 11
 */
typedef void (*OH_PreviewOutput_OnError)(Camera_PreviewOutput* previewOutput, Camera_ErrorCode errorCode);

/**
 * @brief A listener for preview output.
 *
 * @see OH_PreviewOutput_RegisterCallback
 * @since 11
 * @version 1.0
 */
typedef struct PreviewOutput_Callbacks {
    OH_PreviewOutput_OnFrameStart onFrameStart;
    OH_PreviewOutput_OnFrameEnd onFrameEnd;
    OH_PreviewOutput_OnError onError;
} PreviewOutput_Callbacks;

/**
 * @since 11
 * @version 1.0
 */
Camera_ErrorCode OH_PreviewOutput_RegisterCallback(Camera_PreviewOutput* previewOutput,
    PreviewOutput_Callbacks* callback);

/**
 * @since 11
 * @version 1.0
 */
Camera_ErrorCode OH_PreviewOutput_UnregisterCallback(Camera_PreviewOutput* previewOutput,
    PreviewOutput_Callbacks* callback);

/**
 * @since 11
 * @version 1.0
 */
Camera_ErrorCode OH_PreviewOutput_Start(Camera_PreviewOutput* previewOutput);

/**
 * @since 11
 * @version 1.0
 */
Camera_ErrorCode OH_PreviewOutput_Stop(Camera_PreviewOutput* previewOutput);

/**
 * @since 11
 * @version 1.0
 */
Camera_ErrorCode OH_PreviewOutput_Release(Camera_PreviewOutput* previewOutput);

#ifdef __cplusplus
}
#endif

#endif // NATIVE_INCLUDE_CAMERA_PREVIEWOUTPUT_H