/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

#include "kits/native/include/camera/photo_output.h"
#include "impl/photo_output_impl.h"
#include "camera_log.h"
#include "hilog/log.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @since 11
 * @version 1.0
 */
Camera_ErrorCode OH_PhotoOutput_RegisterCallback(Camera_PhotoOutput* photoOutput, PhotoOutput_Callbacks* callback)
{
    CHECK_AND_RETURN_RET_LOG(photoOutput != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, photoOutput is null!");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, callback is null!");
    CHECK_AND_RETURN_RET_LOG(callback->onFrameStart != nullptr ||
        callback->onFrameEnd != nullptr ||
        callback->onFrameShutter != nullptr ||
        callback->onError != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, invalid callback!");

    photoOutput->RegisterCallback(callback);
    return CAMERA_OK;
}

/**
 * @since 11
 * @version 1.0
 */
Camera_ErrorCode OH_PhotoOutput_UnregisterCallback(Camera_PhotoOutput* photoOutput, PhotoOutput_Callbacks* callback)
{
    CHECK_AND_RETURN_RET_LOG(photoOutput != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, photoOutput is null!");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, callback is null!");
    CHECK_AND_RETURN_RET_LOG(callback->onFrameStart != nullptr ||
        callback->onFrameEnd != nullptr ||
        callback->onFrameShutter != nullptr ||
        callback->onError != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, invalid callback!");

    photoOutput->UnregisterCallback(callback);
    return CAMERA_OK;
}

/**
 * @since 12
 * @version 1.0
 */
Camera_ErrorCode OH_PhotoOutput_RegisterCaptureStartWithInfoCallback(Camera_PhotoOutput* photoOutput,
    OH_PhotoOutput_CaptureStartWithInfo callback)
{
    CHECK_AND_RETURN_RET_LOG(photoOutput != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, photoOutput is null!");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, callback is null!");
    photoOutput->RegisterCaptureStartWithInfoCallback(callback);
    return CAMERA_OK;
}

/**
 * @since 12
 * @version 1.0
 */
Camera_ErrorCode OH_PhotoOutput_UnregisterCaptureStartWithInfoCallback(Camera_PhotoOutput* photoOutput,
    OH_PhotoOutput_CaptureStartWithInfo callback)
{
    CHECK_AND_RETURN_RET_LOG(photoOutput != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, photoOutput is null!");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, callback is null!");
    photoOutput->UnregisterCaptureStartWithInfoCallback(callback);
    return CAMERA_OK;
}

/**
 * @since 12
 * @version 1.0
 */
Camera_ErrorCode OH_PhotoOutput_RegisterCaptureEndCallback(Camera_PhotoOutput* photoOutput,
    OH_PhotoOutput_CaptureEnd callback)
{
    CHECK_AND_RETURN_RET_LOG(photoOutput != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, photoOutput is null!");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, callback is null!");
    photoOutput->RegisterCaptureEndCallback(callback);
    return CAMERA_OK;
}

/**
 * @since 12
 * @version 1.0
 */
Camera_ErrorCode OH_PhotoOutput_UnregisterCaptureEndCallback(Camera_PhotoOutput* photoOutput,
    OH_PhotoOutput_CaptureEnd callback)
{
    CHECK_AND_RETURN_RET_LOG(photoOutput != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, photoOutput is null!");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, callback is null!");
    photoOutput->UnregisterCaptureEndCallback(callback);
    return CAMERA_OK;
}

/**
 * @since 12
 * @version 1.0
 */
Camera_ErrorCode OH_PhotoOutput_RegisterFrameShutterEndCallback(Camera_PhotoOutput* photoOutput,
    OH_PhotoOutput_OnFrameShutterEnd callback)
{
    CHECK_AND_RETURN_RET_LOG(photoOutput != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, photoOutput is null!");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, callback is null!");
    photoOutput->RegisterFrameShutterEndCallback(callback);
    return CAMERA_OK;
}

/**
 * @since 12
 * @version 1.0
 */
Camera_ErrorCode OH_PhotoOutput_UnregisterFrameShutterEndCallback(Camera_PhotoOutput* photoOutput,
    OH_PhotoOutput_OnFrameShutterEnd callback)
{
    CHECK_AND_RETURN_RET_LOG(photoOutput != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, photoOutput is null!");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, callback is null!");
    photoOutput->UnregisterFrameShutterEndCallback(callback);
    return CAMERA_OK;
}

/**
 * @since 12
 * @version 1.0
 */
Camera_ErrorCode OH_PhotoOutput_RegisterCaptureReadyCallback(Camera_PhotoOutput* photoOutput,
    OH_PhotoOutput_CaptureReady callback)
{
    CHECK_AND_RETURN_RET_LOG(photoOutput != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, photoOutput is null!");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, callback is null!");
    photoOutput->RegisterCaptureReadyCallback(callback);
    return CAMERA_OK;
}

/**
 * @since 12
 * @version 1.0
 */
Camera_ErrorCode OH_PhotoOutput_UnregisterCaptureReadyCallback(Camera_PhotoOutput* photoOutput,
    OH_PhotoOutput_CaptureReady callback)
{
    CHECK_AND_RETURN_RET_LOG(photoOutput != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, photoOutput is null!");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, callback is null!");
    photoOutput->UnregisterCaptureReadyCallback(callback);
    return CAMERA_OK;
}

/**
 * @since 12
 * @version 1.0
 */
Camera_ErrorCode OH_PhotoOutput_RegisterEstimatedCaptureDurationCallback(Camera_PhotoOutput* photoOutput,
    OH_PhotoOutput_EstimatedCaptureDuration callback)
{
    CHECK_AND_RETURN_RET_LOG(photoOutput != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, photoOutput is null!");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, callback is null!");
    photoOutput->RegisterEstimatedCaptureDurationCallback(callback);
    return CAMERA_OK;
}

/**
 * @since 12
 * @version 1.0
 */
Camera_ErrorCode OH_PhotoOutput_UnregisterEstimatedCaptureDurationCallback(Camera_PhotoOutput* photoOutput,
    OH_PhotoOutput_EstimatedCaptureDuration callback)
{
    CHECK_AND_RETURN_RET_LOG(photoOutput != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, photoOutput is null!");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, callback is null!");
    photoOutput->UnregisterEstimatedCaptureDurationCallback(callback);
    return CAMERA_OK;
}

/**
 * @since 11
 * @version 1.0
 */
Camera_ErrorCode OH_PhotoOutput_Capture(Camera_PhotoOutput* photoOutput)
{
    CHECK_AND_RETURN_RET_LOG(photoOutput != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, photoOutput is null!");

    return photoOutput->Capture();
}

/**
 * @since 11
 * @version 1.0
 */
Camera_ErrorCode OH_PhotoOutput_Capture_WithCaptureSetting(Camera_PhotoOutput* photoOutput,
    Camera_PhotoCaptureSetting setting)
{
    CHECK_AND_RETURN_RET_LOG(photoOutput != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, photoOutput is null!");

    return photoOutput->Capture_WithCaptureSetting(setting);
}

/**
 * @since 11
 * @version 1.0
 */
Camera_ErrorCode OH_PhotoOutput_Release(Camera_PhotoOutput* photoOutput)
{
    CHECK_AND_RETURN_RET_LOG(photoOutput != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, photoOutput is null!");

    Camera_ErrorCode retCode = photoOutput->Release();
    if (photoOutput != nullptr) {
        delete photoOutput;
    }
    return retCode;
}

/**
 * @since 11
 * @version 1.0
 */
Camera_ErrorCode OH_PhotoOutput_IsMirrorSupported(Camera_PhotoOutput* photoOutput, bool* isSupported)
{
    CHECK_AND_RETURN_RET_LOG(photoOutput != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, photoOutput is null!");
    CHECK_AND_RETURN_RET_LOG(isSupported != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, isSupported is null!");

    return photoOutput->IsMirrorSupported(isSupported);
}

/**
 * @since 12
 * @version 1.0
 */
Camera_ErrorCode OH_PhotoOutput_GetActiveProfile(Camera_PhotoOutput* photoOutput, Camera_Profile** profile)
{
    MEDIA_DEBUG_LOG("OH_PhotoOutput_GetActiveProfile is called.");
    CHECK_AND_RETURN_RET_LOG(photoOutput != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, photoOutput is null!");
    CHECK_AND_RETURN_RET_LOG(profile != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, profile is null!");

    return photoOutput->GetActiveProfile(profile);
}

/**
 * @since 12
 * @version 1.0
 */
Camera_ErrorCode OH_PhotoOutput_DeleteProfile(Camera_Profile* profile)
{
    MEDIA_DEBUG_LOG("OH_PhotoOutput_DeleteProfile is called.");
    CHECK_AND_RETURN_RET_LOG(profile != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, profile is null!");

    delete profile;
    profile = nullptr;
    return CAMERA_OK;
}
#ifdef __cplusplus
}
#endif