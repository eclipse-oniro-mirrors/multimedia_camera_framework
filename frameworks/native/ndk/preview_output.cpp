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

#include "kits/native/include/camera/preview_output.h"
#include "impl/preview_output_impl.h"
#include "camera_log.h"
#include "hilog/log.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @since 11
 * @version 1.0
 */
Camera_ErrorCode OH_PreviewOutput_RegisterCallback(Camera_PreviewOutput* previewOutput,
    PreviewOutput_Callbacks* callback)
{
    CHECK_AND_RETURN_RET_LOG(previewOutput != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, previewOutput is null!");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, callback is null!");
    CHECK_AND_RETURN_RET_LOG(callback->onFrameStart!= nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, callback onFrameStart is null!");
    CHECK_AND_RETURN_RET_LOG(callback->onFrameEnd!= nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, callback onFrameEnd is null!");
    CHECK_AND_RETURN_RET_LOG(callback->onError!= nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, callback onError is null!");

    previewOutput->RegisterCallback(callback);
    return CAMERA_OK;
}

/**
 * @since 11
 * @version 1.0
 */
Camera_ErrorCode OH_PreviewOutput_UnregisterCallback(Camera_PreviewOutput* previewOutput,
    PreviewOutput_Callbacks* callback)
{
    CHECK_AND_RETURN_RET_LOG(previewOutput != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, previewOutput is null!");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, callback is null!");
    CHECK_AND_RETURN_RET_LOG(callback->onFrameStart!= nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, callback onFrameStart is null!");
    CHECK_AND_RETURN_RET_LOG(callback->onFrameEnd!= nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, callback onFrameEnd is null!");
    CHECK_AND_RETURN_RET_LOG(callback->onError!= nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, callback onError is null!");

    previewOutput->UnregisterCallback(callback);
    return CAMERA_OK;
}

/**
 * @since 11
 * @version 1.0
 */
Camera_ErrorCode OH_PreviewOutput_Start(Camera_PreviewOutput* previewOutput)
{
    CHECK_AND_RETURN_RET_LOG(previewOutput != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, previewOutput is null!");

    return previewOutput->Start();
}

/**
 * @since 11
 * @version 1.0
 */
Camera_ErrorCode OH_PreviewOutput_Stop(Camera_PreviewOutput* previewOutput)
{
    CHECK_AND_RETURN_RET_LOG(previewOutput != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, previewOutput is null!");

    return previewOutput->Stop();
}

/**
 * @since 11
 * @version 1.0
 */
Camera_ErrorCode OH_PreviewOutput_Release(Camera_PreviewOutput* previewOutput)
{
    CHECK_AND_RETURN_RET_LOG(previewOutput != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, previewOutput is null!");

    Camera_ErrorCode retCode = previewOutput->Release();
    if (previewOutput != nullptr) {
        delete previewOutput;
    }
    return retCode;
}

/**
 * @since 12
 * @version 1.0
 */
Camera_ErrorCode OH_PreviewOutput_GetActiveProfile(Camera_PreviewOutput* previewOutput, Camera_Profile** profile)
{
    MEDIA_DEBUG_LOG("OH_PreviewOutput_GetActiveProfile is called.");
    CHECK_AND_RETURN_RET_LOG(previewOutput != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, previewOutput is null!");
    CHECK_AND_RETURN_RET_LOG(profile != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, profile is null!");

    return previewOutput->GetActiveProfile(profile);
}

/**
 * @since 12
 * @version 1.0
 */
Camera_ErrorCode OH_PreviewOutput_DeleteProfile(Camera_Profile* profile)
{
    MEDIA_DEBUG_LOG("OH_PreviewOutput_DeleteProfile is called.");
    CHECK_AND_RETURN_RET_LOG(profile != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, profile is null!");

    delete profile;
    profile = nullptr;
    return CAMERA_OK;
}

/**
 * @since 12
 * @version 1.0
 */
Camera_ErrorCode OH_PreviewOutput_GetSupportedFrameRates(Camera_PreviewOutput* previewOutput,
    Camera_FrameRateRange** frameRateRange, uint32_t* size)
{
    CHECK_AND_RETURN_RET_LOG(previewOutput != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, previewOutput is null!");
    CHECK_AND_RETURN_RET_LOG(frameRateRange != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, frameRateRange is null!");
    CHECK_AND_RETURN_RET_LOG(size != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, size is null!");

    return previewOutput->GetSupportedFrameRates(frameRateRange, size);
}

/**
 * @since 12
 * @version 1.0
 */
Camera_ErrorCode OH_PreviewOutput_DeleteFrameRates(Camera_PreviewOutput* previewOutput,
    Camera_FrameRateRange* frameRateRange)
{
    CHECK_AND_RETURN_RET_LOG(previewOutput != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, previewOutput is null!");
    CHECK_AND_RETURN_RET_LOG(frameRateRange != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, frameRateRange is null!");

    return previewOutput->DeleteFrameRates(frameRateRange);
}

/**
 * @since 12
 * @version 1.0
 */
Camera_ErrorCode OH_PreviewOutput_SetFrameRate(Camera_PreviewOutput* previewOutput,
    int32_t minFps, int32_t maxFps)
{
    CHECK_AND_RETURN_RET_LOG(previewOutput != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, previewOutput is null!");

    return previewOutput->SetFrameRate(minFps, maxFps);
}

/**
 * @since 12
 * @version 1.0
 */
Camera_ErrorCode OH_PreviewOutput_GetActiveFrameRate(Camera_PreviewOutput* previewOutput,
    Camera_FrameRateRange* frameRateRange)
{
    CHECK_AND_RETURN_RET_LOG(previewOutput != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, previewOutput is null!");
    CHECK_AND_RETURN_RET_LOG(frameRateRange != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, frameRateRange is null!");

    return previewOutput->GetActiveFrameRate(frameRateRange);
}
#ifdef __cplusplus
}
#endif