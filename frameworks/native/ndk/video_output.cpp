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

#include "kits/native/include/camera/video_output.h"
#include "impl/video_output_impl.h"
#include "camera_log.h"
#include "hilog/log.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @since 11
 * @version 1.0
 */
Camera_ErrorCode OH_VideoOutput_RegisterCallback(Camera_VideoOutput* videoOutput, VideoOutput_Callbacks* callback)
{
    CHECK_AND_RETURN_RET_LOG(videoOutput != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, videoOutput is null!");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, callback is null!");
    CHECK_AND_RETURN_RET_LOG(callback->onFrameStart!= nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, callback onFrameStart is null!");
    CHECK_AND_RETURN_RET_LOG(callback->onFrameEnd!= nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, callback onFrameEnd is null!");
    CHECK_AND_RETURN_RET_LOG(callback->onError!= nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, callback onError is null!");

    videoOutput->RegisterCallback(callback);
    return CAMERA_OK;
}

/**
 * @since 11
 * @version 1.0
 */
Camera_ErrorCode OH_VideoOutput_UnregisterCallback(Camera_VideoOutput* videoOutput, VideoOutput_Callbacks* callback)
{
    CHECK_AND_RETURN_RET_LOG(videoOutput != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, videoOutput is null!");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, callback is null!");
    CHECK_AND_RETURN_RET_LOG(callback->onFrameStart!= nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, callback onFrameStart is null!");
    CHECK_AND_RETURN_RET_LOG(callback->onFrameEnd!= nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, callback onFrameEnd is null!");
    CHECK_AND_RETURN_RET_LOG(callback->onError!= nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, callback onError is null!");

    videoOutput->UnregisterCallback(callback);
    return CAMERA_OK;
}

/**
 * @since 11
 * @version 1.0
 */
Camera_ErrorCode OH_VideoOutput_Start(Camera_VideoOutput* videoOutput)
{
    CHECK_AND_RETURN_RET_LOG(videoOutput != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, videoOutput is null!");

    return videoOutput->Start();
}

/**
 * @since 11
 * @version 1.0
 */
Camera_ErrorCode OH_VideoOutput_Stop(Camera_VideoOutput* videoOutput)
{
    CHECK_AND_RETURN_RET_LOG(videoOutput != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, videoOutput is null!");

    return videoOutput->Stop();
}

/**
 * @since 11
 * @version 1.0
 */
Camera_ErrorCode OH_VideoOutput_Release(Camera_VideoOutput* videoOutput)
{
    CHECK_AND_RETURN_RET_LOG(videoOutput != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, videoOutput is null!");

    Camera_ErrorCode retCode = videoOutput->Release();
    if (videoOutput != nullptr) {
        delete videoOutput;
    }
    return retCode;
}

#ifdef __cplusplus
}
#endif