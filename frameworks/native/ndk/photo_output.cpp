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
 * @brief Acquire the video buffer for the av screen capture
 * @syscap SystemCapability.Multimedia.Media.AVScreenCapture
 * @param capture Pointer to an OH_AVScreenCapture instance
 * @param fence A processing state of display buffer
 * @param timestamp Information about the video buffer
 * @param region Information about the video buffer
 * @return Returns a pointer to an OH_NativeBuffer instance
 * @since 10
 * @version 1.0
 */
Camera_ErrorCode OH_PhotoOutput_RegisterCallback(Camera_PhotoOutput* photoOutput, PhotoOutput_Callbacks* callback)
{
    CHECK_AND_RETURN_RET_LOG(photoOutput != nullptr, CAMERA_INVALID_ARGUMENT,
        "invaild argument! photoOutput is null!");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, CAMERA_INVALID_ARGUMENT,
        "invaild argument! callback is null!");
    CHECK_AND_RETURN_RET_LOG(callback->onFrameStart!= nullptr, CAMERA_INVALID_ARGUMENT,
        "invaild argument! callback onFrameStart is null!");
    CHECK_AND_RETURN_RET_LOG(callback->onFrameEnd!= nullptr, CAMERA_INVALID_ARGUMENT,
        "invaild argument! callback onFrameEnd is null!");
    CHECK_AND_RETURN_RET_LOG(callback->onFrameShutter!= nullptr, CAMERA_INVALID_ARGUMENT,
        "invaild argument! callback onFrameShutter is null!");
    CHECK_AND_RETURN_RET_LOG(callback->onError!= nullptr, CAMERA_INVALID_ARGUMENT,
        "invaild argument! callback onError is null!");

    photoOutput->RegisterCallback(callback);
    return CAMERA_OK;
}

/**
 * @brief Acquire the video buffer for the av screen capture
 * @syscap SystemCapability.Multimedia.Media.AVScreenCapture
 * @param capture Pointer to an OH_AVScreenCapture instance
 * @param fence A processing state of display buffer
 * @param timestamp Information about the video buffer
 * @param region Information about the video buffer
 * @return Returns a pointer to an OH_NativeBuffer instance
 * @since 10
 * @version 1.0
 */
Camera_ErrorCode OH_PhotoOutput_UnregisterCallback(Camera_PhotoOutput* photoOutput, PhotoOutput_Callbacks* callback)
{
    CHECK_AND_RETURN_RET_LOG(photoOutput != nullptr, CAMERA_INVALID_ARGUMENT,
        "invaild argument! photoOutput is null!");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, CAMERA_INVALID_ARGUMENT,
        "invaild argument! callback is null!");
    CHECK_AND_RETURN_RET_LOG(callback->onFrameStart!= nullptr, CAMERA_INVALID_ARGUMENT,
        "invaild argument! callback onFrameStart is null!");
    CHECK_AND_RETURN_RET_LOG(callback->onFrameEnd!= nullptr, CAMERA_INVALID_ARGUMENT,
        "invaild argument! callback onFrameEnd is null!");
    CHECK_AND_RETURN_RET_LOG(callback->onError!= nullptr, CAMERA_INVALID_ARGUMENT,
        "invaild argument! callback onError is null!");

    photoOutput->UnregisterCallback(callback);
    return CAMERA_OK;
}

/**
 * @brief Acquire the video buffer for the av screen capture
 * @syscap SystemCapability.Multimedia.Media.AVScreenCapture
 * @param capture Pointer to an OH_AVScreenCapture instance
 * @param fence A processing state of display buffer
 * @param timestamp Information about the video buffer
 * @param region Information about the video buffer
 * @return Returns a pointer to an OH_NativeBuffer instance
 * @since 10
 * @version 1.0
 */
Camera_ErrorCode OH_PhotoOutput_Capture(Camera_PhotoOutput* photoOutput)
{
    CHECK_AND_RETURN_RET_LOG(photoOutput != nullptr, CAMERA_INVALID_ARGUMENT,
        "invaild argument! photoOutput is null!");

    return photoOutput->Capture();
}

/**
 * @brief Acquire the video buffer for the av screen capture
 * @syscap SystemCapability.Multimedia.Media.AVScreenCapture
 * @param capture Pointer to an OH_AVScreenCapture instance
 * @param fence A processing state of display buffer
 * @param timestamp Information about the video buffer
 * @param region Information about the video buffer
 * @return Returns a pointer to an OH_NativeBuffer instance
 * @since 10
 * @version 1.0
 */
Camera_ErrorCode OH_PhotoOutput_Capture_WithCaptureSetting(Camera_PhotoOutput* photoOutput,
    Camera_PhotoCaptureSetting setting)
{
    CHECK_AND_RETURN_RET_LOG(photoOutput != nullptr, CAMERA_INVALID_ARGUMENT,
        "invaild argument! photoOutput is null!");

    return photoOutput->Capture_WithCaptureSetting(setting);
}

/**
 * @brief Acquire the video buffer for the av screen capture
 * @syscap SystemCapability.Multimedia.Media.AVScreenCapture
 * @param capture Pointer to an OH_AVScreenCapture instance
 * @param fence A processing state of display buffer
 * @param timestamp Information about the video buffer
 * @param region Information about the video buffer
 * @return Returns a pointer to an OH_NativeBuffer instance
 * @since 10
 * @version 1.0
 */
Camera_ErrorCode OH_PhotoOutput_Release(Camera_PhotoOutput* photoOutput)
{
    CHECK_AND_RETURN_RET_LOG(photoOutput != nullptr, CAMERA_INVALID_ARGUMENT,
        "invaild argument! photoOutput is null!");

    return photoOutput->Release();
}

/**
 * @brief Acquire the video buffer for the av screen capture
 * @syscap SystemCapability.Multimedia.Media.AVScreenCapture
 * @param capture Pointer to an OH_AVScreenCapture instance
 * @param fence A processing state of display buffer
 * @param timestamp Information about the video buffer
 * @param region Information about the video buffer
 * @return Returns a pointer to an OH_NativeBuffer instance
 * @since 10
 * @version 1.0
 */
Camera_ErrorCode OH_PhotoOutput_IsMirrorSupported(Camera_PhotoOutput* photoOutput, bool* isSupported)
{
    CHECK_AND_RETURN_RET_LOG(photoOutput != nullptr, CAMERA_INVALID_ARGUMENT,
        "invaild argument! photoOutput is null!");
    CHECK_AND_RETURN_RET_LOG(isSupported != nullptr, CAMERA_INVALID_ARGUMENT,
        "invaild argument! isSupported is null!");

    return photoOutput->IsMirrorSupported(isSupported);
}

#ifdef __cplusplus
}
#endif
