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
Camera_ErrorCode OH_PreviewOutput_RegisterCallback(Camera_PreviewOutput* previewOutput,
    PreviewOutput_Callbacks* callback)
{
    CHECK_AND_RETURN_RET_LOG(previewOutput != nullptr, CAMERA_INVALID_ARGUMENT,
        "invaild argument! previewOutput is null!");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, CAMERA_INVALID_ARGUMENT,
        "invaild argument! callback is null!");
    CHECK_AND_RETURN_RET_LOG(callback->onFrameStart!= nullptr, CAMERA_INVALID_ARGUMENT,
        "invaild argument! callback onFrameStart is null!");
    CHECK_AND_RETURN_RET_LOG(callback->onFrameEnd!= nullptr, CAMERA_INVALID_ARGUMENT,
        "invaild argument! callback onFrameEnd is null!");
    CHECK_AND_RETURN_RET_LOG(callback->onError!= nullptr, CAMERA_INVALID_ARGUMENT,
        "invaild argument! callback onError is null!");

    previewOutput->RegisterCallback(callback);
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
Camera_ErrorCode OH_PreviewOutput_UnregisterCallback(Camera_PreviewOutput* previewOutput,
    PreviewOutput_Callbacks* callback)
{
    CHECK_AND_RETURN_RET_LOG(previewOutput != nullptr, CAMERA_INVALID_ARGUMENT,
        "invaild argument! previewOutput is null!");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, CAMERA_INVALID_ARGUMENT,
        "invaild argument! callback is null!");
    CHECK_AND_RETURN_RET_LOG(callback->onFrameStart!= nullptr, CAMERA_INVALID_ARGUMENT,
        "invaild argument! callback onFrameStart is null!");
    CHECK_AND_RETURN_RET_LOG(callback->onFrameEnd!= nullptr, CAMERA_INVALID_ARGUMENT,
        "invaild argument! callback onFrameEnd is null!");
    CHECK_AND_RETURN_RET_LOG(callback->onError!= nullptr, CAMERA_INVALID_ARGUMENT,
        "invaild argument! callback onError is null!");

    previewOutput->UnregisterCallback(callback);
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
Camera_ErrorCode OH_PreviewOutput_Start(Camera_PreviewOutput* previewOutput)
{
    CHECK_AND_RETURN_RET_LOG(previewOutput != nullptr, CAMERA_INVALID_ARGUMENT,
        "invaild argument! previewOutput is null!");

    return previewOutput->Start();
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
Camera_ErrorCode OH_PreviewOutput_Stop(Camera_PreviewOutput* previewOutput)
{
    CHECK_AND_RETURN_RET_LOG(previewOutput != nullptr, CAMERA_INVALID_ARGUMENT,
        "invaild argument! previewOutput is null!");

    return previewOutput->Stop();
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
Camera_ErrorCode OH_PreviewOutput_Release(Camera_PreviewOutput* previewOutput)
{
    CHECK_AND_RETURN_RET_LOG(previewOutput != nullptr, CAMERA_INVALID_ARGUMENT,
        "invaild argument! previewOutput is null!");

    return previewOutput->Release();
}
#ifdef __cplusplus
}
#endif
