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

#include "kits/native/include/camera/camera_input.h"
#include "impl/camera_input_impl.h"
#include "camera_log.h"
#include "hilog/log.h"

#ifdef __cplusplus
extern "C" {
#endif

Camera_ErrorCode OH_CameraInput_RegisterCallback(Camera_Input* cameraInput, CameraInput_Callbacks* callback)
{
    CHECK_RETURN_RET_ELOG(cameraInput == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, cameraInput is null!");
    CHECK_RETURN_RET_ELOG(callback == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, callback is null!");
    CHECK_RETURN_RET_ELOG(callback->onError == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, callback onError is null!");
    cameraInput->RegisterCallback(callback);
    return CAMERA_OK;
}

Camera_ErrorCode OH_CameraInput_UnregisterCallback(Camera_Input* cameraInput, CameraInput_Callbacks* callback)
{
    CHECK_RETURN_RET_ELOG(cameraInput == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, cameraInput is null!");
    CHECK_RETURN_RET_ELOG(callback == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, callback is null!");
    CHECK_RETURN_RET_ELOG(callback->onError == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, callback onError is null!");
    cameraInput->UnregisterCallback(callback);
    return CAMERA_OK;
}

Camera_ErrorCode OH_CameraInput_Open(Camera_Input* cameraInput)
{
    CHECK_RETURN_RET_ELOG(cameraInput == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, cameraInput is null!");

    return cameraInput->Open();
}

Camera_ErrorCode OH_CameraInput_OpenSecureCamera(Camera_Input* cameraInput, uint64_t* secureSeqId)
{
    CHECK_RETURN_RET_ELOG(cameraInput == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, cameraInput is null!");
    CHECK_RETURN_RET_ELOG(secureSeqId == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, secureSeqId is null!");
    Camera_ErrorCode errorCode = cameraInput->OpenSecureCamera(secureSeqId);
    MEDIA_INFO_LOG("Camera_Input::OpenSecureCamera secureSeqId = %{public}" PRIu64 "", *secureSeqId);
    return errorCode;
}

Camera_ErrorCode OH_CameraInput_OpenConcurrentCameras(Camera_Input* cameraInput, Camera_ConcurrentType type)
{
    CHECK_RETURN_RET_ELOG(cameraInput == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, cameraInput is null!");
    Camera_ErrorCode errorCode = cameraInput->OpenConcurrentCameras(type);
    MEDIA_INFO_LOG("Camera_Input::OpenConcurrentCameras concurrentType = %{public}" PRIu32 "", type);
    return errorCode;
}

Camera_ErrorCode OH_CameraInput_Close(Camera_Input* cameraInput)
{
    CHECK_RETURN_RET_ELOG(cameraInput == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, cameraInput is null!");

    return cameraInput->Close();
}

Camera_ErrorCode OH_CameraInput_Release(Camera_Input* cameraInput)
{
    CHECK_RETURN_RET_ELOG(cameraInput == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, cameraInput is null!");

    cameraInput->Release();
    if (cameraInput != nullptr) {
        delete cameraInput;
    }
    return CAMERA_OK;
}

Camera_ErrorCode OH_CameraInput_IsPhysicalCameraOrientationVariable(Camera_Input* cameraInput, bool* isVariable)
{
    CHECK_RETURN_RET_ELOG(cameraInput == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, cameraInput is null!");
    CHECK_RETURN_RET_ELOG(isVariable == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, isVariable is null!");
    return cameraInput->IsPhysicalCameraOrientationVariable(isVariable);
}

Camera_ErrorCode OH_CameraInput_GetPhysicalCameraOrientation(Camera_Input* cameraInput, uint32_t* orientation)
{
    CHECK_RETURN_RET_ELOG(cameraInput == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, cameraInput is null!");
    CHECK_RETURN_RET_ELOG(orientation == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, orientation is null!");
    return cameraInput->GetPhysicalCameraOrientation(orientation);
}

Camera_ErrorCode OH_CameraInput_UsePhysicalCameraOrientation(Camera_Input* cameraInput, bool isUsed)
{
    CHECK_RETURN_RET_ELOG(cameraInput == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, cameraInput is null!");
    return cameraInput->UsePhysicalCameraOrientation(isUsed);
}

Camera_ErrorCode OH_CameraInput_RegisterOcclusionDetectionCallback(Camera_Input* cameraInput,
    OH_CameraInput_OnOcclusionDetectionCallback occlusionDetectionCallback)
{
    CHECK_RETURN_RET_ELOG(cameraInput == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, cameraInput is null!");
    CHECK_RETURN_RET_ELOG(occlusionDetectionCallback == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, callback is null!");
    return cameraInput->RegisterOcclusionDetectionCallback(occlusionDetectionCallback);
}

Camera_ErrorCode OH_CameraInput_UnregisterOcclusionDetectionCallback(Camera_Input* cameraInput,
    OH_CameraInput_OnOcclusionDetectionCallback occlusionDetectionCallback)
{
    CHECK_RETURN_RET_ELOG(cameraInput == nullptr, CAMERA_INVALID_ARGUMENT,
        "Invalid argument, cameraInput is null!");
    return cameraInput->UnregisterOcclusionDetectionCallback(occlusionDetectionCallback);
}

#ifdef __cplusplus
}
#endif