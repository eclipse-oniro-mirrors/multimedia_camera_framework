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
    CHECK_AND_RETURN_RET_LOG(cameraInput != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, cameraInput is null!");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, callback is null!");
    CHECK_AND_RETURN_RET_LOG(callback->onError!= nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, callback onError is null!");
    cameraInput->RegisterCallback(callback);
    return CAMERA_OK;
}

Camera_ErrorCode OH_CameraInput_UnregisterCallback(Camera_Input* cameraInput, CameraInput_Callbacks* callback)
{
    CHECK_AND_RETURN_RET_LOG(cameraInput != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, cameraInput is null!");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, callback is null!");
    CHECK_AND_RETURN_RET_LOG(callback->onError!= nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, callback onError is null!");
    cameraInput->UnregisterCallback(callback);
    return CAMERA_OK;
}

Camera_ErrorCode OH_CameraInput_Open(Camera_Input* cameraInput)
{
    CHECK_AND_RETURN_RET_LOG(cameraInput != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, cameraInput is null!");

    return cameraInput->Open();
}

Camera_ErrorCode OH_CameraInput_OpenSecureCamera(Camera_Input* cameraInput, uint64_t* secureSeqId)
{
    CHECK_AND_RETURN_RET_LOG(cameraInput != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, cameraInput is null!");
    Camera_ErrorCode errorCode = cameraInput->OpenSecureCamera(secureSeqId);
    MEDIA_INFO_LOG("Camera_Input::OpenSecureCamera secureSeqId = %{public}" PRIu64 "", *secureSeqId);
    return errorCode;
}

Camera_ErrorCode OH_CameraInput_Close(Camera_Input* cameraInput)
{
    CHECK_AND_RETURN_RET_LOG(cameraInput != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, cameraInput is null!");

    return cameraInput->Close();
}

Camera_ErrorCode OH_CameraInput_Release(Camera_Input* cameraInput)
{
    CHECK_AND_RETURN_RET_LOG(cameraInput != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, cameraInput is null!");

    Camera_ErrorCode retCode = cameraInput->Release();
    if (cameraInput != nullptr) {
        delete cameraInput;
    }
    return retCode;
}

#ifdef __cplusplus
}
#endif