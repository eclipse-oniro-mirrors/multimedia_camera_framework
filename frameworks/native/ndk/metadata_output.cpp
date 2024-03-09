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

#include "kits/native/include/camera/metadata_output.h"
#include "impl/metadata_output_impl.h"
#include "camera_log.h"
#include "hilog/log.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @since 11
 * @version 1.0
 */
Camera_ErrorCode OH_MetadataOutput_RegisterCallback(Camera_MetadataOutput* metadataOutput,
    MetadataOutput_Callbacks* callback)
{
    CHECK_AND_RETURN_RET_LOG(metadataOutput != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, metadataOutput is null!");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, callback is null!");
    CHECK_AND_RETURN_RET_LOG(callback->onMetadataObjectAvailable!= nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, callback onMetadataObjectAvailable is null!");
    CHECK_AND_RETURN_RET_LOG(callback->onError!= nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, callback onError is null!");

    metadataOutput->RegisterCallback(callback);
    return CAMERA_OK;
}

/**
 * @since 11
 * @version 1.0
 */
Camera_ErrorCode OH_MetadataOutput_UnregisterCallback(Camera_MetadataOutput* metadataOutput,
    MetadataOutput_Callbacks* callback)
{
    CHECK_AND_RETURN_RET_LOG(metadataOutput != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, previewOutput is null!");
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, callback is null!");
    CHECK_AND_RETURN_RET_LOG(callback->onMetadataObjectAvailable!= nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, callback onMetadataObjectAvailable is null!");
    CHECK_AND_RETURN_RET_LOG(callback->onError!= nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, callback onError is null!");

    metadataOutput->UnregisterCallback(callback);
    return CAMERA_OK;
}

/**
 * @since 11
 * @version 1.0
 */
Camera_ErrorCode OH_MetadataOutput_Start(Camera_MetadataOutput* metadataOutput)
{
    CHECK_AND_RETURN_RET_LOG(metadataOutput != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, metadataOutput is null!");

    return metadataOutput->Start();
}

/**
 * @since 11
 * @version 1.0
 */
Camera_ErrorCode OH_MetadataOutput_Stop(Camera_MetadataOutput* metadataOutput)
{
    CHECK_AND_RETURN_RET_LOG(metadataOutput != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, metadataOutput is null!");

    return metadataOutput->Stop();
}

/**
 * @since 11
 * @version 1.0
 */
Camera_ErrorCode OH_MetadataOutput_Release(Camera_MetadataOutput* metadataOutput)
{
    CHECK_AND_RETURN_RET_LOG(metadataOutput != nullptr, CAMERA_INVALID_ARGUMENT,
        "Invaild argument, metadataOutput is null!");

    Camera_ErrorCode retCode = metadataOutput->Release();
    if (metadataOutput != nullptr) {
        delete metadataOutput;
    }
    return retCode;
}
#ifdef __cplusplus
}
#endif