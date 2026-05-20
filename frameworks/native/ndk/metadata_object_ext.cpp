/*
 * Copyright (c) 2026-2026 Huawei Device Co., Ltd.
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

#include "kits/native/include/camera/metadata_object_ext.h"
#include "impl/metadata_object_ext_impl.h"
#include "camera_log.h"
#include "hilog/log.h"

#ifdef __cplusplus
extern "C" {
#endif

Camera_ErrorCode OH_MetadataObjectExt_GetMetadataObjectType(
    const OH_Camera_MetadataObjectExt* metadataObjectExt,
    Camera_MetadataObjectType* type)
{
    CHECK_RETURN_RET_ELOG(
        metadataObjectExt == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, metadataObjectExt is null!");
    CHECK_RETURN_RET_ELOG(
        type == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, type is null!");

    return metadataObjectExt->GetMetadataObjectType(type);
}

Camera_ErrorCode OH_MetadataObjectExt_GetTimestamp(
    const OH_Camera_MetadataObjectExt* metadataObjectExt,
    int64_t* timestamp)
{
    CHECK_RETURN_RET_ELOG(
        metadataObjectExt == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, metadataObjectExt is null!");
    CHECK_RETURN_RET_ELOG(
        timestamp == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, timestamp is null!");

    return metadataObjectExt->GetTimestamp(timestamp);
}

Camera_ErrorCode OH_MetadataObjectExt_GetBoundingBox(
    const OH_Camera_MetadataObjectExt* metadataObjectExt,
    OH_Camera_Rect_Ext* boundingBox)
{
    CHECK_RETURN_RET_ELOG(
        metadataObjectExt == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, metadataObjectExt is null!");
    CHECK_RETURN_RET_ELOG(
        boundingBox == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, boundingBox is null!");

    return metadataObjectExt->GetBoundingBox(boundingBox);
}

Camera_ErrorCode OH_MetadataObjectExt_GetPitchAngle(
    const OH_Camera_MetadataObjectExt* metadataObjectExt,
    float* pitchAngle)
{
    CHECK_RETURN_RET_ELOG(
        metadataObjectExt == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, metadataObjectExt is null!");
    CHECK_RETURN_RET_ELOG(
        pitchAngle == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, pitchAngle is null!");

    return metadataObjectExt->GetPitchAngle(pitchAngle);
}

Camera_ErrorCode OH_MetadataObjectExt_GetYawAngle(
    const OH_Camera_MetadataObjectExt* metadataObjectExt,
    float* yawAngle)
{
    CHECK_RETURN_RET_ELOG(
        metadataObjectExt == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, metadataObjectExt is null!");
    CHECK_RETURN_RET_ELOG(
        yawAngle == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, yawAngle is null!");

    return metadataObjectExt->GetYawAngle(yawAngle);
}

Camera_ErrorCode OH_MetadataObjectExt_GetRollAngle(
    const OH_Camera_MetadataObjectExt* metadataObjectExt,
    float* rollAngle)
{
    CHECK_RETURN_RET_ELOG(
        metadataObjectExt == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, metadataObjectExt is null!");
    CHECK_RETURN_RET_ELOG(
        rollAngle == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, rollAngle is null!");

    return metadataObjectExt->GetRollAngle(rollAngle);
}

Camera_ErrorCode OH_MetadataObjectExt_GetLeftEyeBoundingBox(
    const OH_Camera_MetadataObjectExt* metadataObjectExt,
    OH_Camera_Rect_Ext* boundingBox)
{
    CHECK_RETURN_RET_ELOG(
        metadataObjectExt == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, metadataObjectExt is null!");
    CHECK_RETURN_RET_ELOG(
        boundingBox == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, boundingBox is null!");

    return metadataObjectExt->GetLeftEyeBoundingBox(boundingBox);
}

Camera_ErrorCode OH_MetadataObjectExt_GetRightEyeBoundingBox(
    const OH_Camera_MetadataObjectExt* metadataObjectExt,
    OH_Camera_Rect_Ext* boundingBox)
{
    CHECK_RETURN_RET_ELOG(
        metadataObjectExt == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, metadataObjectExt is null!");
    CHECK_RETURN_RET_ELOG(
        boundingBox == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, boundingBox is null!");

    return metadataObjectExt->GetRightEyeBoundingBox(boundingBox);
}

Camera_ErrorCode OH_MetadataObjectExt_GetEmotion(
    const OH_Camera_MetadataObjectExt* metadataObjectExt,
    OH_Camera_MetadataObjectEmotion* emotion)
{
    CHECK_RETURN_RET_ELOG(
        metadataObjectExt == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, metadataObjectExt is null!");
    CHECK_RETURN_RET_ELOG(
        emotion == nullptr, CAMERA_INVALID_ARGUMENT, "Invalid argument, emotion is null!");

    return metadataObjectExt->GetEmotion(emotion);
}

void OH_MetadataObjectExt_Destroy(
    OH_Camera_MetadataObjectExt** metadataObjectExt,
    uint32_t objectCount)
{
    CHECK_RETURN_ELOG(metadataObjectExt == nullptr, "Invalid argument, metadataObjectExt is null!");
    for (uint32_t i = 0; i < objectCount; i++) {
        CHECK_EXECUTE(metadataObjectExt[i] != nullptr,
                      delete metadataObjectExt[i];
                      metadataObjectExt[i] = nullptr);
    }
    delete[] metadataObjectExt;
}

#ifdef __cplusplus
}
#endif
