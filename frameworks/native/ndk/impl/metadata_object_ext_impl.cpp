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

#include "metadata_object_ext_impl.h"
#include "camera_log.h"

using namespace OHOS;
using namespace OHOS::CameraStandard;

OH_Camera_MetadataObjectExt::OH_Camera_MetadataObjectExt(
    const OHOS::sptr<OHOS::CameraStandard::MetadataObject> &innerObject)
    : innerObject_(innerObject)
{
    MEDIA_DEBUG_LOG("Camera_MetadataObjectExt Constructor is called");
}

OH_Camera_MetadataObjectExt::~OH_Camera_MetadataObjectExt()
{
    MEDIA_DEBUG_LOG("~OH_Camera_MetadataObjectExt is called");
    innerObject_ = nullptr;
}

Camera_ErrorCode OH_Camera_MetadataObjectExt::GetMetadataObjectType(Camera_MetadataObjectType* type) const
{
    CHECK_RETURN_RET_ELOG(type == nullptr, CAMERA_INVALID_ARGUMENT,
                          "Camera_MetadataObjectExt: type == nullptr");
    *type = static_cast<Camera_MetadataObjectType>(innerObject_->GetType());
    return CAMERA_OK;
}

Camera_ErrorCode OH_Camera_MetadataObjectExt::GetTimestamp(int64_t* timestamp) const
{
    CHECK_RETURN_RET_ELOG(timestamp == nullptr, CAMERA_INVALID_ARGUMENT,
                          "OH_Camera_MetadataObjectExt: timestamp == nullptr");
    *timestamp = innerObject_->GetTimestamp();
    return CAMERA_OK;
}

Camera_ErrorCode OH_Camera_MetadataObjectExt::GetBoundingBox(OH_Camera_Rect_Ext* boundingBox) const
{
    CHECK_RETURN_RET_ELOG(boundingBox == nullptr, CAMERA_INVALID_ARGUMENT,
                          "Camera_MetadataObjectExt: boundingBox == nullptr");
    OHOS::CameraStandard::Rect innerRect = innerObject_->GetBoundingBox();
    boundingBox->topLeftX = innerRect.topLeftX;
    boundingBox->topLeftY = innerRect.topLeftY;
    boundingBox->width = innerRect.width;
    boundingBox->height = innerRect.height;
    return CAMERA_OK;
}

Camera_ErrorCode OH_Camera_MetadataObjectExt::GetPitchAngle(float* pitchAngle) const
{
    CHECK_RETURN_RET_ELOG(pitchAngle == nullptr, CAMERA_INVALID_ARGUMENT,
                          "Camera_MetadataObjectExt: pitchAngle == nullptr");

    CHECK_EXECUTE(innerObject_->GetType() == MetadataObjectType::FACE,
                  *pitchAngle = static_cast<MetadataFaceObject*>(innerObject_.GetRefPtr())->GetPitchAngle();
                   return CAMERA_OK);
    return CAMERA_ERROR_OPTIONAL_PROPERTY_NOT_EXIST;
}

Camera_ErrorCode OH_Camera_MetadataObjectExt::GetYawAngle(float* yawAngle) const
{
    CHECK_RETURN_RET_ELOG(yawAngle == nullptr, CAMERA_INVALID_ARGUMENT,
                          "Camera_MetadataObjectExt: yawAngle == nullptr");

    CHECK_EXECUTE(innerObject_->GetType() == MetadataObjectType::FACE,
                  *yawAngle = static_cast<MetadataFaceObject*>(innerObject_.GetRefPtr())->GetYawAngle();
                   return CAMERA_OK);
    return CAMERA_ERROR_OPTIONAL_PROPERTY_NOT_EXIST;
}

Camera_ErrorCode OH_Camera_MetadataObjectExt::GetRollAngle(float* rollAngle) const
{
    CHECK_RETURN_RET_ELOG(rollAngle == nullptr, CAMERA_INVALID_ARGUMENT,
                          "Camera_MetadataObjectExt: rollAngle == nullptr");

    CHECK_EXECUTE(innerObject_->GetType() == MetadataObjectType::FACE,
                  *rollAngle = static_cast<MetadataFaceObject*>(innerObject_.GetRefPtr())->GetRollAngle();
                   return CAMERA_OK);
    return CAMERA_ERROR_OPTIONAL_PROPERTY_NOT_EXIST;
}

Camera_ErrorCode OH_Camera_MetadataObjectExt::GetLeftEyeBoundingBox(OH_Camera_Rect_Ext* boundingBox) const
{
    CHECK_RETURN_RET_ELOG(boundingBox == nullptr, CAMERA_INVALID_ARGUMENT,
                          "Camera_MetadataObjectExt: boundingBox == nullptr");

    OHOS::CameraStandard::Rect innerRect;
    bool supported = false;

    CHECK_EXECUTE(innerObject_->GetType() == MetadataObjectType::FACE,
                  innerRect = static_cast<MetadataFaceObject*>(innerObject_.GetRefPtr())->GetLeftEyeBoundingBox();
                  supported = true);
    CHECK_EXECUTE(innerObject_->GetType() == MetadataObjectType::CAT_FACE,
                  innerRect = static_cast<MetadataCatFaceObject*>(innerObject_.GetRefPtr())->GetLeftEyeBoundingBox();
                  supported = true);
    CHECK_EXECUTE(innerObject_->GetType() == MetadataObjectType::DOG_FACE,
                  innerRect = static_cast<MetadataDogFaceObject*>(innerObject_.GetRefPtr())->GetLeftEyeBoundingBox();
                  supported = true);

    CHECK_RETURN_RET_ELOG(!supported, CAMERA_ERROR_OPTIONAL_PROPERTY_NOT_EXIST,
                          "Camera_MetadataObjectExt: GetLeftEyeBoundingBox not support");

    boundingBox->topLeftX = innerRect.topLeftX;
    boundingBox->topLeftY = innerRect.topLeftY;
    boundingBox->width = innerRect.width;
    boundingBox->height = innerRect.height;
    return CAMERA_OK;
}

Camera_ErrorCode OH_Camera_MetadataObjectExt::GetRightEyeBoundingBox(OH_Camera_Rect_Ext* boundingBox) const
{
    CHECK_RETURN_RET_ELOG(boundingBox == nullptr, CAMERA_INVALID_ARGUMENT,
                          "Camera_MetadataObjectExt: boundingBox == nullptr");

    OHOS::CameraStandard::Rect innerRect;
    bool supported = false;

    CHECK_EXECUTE(innerObject_->GetType() == MetadataObjectType::FACE,
                  innerRect = static_cast<MetadataFaceObject*>(innerObject_.GetRefPtr())->GetRightEyeBoundingBox();
                  supported = true);
    CHECK_EXECUTE(innerObject_->GetType() == MetadataObjectType::CAT_FACE,
                  innerRect = static_cast<MetadataCatFaceObject*>(innerObject_.GetRefPtr())->GetRightEyeBoundingBox();
                  supported = true);
    CHECK_EXECUTE(innerObject_->GetType() == MetadataObjectType::DOG_FACE,
                  innerRect = static_cast<MetadataDogFaceObject*>(innerObject_.GetRefPtr())->GetRightEyeBoundingBox();
                  supported = true);

    CHECK_RETURN_RET_ELOG(!supported, CAMERA_ERROR_OPTIONAL_PROPERTY_NOT_EXIST,
                          "Camera_MetadataObjectExt: GetRightEyeBoundingBox not support");

    boundingBox->topLeftX = innerRect.topLeftX;
    boundingBox->topLeftY = innerRect.topLeftY;
    boundingBox->width = innerRect.width;
    boundingBox->height = innerRect.height;
    return CAMERA_OK;
}

Camera_ErrorCode OH_Camera_MetadataObjectExt::GetEmotion(OH_Camera_MetadataObjectEmotion* emotion) const
{
    CHECK_RETURN_RET_ELOG(emotion == nullptr, CAMERA_INVALID_ARGUMENT,
                          "Camera_MetadataObjectExt: emotion == nullptr");
    CHECK_EXECUTE(
        innerObject_->GetType() == MetadataObjectType::FACE,
        *emotion = static_cast<OH_Camera_MetadataObjectEmotion>(
            static_cast<MetadataFaceObject *>(innerObject_.GetRefPtr())->GetEmotion());
        return CAMERA_OK);
    return CAMERA_ERROR_OPTIONAL_PROPERTY_NOT_EXIST;
}
