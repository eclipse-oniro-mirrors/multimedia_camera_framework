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

#ifndef OHOS_METADATA_OBJECT_EXT_IMPL_H
#define OHOS_METADATA_OBJECT_EXT_IMPL_H

#include "kits/native/include/camera/camera.h"
#include "output/metadata_output.h"

struct OH_Camera_MetadataObjectExt {
public:
    explicit OH_Camera_MetadataObjectExt(const OHOS::sptr<OHOS::CameraStandard::MetadataObject> &innerObject);
    ~OH_Camera_MetadataObjectExt();

    Camera_ErrorCode GetMetadataObjectType(Camera_MetadataObjectType* type) const;

    Camera_ErrorCode GetTimestamp(int64_t* timestamp) const;

    Camera_ErrorCode GetBoundingBox(OH_Camera_Rect_Ext* boundingBox) const;

    Camera_ErrorCode GetPitchAngle(float* pitchAngle) const;

    Camera_ErrorCode GetYawAngle(float* yawAngle) const;

    Camera_ErrorCode GetRollAngle(float* rollAngle) const;

    Camera_ErrorCode GetLeftEyeBoundingBox(OH_Camera_Rect_Ext* boundingBox) const;

    Camera_ErrorCode GetRightEyeBoundingBox(OH_Camera_Rect_Ext* boundingBox) const;

    Camera_ErrorCode GetEmotion(OH_Camera_MetadataObjectEmotion* emotion) const;

private:
    OHOS::sptr<OHOS::CameraStandard::MetadataObject> innerObject_;
};
#endif // OHOS_METADATA_OBJECT_EXT_IMPL_H
