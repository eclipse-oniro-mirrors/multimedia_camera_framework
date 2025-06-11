/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_CAMERA_PICTURE_INTERFACE_H
#define OHOS_CAMERA_PICTURE_INTERFACE_H
#include "parcel.h"
#include "surface_buffer.h"
/**
 * @brief Internal usage only, for camera framework interacts with photo asset related interfaces.
 * @since 12
 */
namespace OHOS::CameraStandard {

enum class CameraAuxiliaryPictureType {
    NONE = 0,
    GAINMAP = 1,
    DEPTH_MAP = 2,
    UNREFOCUS_MAP = 3,
    LINEAR_MAP = 4,
    FRAGMENT_MAP = 5,
};

class PictureIntf : public Parcelable {
public:
    virtual ~PictureIntf() = default;
    virtual void Create(sptr<SurfaceBuffer> &surfaceBuffer) = 0;
    virtual void SetAuxiliaryPicture(sptr<SurfaceBuffer> &surfaceBuffer,
        CameraAuxiliaryPictureType type) = 0;
    virtual void CreateWithDeepCopySurfaceBuffer(sptr<SurfaceBuffer> &surfaceBuffer) = 0;
    virtual bool Marshalling(Parcel &data) const
    {
        return true;
    }
    static PictureIntf* Unmarshalling(Parcel &data)
    {
        return nullptr;
    }
    virtual void UnmarshallingPicture(Parcel &data) = 0;
    virtual int32_t SetExifMetadata(sptr<SurfaceBuffer> &surfaceBuffer) = 0;
    virtual bool SetMaintenanceData(sptr<SurfaceBuffer> &surfaceBuffer) = 0;
    virtual void RotatePicture() = 0;
};
typedef PictureIntf* (*GetPictureAdapter)();
} // namespace OHOS::CameraStandard
#endif