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

#ifndef CAMERA_PICTURE_ADAPTER_INTERFACE_H
#define CAMERA_PICTURE_ADAPTER_INTERFACE_H

#include "surface_buffer.h"
#include "picture_interface.h"
namespace OHOS::Media {
    class Picture;
}
namespace OHOS {
namespace CameraStandard {
class PictureAdapter : public OHOS::CameraStandard::PictureIntf {
public:
    PictureAdapter();
    ~PictureAdapter() override;
    void Create(sptr<SurfaceBuffer> &surfaceBuffer) override;
    void SetAuxiliaryPicture(sptr<SurfaceBuffer> &surfaceBuffer,
        CameraAuxiliaryPictureType type) override;
    void CreateWithDeepCopySurfaceBuffer(sptr<SurfaceBuffer> &surfaceBuffer) override;
    bool Marshalling(Parcel &data) const override;
    void UnmarshallingPicture(Parcel &data) override;
    int32_t SetExifMetadata(sptr<SurfaceBuffer> &surfaceBuffer) override;
    bool SetMaintenanceData(sptr<SurfaceBuffer> &surfaceBuffer) override;
    void RotatePicture() override;
    std::shared_ptr<Media::Picture> GetPicture() const;
private:
    // Keep the order of members in this class, the bottom member will be destroyed first
    std::shared_ptr<Media::Picture> picture_;
};
} // namespace CameraStandard
} // namespace OHOS

#endif // CAMERA_PICTURE_ADAPTER_INTERFACE_H