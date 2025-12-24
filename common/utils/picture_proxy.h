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

#ifndef CAMERA_PICTURE_PROXY_INTERFACE_H
#define CAMERA_PICTURE_PROXY_INTERFACE_H

#include "surface_buffer.h"
#include "picture_interface.h"
#include "camera_dynamic_loader.h"
namespace OHOS {
namespace CameraStandard {

class PictureProxy : public PictureIntf {
public:
    explicit PictureProxy(
        std::shared_ptr<Dynamiclib> mediaLibraryLib, std::shared_ptr<PictureIntf> pictureIntf);

    ~PictureProxy() override;
    static std::shared_ptr<PictureProxy> CreatePictureProxy();
    void Create(sptr<SurfaceBuffer> &surfaceBuffer) override;
    void SetAuxiliaryPicture(sptr<SurfaceBuffer> &surfaceBuffer,
        CameraAuxiliaryPictureType type) override;
    bool Marshalling(Parcel &data) const override;
    void UnmarshallingPicture(Parcel &data) override;
    int32_t SetExifMetadata(sptr<SurfaceBuffer> &surfaceBuffer) override;
    bool SetMaintenanceData(sptr<SurfaceBuffer> &surfaceBuffer) override;
    void RotatePicture() override;
    uint32_t SetXtStyleMetadataBlob(const uint8_t *source, const uint32_t bufferSize) override;
    std::shared_ptr<Media::Picture> GetPicture() const override;
    std::shared_ptr<PictureIntf> GetPictureIntf() const;
private:
    // Keep the order of members in this class, the bottom member will be destroyed first
    std::shared_ptr<Dynamiclib> pictureLib_ = nullptr;
    std::shared_ptr<PictureIntf> pictureIntf_ = nullptr;
};
} // namespace CameraStandard
} // namespace OHOS

#endif // CAMERA_PICTURE_PROXY_INTERFACE_H