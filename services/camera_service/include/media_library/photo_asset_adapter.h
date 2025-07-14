/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef CAMERA_PHOTO_ASSET_INTERFACE_H
#define CAMERA_PHOTO_ASSET_INTERFACE_H

#include "photo_asset_interface.h"
#include "media_library_manager.h"
#include "media_photo_asset_proxy.h"
namespace OHOS {
namespace CameraStandard {

class PhotoAssetAdapter : public OHOS::CameraStandard::PhotoAssetIntf {
public:
    PhotoAssetAdapter(int32_t cameraShotType, int32_t uid, uint32_t callingTokenID);
    virtual ~PhotoAssetAdapter() = default;
    void AddPhotoProxy(sptr<Media::PhotoProxy> photoProxy);
    std::string GetPhotoAssetUri();
    int32_t GetVideoFd();
    void NotifyVideoSaveFinished();
    int32_t GetUserId();
private:
    std::shared_ptr<Media::PhotoAssetProxy> photoAssetProxy_ = nullptr;
    int32_t userId_ = -1;
};

} // namespace CameraStandard
} // namespace OHOS

#endif // CAMERA_PHOTO_ASSET_INTERFACE_H