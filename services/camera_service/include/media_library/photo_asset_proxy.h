/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_CAMERA_PHOTO_ASSERT_PROXY_H
#define OHOS_CAMERA_PHOTO_ASSERT_PROXY_H

#include <cstdint>
#include <memory>

#include "camera_dynamic_loader.h"
#include "photo_asset_interface.h"

namespace OHOS {
namespace CameraStandard {
class PhotoAssetProxy : public PhotoAssetIntf {
public:
    static std::shared_ptr<PhotoAssetProxy> GetPhotoAssetProxy(int32_t shotType, int32_t callingUid);
    explicit PhotoAssetProxy(
        std::shared_ptr<Dynamiclib> mediaLibraryLib, std::shared_ptr<PhotoAssetIntf> photoAssetIntf);
    ~PhotoAssetProxy() override = default;

    void AddPhotoProxy(sptr<Media::PhotoProxy> photoProxy) override;
    std::string GetPhotoAssetUri() override;
    int32_t GetVideoFd() override;
    void NotifyVideoSaveFinished() override;
    int32_t GetUserId() override;

private:
    // Keep the order of members in this class, the bottom member will be destroyed first
    std::shared_ptr<Dynamiclib> mediaLibraryLib_;
    std::shared_ptr<PhotoAssetIntf> photoAssetIntf_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif