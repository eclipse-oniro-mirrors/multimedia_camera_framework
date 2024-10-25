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
 
#include "photo_asset_adapter.h"
#include "camera_log.h"
#include "iservice_registry.h"
#include <cstdint>
#include "media_photo_asset_proxy.h"
#include "system_ability_definition.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace CameraStandard {

PhotoAssetAdapter::PhotoAssetAdapter(int32_t cameraShotType)
{
    MEDIA_INFO_LOG("PhotoAssetAdapter ctor");
    auto mediaLibraryManager = Media::MediaLibraryManager::GetMediaLibraryManager();
    CHECK_ERROR_RETURN_LOG(mediaLibraryManager == nullptr, "GetMediaLibraryManager failed!");
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_ERROR_RETURN_LOG(samgr == nullptr, "Failed to get System ability manager!");
    sptr<IRemoteObject> object = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
    CHECK_ERROR_RETURN_LOG(object == nullptr, "object is null!");
    mediaLibraryManager->InitMediaLibraryManager(object);
    const static int32_t INVALID_UID = -1;
    const static int32_t BASE_USER_RANGE = 200000;
    int uid = IPCSkeleton::GetCallingUid();
    CHECK_ERROR_PRINT_LOG(uid <= INVALID_UID, "Get INVALID_UID UID %{public}d", uid);
    userId_ = uid / BASE_USER_RANGE;
    MEDIA_DEBUG_LOG("get uid:%{public}d, userId:%{public}d", uid, userId_);
    photoAssetProxy_ = mediaLibraryManager->CreatePhotoAssetProxy(
        static_cast<Media::CameraShotType>(cameraShotType), uid, userId_);
}

void PhotoAssetAdapter::AddPhotoProxy(sptr<Media::PhotoProxy> photoProxy)
{
    if (photoAssetProxy_) {
        photoAssetProxy_->AddPhotoProxy(photoProxy);
    }
}

std::string PhotoAssetAdapter::GetPhotoAssetUri()
{
    if (photoAssetProxy_) {
        return photoAssetProxy_->GetPhotoAssetUri();
    }
    return "";
}

int32_t PhotoAssetAdapter::GetVideoFd()
{
    if (photoAssetProxy_) {
        return photoAssetProxy_->GetVideoFd();
    }
    return -1;
}

int32_t PhotoAssetAdapter::GetUserId()
{
    return photoAssetProxy_ ? userId_ : -1;
}

void PhotoAssetAdapter::NotifyVideoSaveFinished()
{
    if (photoAssetProxy_) {
        photoAssetProxy_->NotifyVideoSaveFinished();
    }
}

extern "C" PhotoAssetIntf *createPhotoAssetIntf(int32_t cameraShotType)
{
    return new PhotoAssetAdapter(cameraShotType);
}
 
}  // namespace AVSession
}  // namespace OHOS