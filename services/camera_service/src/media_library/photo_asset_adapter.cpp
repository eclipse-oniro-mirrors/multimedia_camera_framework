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

namespace OHOS {
namespace CameraStandard {

Media::MediaLibraryManager *g_mediaLibraryManager = nullptr;
PhotoAssetAdapter::PhotoAssetAdapter(int32_t cameraShotType, int32_t uid, uint32_t callingTokenID)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("PhotoAssetAdapter ctor");
    if (g_mediaLibraryManager == nullptr) {
        g_mediaLibraryManager = Media::MediaLibraryManager::GetMediaLibraryManager();
        CHECK_RETURN_ELOG(g_mediaLibraryManager == nullptr, "GetMediaLibraryManager failed!");
        auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        CHECK_RETURN_ELOG(samgr == nullptr, "Failed to get System ability manager!");
        sptr<IRemoteObject> object = samgr->GetSystemAbility(CAMERA_SERVICE_ID);
        CHECK_RETURN_ELOG(object == nullptr, "object is null!");
        g_mediaLibraryManager->InitMediaLibraryManager(object);
    }
    const static int32_t INVALID_UID = -1;
    const static int32_t BASE_USER_RANGE = 200000;
    CHECK_PRINT_ELOG(uid <= INVALID_UID, "Get INVALID_UID UID %{public}d", uid);
    userId_ = uid / BASE_USER_RANGE;
    MEDIA_DEBUG_LOG("get uid:%{public}d, userId:%{public}d.", uid, userId_);
    MEDIA_INFO_LOG("start mediaLibray CreatePhotoAssetProxy");
    photoAssetProxy_ = g_mediaLibraryManager->CreatePhotoAssetProxy(
        static_cast<Media::CameraShotType>(cameraShotType), uid, userId_, callingTokenID);
}

void PhotoAssetAdapter::AddPhotoProxy(sptr<Media::PhotoProxy> photoProxy)
{
    CHECK_EXECUTE(photoAssetProxy_, photoAssetProxy_->AddPhotoProxy(photoProxy));
}

std::string PhotoAssetAdapter::GetPhotoAssetUri()
{
    CHECK_RETURN_RET(photoAssetProxy_, photoAssetProxy_->GetPhotoAssetUri());
    return "";
}

int32_t PhotoAssetAdapter::GetVideoFd()
{
    CHECK_RETURN_RET(photoAssetProxy_, photoAssetProxy_->GetVideoFd());
    return -1;
}

int32_t PhotoAssetAdapter::GetUserId()
{
    return photoAssetProxy_ ? userId_ : -1;
}

void PhotoAssetAdapter::NotifyVideoSaveFinished()
{
    CHECK_EXECUTE(photoAssetProxy_, photoAssetProxy_->NotifyVideoSaveFinished());
}

extern "C" PhotoAssetIntf *createPhotoAssetIntf(int32_t cameraShotType, int32_t uid, uint32_t callingTokenID)
{
    return new PhotoAssetAdapter(cameraShotType, uid, callingTokenID);
}

}  // namespace AVSession
}  // namespace OHOS