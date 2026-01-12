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
#include "photo_asset_proxy.h"
#include "camera_log.h"
#include "photo_proxy.h"
#ifdef CAMERA_CAPTURE_YUV
#include "iservice_registry.h"
#include "bundle_mgr_interface.h"
#include "system_ability_definition.h"
#endif

namespace OHOS {
namespace CameraStandard {
typedef PhotoAssetIntf* (*CreatePhotoAssetIntf)(int32_t, int32_t, uint32_t, int32_t, std::string);
#ifdef CAMERA_CAPTURE_YUV
typedef MediaLibraryManagerIntf* (*CreateMediaLibraryManagerIntf)();
std::string PhotoAssetProxy::GetBundleName(int32_t callingUid)
{
    std::string bundleName = "";
    OHOS::sptr<OHOS::ISystemAbilityManager> samgr =
            OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    CHECK_RETURN_RET_ELOG(samgr == nullptr, bundleName, "GetClientBundle Get ability manager failed");
    OHOS::sptr<OHOS::IRemoteObject> remoteObject =
            samgr->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    CHECK_RETURN_RET_ELOG(remoteObject == nullptr, bundleName, "GetClientBundle object is NULL.");
    sptr<AppExecFwk::IBundleMgr> bms = OHOS::iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    CHECK_RETURN_RET_ELOG(bms == nullptr, bundleName, "GetClientBundle bundle manager service is NULL.");
    auto ret = bms->GetNameForUid(callingUid, bundleName);
    CHECK_RETURN_RET_ELOG(ret != ERR_OK, bundleName, "GetBundleInfoForSelf failed.");
    MEDIA_INFO_LOG("bundleName: [%{public}s]", bundleName.c_str());
    return bundleName;
}
#endif

std::shared_ptr<PhotoAssetProxy> PhotoAssetProxy::GetPhotoAssetProxy(
    int32_t shootType, int32_t callingUid, uint32_t callingTokenID, int32_t photoCount)
{
    MEDIA_DEBUG_LOG("GetPhotoAssetProxy E callingUid:%{public}d", callingUid);
    auto dynamiclib = CameraDynamicLoader::GetDynamiclib(MEDIA_LIB_SO);
    if (dynamiclib == nullptr){
        HILOG_COMM_ERROR("PhotoAssetProxy::GetPhotoAssetProxy get dynamiclib fail");
        return nullptr;
    }
    CreatePhotoAssetIntf createPhotoAssetIntf = (CreatePhotoAssetIntf)dynamiclib->GetFunction("createPhotoAssetIntf");
    if (createPhotoAssetIntf == nullptr) {
        HILOG_COMM_ERROR("PhotoAssetProxy::GetPhotoAssetProxy get createPhotoAssetIntf fail");
        return nullptr;
    }
#ifdef CAMERA_CAPTURE_YUV
    std::string bundleName = GetBundleName(callingUid);
#else
    std::string bundleName = "";
#endif
    MEDIA_DEBUG_LOG("GetPhotoAssetProxy bundleName:%{public}s", bundleName.c_str());
    PhotoAssetIntf* photoAssetIntf = createPhotoAssetIntf(
        shootType, callingUid, callingTokenID, photoCount, bundleName);
    if (photoAssetIntf == nullptr) {
        HILOG_COMM_ERROR("PhotoAssetProxy::GetPhotoAssetProxy get photoAssetIntf fail");
        return nullptr;
    }
    std::shared_ptr<PhotoAssetProxy> photoAssetProxy =
        std::make_shared<PhotoAssetProxy>(dynamiclib, std::shared_ptr<PhotoAssetIntf>(photoAssetIntf));
    return photoAssetProxy;
}

PhotoAssetProxy::PhotoAssetProxy(
    std::shared_ptr<Dynamiclib> mediaLibraryLib, std::shared_ptr<PhotoAssetIntf> photoAssetIntf)
    : mediaLibraryLib_(mediaLibraryLib), photoAssetIntf_(photoAssetIntf)
{
    CHECK_RETURN_ELOG(mediaLibraryLib_ == nullptr, "PhotoAssetProxy construct mediaLibraryLib is null");
    CHECK_RETURN_ELOG(photoAssetIntf_ == nullptr, "PhotoAssetProxy construct photoAssetIntf is null");
}

// LCOV_EXCL_START
void PhotoAssetProxy::AddPhotoProxy(sptr<Media::PhotoProxy> photoProxy)
{
    CAMERA_SYNC_TRACE;
    std::lock_guard<std::mutex> lock(opMutex_);
    CHECK_RETURN_ELOG(photoAssetIntf_ == nullptr, "PhotoAssetProxy::AddPhotoProxy photoAssetIntf_ is null");
    photoAssetIntf_->AddPhotoProxy(photoProxy);
}

std::string PhotoAssetProxy::GetPhotoAssetUri()
{
    CAMERA_SYNC_TRACE;
    std::lock_guard<std::mutex> lock(opMutex_);
    CHECK_RETURN_RET_ELOG(photoAssetIntf_ == nullptr, "", "PhotoAssetProxy::GetPhotoAssetUri photoAssetIntf_ is null");
    return photoAssetIntf_->GetPhotoAssetUri();
}

int32_t PhotoAssetProxy::GetVideoFd(VideoType videoType)
{
    CHECK_RETURN_RET_ELOG(photoAssetIntf_ == nullptr, -1, "PhotoAssetProxy::GetVideoFd photoAssetIntf_ is null");
    return photoAssetIntf_->GetVideoFd(videoType);
}

void PhotoAssetProxy::NotifyVideoSaveFinished(VideoType videoType)
{
    CHECK_RETURN_ELOG(photoAssetIntf_ == nullptr, "PhotoAssetProxy::NotifyVideoSaveFinished photoAssetIntf_ is null");
    photoAssetIntf_->NotifyVideoSaveFinished(videoType);
}

int32_t PhotoAssetProxy::GetUserId()
{
    CHECK_RETURN_RET_ELOG(photoAssetIntf_ == nullptr, -1, "PhotoAssetProxy::GetUserId photoAssetIntf_ is null");
    return photoAssetIntf_->GetUserId();
}

int32_t PhotoAssetProxy::OpenAsset()
{
    MEDIA_INFO_LOG("PhotoAssetProxy::OpenAsset() is called");
    CHECK_RETURN_RET_ELOG(photoAssetIntf_ == nullptr, -1, "PhotoAssetProxy::OpenAsset photoAssetIntf_ is null");
    return photoAssetIntf_->OpenAsset();
}

void PhotoAssetProxy::UpdatePhotoProxy(const sptr<Media::PhotoProxy> &photoProxy)
{
    MEDIA_INFO_LOG("PhotoAssetProxy::UpdatePhotoProxy is called");
    if (photoAssetIntf_ == nullptr) {
        HILOG_COMM_ERROR("PhotoAssetProxy::UpdatePhotoProxy photoAssetIntf_ is null");
        return;
    }
    photoAssetIntf_->UpdatePhotoProxy(photoProxy);
}

#ifdef CAMERA_CAPTURE_YUV
std::shared_ptr<MediaLibraryManagerProxy> MediaLibraryManagerProxy::GetMediaLibraryManagerProxy()
{
    MEDIA_DEBUG_LOG("GetMediaLibraryManagerProxy E");
    auto dynamiclib = CameraDynamicLoader::GetDynamiclib(MEDIA_LIB_SO);
    if (dynamiclib == nullptr) {
        HILOG_COMM_ERROR("MediaLibraryManagerProxy::GetMediaLibraryManagerProxy get dynamiclib fail");
        return nullptr;
    }
    CreateMediaLibraryManagerIntf createMediaLibraryManagerIntf =
        (CreateMediaLibraryManagerIntf)dynamiclib->GetFunction("createMediaLibraryManagerIntf");
    if (createMediaLibraryManagerIntf == nullptr) {
        HILOG_COMM_ERROR(
            "MediaLibraryManagerProxy::GetMediaLibraryManagerProxy get createMediaLibraryManagerIntf fail");
        return nullptr;
    }
    MediaLibraryManagerIntf* mediaLibraryManagerIntf = createMediaLibraryManagerIntf();
    if (mediaLibraryManagerIntf == nullptr) {
        HILOG_COMM_ERROR(
            "MediaLibraryManagerProxy::GetMediaLibraryManagerProxy get mediaLibraryManagerIntf fail");
        return nullptr;
    }
    std::shared_ptr<MediaLibraryManagerProxy> mediaLibraryManagerProxy =
        std::make_shared<MediaLibraryManagerProxy>(
            dynamiclib, std::shared_ptr<MediaLibraryManagerIntf>(mediaLibraryManagerIntf));
    return mediaLibraryManagerProxy;
}

void MediaLibraryManagerProxy::LoadMediaLibraryDynamiclibAsync()
{
    MEDIA_DEBUG_LOG("MediaLibraryManagerProxy::LoadMediaLibraryDynamiclibAsync");
    CameraDynamicLoader::LoadDynamiclibAsync(MEDIA_LIB_SO);
}

void MediaLibraryManagerProxy::FreeMediaLibraryDynamiclibDelayed()
{
    MEDIA_DEBUG_LOG("MediaLibraryManagerProxy::FreeMediaLibraryDynamiclibDelayed");
    CameraDynamicLoader::FreeDynamicLibDelayed(MEDIA_LIB_SO);
}

MediaLibraryManagerProxy::MediaLibraryManagerProxy(
    std::shared_ptr<Dynamiclib> mediaLibraryLib,
    std::shared_ptr<MediaLibraryManagerIntf> mediaLibraryManagerIntf)
    : mediaLibraryLib_(mediaLibraryLib), mediaLibraryManagerIntf_(mediaLibraryManagerIntf)
{
    CHECK_RETURN_ELOG(mediaLibraryLib_ == nullptr, "MediaLibraryManagerProxy construct mediaLibraryLib is null");
    CHECK_RETURN_ELOG(
        mediaLibraryManagerIntf_ == nullptr, "MediaLibraryManagerProxy construct mediaLibraryManagerIntf is null");
}

void MediaLibraryManagerProxy::RegisterPhotoStateCallback(const std::function<void(int32_t)> &callback)
{
    MEDIA_DEBUG_LOG("MediaLibraryManagerProxy::RegisterPhotoStateCallback is called");
    CHECK_RETURN_ELOG(
        mediaLibraryManagerIntf_ == nullptr,
        "MediaLibraryManagerProxy::RegisterPhotoStateCallback mediaLibraryManagerIntf_ is null");
    mediaLibraryManagerIntf_->RegisterPhotoStateCallback(callback);
}

void MediaLibraryManagerProxy::UnregisterPhotoStateCallback()
{
    MEDIA_DEBUG_LOG("MediaLibraryManagerProxy::UnregisterPhotoStateCallback is called");
    CHECK_RETURN_ELOG(
        mediaLibraryManagerIntf_ == nullptr,
        "MediaLibraryManagerProxy::UnregisterPhotoStateCallback mediaLibraryManagerIntf_ is null");
    mediaLibraryManagerIntf_->UnregisterPhotoStateCallback();
}
#endif
// LCOV_EXCL_STOP
} // namespace CameraStandard
} // namespace OHOS