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

#include "dfx_report.h"
#include "photo_asset_adapter.h"
#include "photo_proxy.h"
#include "camera_log.h"
#include "iservice_registry.h"
#include <cstdint>
#include "media_photo_asset_proxy.h"
#include "system_ability_definition.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace CameraStandard {
Media::MediaLibraryManager *g_mediaLibraryManager = nullptr;
PhotoAssetAdapter::PhotoAssetAdapter(
    int32_t cameraShotType, int32_t uid, uint32_t callingTokenID, int32_t photoCount,
    std::string bundleName)
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("PhotoAssetAdapter ctor");
    if (g_mediaLibraryManager == nullptr) {
        g_mediaLibraryManager = Media::MediaLibraryManager::GetMediaLibraryManager();
        CHECK_EXECUTE(g_mediaLibraryManager == nullptr, CameraReportUtils::GetInstance().ReportCameraCreateNullptr(
            "PhotoAssetAdapter::PhotoAssetAdapter", "Media::MediaLibraryManager::GetMediaLibraryManager"));
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
    Media::PhotoAssetProxyCallerInfo callerInfo {
        .callingUid = uid,
        .userId = userId_,
        .callingTokenId = callingTokenID,
        .packageName = bundleName
    };
    photoAssetProxy_ = g_mediaLibraryManager->CreatePhotoAssetProxy(
        callerInfo, static_cast<Media::CameraShotType>(cameraShotType), photoCount);
    CHECK_EXECUTE(!photoAssetProxy_, CameraReportUtils::GetInstance().ReportCameraCreateNullptr(
        "PhotoAssetAdapter::PhotoAssetAdapter", "Media::MediaLibraryManager::CreatePhotoAssetProxy"));
}
// LCOV_EXCL_START
void PhotoAssetAdapter::AddPhotoProxy(sptr<Media::PhotoProxy> photoProxy)
{
    if (photoAssetProxy_) {
        photoAssetProxy_->AddPhotoProxy(photoProxy);
    }
}

std::string PhotoAssetAdapter::GetPhotoAssetUri()
{
    std::string res = "";
    CHECK_RETURN_RET(!photoAssetProxy_, res);
    res = photoAssetProxy_->GetPhotoAssetUri();
    CHECK_EXECUTE(res == "", CameraReportUtils::GetInstance().ReportCameraGetNullStr(
        "PhotoAssetAdapter::GetPhotoAssetUri", "Media::PhotoAssetProxy::GetPhotoAssetUri"));
    return res;
}

int32_t PhotoAssetAdapter::GetVideoFd(VideoType videoType)
{
    int32_t res = -1;
    CHECK_RETURN_RET(!photoAssetProxy_, res);
    res = photoAssetProxy_->GetVideoFd(static_cast<Media::VideoType>(videoType));
    CHECK_EXECUTE(res == -1, CameraReportUtils::GetInstance().ReportCameraFail(
        "PhotoAssetAdapter::GetVideoFd", "Media::PhotoAssetProxy::GetVideoFd"));
    return res;
}

int32_t PhotoAssetAdapter::GetUserId()
{
    return photoAssetProxy_ ? userId_ : -1;
}

void PhotoAssetAdapter::NotifyVideoSaveFinished(VideoType videoType)
{
    if (photoAssetProxy_) {
        photoAssetProxy_->NotifyVideoSaveFinished(static_cast<Media::VideoType>(videoType));
    }
}

int32_t PhotoAssetAdapter::OpenAsset()
{
    MEDIA_INFO_LOG("PhotoAssetAdapter::OpenAsset is called");
    if (photoAssetProxy_) {
        std::string uri = photoAssetProxy_->GetPhotoAssetUri();
        CHECK_EXECUTE(uri == "", CameraReportUtils::GetInstance().ReportCameraGetNullStr(
            "PhotoAssetAdapter::OpenAsset", "Media::PhotoAssetProxy::GetPhotoAssetUri"));
        int32_t fd = g_mediaLibraryManager->OpenAsset(uri, "rw");
        CHECK_EXECUTE(fd == -1,  CameraReportUtils::GetInstance().ReportCameraError(
            "PhotoAssetAdapter::OpenAsset", "Media::PhotoAssetProxy::GetPhotoAssetUri", fd));
        MEDIA_INFO_LOG("PhotoAssetAdapter::OpenAsset uri %{public}s, fd: %{public}d openMode: rw", uri.c_str(), fd);
        return fd;
    }
    return -1;
}

void PhotoAssetAdapter::UpdatePhotoProxy(const sptr<Media::PhotoProxy> &photoProxy)
{
    MEDIA_INFO_LOG("PhotoAssetAdapter::UpdatePhotoProxy is called");
    if (photoAssetProxy_) {
        photoAssetProxy_->UpdatePhotoProxy(photoProxy);
    }
}

#ifdef CAMERA_CAPTURE_YUV
void PhotoAssetAdapter::RegisterPhotoStateCallback(const std::function<void(int32_t)> &callback)
{
    MEDIA_DEBUG_LOG("PhotoAssetAdapter::RegisterPhotoStateCallback is called");
    CHECK_EXECUTE(photoAssetProxy_ != nullptr, photoAssetProxy_->RegisterPhotoStateCallback(callback));
}

void PhotoAssetAdapter::UnregisterPhotoStateCallback()
{
    MEDIA_DEBUG_LOG("PhotoAssetAdapter::UnregisterPhotoStateCallback is called");
    CHECK_EXECUTE(photoAssetProxy_ != nullptr, photoAssetProxy_->UnregisterPhotoStateCallback());
}
#endif

// LCOV_EXCL_STOP
extern "C" PhotoAssetIntf *createPhotoAssetIntf(
    int32_t cameraShotType, int32_t uid, uint32_t callingTokenID, int32_t photoCount,
    std::string bundleName)
{
    return new PhotoAssetAdapter(cameraShotType, uid, callingTokenID, photoCount, bundleName);
}

}  // namespace AVSession
}  // namespace OHOS