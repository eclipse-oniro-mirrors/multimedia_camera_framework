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
#include "photo_asset_proxy.h"
#include "camera_log.h"
#include "photo_proxy.h"
#include "iservice_registry.h"
#include "bundle_mgr_interface.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace CameraStandard {
typedef PhotoAssetIntf* (*CreatePhotoAssetIntf)(int32_t, int32_t, uint32_t, std::string);

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

std::shared_ptr<PhotoAssetProxy> PhotoAssetProxy::GetPhotoAssetProxy(
    int32_t shootType, int32_t callingUid, uint32_t callingTokenID)
{
    MEDIA_DEBUG_LOG("GetPhotoAssetProxy E callingUid:%{public}d", callingUid);
    auto dynamiclib = CameraDynamicLoader::GetDynamiclib(MEDIA_LIB_SO);
    if (dynamiclib == nullptr) {
        HILOG_COMM_ERROR("PhotoAssetProxy::GetPhotoAssetProxy get dynamiclib fail");
        return nullptr;
    }
    CreatePhotoAssetIntf createPhotoAssetIntf = (CreatePhotoAssetIntf)dynamiclib->GetFunction("createPhotoAssetIntf");
    if (createPhotoAssetIntf == nullptr) {
        HILOG_COMM_ERROR("PhotoAssetProxy::GetPhotoAssetProxy get createPhotoAssetIntf fail");
        return nullptr;
    }
    std::string bundleName = GetBundleName(callingUid);
    MEDIA_DEBUG_LOG("GetPhotoAssetProxy bundleName:%{public}s", bundleName.c_str());
    PhotoAssetIntf* photoAssetIntf = createPhotoAssetIntf(shootType, callingUid, callingTokenID, bundleName);
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
    CHECK_RETURN_ELOG(photoAssetIntf_ == nullptr, "PhotoAssetProxy::AddPhotoProxy photoAssetIntf_ is null");
    photoAssetIntf_->AddPhotoProxy(photoProxy);
}

std::string PhotoAssetProxy::GetPhotoAssetUri()
{
    CHECK_RETURN_RET_ELOG(
        photoAssetIntf_ == nullptr, "", "PhotoAssetProxy::GetPhotoAssetUri photoAssetIntf_ is null");
    return photoAssetIntf_->GetPhotoAssetUri();
}

int32_t PhotoAssetProxy::GetVideoFd()
{
    CHECK_RETURN_RET_ELOG(photoAssetIntf_ == nullptr, -1, "PhotoAssetProxy::GetVideoFd photoAssetIntf_ is null");
    return photoAssetIntf_->GetVideoFd();
}

void PhotoAssetProxy::NotifyVideoSaveFinished()
{
    CHECK_RETURN_ELOG(
        photoAssetIntf_ == nullptr, "PhotoAssetProxy::NotifyVideoSaveFinished photoAssetIntf_ is null");
    photoAssetIntf_->NotifyVideoSaveFinished();
}

int32_t PhotoAssetProxy::GetUserId()
{
    CHECK_RETURN_RET_ELOG(photoAssetIntf_ == nullptr, -1, "PhotoAssetProxy::GetUserId photoAssetIntf_ is null");
    return photoAssetIntf_->GetUserId();
}

void PhotoAssetProxy::RegisterPhotoStateCallback(const std::function<void(int32_t)> &callback)
{
    MEDIA_DEBUG_LOG("PhotoAssetProxy::RegisterPhotoStateCallback is called");
    CHECK_RETURN_ELOG(
        photoAssetIntf_ == nullptr, "PhotoAssetProxy::RegisterPhotoStateCallback photoAssetIntf_ is null");
    photoAssetIntf_->RegisterPhotoStateCallback(callback);
}

void PhotoAssetProxy::UnregisterPhotoStateCallback()
{
    MEDIA_DEBUG_LOG("PhotoAssetProxy::UnregisterPhotoStateCallback is called");
    CHECK_RETURN_ELOG(
        photoAssetIntf_ == nullptr, "PhotoAssetProxy::UnregisterPhotoStateCallback photoAssetIntf_ is null");
    photoAssetIntf_->UnregisterPhotoStateCallback();
}
// LCOV_EXCL_STOP
} // namespace CameraStandard
} // namespace OHOS