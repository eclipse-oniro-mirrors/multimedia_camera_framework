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

#include "media_library/photo_asset_proxy.h"

#include "camera_log.h"

namespace OHOS {
namespace CameraStandard {
typedef PhotoAssetIntf* (*CreatePhotoAssetIntf)(int32_t, int32_t);
std::shared_ptr<PhotoAssetProxy> PhotoAssetProxy::GetPhotoAssetProxy(int32_t shootType, int32_t callingUid)
{
    auto dynamiclib = CameraDynamicLoader::GetDynamiclib(MEDIA_LIB_SO);
    CHECK_ERROR_RETURN_RET_LOG(
        dynamiclib == nullptr, nullptr, "PhotoAssetProxy::GetPhotoAssetProxy get dynamiclib fail");
    CreatePhotoAssetIntf createPhotoAssetIntf = (CreatePhotoAssetIntf)dynamiclib->GetFunction("createPhotoAssetIntf");
    CHECK_ERROR_RETURN_RET_LOG(
        createPhotoAssetIntf == nullptr, nullptr, "PhotoAssetProxy::CreateMediaLibrary get createPhotoAssetIntf fail");
    PhotoAssetIntf* photoAssetIntf = createPhotoAssetIntf(shootType, callingUid);
    CHECK_ERROR_RETURN_RET_LOG(
        photoAssetIntf == nullptr, nullptr, "PhotoAssetProxy::CreateMediaLibrary get photoAssetIntf fail");
    std::shared_ptr<PhotoAssetProxy> photoAssetProxy =
        std::make_shared<PhotoAssetProxy>(dynamiclib, std::shared_ptr<PhotoAssetIntf>(photoAssetIntf));
    return photoAssetProxy;
}

PhotoAssetProxy::PhotoAssetProxy(
    std::shared_ptr<Dynamiclib> mediaLibraryLib, std::shared_ptr<PhotoAssetIntf> photoAssetIntf)
    : mediaLibraryLib_(mediaLibraryLib), photoAssetIntf_(photoAssetIntf)
{
    CHECK_ERROR_RETURN_LOG(mediaLibraryLib_ == nullptr, "PhotoAssetProxy construct mediaLibraryLib is null");
    CHECK_ERROR_RETURN_LOG(photoAssetIntf_ == nullptr, "PhotoAssetProxy construct photoAssetIntf is null");
}

void PhotoAssetProxy::AddPhotoProxy(sptr<Media::PhotoProxy> photoProxy)
{
    CHECK_ERROR_RETURN_LOG(photoAssetIntf_ == nullptr, "PhotoAssetProxy::AddPhotoProxy photoAssetIntf_ is null");
    photoAssetIntf_->AddPhotoProxy(photoProxy);
}

std::string PhotoAssetProxy::GetPhotoAssetUri()
{
    CHECK_ERROR_RETURN_RET_LOG(
        photoAssetIntf_ == nullptr, "", "PhotoAssetProxy::GetPhotoAssetUri photoAssetIntf_ is null");
    return photoAssetIntf_->GetPhotoAssetUri();
}

int32_t PhotoAssetProxy::GetVideoFd()
{
    CHECK_ERROR_RETURN_RET_LOG(photoAssetIntf_ == nullptr, -1, "PhotoAssetProxy::GetVideoFd photoAssetIntf_ is null");
    return photoAssetIntf_->GetVideoFd();
}

void PhotoAssetProxy::NotifyVideoSaveFinished()
{
    CHECK_ERROR_RETURN_LOG(
        photoAssetIntf_ == nullptr, "PhotoAssetProxy::NotifyVideoSaveFinished photoAssetIntf_ is null");
    photoAssetIntf_->NotifyVideoSaveFinished();
}

int32_t PhotoAssetProxy::GetUserId()
{
    CHECK_ERROR_RETURN_RET_LOG(photoAssetIntf_ == nullptr, -1, "PhotoAssetProxy::GetUserId photoAssetIntf_ is null");
    return photoAssetIntf_->GetUserId();
}
} // namespace CameraStandard
} // namespace OHOS