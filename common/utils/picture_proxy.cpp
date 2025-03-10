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

#include "picture_proxy.h"
#include "camera_log.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace CameraStandard {

PictureProxy::PictureProxy(
    std::shared_ptr<Dynamiclib> pictureLib, std::shared_ptr<PictureIntf> pictureIntf)
    : pictureLib_(pictureLib), pictureIntf_(pictureIntf)
{
    CHECK_ERROR_RETURN_LOG(pictureLib_ == nullptr, "PictureProxy construct pictureLib is null");
    CHECK_ERROR_RETURN_LOG(pictureIntf_ == nullptr, "PictureProxy construct pictureIntf is null");
}

PictureProxy::~PictureProxy()
{
    MEDIA_INFO_LOG("PictureProxy dctor");
}

void PictureProxy::Create(sptr<SurfaceBuffer> &surfaceBuffer)
{
    MEDIA_INFO_LOG("PictureProxy ctor");
    std::shared_ptr<PictureIntf> pictureIntf = GetPictureIntf();
    if (!pictureIntf) {
        MEDIA_ERR_LOG("PictureProxy::Create pictureIntf_ is nullptr");
        return;
    }
    pictureIntf->Create(surfaceBuffer);
}

typedef PictureIntf* (*CreatePictureIntf)();
std::shared_ptr<PictureProxy> PictureProxy::CreatePictureProxy()
{
    auto dynamiclib = CameraDynamicLoader::GetDynamiclib(PICTURE_SO);
    CHECK_ERROR_RETURN_RET_LOG(
        dynamiclib == nullptr, nullptr, "PictureProxy::CreatePictureProxy get dynamiclib fail");
    CreatePictureIntf createPictureIntf = (CreatePictureIntf)dynamiclib->GetFunction("createPictureAdapterIntf");
    CHECK_ERROR_RETURN_RET_LOG(
        createPictureIntf == nullptr, nullptr, "PictureProxy::CreatePictureProxy get createPictureIntf fail");
    PictureIntf* pictureIntf = createPictureIntf();
    CHECK_ERROR_RETURN_RET_LOG(
        pictureIntf == nullptr, nullptr, "PictureProxy::CreatePictureProxy get pictureIntf fail");
    std::shared_ptr<PictureProxy> pictureProxy =
        std::make_shared<PictureProxy>(dynamiclib, std::shared_ptr<PictureIntf>(pictureIntf));
    return pictureProxy;
}

std::shared_ptr<PictureIntf> PictureProxy::GetPictureIntf()
{
    return pictureIntf_;
}
void PictureProxy::SetAuxiliaryPicture(sptr<SurfaceBuffer> &surfaceBuffer, CameraAuxiliaryPictureType type)
{
    MEDIA_INFO_LOG("PictureProxy::SetAuxiliaryPicture enter");
    std::shared_ptr<PictureIntf> pictureIntf = GetPictureIntf();
    if (!pictureIntf) {
        MEDIA_ERR_LOG("PictureProxy::SetAuxiliaryPicture pictureIntf_ is nullptr");
        return;
    }
    pictureIntf->SetAuxiliaryPicture(surfaceBuffer, type);
}

bool PictureProxy::Marshalling(Parcel &data)
{
    MEDIA_INFO_LOG("PictureProxy::Marshalling enter");
    std::shared_ptr<PictureIntf> pictureIntf = GetPictureIntf();
    if (pictureIntf == nullptr) {
        MEDIA_ERR_LOG("PictureProxy::Marshalling pictureIntf_ is nullptr");
        return false;
    }
    return pictureIntf->Marshalling(data);
}

void PictureProxy::Unmarshalling(Parcel &data)
{
    MEDIA_INFO_LOG("PictureProxy::Unmarshalling enter");
    std::shared_ptr<PictureIntf> pictureIntf = GetPictureIntf();
    if (!pictureIntf) {
        MEDIA_ERR_LOG("PictureProxy::Unmarshalling failed! pictureIntf is nullptr");
        return;
    }
    pictureIntf->Unmarshalling(data);
}

int32_t PictureProxy::SetExifMetadata(sptr<SurfaceBuffer> &surfaceBuffer)
{
    MEDIA_INFO_LOG("PictureProxy::SetExifMetadata enter");
    int32_t retCode = -1;
    std::shared_ptr<PictureIntf> pictureIntf = GetPictureIntf();
    if (!pictureIntf) {
        MEDIA_ERR_LOG("PictureProxy::SetExifMetadata pictureIntf is nullptr");
        return retCode;
    }
    retCode = pictureIntf->SetExifMetadata(surfaceBuffer);
    return retCode;
}

bool PictureProxy::SetMaintenanceData(sptr<SurfaceBuffer> &surfaceBuffer)
{
    bool retCode = false;
    std::shared_ptr<PictureIntf> pictureIntf = GetPictureIntf();
    if (!pictureIntf) {
        MEDIA_ERR_LOG("PictureProxy::SetMaintenanceData pictureIntf is nullptr");
        return retCode;
    }
    retCode = pictureIntf->SetMaintenanceData(surfaceBuffer);
    return retCode;
}

void PictureProxy::RotatePicture()
{
    std::shared_ptr<PictureIntf> pictureIntf = GetPictureIntf();
    if (!pictureIntf) {
        MEDIA_ERR_LOG("PictureProxy::RotatePicture pictureIntf is nullptr");
        return;
    }
    pictureIntf->RotatePicture();
}
}  // namespace CameraStandard
}  // namespace OHOS