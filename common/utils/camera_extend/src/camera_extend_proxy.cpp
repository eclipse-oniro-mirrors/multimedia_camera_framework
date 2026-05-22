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

#include "camera_extend_proxy.h"
#include "camera_log.h"

namespace OHOS {
namespace CameraStandard {

CameraExtendProxy::CameraExtendProxy(std::shared_ptr<Dynamiclib> cameraExtendLib,
    std::shared_ptr<CameraExtendIntf> cameraExtendIntf)
    : cameraExtendLib_(cameraExtendLib), cameraExtendIntf_(cameraExtendIntf)
{
    MEDIA_INFO_LOG("CameraExtendProxy constructor");
}

CameraExtendProxy::~CameraExtendProxy()
{
    MEDIA_INFO_LOG("CameraExtendProxy deconstructor");
}

using CreateCameraExtendIntf = CameraExtendIntf*(*)();

std::shared_ptr<CameraExtendProxy> CameraExtendProxy::CreateCameraExtendProxy()
{
    MEDIA_INFO_LOG("CreateCameraExtendProxy start");
    auto dynamiclib = CameraDynamicLoader::GetDynamiclib(CAMERA_EXTEND_SO);
    CHECK_RETURN_RET_ELOG(dynamiclib == nullptr, nullptr, "CameraExtendProxy get dynamiclib fail");
    CreateCameraExtendIntf createCameraExtendIntf =
            (CreateCameraExtendIntf)dynamiclib->GetFunction("createCameraExtendIntf");
    CHECK_RETURN_RET_ELOG(createCameraExtendIntf == nullptr, nullptr, "CreateCameraExtendIntf fail");
    CameraExtendIntf* cameraExtendIntf = createCameraExtendIntf();
    CHECK_RETURN_RET_ELOG(cameraExtendIntf == nullptr, nullptr, "get cameraExtendIntf fail");
    auto cameraExtendProxy = std::make_shared<CameraExtendProxy>(dynamiclib,
                                                    std::shared_ptr<CameraExtendIntf>(cameraExtendIntf));
    return cameraExtendProxy;
}

void CameraExtendProxy::FreeHCameraServiceHmsDynamiclib()
{
    MEDIA_INFO_LOG("CameraExtendProxy::FreeHCameraServiceHmsDynamiclib is called");
    CameraDynamicLoader::FreeDynamicLibDelayed(CAMERA_EXTEND_SO, 0);
}

void CameraExtendProxy::SetCameraAbility(
    std::vector<std::string>& cameraIds, std::vector<std::shared_ptr<OHOS::Camera::CameraMetadata>>& cameraAbilityList)
{
    MEDIA_INFO_LOG("CameraExtendProxy::SetCameraAbility is called");
    CHECK_RETURN_ELOG(cameraExtendIntf_ == nullptr,
        "CameraExtendProxy::SetCameraAbility cameraResourceIntf_ is nullptr");
    return cameraExtendIntf_->SetCameraAbility(cameraIds, cameraAbilityList);
}
}
}
