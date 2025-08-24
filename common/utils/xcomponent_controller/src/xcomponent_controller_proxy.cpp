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

#include "xcomponent_controller_proxy.h"
#include "camera_log.h"

namespace OHOS {
namespace CameraStandard {
XComponentControllerProxy::XComponentControllerProxy(std::shared_ptr<Dynamiclib> lib,
    std::shared_ptr<XComponentControllerIntf> intf) : xcomponentControllerLib_ (lib), xcomponentControllerIntf_ (intf)
{
    MEDIA_DEBUG_LOG("XComponentControllerProxy constructor");
    CHECK_RETURN_ELOG(xcomponentControllerLib_  == nullptr, "xcomponentControllerLib_  is nullptr");
    CHECK_RETURN_ELOG(xcomponentControllerIntf_  == nullptr, "xcomponentControllerIntf_ is nullptr");
}

XComponentControllerProxy::~XComponentControllerProxy()
{
    MEDIA_DEBUG_LOG("XComponentControllerProxy destructor");
}

typedef XComponentControllerIntf* (*CreateXComponentControllerIntf)();
std::shared_ptr<XComponentControllerProxy> XComponentControllerProxy::CreateXComponentControllerProxy()
{
    MEDIA_DEBUG_LOG("CreateXComponentControllerProxy start");
    auto dynamiclib = CameraDynamicLoader::GetDynamiclib(XCOMPONENT_CONTROLLER_SO);
    CHECK_RETURN_RET_ELOG(dynamiclib == nullptr, nullptr, "get dynamiclib fail");
    CreateXComponentControllerIntf createXComponentControllerIntf =
        (CreateXComponentControllerIntf)dynamiclib->GetFunction("createXComponentControllerIntf");
    CHECK_RETURN_RET_ELOG(createXComponentControllerIntf == nullptr, nullptr, "createXComponentControllerIntf fail");
    XComponentControllerIntf* xcomponentControllerIntf = createXComponentControllerIntf();
    CHECK_RETURN_RET_ELOG(xcomponentControllerIntf == nullptr, nullptr, "get xcomponentControllerIntf fail");
    auto xcomponentControllerProxy = std::make_shared<XComponentControllerProxy>(
        dynamiclib, std::shared_ptr<XComponentControllerIntf>(xcomponentControllerIntf));
    return xcomponentControllerProxy;
}

int32_t XComponentControllerProxy::GetRenderFitBySurfaceId(
    const std::string& surfaceId, int32_t& renderFitNumber, bool& isRenderFitNewVersionEnabled)
{
    MEDIA_DEBUG_LOG("XComponentControllerProxy::GetRenderFitBySurfaceId");
    CHECK_RETURN_RET_ELOG(
        xcomponentControllerIntf_ == nullptr, MEDIA_ERR, "xcomponentControllerIntf_ is nullptr");
    return xcomponentControllerIntf_->GetRenderFitBySurfaceId(surfaceId, renderFitNumber, isRenderFitNewVersionEnabled);
}

int32_t XComponentControllerProxy::SetRenderFitBySurfaceId(
    const std::string& surfaceId, int32_t renderFitNumber, bool isRenderFitNewVersionEnabled)
{
    MEDIA_DEBUG_LOG("XComponentControllerProxy::SetRenderFitBySurfaceId");
    CHECK_RETURN_RET_ELOG(
        xcomponentControllerIntf_ == nullptr, MEDIA_ERR, "xcomponentControllerIntf_ is nullptr");
    return xcomponentControllerIntf_->SetRenderFitBySurfaceId(surfaceId, renderFitNumber, isRenderFitNewVersionEnabled);
}

void XComponentControllerProxy::FreeXComponentControllerDynamiclib()
{
    auto delayMs = 300;
    CameraDynamicLoader::FreeDynamicLibDelayed(XCOMPONENT_CONTROLLER_SO, delayMs);
}
}  // namespace CameraStandard
}  // namespace OHOS