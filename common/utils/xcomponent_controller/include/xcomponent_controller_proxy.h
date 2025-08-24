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

#ifndef OHOS_CAMERA_XCOMPONENT_CONTROLLER_PROXY_H
#define OHOS_CAMERA_XCOMPONENT_CONTROLLER_PROXY_H

#include "camera_dynamic_loader.h"
#include "xcomponent_controller_interface.h"

namespace OHOS {
namespace CameraStandard {
class XComponentControllerProxy : public XComponentControllerIntf {
public:
    explicit XComponentControllerProxy(std::shared_ptr<Dynamiclib> xcomponentControllerLib,
                                       std::shared_ptr<XComponentControllerIntf> xcomponentControllerIntf);

    ~XComponentControllerProxy() override;
    static std::shared_ptr<XComponentControllerProxy> CreateXComponentControllerProxy();
    static void FreeXComponentControllerDynamiclib();
    int32_t GetRenderFitBySurfaceId(
        const std::string& surfaceId, int32_t& renderFitNumber, bool& isRenderFitNewVersionEnabled) override;
    int32_t SetRenderFitBySurfaceId(
        const std::string& surfaceId, int32_t renderFitNumber, bool isRenderFitNewVersionEnabled) override;

private:
    // Keep the order of members in this class, the bottom member will be destroyed first
    std::shared_ptr<Dynamiclib> xcomponentControllerLib_ = {nullptr};
    std::shared_ptr<XComponentControllerIntf> xcomponentControllerIntf_ = {nullptr};
};
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_XCOMPONENT_CONTROLLER_PROXY_H