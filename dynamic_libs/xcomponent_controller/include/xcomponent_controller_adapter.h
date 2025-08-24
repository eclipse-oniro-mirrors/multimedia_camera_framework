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

#ifndef OHOS_CAMERA_XCOMPONENT_CONTROLLER_ADAPTER_H
#define OHOS_CAMERA_XCOMPONENT_CONTROLLER_ADAPTER_H

#include <string>
#include "xcomponent_controller_interface.h"

namespace OHOS::CameraStandard {
class XComponentControllerAdapter : public XComponentControllerIntf {
public:
    XComponentControllerAdapter();
    virtual ~XComponentControllerAdapter() = default;

    int32_t GetRenderFitBySurfaceId(
        const std::string& surfaceId, int32_t& renderFitNumber, bool& isRenderFitNewVersionEnabled) override;
    int32_t SetRenderFitBySurfaceId(
        const std::string& surfaceId, int32_t renderFitNumber, bool isRenderFitNewVersionEnabled) override;
};
} // namespace OHOS::CameraStandard
#endif // OHOS_CAMERA_XCOMPONENT_CONTROLLER_ADAPTER_H