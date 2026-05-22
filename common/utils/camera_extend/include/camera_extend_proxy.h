/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef CAMERA_EXTEND_PROXY_H
#define CAMERA_EXTEND_PROXY_H

#include <cstdint>
#include <string>
#include <vector>

#include "camera_extend_interface.h"
#include "camera_dynamic_loader.h"
#include "camera_metadata_info.h"

namespace OHOS {
namespace CameraStandard {
class CameraExtendProxy : public CameraExtendIntf {
public:
    explicit CameraExtendProxy(
        std::shared_ptr<Dynamiclib> cameraExtendLib, std::shared_ptr<CameraExtendIntf> cameraExtendIntf);
    ~CameraExtendProxy() override;
    static std::shared_ptr<CameraExtendProxy> CreateCameraExtendProxy();
    static void FreeHCameraServiceHmsDynamiclib();

    void SetCameraAbility(std::vector<std::string>& cameraIds,
        std::vector<std::shared_ptr<OHOS::Camera::CameraMetadata>>& cameraAbilityList) override;

private:
    std::shared_ptr<Dynamiclib> cameraExtendLib_ = {nullptr};
    std::shared_ptr<CameraExtendIntf> cameraExtendIntf_ = {nullptr};
};
}
}
#endif  // CAMERA_EXTEND_PROXY_H
