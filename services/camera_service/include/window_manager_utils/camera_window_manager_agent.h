/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
 
#ifndef OHOS_CAMERA_CAMERA_WINDOW_MANAGER_AGENT_H
#define OHOS_CAMERA_CAMERA_WINDOW_MANAGER_AGENT_H
 
#include "hcamera_window_manager_callback_stub.h"
#include <cstdint>
namespace OHOS {
namespace CameraStandard {
class CameraWindowManagerAgent : public CameraWindowManagerAgentStub {
public:
    CameraWindowManagerAgent() = default;
    ~CameraWindowManagerAgent() = default;
    void UpdateCameraWindowStatus(uint32_t accessTokenId, bool isShowing) override;
    uint32_t GetAccessTokenId();
    void SetAccessTokenId(uint32_t accessTokenId);
private:
    uint32_t accessTokenId_;
};
} // namespace CameraStandard
} // namespace OHOS
#endif