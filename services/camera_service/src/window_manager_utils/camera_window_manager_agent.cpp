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
 
#include "camera_log.h"
#include "camera_window_manager_agent.h"
 
namespace OHOS {
namespace CameraStandard {
void CameraWindowManagerAgent::UpdateCameraWindowStatus(uint32_t accessTokenId, bool isShowing)
{
    MEDIA_DEBUG_LOG("UpdateCameraWindowStatus get accessTokenId: %{public}d changed, isShowing: %{public}d",
        accessTokenId, isShowing);
    if (isShowing == 1) {
        accessTokenId_ = accessTokenId;
    } else {
        accessTokenId_ = 0;
    }
}
 
uint32_t CameraWindowManagerAgent::GetAccessTokenId()
{
    return accessTokenId_;
}
 
void CameraWindowManagerAgent::SetAccessTokenId(uint32_t accessTokenId)
{
    accessTokenId_ = accessTokenId;
}
} // namespace CameraStandard
} // namespace OHOS