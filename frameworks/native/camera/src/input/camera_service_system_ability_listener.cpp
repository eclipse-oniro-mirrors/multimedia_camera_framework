/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "input/camera_service_system_ability_listener.h"

#include "camera_log.h"
#include "input/camera_manager.h"

namespace OHOS {
namespace CameraStandard {
void CameraServiceSystemAbilityListener::OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    MEDIA_INFO_LOG("OnAddSystemAbility,id: %{public}d", systemAbilityId);
    CameraManager::GetInstance()->OnCameraServerAlive();
}

void CameraServiceSystemAbilityListener::OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId)
{
    MEDIA_INFO_LOG("OnRemoveSystemAbility,id: %{public}d", systemAbilityId);
}
} // namespace CameraStandard
} // namespace OHOS