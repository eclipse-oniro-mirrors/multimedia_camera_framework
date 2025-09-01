/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#include "suspend_state_observer.h"
#include "hcamera_service.h"

namespace OHOS::CameraStandard {
ErrCode SuspendStateObserver::OnActive(const std::vector<int32_t> &pidList, int32_t uid)
{
    MEDIA_DEBUG_LOG("SuspendStateObserver::OnActive is called");
    if (auto service = service_.promote()) {
        service->EraseActivePidList(pidList);
        service->ExecuteDelayCallbackTask(pidList);
    }
    return ERR_OK;
}
 
ErrCode SuspendStateObserver::OnDoze(const std::vector<int32_t> &pidList, int32_t uid)
{
    (void)pidList;
    (void)uid;
    return ERR_OK;
}
 
ErrCode SuspendStateObserver::OnFrozen(const std::vector<int32_t> &pidList, int32_t uid)
{
    MEDIA_DEBUG_LOG("SuspendStateObserver::OnFrozen is called");
    if (auto service = service_.promote()) {
        service->InsertFrozenPidList(pidList);
    }
    return ERR_OK;
}
} // namespace OHOS::CameraStandard