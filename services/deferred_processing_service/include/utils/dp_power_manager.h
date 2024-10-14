/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
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

#ifndef OHOS_CAMERA_DPS_POWER_MANAGER_H
#define OHOS_CAMERA_DPS_POWER_MANAGER_H

#include "singleton.h"
#ifdef CAMERA_USE_POWER
#include "power_mgr_client.h"
#include "running_lock.h"
#endif

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class DPSProwerManager : public Singleton<DPSProwerManager> {
    DECLARE_SINGLETON(DPSProwerManager)

public:
    void Initialize();
    void SetAutoSuspend(bool isAutoSuspend, uint32_t time = 0);

private:
    void EnableAutoSuspend();
    void DisableAutoSuspend(uint32_t time);

    std::mutex mutex_;
    std::atomic<bool> initialized_ {false};
    bool isSuspend_ {false};
    std::shared_ptr<PowerMgr::RunningLock> wakeLock_ {nullptr};
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_POWER_MANAGER_H