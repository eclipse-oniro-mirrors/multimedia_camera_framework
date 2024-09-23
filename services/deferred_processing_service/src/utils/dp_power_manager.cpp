/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

#include "dp_power_manager.h"

#include "dp_log.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
namespace {
    const std::string DEFERRED_LOCK_NAME = "DeferredProcessingWakeLock";
}

DPSProwerManager::DPSProwerManager()
{
    DP_DEBUG_LOG("entered.");
    Initialize();
}

DPSProwerManager::~DPSProwerManager()
{
    DP_DEBUG_LOG("entered.");
    wakeLock_ = nullptr;
}

void DPSProwerManager::Initialize()
{
    std::lock_guard<std::mutex> lock(mutex_);
    DP_DEBUG_LOG("entered.");
    if (initialized_.load()) {
        return;
    }

#ifdef CAMERA_USE_POWER
    auto& power = PowerMgr::PowerMgrClient::GetInstance();
    wakeLock_ = power.CreateRunningLock(DEFERRED_LOCK_NAME, PowerMgr::RunningLockType::RUNNINGLOCK_BACKGROUND);
    if (wakeLock_ == nullptr) {
        DP_ERR_LOG("DPSProwerManager initialize failed.");
        return;
    }
#endif
    initialized_.store(true);
}

void DPSProwerManager::SetAutoSuspend(bool isAutoSuspend, uint32_t time)
{
    std::lock_guard<std::mutex> lock(mutex_);
    DP_DEBUG_LOG("entered.");
    if (wakeLock_ == nullptr) {
        DP_ERR_LOG("WakeLock is null.");
        return;
    }

    if (isAutoSuspend) {
        if (isSuspend_) {
            EnableAutoSuspend();
            isSuspend_ = false;
        } else {
            DP_DEBUG_LOG("AutoSuspend already turn on.");
        }
    } else {
        if (!isSuspend_) {
            DisableAutoSuspend(time);
            isSuspend_ = true;
        } else {
            DP_DEBUG_LOG("AutoSuspend already not turn on yet.");
        }
    }
}

void DPSProwerManager::EnableAutoSuspend()
{
    DP_CHECK_EXECUTE(wakeLock_ != nullptr, wakeLock_->UnLock());
}

void DPSProwerManager::DisableAutoSuspend(uint32_t time)
{
    DP_CHECK_EXECUTE(wakeLock_ != nullptr, wakeLock_->Lock(time));
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS