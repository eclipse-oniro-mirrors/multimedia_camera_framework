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

#include "dps.h"

#include "dp_catch.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
struct DpsInfo {
    std::atomic<bool> initialized_{false};
    std::mutex mutex{};
    std::shared_ptr<CommandServer> server;
    std::shared_ptr<SessionManager> session;
    std::shared_ptr<SchedulerManager> scheduler;
};

DpsInfo g_dpsInfo;

int32_t DPS_Initialize()
{
PROSS
    std::unique_lock<std::mutex> lock(g_dpsInfo.mutex);
    if (g_dpsInfo.initialized_) {
        DP_DEBUG_LOG("Already initialized.");
        return DP_OK;
    }
    DP_DEBUG_LOG("entered.");
    g_dpsInfo.server = std::make_shared<CommandServer>();
    g_dpsInfo.session = SessionManager::Create();
    g_dpsInfo.scheduler = SchedulerManager::Create();
    JUDEG(DP_NULL_POINTER, g_dpsInfo.server != nullptr);
    JUDEG(DP_NULL_POINTER, g_dpsInfo.session != nullptr);
    JUDEG(DP_NULL_POINTER, g_dpsInfo.scheduler != nullptr);
    EXEC(g_dpsInfo.server->Initialize());
    EXEC(g_dpsInfo.scheduler->Initialize());
    g_dpsInfo.initialized_ = true;
    DP_INFO_LOG("DPS_Initialize success.");
    return DP_OK;
END_PROSS
CATCH_ERROR
    DPS_Destroy();
    DP_ERR_LOG("DPS_Initialize failed, line: %{public}u, error: %{public}u.", ERROR_LINE(), ERROR_CODE());
    return ERROR_CODE();
END_CATCH_ERROR
}

void DPS_Destroy()
{
    std::unique_lock<std::mutex> lock(g_dpsInfo.mutex);
    DP_DEBUG_LOG("entered.");
    if (!g_dpsInfo.initialized_) {
        return;
    }
    g_dpsInfo.server.reset();
    g_dpsInfo.session.reset();
    g_dpsInfo.scheduler.reset();
    g_dpsInfo.initialized_ = false;
    DP_INFO_LOG("DPS_Destroy success.");
}

std::shared_ptr<CommandServer> DPS_GetCommandServer()
{
    std::unique_lock<std::mutex> lock(g_dpsInfo.mutex);
    if (g_dpsInfo.server) {
        return g_dpsInfo.server;
    }
    return nullptr;
}

std::shared_ptr<SessionManager> DPS_GetSessionManager()
{
    std::unique_lock<std::mutex> lock(g_dpsInfo.mutex);
    if (g_dpsInfo.session) {
        return g_dpsInfo.session;
    }
    return nullptr;
}

std::shared_ptr<SchedulerManager> DPS_GetSchedulerManager()
{
    std::unique_lock<std::mutex> lock(g_dpsInfo.mutex);
    if (g_dpsInfo.scheduler) {
        return g_dpsInfo.scheduler;
    }
    return nullptr;
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS