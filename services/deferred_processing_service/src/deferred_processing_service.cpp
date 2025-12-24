/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include "deferred_processing_service.h"

#include "events_info.h"
#include "events_monitor.h"
#include "dp_log.h"
#include "dps.h"
#include "picture_interface.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
DeferredProcessingService::DeferredProcessingService()
{
    DP_DEBUG_LOG("entered.");
}

DeferredProcessingService::~DeferredProcessingService()
{
    HILOG_COMM_INFO("entered.");
    DPS_Destroy();
}

void DeferredProcessingService::Initialize()
{
    DP_DEBUG_LOG("entered.");
    EventsMonitor::GetInstance().Initialize();
    auto ret = DPS_Initialize();
    DP_CHECK_ERROR_RETURN_LOG(ret != DP_OK, "DeferredProcessingService init failed, ret: %{public}d", ret);
    initialized_.store(true);
}

void DeferredProcessingService::NotifyLowQualityImage(const int32_t userId, const std::string& imageId,
    std::shared_ptr<PictureIntf> picture)
{
    DP_CHECK_RETURN(!initialized_.load());

    auto sessionManager = DPS_GetSessionManager();
    DP_CHECK_ERROR_RETURN_LOG(sessionManager == nullptr, "SessionManager is nullptr, userId: %{public}d", userId);

    if (auto callback = sessionManager->GetCallback(userId)) {
        callback->OnDeliveryLowQualityImage(imageId, picture);
        return;
    }
    DP_ERR_LOG("DeferredPhotoProcessingSessionCallback::NotifyLowQualityImage not set!, Discarding callback");
}

sptr<IDeferredPhotoProcessingSession> DeferredProcessingService::CreateDeferredPhotoProcessingSession(
    const int32_t userId, const sptr<IDeferredPhotoProcessingSessionCallback>& callback)
{
    DP_CHECK_RETURN_RET(!initialized_.load(), nullptr);

    DP_INFO_LOG("Create photo session for userId: %{public}d", userId);
    auto sessionManager = DPS_GetSessionManager();
    DP_CHECK_ERROR_RETURN_RET_LOG(sessionManager == nullptr, nullptr,
        "SessionManager is nullptr, userId: %{public}d", userId);
    return sessionManager->CreateDeferredPhotoProcessingSession(userId, callback);
}

sptr<IDeferredVideoProcessingSession> DeferredProcessingService::CreateDeferredVideoProcessingSession(
    const int32_t userId, const sptr<IDeferredVideoProcessingSessionCallback>& callbacks)
{
    DP_CHECK_RETURN_RET(!initialized_.load(), nullptr);

    DP_INFO_LOG("Create video session for userId: %{public}d", userId);
    auto sessionManager = DPS_GetSessionManager();
    DP_CHECK_ERROR_RETURN_RET_LOG(sessionManager == nullptr, nullptr,
        "SessionManager is null, userId: %{public}d", userId);
    return sessionManager->CreateDeferredVideoProcessingSession(userId, callbacks);
}

void DeferredProcessingService::NotifyInterrupt()
{
    EventsMonitor::GetInstance().NotifyInterrupt();
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS