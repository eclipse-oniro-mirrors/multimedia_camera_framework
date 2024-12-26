/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions andPhotoProcessResult
 * limitations under the License.
 */

#include "photo_process_result.h"

#include "dp_log.h"
#include "dps.h"
#include "events_monitor.h"
#include "photo_process_command.h"
#include "service_died_command.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
PhotoProcessResult::PhotoProcessResult(const int32_t userId) : userId_(userId)
{
    DP_DEBUG_LOG("entered.");
}

PhotoProcessResult::~PhotoProcessResult()
{
    DP_DEBUG_LOG("entered.");
}

void PhotoProcessResult::OnProcessDone(const std::string& imageId, const std::shared_ptr<BufferInfo>& bufferInfo)
{
    DP_DEBUG_LOG("DPS_PHOTO: OnProcessDone imageId: %{public}s", imageId.c_str());
    auto ret = DPS_SendCommand<PhotoProcessSuccessCommand>(userId_, imageId, bufferInfo);
    DP_CHECK_ERROR_RETURN_LOG(ret != DP_OK,
        "process success imageId: %{public}s failed. ret: %{public}d", imageId.c_str(), ret);
}

void PhotoProcessResult::OnProcessDoneExt(const std::string& imageId, const std::shared_ptr<BufferInfoExt>& bufferInfo)
{
    DP_DEBUG_LOG("DPS_PHOTO: OnProcessDoneExt imageId: %{public}s", imageId.c_str());
    auto ret = DPS_SendCommand<PhotoProcessSuccessExtCommand>(userId_, imageId, bufferInfo);
    DP_CHECK_ERROR_RETURN_LOG(ret != DP_OK,
        "processExt success imageId: %{public}s failed. ret: %{public}d", imageId.c_str(), ret);
}

void PhotoProcessResult::OnError(const std::string& imageId,  DpsError errorCode)
{
    DP_DEBUG_LOG("DPS_PHOTO: OnError imageId: %{public}s, error: %{public}d", imageId.c_str(), errorCode);
    auto ret = DPS_SendCommand<PhotoProcessFailedCommand>(userId_, imageId, errorCode);
    DP_CHECK_ERROR_RETURN_LOG(ret != DP_OK,
        "processExt success imageId: %{public}s failed. ret: %{public}d", imageId.c_str(), ret);
}

void PhotoProcessResult::OnStateChanged(HdiStatus hdiStatus)
{
    DP_DEBUG_LOG("DPS_PHOTO: OnStateChanged hdiStatus: %{public}d", hdiStatus);
    EventsMonitor::GetInstance().NotifyImageEnhanceStatus(hdiStatus);
}

void PhotoProcessResult::OnPhotoSessionDied()
{
    DP_ERR_LOG("DPS_PHOTO: OnPhotoSessionDied");
    auto ret = DPS_SendCommand<PhotoDiedCommand>(userId_);
    DP_CHECK_ERROR_RETURN_LOG(ret != DP_OK, "process photoSessionDied. ret: %{public}d", ret);
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS