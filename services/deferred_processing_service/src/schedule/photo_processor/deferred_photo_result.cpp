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

#include "deferred_photo_result.h"

#include "dp_log.h"
#include "dps.h"
#include "events_monitor.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
namespace {
    constexpr int32_t DEFAULT_TIMEOUT_COUNT = 3;
    constexpr uint32_t MAX_CONSECUTIVE_CRASH_COUNT = 3;
    constexpr char DEFAULT_BP_CACHE_ID[] = "Null";
}
DeferredPhotoResult::DeferredPhotoResult()
{
    DP_DEBUG_LOG("entered.");
}

DeferredPhotoResult::~DeferredPhotoResult()
{
    DP_INFO_LOG("entered.");
    fatalStatusCodes_.clear();
    imageId2CrashCount_.clear();
}

int32_t DeferredPhotoResult::Initialize()
{
    fatalStatusCodes_ = {
        DpsError::DPS_ERROR_IMAGE_PROC_INVALID_PHOTO_ID,
        DpsError::DPS_ERROR_IMAGE_PROC_FAILED
    };
    return DP_OK;
}

void DeferredPhotoResult::RecordHigh(const std::string& imageId)
{
    DP_INFO_LOG("imageId: %{public}s", imageId.c_str());
    highImages_.insert(imageId);
}

void DeferredPhotoResult::DeRecordHigh(const std::string& imageId)
{
    if (highImages_.erase(imageId) > 0) {
        DP_INFO_LOG("imageId: %{public}s", imageId.c_str());
    }
}

void DeferredPhotoResult::OnSuccess(const std::string& imageId)
{
    ResetTimeoutCount();
}

JobErrorType DeferredPhotoResult::OnError(const std::string& imageId, DpsError& error, bool isHighJob)
{
    DP_INFO_LOG("entered imageId: %{public}s, error: %{public}d, isHighJob: %{public}d",
        imageId.c_str(), error, isHighJob);
    DP_CHECK_EXECUTE(error == DpsError::DPS_ERROR_SESSION_NOT_READY_TEMPORARILY, CheckCrashCount(imageId, error));
    DP_CHECK_EXECUTE(error != DpsError::DPS_ERROR_IMAGE_PROC_TIMEOUT, ResetTimeoutCount());
    DP_CHECK_RETURN_RET(IsFatalError(error), JobErrorType::FATAL_NOTIFY);

    if (isHighJob) {
        bool isNeedRetry = error == DpsError::DPS_ERROR_IMAGE_PROC_INTERRUPTED && highImages_.count(imageId) != 0;
        DP_CHECK_RETURN_RET_LOG(isNeedRetry, JobErrorType::RETRY,
            "High priority job %{public}s already in retry", imageId.c_str());
        return JobErrorType::HIGH_FAILED;
    }
    DP_CHECK_RETURN_RET(error == DpsError::DPS_ERROR_IMAGE_PROC_HIGH_TEMPERATURE, JobErrorType::FAILED_NOTIFY);
    return JobErrorType::NORMAL_FAILED;
}

void DeferredPhotoResult::RecordResult(const std::string& imageId,
    const std::shared_ptr<ImageInfo>& result, bool isBPcache)
{
    DP_INFO_LOG("DPS_PHOTO: Cache imageId: %{public}s", imageId.c_str());
    cacheMap_.emplace(imageId, result);
    DP_CHECK_EXECUTE(isBPcache, SetBPCacheId(imageId));
}

void DeferredPhotoResult::DeRecordResult(const std::string& imageId)
{
    DP_INFO_LOG("DPS_PHOTO: Remove cache imageId: %{public}s", imageId.c_str());
    cacheMap_.erase(imageId);
    DP_CHECK_EXECUTE(GetBPCacheId() == imageId, SetBPCacheId(DEFAULT_BP_CACHE_ID));
}

std::shared_ptr<ImageInfo> DeferredPhotoResult::GetCacheResult(const std::string& imageId)
{
    auto it = cacheMap_.find(imageId);
    return it != cacheMap_.end() ? it->second : nullptr;
}

void DeferredPhotoResult::CheckCrashCount(const std::string& imageId, DpsError& error)
{
    auto image = imageId2CrashCount_.find(imageId);
    DP_CHECK_EXECUTE_AND_RETURN(image == imageId2CrashCount_.end(), imageId2CrashCount_.emplace(imageId, 1));

    image->second += 1;
    DP_CHECK_EXECUTE(image->second >= MAX_CONSECUTIVE_CRASH_COUNT, error = DPS_ERROR_IMAGE_PROC_FAILED);
}

bool DeferredPhotoResult::IsFatalError(DpsError error) const
{
    return fatalStatusCodes_.count(error) != 0;
}

bool DeferredPhotoResult::IsNeedReset()
{
    processTimeoutCount_.fetch_add(1);
    if (processTimeoutCount_.load() >= DEFAULT_TIMEOUT_COUNT) {
        processTimeoutCount_.store(DEFAULT_COUNT);
        return true;
    }
    return false;
}

void DeferredPhotoResult::SetBPCacheId(const std::string& imageId)
{
    DP_INFO_LOG("DPS_PHOTO: Backpressure cache imageId: %{public}s", imageId.c_str());
    cachePhotoId_ = imageId;
    if (DEFAULT_BP_CACHE_ID == cachePhotoId_) {
        EventsMonitor::GetInstance().NotifyEventToObervers(EventType::PHOTO_CACHE_EVENT, NO_CACHE);
        return;
    }
    EventsMonitor::GetInstance().NotifyEventToObervers(EventType::PHOTO_CACHE_EVENT, CACHED);
}

std::string DeferredPhotoResult::GetBPCacheId()
{
    return cachePhotoId_;
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS