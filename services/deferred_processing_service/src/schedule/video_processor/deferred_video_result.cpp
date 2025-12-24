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

#include "deferred_video_result.h"

#include "dp_log.h"
#include "dps.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
namespace {
    constexpr uint32_t MAX_CONSECUTIVE_CRASH_COUNT = 3;
}
DeferredVideoResult::DeferredVideoResult()
{
    DP_DEBUG_LOG("entered.");
}

DeferredVideoResult::~DeferredVideoResult()
{
    DP_INFO_LOG("entered.");
    fatalStatusCodes_.clear();
}

int32_t DeferredVideoResult::Initialize()
{
    fatalStatusCodes_ = {
        DpsError::DPS_ERROR_VIDEO_PROC_INVALID_VIDEO_ID,
        DpsError::DPS_ERROR_VIDEO_PROC_FAILED
    };
    return DP_OK;
}

void DeferredVideoResult::RecordResult(const std::string& videoId, DpsError error)
{
    std::lock_guard lock(mutex_);
    DP_INFO_LOG("DPS_PHOTO: Cache videoId: %{public}s", videoId.c_str());
    cacheMap_.emplace(videoId, error);
}

void DeferredVideoResult::DeRecordResult(const std::string& videoId)
{
    std::lock_guard lock(mutex_);
    DP_INFO_LOG("DPS_PHOTO: Remove cache videoId: %{public}s", videoId.c_str());
    cacheMap_.erase(videoId);
}

DpsError DeferredVideoResult::GetCacheResult(const std::string& videoId)
{
    std::lock_guard lock(mutex_);
    auto it = cacheMap_.find(videoId);
    if (it != cacheMap_.end()) {
        return it->second;
    }
    return DpsError::DPS_ERROR_UNKNOWN;
}

JobErrorType DeferredVideoResult::OnError(const std::string& videoId, DpsError& error, bool isHighJob)
{
    DP_CHECK_EXECUTE(error == DPS_ERROR_SESSION_NOT_READY_TEMPORARILY, CheckCrashCount(videoId, error));
    DP_CHECK_RETURN_RET(IsFatalError(error), JobErrorType::FATAL_NOTIFY);
    if (isHighJob) {
        DP_CHECK_RETURN_RET(error == DPS_ERROR_VIDEO_PROC_INTERRUPTED, JobErrorType::PAUSE_NOTIFY);
        return JobErrorType::HIGH_FAILED;
    }
    DP_CHECK_RETURN_RET(error == DPS_ERROR_VIDEO_PROC_INTERRUPTED, JobErrorType::PAUSE);
    return JobErrorType::RETRY;
}

void DeferredVideoResult::CheckCrashCount(const std::string& videoId, DpsError& error)
{
    auto video = videoId2CrashCount_.find(videoId);
    DP_CHECK_EXECUTE_AND_RETURN(video == videoId2CrashCount_.end(), videoId2CrashCount_.emplace(videoId, 1));

    video->second += 1;
    DP_CHECK_EXECUTE(video->second >= MAX_CONSECUTIVE_CRASH_COUNT, error = DPS_ERROR_VIDEO_PROC_FAILED);
}

bool DeferredVideoResult::IsFatalError(DpsError error) const
{
    return fatalStatusCodes_.count(error) != 0;
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS