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
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "deferred_video_job.h"
#include "dp_log.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
DeferredVideoJob::DeferredVideoJob(const std::string& videoId, const DpsFdPtr& srcFd,
    const DpsFdPtr& dstFd, const DpsFdPtr& movieFd, const DpsFdPtr& movieCopyFd)
    : videoId_(videoId), srcFd_(srcFd), dstFd_(dstFd), movieFd_(movieFd),
      movieCopyFd_(movieCopyFd), createTime_(GetSteadyNow())
{
    DP_CHECK_EXECUTE(movieFd_ != nullptr && movieCopyFd_ != nullptr, type_ = VideoJobType::MOVIE);
    DP_INFO_LOG("videoId: %{public}s, type: %{public}d, srcFd: %{public}d, dstFd: %{public}d",
        videoId_.c_str(), type_, srcFd_->GetFd(), dstFd_->GetFd());
}

bool DeferredVideoJob::SetJobState(VideoJobState status)
{
    DP_DEBUG_LOG("videoId: %{public}s, current status: %{public}d, previous status: %{public}d, "
        "status to set: %{public}d", videoId_.c_str(), curStatus_, preStatus_, status);
    DP_CHECK_RETURN_RET(curStatus_ == status, false);

    preStatus_ = curStatus_;
    curStatus_ = status;
    return true;
}

bool DeferredVideoJob::SetJobPriority(JobPriority priority)
{
    DP_DEBUG_LOG("videoId: %{public}s, current priority: %{public}d, priority to set: %{public}d",
        videoId_.c_str(), priority_, priority);
    DP_CHECK_EXECUTE(priority == JobPriority::HIGH, UpdateTime());
    DP_CHECK_RETURN_RET(priority_ == priority, false);
    priority_ = priority;
    return true;
}

void DeferredVideoJob::UpdateTime()
{
    createTime_ = GetSteadyNow();
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS