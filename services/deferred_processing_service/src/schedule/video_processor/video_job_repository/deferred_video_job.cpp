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
DeferredVideoJob::DeferredVideoJob(const std::string& videoId, std::unique_ptr<VideoInfo> info)
    : videoId_(videoId), info_(std::move(info)), createTime_(GetSteadyNow())
{
    DP_CHECK_EXECUTE(!info_->GetMoviePath().empty(), type_ = VideoJobType::MOVIE);
    DP_INFO_LOG("videoId: %{public}s, type: %{public}d", videoId_.c_str(), type_);
}

DpsFdPtr DeferredVideoJob::GetInputFd()
{
    DP_INFO_LOG("GetInputFd start.");
    DP_CHECK_RETURN_RET(srcFd_ != nullptr && srcFd_->GetFd() >= 0, srcFd_);
    int fd = open(info_->GetSrcPath().c_str(), O_RDONLY);
    DP_CHECK_RETURN_RET_LOG(fd < 0, nullptr, "Failed to open srcPath file: %{public}s", strerror(errno));
    srcFd_ = std::make_shared<DpsFd>(fd);
    return srcFd_;
}

DpsFdPtr DeferredVideoJob::GetMovieFd()
{
    DP_INFO_LOG("GetMovieFd start.");
    int fd = open(info_->GetMoviePath().c_str(), O_RDONLY);
    DP_CHECK_RETURN_RET_LOG(fd < 0, nullptr, "Failed to open moviePath file: %{public}s", strerror(errno));
    return std::make_shared<DpsFd>(fd);
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