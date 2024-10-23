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

#include "deferred_video_job.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {


DeferredVideoWork::DeferredVideoWork(const DeferredVideoJobPtr& jobPtr, ExecutionMode mode, bool isCharging)
    : jobPtr_(jobPtr),
      executionMode_(mode),
      startTime_(GetSteadyNow()),
      isCharging_(isCharging)
{
    DP_DEBUG_LOG("entered");
}

DeferredVideoWork::~DeferredVideoWork()
{
    DP_DEBUG_LOG("entered");
    jobPtr_ = nullptr;
}

DeferredVideoJob::DeferredVideoJob(const std::string& videoId, const sptr<IPCFileDescriptor>& srcFd,
    const sptr<IPCFileDescriptor>& dstFd)
    : videoId_(videoId),
      srcFd_(srcFd),
      dstFd_(dstFd),
      createTime_(GetSteadyNow())
{
    DP_DEBUG_LOG("videoId: %{public}s, srcFd: %{public}d, dstFd: %{public}d",
        videoId_.c_str(), srcFd_->GetFd(), dstFd_->GetFd());
}

DeferredVideoJob::~DeferredVideoJob()
{
    DP_DEBUG_LOG("entered");
    srcFd_ = nullptr;
    dstFd_ = nullptr;
}

bool DeferredVideoJob::SetJobStatus(VideoJobStatus status)
{
    DP_DEBUG_LOG("videoId: %{public}s, current status: %{public}d, previous status: %{public}d, "
        "status to set: %{public}d", videoId_.c_str(), curStatus_, preStatus_, status);
    DP_CHECK_RETURN_RET(curStatus_ == status, false);
    
    preStatus_ = curStatus_;
    curStatus_ = status;
    return true;
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS