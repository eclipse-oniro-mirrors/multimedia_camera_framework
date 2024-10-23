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

#ifndef OHOS_CAMERA_DPS_DEFERRED_VIDEO_JOB_H
#define OHOS_CAMERA_DPS_DEFERRED_VIDEO_JOB_H

#include "basic_definitions.h"
#include "dp_utils.h"
#include "ipc_file_descriptor.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
enum class VideoJobStatus {
    NONE = 0,
    PAUSE = 1,
    PENDING = 2,
    FAILED = 3,
    DELETED = 4,
    RUNNING = 5,
    COMPLETED = 6,
    ERROR = 7,
};

class DeferredVideoJob {
public:
    DeferredVideoJob(const std::string& videoId, const sptr<IPCFileDescriptor>& srcFd,
        const sptr<IPCFileDescriptor>& dstFd);
    ~DeferredVideoJob();

    inline VideoJobStatus GetCurStatus()
    {
        DP_DEBUG_LOG("videoId: %{public}s, current status: %{public}d, previous status: %{public}d",
            videoId_.c_str(), curStatus_, preStatus_);
        return curStatus_;
    }

    inline VideoJobStatus GetPreStatus()
    {
        DP_DEBUG_LOG("videoId: %{public}s, current status: %{public}d, previous status: %{public}d",
            videoId_.c_str(), curStatus_, preStatus_);
        return preStatus_;
    }

    inline std::string GetVideoId()
    {
        return videoId_;
    }

    inline sptr<IPCFileDescriptor> GetInputFd()
    {
        return srcFd_;
    }

    inline sptr<IPCFileDescriptor> GetOutputFd()
    {
        return dstFd_;
    }

    bool operator==(const DeferredVideoJob& other) const
    {
        return videoId_ == other.videoId_;
    }

    bool operator>(const DeferredVideoJob& other) const
    {
        if (curStatus_ == other.curStatus_) {
            return createTime_ < other.createTime_;
        }
        return curStatus_ < other.curStatus_;
    }

private:
    friend class VideoJobRepository;
    bool SetJobStatus(VideoJobStatus curStatus);

    const std::string videoId_;
    sptr<IPCFileDescriptor> srcFd_;
    sptr<IPCFileDescriptor> dstFd_;
    VideoJobStatus preStatus_ {VideoJobStatus::NONE};
    VideoJobStatus curStatus_ {VideoJobStatus::NONE};
    SteadyTimePoint createTime_;
};
using DeferredVideoJobPtr = std::shared_ptr<DeferredVideoJob>;

class DeferredVideoWork {
public:
    DeferredVideoWork(const DeferredVideoJobPtr& jobPtr, ExecutionMode mode, bool isAutoSuspend);
    ~DeferredVideoWork();

    inline DeferredVideoJobPtr GetDeferredVideoJob() const
    {
        return jobPtr_;
    }

    inline ExecutionMode GetExecutionMode() const
    {
        return executionMode_;
    }

    inline bool IsSuspend() const
    {
        return !isCharging_;
    }

    inline SteadyTimePoint GetStartTime() const
    {
        return startTime_;
    }

    inline uint32_t GetExecutionTime() const
    {
        return static_cast<uint32_t>(GetDiffTime<Milli>(GetStartTime()));
    }

    inline uint32_t GetTimeId() const
    {
        return timeId_;
    }

    inline void SetTimeId(const uint32_t timeId)
    {
        timeId_ = timeId;
    }

private:
    DeferredVideoJobPtr jobPtr_;
    ExecutionMode executionMode_;
    SteadyTimePoint startTime_;
    bool isCharging_;
    uint32_t timeId_ {0};
};
using DeferredVideoWorkPtr = std::shared_ptr<DeferredVideoWork>;
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_DEFERRED_VIDEO_JOB_H