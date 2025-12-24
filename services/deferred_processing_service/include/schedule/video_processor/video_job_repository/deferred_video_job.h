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
#include "dps_fd.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
enum class VideoJobState {
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
    DeferredVideoJob(const std::string& videoId, const DpsFdPtr& srcFd,
        const DpsFdPtr& dstFd, const DpsFdPtr& movieFd, const DpsFdPtr& movieCopyFd);
    ~DeferredVideoJob() = default;

    inline VideoJobState GetCurStatus()
    {
        return curStatus_;
    }

    inline VideoJobState GetPreStatus()
    {
        return preStatus_;
    }

    inline JobPriority GetCurPriority()
    {
        return priority_;
    }

    inline std::string GetVideoId()
    {
        return videoId_;
    }

    inline DpsFdPtr GetInputFd()
    {
        return srcFd_;
    }

    inline DpsFdPtr GetOutputFd()
    {
        return dstFd_;
    }

    inline DpsFdPtr GetMovieFd()
    {
        return movieFd_;
    }

    inline DpsFdPtr GetMovieCopyFd()
    {
        return movieCopyFd_;
    }

    inline ExecutionMode GetExecutionMode() const
    {
        return executionMode_;
    }

    inline void SetExecutionMode(ExecutionMode mode)
    {
        executionMode_ = mode;
        startTime_ = GetSteadyNow();
    }

    inline bool IsSuspend() const
    {
        return !isCharging_;
    }

    inline void SetChargState(bool isCharging)
    {
        isCharging_ = isCharging;
    }

    inline SteadyTimePoint GetStartTime() const
    {
        return startTime_;
    }

    inline uint32_t GetExecutionTime() const
    {
        return static_cast<uint32_t>(GetDiffTime<Milli>(GetStartTime()));
    }

    inline uint32_t GetTimerId() const
    {
        return timerId_;
    }

    inline void SetTimerId(const uint32_t timerId)
    {
        timerId_ = timerId;
    }

    inline bool isMoving()
    {
        return type_ == VideoJobType::MOVIE;
    }

    bool operator==(const DeferredVideoJob& other) const
    {
        return videoId_ == other.videoId_;
    }

    bool operator>(const DeferredVideoJob& other) const
    {
        // Compare based on priority first
        if (priority_ != other.priority_) {
            // If the job's status is more than running, compare the priority
            if (curStatus_ >= VideoJobState::RUNNING &&
                other.curStatus_ >= VideoJobState::RUNNING) {
                return priority_ > other.priority_;
            }
            // If only this job status is more than running, it is lesser
            if (curStatus_ >= VideoJobState::RUNNING) {
                return false;
            }
            // If only the other job status is more than running, this job is greater
            if (other.curStatus_ >= VideoJobState::RUNNING) {
                return true;
            }
            // If neither job status is more than running, compare priority
            return priority_ > other.priority_;
        }
        // If the priorities are the same and both are high priority, compare creation time
        if (priority_ == JobPriority::HIGH) {
            if (curStatus_ == other.curStatus_) {
                return createTime_ > other.createTime_;
            }
            return curStatus_ < other.curStatus_;
        }
        // If statuses are equal, compare creation time
        if (curStatus_ == other.curStatus_) {
            return createTime_ < other.createTime_;
        }
        return curStatus_ < other.curStatus_;
    }

private:
    friend class VideoJobRepository;
    bool SetJobState(VideoJobState curStatus);
    bool SetJobPriority(JobPriority priority);
    void UpdateTime();

    const std::string videoId_;
    DpsFdPtr srcFd_;
    DpsFdPtr dstFd_;
    DpsFdPtr movieFd_;
    DpsFdPtr movieCopyFd_;
    JobPriority priority_ {JobPriority::NORMAL};
    VideoJobState preStatus_ {VideoJobState::NONE};
    VideoJobState curStatus_ {VideoJobState::NONE};
    SteadyTimePoint createTime_;
    SteadyTimePoint startTime_;
    ExecutionMode executionMode_ {ExecutionMode::DUMMY};
    bool isCharging_ {false};
    uint32_t timerId_ {INVALID_TIMERID};
    VideoJobType type_ {VideoJobType::NORMAL};
};
using DeferredVideoJobPtr = std::shared_ptr<DeferredVideoJob>;
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_DEFERRED_VIDEO_JOB_H