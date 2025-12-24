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

#ifndef OHOS_CAMERA_DPS_DEFERRED_PHOTO_JOB_H
#define OHOS_CAMERA_DPS_DEFERRED_PHOTO_JOB_H

#include "basic_definitions.h"
#include "dp_utils.h"
#include "istate_change_listener.h"
#include "state_machine.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
struct PhotoState : State {
    explicit PhotoState(JobState state, const std::string& imageId,
        const std::weak_ptr<IJobStateChangeListener>& listener)
        : State(state), imageId_(imageId), listener_(listener) {}

protected:
    void OnStateEntered() override;

    const std::string imageId_;
    std::weak_ptr<IJobStateChangeListener> listener_;
};

struct PendingState : PhotoState {
    explicit PendingState(const std::string& imageId, const std::weak_ptr<IJobStateChangeListener>& listener)
        : PhotoState(JobState::PENDING, imageId, listener) {}

private:
    void OnStateEntered() override;
};

struct FailedState : PhotoState {
    explicit FailedState(const std::string& imageId, const std::weak_ptr<IJobStateChangeListener>& listener)
        : PhotoState(JobState::FAILED, imageId, listener) {}
};

struct RunningState : PhotoState {
    explicit RunningState(const std::string& imageId, const std::weak_ptr<IJobStateChangeListener>& listener)
        : PhotoState(JobState::RUNNING, imageId, listener) {}

private:
    void OnStateEntered() override;
    void OnStateExited() override;
};

struct CompletedState : PhotoState {
    explicit CompletedState(const std::string& imageId, const std::weak_ptr<IJobStateChangeListener>& listener)
        : PhotoState(JobState::COMPLETED, imageId, listener) {}
};

struct ErrorState : PhotoState {
    explicit ErrorState(const std::string& imageId, const std::weak_ptr<IJobStateChangeListener>& listener)
        : PhotoState(JobState::ERROR, imageId, listener) {}
};

struct AddState : PhotoState {
    explicit AddState(const std::string& imageId, const std::weak_ptr<IJobStateChangeListener>& listener)
        : PhotoState(JobState::NONE, imageId, listener) {}

private:
    void OnStateEntered() override;
    void OnStateExited() override;
};

struct DeleteState : PhotoState {
    explicit DeleteState(const std::string& imageId, const std::weak_ptr<IJobStateChangeListener>& listener)
        : PhotoState(JobState::NONE, imageId, listener) {}

private:
    void OnStateEntered() override;
};

class DeferredPhotoJob : public StateMachine {
public:
    DeferredPhotoJob(const std::string& imageId, const PhotoJobType photoJobType, const bool discardable,
        const std::weak_ptr<IJobStateChangeListener>& jobChangeListener);
    ~DeferredPhotoJob() = default;

    bool Prepare();
    bool Start(uint32_t timerId);
    bool Complete();
    bool Fail();
    bool Error();
    bool Delete();
    bool SetJobPriority(JobPriority priority);
    void SetExecutionMode(ExecutionMode mode);

    bool operator==(const DeferredPhotoJob& other) const
    {
        return imageId_ == other.imageId_;
    }

    bool operator>(const DeferredPhotoJob& other) const
    {
        // Compare based on priority first
        if (priority_ != other.priority_) {
            // If the job's status is more than running, compare the priority
            if (currState_->GetState() >= JobState::RUNNING &&
                other.currState_->GetState() >= JobState::RUNNING) {
                return priority_ > other.priority_;
            }
            // If only this job status is more than running, it is lesser
            if (currState_->GetState() >= JobState::RUNNING) {
                return false;
            }
            // If only the other job status is more than running, this job is greater
            if (other.currState_->GetState() >= JobState::RUNNING) {
                return true;
            }
            // If neither job status is more than running, compare priority
            return priority_ > other.priority_;
        }
        // If the priorities are the same and both are high priority, compare creation time
        if (priority_ == JobPriority::HIGH) {
            if (currState_->GetState() == other.currState_->GetState()) {
                return createTime_ > other.createTime_;
            }
            return currState_->GetState() < other.currState_->GetState();
        }
        // If statuses are equal, compare creation time
        if (currState_->GetState() == other.currState_->GetState()) {
            return createTime_ < other.createTime_;
        }
        return currState_->GetState() < other.currState_->GetState();
    }

    inline JobPriority GetCurPriority()
    {
        return priority_;
    }

    inline JobPriority GetRunningPriority()
    {
        return runningPriority_;
    }

    inline JobState GetCurStatus()
    {
        return currState_->GetState();
    }

    inline const std::string& GetImageId() const
    {
        return imageId_;
    }

    inline ExecutionMode GetExecutionMode()
    {
        return executionMode_;
    }

    inline PhotoJobType GetPhotoJobType()
    {
        return photoJobType_;
    }

    inline bool GetDiscardable()
    {
        return discardable_;
    }

    inline uint64_t GetTime()
    {
        return createTime_.time_since_epoch().count();
    }

    inline uint32_t GetTimerId()
    {
        return timerId_;
    }

    inline void ResetTimer()
    {
        timerId_ = INVALID_TIMERID;
    }

private:
    void UpdateTime();
    void RecordJobRunningPriority();

    const std::string imageId_;
    const PhotoJobType photoJobType_;
    const bool discardable_;
    SteadyTimePoint createTime_;
    std::weak_ptr<IJobStateChangeListener> jobChangeListener_;
    uint32_t timerId_ {INVALID_TIMERID};
    JobPriority priority_ {JobPriority::NONE};
    JobPriority runningPriority_ {JobPriority::NORMAL};
    ExecutionMode executionMode_ {ExecutionMode::DUMMY};
    std::shared_ptr<AddState> add_;
    std::shared_ptr<PendingState> pending_;
    std::shared_ptr<FailedState> failed_;
    std::shared_ptr<RunningState> running_;
    std::shared_ptr<CompletedState> completed_;
    std::shared_ptr<ErrorState> error_;
    std::shared_ptr<DeleteState> delete_;
};
using DeferredPhotoJobPtr = std::shared_ptr<DeferredPhotoJob>;
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_DEFERRED_PHOTO_JOB_H