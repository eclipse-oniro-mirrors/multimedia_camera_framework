/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "cfilter.h"

#include <algorithm>
#include <sstream>

#include "camera_log.h"

// LCOV_EXCL_START
namespace OHOS {
namespace CameraStandard {
namespace {
    constexpr uint32_t THREAD_PRIORITY_41 = 7;
    constexpr uint32_t TIME_OUT = 30000;
}
CFilter::CFilter(const std::string& name, CFilterType type, bool isAyncMode)
    : name_(name), filterType_(type), isAsyncMode_(isAyncMode)
{
}

CFilter::~CFilter()
{
    MEDIA_INFO_LOG("entered.");
    nextCFiltersMap_.clear();
}

void CFilter::Init(const std::shared_ptr<CEventReceiver>& receiver, const std::shared_ptr<CFilterCallback>& callback)
{
    receiver_ = receiver;
    callback_ = callback;
}

void CFilter::LinkPipeLine(const std::string& groupId, bool needTurbo)
{
    groupId_ = groupId;
    MEDIA_INFO_LOG("CFilter %{public}s LinkPipeLine:%{public}s, isAsyncMode_:%{public}d",
        name_.c_str(), groupId.c_str(), isAsyncMode_);
    if (isAsyncMode_) {
        TaskType taskType;
        switch (filterType_) {
            case CFilterType::VIDEO_ENC:
            case CFilterType::VIDEO_DEC:
            case CFilterType::AUDIO_CAPTURE:
                taskType = TaskType::AUDIO;
                break;
            default:
                taskType = TaskType::SINGLETON;
                break;
        }
        filterTask_ = std::make_unique<Task>(name_, groupId_, taskType, TaskPriority::HIGH, false);
        if (needTurbo) {
            filterTask_->UpdateThreadPriority(THREAD_PRIORITY_41, "camera_service");
        }
        filterTask_->SubmitJobOnce([this] {
            Status ret = DoInitAfterLink();
            SetErrCode(ret);
            ChangeState(ret == Status::OK ? CFilterState::INITIALIZED : CFilterState::ERROR);
        });
    } else {
        Status ret = DoInitAfterLink();
        SetErrCode(ret);
        ChangeState(ret == Status::OK ? CFilterState::INITIALIZED : CFilterState::ERROR);
    }
}

Status CFilter::Prepare()
{
    MEDIA_INFO_LOG("Prepare %{public}s, pState:%{public}d", name_.c_str(), static_cast<int32_t>(curState_));
    if (filterTask_) {
        filterTask_->SubmitJobOnce([this] {
            PrepareDone();
        });
    } else {
        return PrepareDone();
    }
    return Status::OK;
}

Status CFilter::PrepareDone()
{
    MEDIA_INFO_LOG("Prepare enter %{public}s", name_.c_str());
    if (curState_ == CFilterState::ERROR) {
        // if DoInitAfterLink error, do not prepare.
        return Status::ERROR_INVALID_OPERATION;
    }
    // next filters maybe added in DoPrepare, so we must DoPrepare first
    Status ret = DoPrepare();
    SetErrCode(ret);
    if (ret != Status::OK) {
        ChangeState(CFilterState::ERROR);
        return ret;
    }
    for (auto iter : nextCFiltersMap_) {
        for (auto filter : iter.second) {
            ret = filter->Prepare();
            CHECK_RETURN_RET(ret != Status::OK, ret);
        }
    }
    ChangeState(CFilterState::READY);
    return ret;
}

Status CFilter::Start()
{
    MEDIA_INFO_LOG("Start %{public}s, pState: %{public}d", name_.c_str(), static_cast<int32_t>(curState_));
    if (filterTask_) {
        filterTask_->SubmitJobOnce([this] {
            StartDone();
            filterTask_->Start();
        });
        for (auto iter : nextCFiltersMap_) {
            for (auto filter : iter.second) {
                filter->Start();
            }
        }
    } else {
        for (auto iter : nextCFiltersMap_) {
            for (auto filter : iter.second) {
                filter->Start();
            }
        }
        return StartDone();
    }
    return Status::OK;
}

Status CFilter::StartDone()
{
    MEDIA_INFO_LOG("Start in %{public}s", name_.c_str());
    Status ret = DoStart();
    SetErrCode(ret);
    ChangeState(ret == Status::OK ? CFilterState::RUNNING : CFilterState::ERROR);
    return ret;
}

Status CFilter::Pause()
{
    MEDIA_INFO_LOG("Pause %{public}s, pState: %{public}d", name_.c_str(), static_cast<int32_t>(curState_));
    // In offload case, we need pause to interrupt audio_sink_plugin write function,  so do not use asyncmode
    auto ret = PauseDone();
    if (filterTask_) {
        filterTask_->Pause();
    }
    for (auto iter : nextCFiltersMap_) {
        for (auto filter : iter.second) {
            filter->Pause();
        }
    }
    return ret;
}

Status CFilter::PauseDragging()
{
    MEDIA_INFO_LOG("PauseDragging %{public}s, pState: %{public}d", name_.c_str(), static_cast<int32_t>(curState_));
    auto ret = DoPauseDragging();
    if (filterTask_) {
        filterTask_->Pause();
    }
    for (auto iter : nextCFiltersMap_) {
        for (auto filter : iter.second) {
            auto curRet = filter->PauseDragging();
            if (curRet != Status::OK) {
                ret = curRet;
            }
        }
    }
    return ret;
}

Status CFilter::PauseAudioAlign()
{
    MEDIA_INFO_LOG("PauseAudioAlign %{public}s, pState: %{public}d", name_.c_str(), static_cast<int32_t>(curState_));
    auto ret = DoPauseAudioAlign();
    if (filterTask_) {
        filterTask_->Pause();
    }
    for (auto iter : nextCFiltersMap_) {
        for (auto filter : iter.second) {
            auto curRet = filter->PauseAudioAlign();
            if (curRet != Status::OK) {
                ret = curRet;
            }
        }
    }
    return ret;
}

Status CFilter::PauseDone()
{
    MEDIA_INFO_LOG("Pause in %{public}s", name_.c_str());
    Status ret = DoPause();
    SetErrCode(ret);
    ChangeState(ret == Status::OK ? CFilterState::PAUSED : CFilterState::ERROR);
    return ret;
}

Status CFilter::Resume()
{
    MEDIA_INFO_LOG("Resume %{public}s, pState: %{public}d", name_.c_str(), static_cast<int32_t>(curState_));
    if (filterTask_) {
        filterTask_->SubmitJobOnce([this]() {
            ResumeDone();
            filterTask_->Start();
        });
        for (auto iter : nextCFiltersMap_) {
            for (auto filter : iter.second) {
                filter->Resume();
            }
        }
    } else {
        for (auto iter : nextCFiltersMap_) {
            for (auto filter : iter.second) {
                filter->Resume();
            }
        }
        return ResumeDone();
    }
    return Status::OK;
}

Status CFilter::ResumeDone()
{
    MEDIA_INFO_LOG("Resume in %{public}s", name_.c_str());
    Status ret = DoResume();
    SetErrCode(ret);
    ChangeState(ret == Status::OK ? CFilterState::RUNNING : CFilterState::ERROR);
    return ret;
}

Status CFilter::ResumeDragging()
{
    MEDIA_INFO_LOG("ResumeDragging %{public}s, pState: %{public}d", name_.c_str(), static_cast<int32_t>(curState_));
    auto ret = Status::OK;
    ret = DoResumeDragging();
    if (filterTask_) {
        filterTask_->Start();
    }
    for (auto iter : nextCFiltersMap_) {
        for (auto filter : iter.second) {
            auto curRet = filter->ResumeDragging();
            if (curRet != Status::OK) {
                ret = curRet;
            }
        }
    }
    return ret;
}

Status CFilter::ResumeAudioAlign()
{
    MEDIA_INFO_LOG("ResumeAudioAlign %{public}s, pState: %{public}d", name_.c_str(), static_cast<int32_t>(curState_));
    auto ret = Status::OK;
    ret = DoResumeAudioAlign();
    if (filterTask_) {
        filterTask_->Start();
    }
    for (auto iter : nextCFiltersMap_) {
        for (auto filter : iter.second) {
            auto curRet = filter->ResumeAudioAlign();
            if (curRet != Status::OK) {
                ret = curRet;
            }
        }
    }
    return ret;
}

Status CFilter::Stop()
{
    MEDIA_INFO_LOG("Stop %{public}s, pState: %{public}d", name_.c_str(), static_cast<int32_t>(curState_));
    // In offload case, we need stop to interrupt audio_sink_plugin write function,  so do not use asyncmode
    auto ret = StopDone();
    if (filterTask_) {
        filterTask_->Stop();
    }
    for (auto iter : nextCFiltersMap_) {
        for (auto filter : iter.second) {
            filter->Stop();
        }
    }
    return ret;
}

Status CFilter::StopDone()
{
    MEDIA_INFO_LOG("Stop in %{public}s", name_.c_str());
    Status ret = DoStop();
    SetErrCode(ret);
    ChangeState(ret == Status::OK ? CFilterState::STOPPED : CFilterState::ERROR);
    return ret;
}

Status CFilter::Flush()
{
    MEDIA_INFO_LOG("Flush %{public}s, pState: %{public}d", name_.c_str(), static_cast<int32_t>(curState_));
    for (auto iter : nextCFiltersMap_) {
        for (auto filter : iter.second) {
            filter->Flush();
        }
    }
    {
        std::lock_guard lock(generationMutex_);
        jobIdxBase_ = jobIdx_;
    }
    return DoFlush();
}

Status CFilter::Release()
{
    MEDIA_INFO_LOG("Release %{public}s, pState: %{public}d", name_.c_str(), static_cast<int32_t>(curState_));
    if (filterTask_) {
        filterTask_->SubmitJobOnce([this]() {
            ReleaseDone();
        });
        for (auto iter : nextCFiltersMap_) {
            for (auto filter : iter.second) {
                filter->Release();
            }
        }
    } else {
        for (auto iter : nextCFiltersMap_) {
            for (auto filter : iter.second) {
                filter->Release();
            }
        }
        return ReleaseDone();
    }
    return Status::OK;
}

Status CFilter::ReleaseDone()
{
    MEDIA_INFO_LOG("Release in %{public}s", name_.c_str());
    Status ret = DoRelease();
    SetErrCode(ret);
    // at this point, the final state should be RELEASED
    ChangeState(CFilterState::RELEASED);
    return ret;
}

Status CFilter::ClearAllNextCFilters()
{
    for (auto iter : nextCFiltersMap_) {
        for (auto filter : iter.second) {
            filter->ClearAllNextCFilters();
        }
    }
    nextCFiltersMap_.clear();
    return Status::OK;
}

Status CFilter::SetPlayRange(int64_t start, int64_t end)
{
    MEDIA_INFO_LOG("SetPlayRange %{public}s, pState: %{public}d", name_.c_str(), static_cast<int32_t>(curState_));
    for (auto iter : nextCFiltersMap_) {
        for (auto filter : iter.second) {
            filter->SetPlayRange(start, end);
        }
    }
    return DoSetPlayRange(start, end);
}

Status CFilter::Preroll()
{
    Status ret = DoPreroll();
    CHECK_RETURN_RET(ret != Status::OK, ret);
    for (auto iter : nextCFiltersMap_) {
        for (auto filter : iter.second) {
            ret = filter->Preroll();
            CHECK_RETURN_RET(ret != Status::OK, ret);
        }
    }
    return Status::OK;
}

Status CFilter::WaitPrerollDone(bool render)
{
    Status ret = Status::OK;
    for (auto iter : nextCFiltersMap_) {
        for (auto filter : iter.second) {
            auto curRet = filter->WaitPrerollDone(render);
            if (curRet != Status::OK) {
                ret = curRet;
            }
        }
    }
    auto curRet = DoWaitPrerollDone(render);
    if (curRet != Status::OK) {
        ret = curRet;
    }
    return ret;
}

void CFilter::StartCFilterTask()
{
    if (filterTask_) {
        filterTask_->Start();
    }
}

void CFilter::PauseCFilterTask()
{
    if (filterTask_) {
        filterTask_->Pause();
    }
}

Status CFilter::ProcessInputBuffer(int sendArg, int64_t delayUs)
{
    MEDIA_INFO_LOG("CFilter::ProcessInputBuffer  %{public}s", name_.c_str());
    CHECK_RETURN_RET_ELOG(
        isAsyncMode_ && filterTask_ == nullptr, Status::ERROR_INVALID_OPERATION, "no filterTask in async mode");
    if (filterTask_) {
        int64_t processIdx;
        {
            std::lock_guard lock(generationMutex_);
            
            processIdx = ++jobIdx_;
        }
        filterTask_->SubmitJob([this, sendArg, processIdx]() {
            // drop frame after flush
            bool isDrop;
            {
                std::lock_guard lock(generationMutex_);
                isDrop = processIdx <= jobIdxBase_;
            }
            DoProcessInputBuffer(sendArg, isDrop);
            }, delayUs, false);
    } else {
        Task::SleepInTask(delayUs / 1000); // 1000 convert to ms
        DoProcessInputBuffer(sendArg, false);
    }
    return Status::OK;
}

Status CFilter::ProcessOutputBuffer(int sendArg, int64_t delayUs, bool byIdx, uint32_t idx, int64_t renderTime)
{
    MEDIA_INFO_LOG("CFilter::ProcessOutputBuffer  %{public}s", name_.c_str());
    CHECK_RETURN_RET_ELOG(
        isAsyncMode_ && filterTask_ == nullptr, Status::ERROR_INVALID_OPERATION, "no filterTask in async mode");
    if (filterTask_) {
        int64_t processIdx;
        {
            std::lock_guard lock(generationMutex_);
            processIdx = ++jobIdx_;
        }
        filterTask_->SubmitJob([this, sendArg, processIdx, byIdx, idx, renderTime]() {
            // drop frame after flush
            bool isDrop;
            {
                std::lock_guard lock(generationMutex_);
                isDrop = processIdx <= jobIdxBase_;
            }
            DoProcessOutputBuffer(sendArg, isDrop, byIdx, idx, renderTime);
            }, delayUs, false);
    } else {
        Task::SleepInTask(delayUs / 1000); // 1000 convert to ms
        DoProcessOutputBuffer(sendArg, false, false, idx, renderTime);
    }
    return Status::OK;
}

Status CFilter::SetPerfRecEnabled(bool perfRecNeeded)
{
    auto ret = DoSetPerfRecEnabled(perfRecNeeded);
    for (auto iter : nextCFiltersMap_) {
        for (auto filter : iter.second) {
            filter->SetPerfRecEnabled(perfRecNeeded);
        }
    }
    return ret;
}

void CFilter::SetClusterId(int32_t clusterId)
{
    clusterId_ = clusterId;
}

Status CFilter::GetClusterId(int32_t& clusterId)
{
    clusterId = clusterId_;
    return Status::OK;
}

Status CFilter::DoSetPerfRecEnabled(bool perfRecNeeded)
{
    isPerfRecEnabled_ = perfRecNeeded;
    return Status::OK;
}

Status CFilter::DoInitAfterLink()
{
    MEDIA_INFO_LOG("CFilter::DoInitAfterLink");
    return Status::OK;
}

Status CFilter::DoPrepare()
{
    return Status::OK;
}

Status CFilter::DoStart()
{
    return Status::OK;
}

Status CFilter::DoPause()
{
    return Status::OK;
}

Status CFilter::DoPauseDragging()
{
    return Status::OK;
}

Status CFilter::DoPauseAudioAlign()
{
    return Status::OK;
}

Status CFilter::DoResume()
{
    return Status::OK;
}

Status CFilter::DoResumeDragging()
{
    return Status::OK;
}

Status CFilter::DoResumeAudioAlign()
{
    return Status::OK;
}

Status CFilter::DoStop()
{
    return Status::OK;
}

Status CFilter::DoFlush()
{
    return Status::OK;
}

Status CFilter::DoRelease()
{
    return Status::OK;
}

Status CFilter::DoPreroll()
{
    return Status::OK;
}

Status CFilter::DoWaitPrerollDone(bool render)
{
    return Status::OK;
}

Status CFilter::DoSetPlayRange(int64_t start, int64_t end)
{
    return Status::OK;
}

Status CFilter::DoProcessInputBuffer(int recvArg, bool dropFrame)
{
    return Status::OK;
}

Status CFilter::DoProcessOutputBuffer(int recvArg, bool dropFrame, bool byIdx, uint32_t idx, int64_t renderTimee)
{
    return Status::OK;
}

void CFilter::ChangeState(CFilterState state)
{
    std::lock_guard lock(stateMutex_);
    curState_ = state == CFilterState::RELEASED ? state : (curState_ ==
        CFilterState::ERROR ? CFilterState::ERROR : state);
    MEDIA_INFO_LOG("%{public}s > %{public}d, target: %{public}d", name_.c_str(), static_cast<int32_t>(curState_),
                   state);
    cond_.notify_one();
}

Status CFilter::WaitAllState(CFilterState state)
{
    std::unique_lock lock(stateMutex_);
    MEDIA_INFO_LOG("%{public}s wait %{public}d", name_.c_str(), static_cast<int32_t>(state));
    if (curState_ != state) {
        bool result = cond_.wait_for(lock, std::chrono::milliseconds(TIME_OUT), [this, state] { // 30000 ms timeout
            return curState_ == state || (state != CFilterState::RELEASED && curState_ == CFilterState::ERROR);
        });
        if (!result) {
            SetErrCode(Status::ERROR_TIMED_OUT);
            return Status::ERROR_TIMED_OUT;
        }
        if (curState_ != state) {
            MEDIA_ERR_LOG("CFilter(%{public}s) wait state %{public}d fail, curState %{public}d",
                name_.c_str(), static_cast<int32_t>(state), static_cast<int32_t>(curState_));
            return GetErrCode();
        }
    }

    Status res = Status::OK;
    for (auto iter : nextCFiltersMap_) {
        for (auto filter : iter.second) {
            if (filter->WaitAllState(state) != Status::OK) {
                res = filter->GetErrCode();
            }
        }
    }
    return res;
}

void CFilter::SetErrCode(Status errCode)
{
    errCode_ = errCode;
}

Status CFilter::GetErrCode()
{
    return errCode_;
}

void CFilter::SetParameter(const std::shared_ptr<Meta>& meta)
{
    meta_ = meta;
}

void CFilter::GetParameter(std::shared_ptr<Meta>& meta)
{
    meta = meta_;
}

Status CFilter::LinkNext(const std::shared_ptr<CFilter>&, CStreamType)
{
    return Status::OK;
}

Status CFilter::UpdateNext(const std::shared_ptr<CFilter>&, CStreamType)
{
    return Status::OK;
}

Status CFilter::UnLinkNext(const std::shared_ptr<CFilter>&, CStreamType)
{
    return Status::OK;
}

CFilterType CFilter::GetCFilterType()
{
    return filterType_;
};

Status CFilter::OnLinked(CStreamType, const std::shared_ptr<Meta>&, const std::shared_ptr<CFilterLinkCallback>&)
{
    return Status::OK;
};

Status CFilter::OnUpdated(CStreamType, const std::shared_ptr<Meta>&, const std::shared_ptr<CFilterLinkCallback>&)
{
    return Status::OK;
}

Status CFilter::OnUnLinked(CStreamType, const std::shared_ptr<CFilterLinkCallback>&)
{
    return Status::OK;
}

} // namespace CameraStandard
} // namespace OHOS
// LCOV_EXCL_STOP