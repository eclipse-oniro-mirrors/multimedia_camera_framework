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

#include "pipeline.h"
#include "camera_log.h"

// LCOV_EXCL_START
namespace OHOS {
namespace CameraStandard {
static std::atomic<uint16_t> pipeLineId = 0;

int32_t Pipeline::GetNextPipelineId()
{
    return pipeLineId++;
}

Pipeline::Pipeline()
{
    MEDIA_DEBUG_LOG("entered.");
}

Pipeline::~Pipeline()
{
    MEDIA_INFO_LOG("entered.");
}

void Pipeline::Init(const std::shared_ptr<CEventReceiver>& receiver, const std::shared_ptr<CFilterCallback>& callback,
    const std::string& groupId)
{
    MEDIA_INFO_LOG("Init enter.");
    eventReceiver_ = receiver;
    filterCallback_ = callback;
    groupId_ = groupId;
}

Status Pipeline::Prepare()
{
    CAMERA_SYNC_TRACE;
    MEDIA_INFO_LOG("Prepare enter.");
    Status ret = Status::OK;
    SubmitJobOnce([&] {
        std::lock_guard lock(mutex_);
        for (const auto& filter : filters_) {
            CHECK_RETURN((ret = filter->Prepare()) != Status::OK);
        }
        for (const auto& filter : filters_) {
            CHECK_RETURN((ret = filter->WaitAllState(CFilterState::READY)) != Status::OK);
        }
    });
    MEDIA_INFO_LOG("Prepare done ret = %{public}d", ret);
    return ret;
}

Status Pipeline::Start()
{
    MEDIA_INFO_LOG("Start enter.");
    Status ret = Status::OK;
    SubmitJobOnce([&] {
        std::lock_guard lock(mutex_);
        for (const auto& filter : filters_) {
            CHECK_RETURN((ret = filter->Start()) != Status::OK);
        }
        for (const auto& filter : filters_) {
            CHECK_RETURN((ret = filter->WaitAllState(CFilterState::RUNNING)) != Status::OK);
        }
    });
    MEDIA_INFO_LOG("Start done ret = %{public}d", ret);
    return ret;
}

Status Pipeline::Pause()
{
    MEDIA_INFO_LOG("Pause enter.");
    Status ret = Status::OK;
    SubmitJobOnce([&] {
        std::lock_guard lock(mutex_);
        for (const auto& filter : filters_) {
            ret = filter->Pause();
        }
        for (const auto& filter : filters_) {
            ret = filter->WaitAllState(CFilterState::PAUSED);
        }
    });
    MEDIA_INFO_LOG("Pause done ret = %{public}d", ret);
    return ret;
}

Status Pipeline::Resume()
{
    MEDIA_INFO_LOG("Resume enter.");
    Status ret = Status::OK;
    SubmitJobOnce([&] {
        std::lock_guard lock(mutex_);
        for (const auto& filter : filters_) {
            CHECK_RETURN((ret = filter->Resume()) != Status::OK);
        }
        for (const auto& filter : filters_) {
            CHECK_RETURN((ret = filter->WaitAllState(CFilterState::RUNNING)) != Status::OK);
        }
    });
    MEDIA_INFO_LOG("Resume done ret = %{public}d", ret);
    return ret;
}

Status Pipeline::Stop()
{
    MEDIA_INFO_LOG("Stop enter.");
    Status ret = Status::OK;
    SubmitJobOnce([&] {
        std::lock_guard lock(mutex_);
        for (const auto& filter : filters_) {
            CHECK_CONTINUE_ELOG(filter == nullptr, "Pipeline error: %{public}zu", filters_.size());
            ret = filter->Stop();
        }
        for (const auto& filter : filters_) {
            CHECK_CONTINUE_ELOG(filter == nullptr, "Pipeline::Stop WaitAllState error: %{public}zu", filters_.size());
            ret = filter->WaitAllState(CFilterState::STOPPED);
        }
        filters_.clear();
    });
    MEDIA_INFO_LOG("Stop done ret = %{public}d", ret);
    return ret;
}

Status Pipeline::Flush()
{
    MEDIA_INFO_LOG("Flush enter.");
    SubmitJobOnce([&] {
        std::lock_guard lock(mutex_);
        for (const auto& filter : filters_) {
            filter->Flush();
        }
    });
    MEDIA_INFO_LOG("Flush done.");
    return Status::OK;
}

Status Pipeline::Release()
{
    MEDIA_INFO_LOG("Release enter.");
    SubmitJobOnce([&] {
        std::lock_guard lock(mutex_);
        for (const auto& filter : filters_) {
            filter->Release();
        }
        for (const auto& filter : filters_) {
            filter->WaitAllState(CFilterState::RELEASED);
        }
        filters_.clear();
    });
    MEDIA_INFO_LOG("Release done.");
    return Status::OK;
}

Status Pipeline::Preroll(bool render)
{
    MEDIA_INFO_LOG("Preroll enter.");
    Status ret = Status::OK;
    std::lock_guard lock(mutex_);
    for (const auto& filter : filters_) {
        CHECK_RETURN_RET_ILOG((ret = filter->Preroll()) != Status::OK, ret, "Preroll done ret = %{public}d", ret);
    }
    for (const auto& filter : filters_) {
        CHECK_RETURN_RET_ILOG(
            (ret = filter->WaitPrerollDone(render)) != Status::OK, ret, "Preroll done ret = %{public}d", ret);
    }
    MEDIA_INFO_LOG("Preroll done ret = %{public}d", ret);
    return ret;
}

Status Pipeline::SetPlayRange(int64_t start, int64_t end)
{
    MEDIA_INFO_LOG("SetPlayRange enter.");
    SubmitJobOnce([&] {
        std::lock_guard lock(mutex_);
        for (const auto& filter : filters_) {
            filter->SetPlayRange(start, end);
        }
    });
    MEDIA_INFO_LOG("SetPlayRange done.");
    return Status::OK;
}

Status Pipeline::AddHeadFilters(std::vector<std::shared_ptr<CFilter>> filtersIn)
{
    MEDIA_INFO_LOG("AddHeadFilters enter.");
    std::vector<std::shared_ptr<CFilter>> filtersToAdd;
    for (const auto& filterIn : filtersIn) {
        bool matched = false;
        for (const auto& filter : filters_) {
            if (filterIn == filter) {
                matched = true;
                break;
            }
        }
        if (!matched) {
            filtersToAdd.push_back(filterIn);
            filterIn->LinkPipeLine(groupId_);
        }
    }
    CHECK_RETURN_RET_ILOG(filtersToAdd.empty(), Status::OK, "filter already exists");
    SubmitJobOnce([&] {
        std::lock_guard lock(mutex_);
        this->filters_.insert(this->filters_.end(), filtersToAdd.begin(), filtersToAdd.end());
    });
    MEDIA_INFO_LOG("AddHeadFilters done.");
    return Status::OK;
}

Status Pipeline::RemoveHeadFilter(const std::shared_ptr<CFilter>& filter)
{
    SubmitJobOnce([&] {
        std::lock_guard lock(mutex_);
        auto it = std::find_if(filters_.begin(), filters_.end(),
            [&filter](const std::shared_ptr<CFilter>& filterPtr) { return filterPtr == filter; });
        if (it != filters_.end()) {
            filters_.erase(it);
        }
        filter->Release();
        filter->WaitAllState(CFilterState::RELEASED);
        filter->ClearAllNextCFilters();
        return Status::OK;
    });
    return Status::OK;
}

Status Pipeline::LinkFilters(const std::shared_ptr<CFilter>& preFilter,
    const std::vector<std::shared_ptr<CFilter>>& nextFilters, CStreamType type, bool needTurbo)
{
    for (const auto& nextFilter : nextFilters) {
        auto ret = preFilter->LinkNext(nextFilter, type);
        nextFilter->LinkPipeLine(groupId_, needTurbo);
        CHECK_RETURN_RET(ret != Status::OK, ret);
    }
    return Status::OK;
}

Status Pipeline::UpdateFilters(const std::shared_ptr<CFilter>& preFilter,
    const std::vector<std::shared_ptr<CFilter>>& nextFilters, CStreamType type)
{
    for (const auto& nextFilter : nextFilters) {
        preFilter->UpdateNext(nextFilter, type);
    }
    return Status::OK;
}

Status Pipeline::UnLinkFilters(const std::shared_ptr<CFilter>& preFilter,
    const std::vector<std::shared_ptr<CFilter>>& nextFilters, CStreamType type)
{
    for (const auto& nextFilter : nextFilters) {
        preFilter->UnLinkNext(nextFilter, type);
    }
    return Status::OK;
}

void Pipeline::OnEvent(const Event& event)
{
}

Status Pipeline::SetStreamStarted(bool isStreamStarted)
{
    std::lock_guard lock(mutex_);
    for (const auto& filter : filters_) {
        filter->SetStreamStarted(isStreamStarted);
    }
    return Status::OK;
}
} // namespace CameraStandard
} // namespace OHOS
// LCOV_EXCL_STOP