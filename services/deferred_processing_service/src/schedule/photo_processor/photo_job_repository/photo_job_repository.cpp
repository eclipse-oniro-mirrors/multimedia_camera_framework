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

#include "photo_job_repository.h"

#include "dp_log.h"
#include "dps_event_report.h"
#include "events_monitor.h"
#include "steady_clock.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {

PhotoJobRepository::PhotoJobRepository(const int32_t userId) : userId_(userId)
{
    DP_DEBUG_LOG("entered, userid: %{public}d", userId_);
}

PhotoJobRepository::~PhotoJobRepository()
{
    DP_DEBUG_LOG("entered, userid: %{public}d", userId_);
    offlineJobMap_.clear();
    backgroundJobMap_.clear();
    offlineJobList_.clear();
    jobQueue_.clear();
    jobListeners_.clear();
    priotyToNum_.clear();
}

void PhotoJobRepository::AddDeferredJob(const std::string& imageId, bool discardable, DpsMetadata& metadata)
{
    DP_INFO_LOG("DPS_PHOTO: imageId: %{public}s, discardable: %{public}d", imageId.c_str(), discardable);
    DeferredPhotoJobPtr jobPtrFind = GetJobUnLocked(imageId);
    if (jobPtrFind != nullptr) {
        DP_INFO_LOG("DPS_PHOTO: already existed, imageId: %{public}s", imageId.c_str());
        return;
    }

    DeferredPhotoJobPtr jobPtr = std::make_shared<DeferredPhotoJob>(imageId, discardable, metadata);
    int type;
    metadata.Get(DEFERRED_PROCESSING_TYPE_KEY, type);
    if (type == DeferredProcessingType::DPS_BACKGROUND) {
        DP_INFO_LOG("DPS_PHOTO: add background job, imageId: %{public}s", imageId.c_str());
        backgroundJobMap_.emplace(imageId, jobPtr);
    } else {
        DP_INFO_LOG("DPS_PHOTO: add offline job, imageId: %{public}s", imageId.c_str());
        offlineJobList_.push_back(jobPtr);
        offlineJobMap_.emplace(imageId, jobPtr);
    }
    jobPtr->SetPhotoJobType(type);
    bool priorityChanged = jobPtr->SetJobPriority(PhotoJobPriority::NORMAL);
    bool statusChanged = jobPtr->SetJobStatus(PhotoJobStatus::PENDING);
    NotifyJobChanged(priorityChanged, statusChanged, jobPtr);
    RecordPriotyNum(priorityChanged, jobPtr);
    ReportEvent(jobPtr, DeferredProcessingServiceInterfaceCode::DPS_ADD_IMAGE);
    EventsMonitor::GetInstance().NotifyPhotoProcessSize(static_cast<int32_t>(offlineJobList_.size()),
        static_cast<int32_t>(backgroundJobMap_.size()));
}

void PhotoJobRepository::RemoveDeferredJob(const std::string& imageId, bool restorable)
{
    DP_INFO_LOG("DPS_PHOTO: imageId: %{public}s, restorable: %{public}d", imageId.c_str(), restorable);
    DeferredPhotoJobPtr jobPtr = GetJobUnLocked(imageId);
    DP_CHECK_ERROR_RETURN_LOG(jobPtr == nullptr, "Does not existed, imageId: %{public}s", imageId.c_str());

    UpdateJobQueueUnLocked(false, jobPtr);
    bool priorityChanged = false;
    bool statusChanged = false;
    if (restorable) {
        priorityChanged = jobPtr->SetJobPriority(PhotoJobPriority::LOW);
        statusChanged = jobPtr->SetJobStatus(PhotoJobStatus::PENDING);
    } else {
        priorityChanged = jobPtr->SetJobPriority(PhotoJobPriority::DELETED);
        statusChanged = jobPtr->SetJobStatus(PhotoJobStatus::DELETED);
        if (backgroundJobMap_.count(imageId) == 1) {
            backgroundJobMap_.erase(imageId);
            DP_INFO_LOG("DPS_PHOTO: Background job removed, imageId: %{public}s", imageId.c_str());
        } else if (offlineJobMap_.count(imageId) == 1) {
            auto it = std::find_if(offlineJobList_.begin(), offlineJobList_.end(),
                [jobPtr](const auto& ptr) { return ptr == jobPtr; });
            if (it != offlineJobList_.end()) {
                offlineJobList_.erase(it);
            }
            offlineJobMap_.erase(imageId);
            DP_INFO_LOG("DPS_PHOTO: Offline job removed, imageId: %{public}s", imageId.c_str());
        }
    }
    UpdateRunningCountUnLocked(statusChanged, jobPtr);
    RecordPriotyNum(priorityChanged, jobPtr);
    ReportEvent(jobPtr, DeferredProcessingServiceInterfaceCode::DPS_REMOVE_IMAGE);
    if (!restorable) {
        EventsMonitor::GetInstance().NotifyPhotoProcessSize(static_cast<int32_t>(offlineJobList_.size()),
            static_cast<int32_t>(backgroundJobMap_.size()));
    }
}

bool PhotoJobRepository::RequestJob(const std::string& imageId)
{
    bool priorityChanged = false;
    bool statusChanged = false;
    DP_INFO_LOG("DPS_PHOTO: RequestJob imageId: %{public}s", imageId.c_str());
    DeferredPhotoJobPtr jobPtr = GetJobUnLocked(imageId);
    DP_CHECK_ERROR_RETURN_RET_LOG(jobPtr == nullptr, false, "Does not existed, imageId: %{public}s", imageId.c_str());

    UpdateJobQueueUnLocked(true, jobPtr);
    priorityChanged = jobPtr->SetJobPriority(PhotoJobPriority::HIGH);
    if (jobPtr->GetCurStatus() == PhotoJobStatus::FAILED) {
        DP_INFO_LOG("Failed to Pending, imageId: %{public}s", imageId.c_str());
        statusChanged = jobPtr->SetJobStatus(PhotoJobStatus::PENDING);
    }
    NotifyJobChanged(priorityChanged, statusChanged, jobPtr);
    RecordPriotyNum(priorityChanged, jobPtr);
    return true;
}

void PhotoJobRepository::CancelJob(const std::string& imageId)
{
    DP_INFO_LOG("DPS_PHOTO: imageId: %{public}s", imageId.c_str());
    DeferredPhotoJobPtr jobPtr = GetJobUnLocked(imageId);
    DP_CHECK_ERROR_RETURN_LOG(jobPtr == nullptr, "Does not existed, imageId: %{public}s", imageId.c_str());

    UpdateJobQueueUnLocked(false, jobPtr);
    bool priorityChanged = jobPtr->SetJobPriority(PhotoJobPriority::NORMAL);
    NotifyJobChanged(priorityChanged, false, jobPtr);
    RecordPriotyNum(priorityChanged, jobPtr);
    ReportEvent(jobPtr, DeferredProcessingServiceInterfaceCode::DPS_CANCEL_PROCESS_IMAGE);
}

void PhotoJobRepository::RestoreJob(const std::string& imageId)
{
    DP_INFO_LOG("DPS_PHOTO: imageId: %{public}s", imageId.c_str());
    DeferredPhotoJobPtr jobPtr = GetJobUnLocked(imageId);
    DP_CHECK_ERROR_RETURN_LOG(jobPtr == nullptr, "Does not existed, imageId: %{public}s", imageId.c_str());

    bool priorityChanged = jobPtr->SetJobPriority(PhotoJobPriority::NORMAL);
    NotifyJobChanged(priorityChanged, false, jobPtr);
    RecordPriotyNum(priorityChanged, jobPtr);
    ReportEvent(jobPtr, DeferredProcessingServiceInterfaceCode::DPS_RESTORE_IMAGE);
}

void PhotoJobRepository::SetJobPending(const std::string& imageId)
{
    DP_INFO_LOG("DPS_PHOTO: imageId: %{public}s", imageId.c_str());
    DeferredPhotoJobPtr jobPtr = GetJobUnLocked(imageId);
    DP_CHECK_ERROR_RETURN_LOG(jobPtr == nullptr, "Does not existed, imageId: %{public}s", imageId.c_str());

    bool statusChanged = jobPtr->SetJobStatus(PhotoJobStatus::PENDING);
    UpdateRunningCountUnLocked(statusChanged, jobPtr);
    NotifyJobChanged(false, statusChanged, jobPtr);
}

void PhotoJobRepository::SetJobRunning(const std::string& imageId)
{
    DP_INFO_LOG("DPS_PHOTO: imageId: %{public}s", imageId.c_str());
    DeferredPhotoJobPtr jobPtr = GetJobUnLocked(imageId);
    DP_CHECK_ERROR_RETURN_LOG(jobPtr == nullptr, "Does not existed, imageId: %{public}s", imageId.c_str());

    bool statusChanged = jobPtr->SetJobStatus(PhotoJobStatus::RUNNING);
    jobPtr->RecordJobRunningPriority();
    UpdateRunningCountUnLocked(statusChanged, jobPtr);
    ReportEvent(jobPtr, DeferredProcessingServiceInterfaceCode::DPS_PROCESS_IMAGE);
}

void PhotoJobRepository::SetJobCompleted(const std::string& imageId)
{
    DP_INFO_LOG("DPS_PHOTO: imageId: %{public}s", imageId.c_str());
    DeferredPhotoJobPtr jobPtr = GetJobUnLocked(imageId);
    DP_CHECK_ERROR_RETURN_LOG(jobPtr == nullptr, "Does not existed, imageId: %{public}s", imageId.c_str());

    UpdateJobQueueUnLocked(false, jobPtr);
    bool priorityChanged = jobPtr->SetJobPriority(PhotoJobPriority::NORMAL);
    bool statusChanged = jobPtr->SetJobStatus(PhotoJobStatus::COMPLETED);
    UpdateRunningCountUnLocked(statusChanged, jobPtr);
    NotifyJobChanged(priorityChanged, statusChanged, jobPtr);
    RecordPriotyNum(priorityChanged, jobPtr);
}

void PhotoJobRepository::SetJobFailed(const std::string& imageId)
{
    DP_INFO_LOG("DPS_PHOTO: imageId: %{public}s", imageId.c_str());
    DeferredPhotoJobPtr jobPtr = GetJobUnLocked(imageId);
    DP_CHECK_ERROR_RETURN_LOG(jobPtr == nullptr, "Does not existed, imageId: %{public}s", imageId.c_str());

    UpdateJobQueueUnLocked(false, jobPtr);
    bool priorityChanged = jobPtr->SetJobPriority(PhotoJobPriority::NORMAL);
    bool statusChanged = jobPtr->SetJobStatus(PhotoJobStatus::FAILED);
    UpdateRunningCountUnLocked(statusChanged, jobPtr);
    NotifyJobChanged(priorityChanged, statusChanged, jobPtr);
    RecordPriotyNum(priorityChanged, jobPtr);
}

PhotoJobStatus PhotoJobRepository::GetJobStatus(const std::string& imageId)
{
    DP_INFO_LOG("DPS_PHOTO: imageId: %{public}s", imageId.c_str());
    DeferredPhotoJobPtr jobPtr = GetJobUnLocked(imageId);
    if (jobPtr == nullptr) {
        DP_INFO_LOG("Does not existed, imageId: %{public}s", imageId.c_str());
        return PhotoJobStatus::NONE;
    } else {
        return jobPtr->GetCurStatus();
    }
}

DeferredPhotoJobPtr PhotoJobRepository::GetLowPriorityJob()
{
    DP_INFO_LOG("DPS_PHOTO: job queue size: %{public}d, offline job size: %{public}d,"
        "background job size: %{public}d, running num: %{public}d",
        static_cast<int>(jobQueue_.size()), static_cast<int>(offlineJobList_.size()),
        static_cast<int>(backgroundJobMap_.size()), runningNum_);
    auto it = std::find_if(offlineJobList_.begin(), offlineJobList_.end(), [](auto& jobPtr) {
        return (jobPtr->GetCurPriority() == PhotoJobPriority::LOW) &&
            (jobPtr->GetCurStatus() == PhotoJobStatus::PENDING);
    });
    if (it != offlineJobList_.end()) {
        return *it;
    }
    it = std::find_if(offlineJobList_.begin(), offlineJobList_.end(), [](auto& jobPtr) {
        return jobPtr->GetCurPriority() == PhotoJobPriority::LOW &&
            jobPtr->GetCurStatus() == PhotoJobStatus::FAILED;
    });
    return it != offlineJobList_.end() ? *it : nullptr;
}

DeferredPhotoJobPtr PhotoJobRepository::GetNormalPriorityJob()
{
    DP_INFO_LOG("DPS_PHOTO: job queue size: %{public}d, offline job size: %{public}d,"
        "background job size: %{public}d, running num: %{public}d",
        static_cast<int>(jobQueue_.size()), static_cast<int>(offlineJobList_.size()),
        static_cast<int>(backgroundJobMap_.size()), runningNum_);
    auto it = std::find_if(offlineJobList_.begin(), offlineJobList_.end(), [](auto& jobPtr) {
        return (jobPtr->GetCurPriority() == PhotoJobPriority::NORMAL) &&
            (jobPtr->GetCurStatus() == PhotoJobStatus::PENDING);
    });
    if (it != offlineJobList_.end()) {
        return *it;
    }
    DP_INFO_LOG("DPS_PHOTO: no job pending, try reset failed to pending");
    for (auto& jobPtr : offlineJobList_) {
        if ((jobPtr->GetCurPriority() == PhotoJobPriority::NORMAL) &&
            (jobPtr->GetCurStatus() == PhotoJobStatus::FAILED)) {
            jobPtr->SetJobStatus(PhotoJobStatus::PENDING);
        }
    }
    it = std::find_if(offlineJobList_.begin(), offlineJobList_.end(), [](auto& jobPtr) {
        return (jobPtr->GetCurPriority() == PhotoJobPriority::NORMAL) &&
            (jobPtr->GetCurStatus() == PhotoJobStatus::PENDING);
    });
    return it != offlineJobList_.end() ? *it : nullptr;
}

DeferredPhotoJobPtr PhotoJobRepository::GetHighPriorityJob()
{
    DP_INFO_LOG("DPS_PHOTO: job queue size: %{public}d, offline job size: %{public}d,"
        "background job size: %{public}d, running num: %{public}d",
        static_cast<int>(jobQueue_.size()), static_cast<int>(offlineJobList_.size()),
        static_cast<int>(backgroundJobMap_.size()), runningNum_);
    auto it = std::find_if(jobQueue_.begin(), jobQueue_.end(), [](auto& jobPtr) {
        return jobPtr->GetCurStatus() == PhotoJobStatus::PENDING;
    });
    return it != jobQueue_.end() ? *it : nullptr;
}

int PhotoJobRepository::GetRunningJobCounts()
{
    DP_DEBUG_LOG("Running jobs num: %{public}d", runningNum_);
    return runningNum_;
}

PhotoJobPriority PhotoJobRepository::GetJobPriority(std::string imageId)
{
    DeferredPhotoJobPtr jobPtr = GetJobUnLocked(imageId);
    if (jobPtr == nullptr) {
        DP_DEBUG_LOG("Does not existed, imageId: %{public}s", imageId.c_str());
        return PhotoJobPriority::NONE;
    } else {
        return jobPtr->GetCurPriority();
    }
}

PhotoJobPriority PhotoJobRepository::GetJobRunningPriority(std::string imageId)
{
    DeferredPhotoJobPtr jobPtr = GetJobUnLocked(imageId);
    if (jobPtr == nullptr) {
        DP_INFO_LOG("Does not existed, imageId: %{public}s", imageId.c_str());
        return PhotoJobPriority::NONE;
    } else {
        return jobPtr->GetRunningPriority();
    }
}

void PhotoJobRepository::NotifyJobChanged(bool priorityChanged, bool statusChanged, DeferredPhotoJobPtr jobPtr)
{
    DP_INFO_LOG("DPS_PHOTO: priorityChanged: %{public}d, statusChanged: %{public}d, imageId: %{public}s",
        priorityChanged, statusChanged, jobPtr->GetImageId().c_str());
    for (auto& listenerWptr : jobListeners_) {
        if (auto listenerSptr = listenerWptr.lock()) {
            listenerSptr->OnPhotoJobChanged(priorityChanged, statusChanged, jobPtr);
        }
    }
}

void PhotoJobRepository::UpdateRunningCountUnLocked(bool statusChanged, DeferredPhotoJobPtr jobPtr)
{
    if (statusChanged && (jobPtr->GetPreStatus() == PhotoJobStatus::RUNNING)) {
        runningNum_ = runningNum_ - 1;
    }
    if (statusChanged && (jobPtr->GetCurStatus() == PhotoJobStatus::RUNNING)) {
        runningNum_ = runningNum_ + 1;
    }
    DP_INFO_LOG("DPS_PHOTO: running jobs num: %{public}d, imageId: %{public}s",
        runningNum_, jobPtr->GetImageId().c_str());
}

void PhotoJobRepository::UpdateJobQueueUnLocked(bool saved, DeferredPhotoJobPtr jobPtr)
{
    if (saved) {
        auto it = std::find_if(jobQueue_.begin(), jobQueue_.end(), [jobPtr](const auto& ptr) { return ptr == jobPtr; });
        if (it != jobQueue_.end()) {
            jobQueue_.erase(it);
            DP_INFO_LOG("already existed, move to front, imageId: %{public}s", jobPtr->GetImageId().c_str());
        }
        //最新的请求最先处理，所以要放到队首。GetHighPriorityJob取任务从队首取。如果确认是这样顺序，则应该用栈保存
        jobQueue_.push_front(jobPtr);
    } else {
        auto it = std::find_if(jobQueue_.begin(), jobQueue_.end(), [jobPtr](const auto& ptr) { return ptr == jobPtr; });
        if (it != jobQueue_.end()) {
            DP_INFO_LOG("erase high priority, imageId: %{public}s", jobPtr->GetImageId().c_str());
            jobQueue_.erase(it);
        } else {
            DP_INFO_LOG("already not high priority, imageId: %{public}s", jobPtr->GetImageId().c_str());
        }
    }
}

void PhotoJobRepository::RegisterJobListener(std::weak_ptr<IPhotoJobRepositoryListener> listener)
{
    jobListeners_.emplace_back(listener);
}

DeferredPhotoJobPtr PhotoJobRepository::GetJobUnLocked(const std::string& imageId)
{
    auto item = backgroundJobMap_.find(imageId);
    if (item != backgroundJobMap_.end()) {
        DP_INFO_LOG("DPS_PHOTO: background job, imageId: %{public}s", imageId.c_str());
        return item->second;
    }

    item = offlineJobMap_.find(imageId);
    if (item != offlineJobMap_.end()) {
        DP_INFO_LOG("DPS_PHOTO: offline job, imageId: %{public}s", imageId.c_str());
        return item->second;
    }

    return nullptr;
}

int PhotoJobRepository::GetBackgroundJobSize()
{
    int size = static_cast<int>(backgroundJobMap_.size());
    DP_DEBUG_LOG("background job size: %{public}d", size);
    return size;
}

int PhotoJobRepository::GetOfflineJobSize()
{
    int size = static_cast<int>(offlineJobMap_.size());
    DP_DEBUG_LOG("offline job size: %{public}d", size);
    return size;
}

bool PhotoJobRepository::IsOfflineJob(std::string imageId)
{
    return offlineJobMap_.find(imageId) != offlineJobMap_.end();
}

bool PhotoJobRepository::HasUnCompletedBackgroundJob()
{
    auto it = std::find_if(backgroundJobMap_.begin(), backgroundJobMap_.end(), [](auto& ptr) {
        return ptr.second->GetCurStatus() == PhotoJobStatus::PENDING;
    });
    return it != backgroundJobMap_.end();
}

void PhotoJobRepository::RecordPriotyNum(bool priorityChanged, const DeferredPhotoJobPtr& jobPtr)
{
    DP_CHECK_RETURN(!priorityChanged);
    auto it = priotyToNum_.find(jobPtr->GetCurPriority());
    if (it != priotyToNum_.end()) {
        (it->second)++;
    }
    it = priotyToNum_.find(jobPtr->GetPrePriority());
    if (it != priotyToNum_.end()) {
        (it->second)--;
    }
}

void PhotoJobRepository::ReportEvent(DeferredPhotoJobPtr jobPtr, DeferredProcessingServiceInterfaceCode event)
{
    int32_t highJobNum = priotyToNum_.find(PhotoJobPriority::HIGH)->second;
    int32_t normalJobNum = priotyToNum_.find(PhotoJobPriority::NORMAL)->second;
    int32_t lowJobNum = priotyToNum_.find(PhotoJobPriority::LOW)->second;
    std::string imageId = jobPtr->GetImageId();
    DPSEventInfo dpsEventInfo;
    dpsEventInfo.imageId = imageId;
    dpsEventInfo.userId = userId_;
    dpsEventInfo.lowJobNum = lowJobNum;
    dpsEventInfo.normalJobNum = normalJobNum;
    dpsEventInfo.highJobNum = highJobNum;
    dpsEventInfo.discardable = jobPtr->GetDiscardable();
    dpsEventInfo.photoJobType = static_cast<PhotoJobType>(jobPtr->GetPhotoJobType());
    dpsEventInfo.operatorStage = event;
    uint64_t endTime = SteadyClock::GetTimestampMilli();
    switch (static_cast<int32_t>(event)) {
        case static_cast<int32_t>(DeferredProcessingServiceInterfaceCode::DPS_ADD_IMAGE): {
            dpsEventInfo.dispatchTimeEndTime = endTime;
            break;
        }
        case static_cast<int32_t>(DeferredProcessingServiceInterfaceCode::DPS_REMOVE_IMAGE): {
            dpsEventInfo.removeTimeBeginTime = endTime;
            break;
        }
        case static_cast<int32_t>(DeferredProcessingServiceInterfaceCode::DPS_RESTORE_IMAGE): {
            dpsEventInfo.restoreTimeBeginTime = endTime;
            break;
        }
        case static_cast<int32_t>(DeferredProcessingServiceInterfaceCode::DPS_PROCESS_IMAGE): {
            dpsEventInfo.processTimeBeginTime = endTime;
            break;
        }
    }
    DPSEventReport::GetInstance().ReportOperateImage(imageId, userId_, dpsEventInfo);
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS