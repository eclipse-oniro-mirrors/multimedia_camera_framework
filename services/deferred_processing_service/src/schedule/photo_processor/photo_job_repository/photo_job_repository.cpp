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
#include "deferred_photo_job.h"
#include "dp_log.h"
#include "dps_event_report.h"
#include "steady_clock.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {

PhotoJobRepository::PhotoJobRepository(int userId)
    : userId_(userId),
      runningNum_(0),
      offlineJobMap_(),
      backgroundJobMap_(),
      offlineJobList_(),
      jobQueue_(),
      jobListeners_()
{
    DP_DEBUG_LOG("entered, userid: %d", userId_);
}

PhotoJobRepository::~PhotoJobRepository()
{
    DP_DEBUG_LOG("entered, userid: %d", userId_);
    offlineJobMap_.clear();
    backgroundJobMap_.clear();
    offlineJobList_.clear();
    jobQueue_.clear();
    jobListeners_.clear();
}

void PhotoJobRepository::AddDeferredJob(const std::string& imageId, bool discardable, DpsMetadata& metadata)
{
    DP_INFO_LOG("entered");
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    DeferredPhotoJobPtr jobPtrFind = GetJobUnLocked(imageId);
    if (jobPtrFind != nullptr) {
        DP_INFO_LOG("already existed, imageId: %s", imageId.c_str());
        return;
    }
    DeferredPhotoJobPtr jobPtr = std::make_shared<DeferredPhotoJob>(imageId, discardable, metadata);
    int type;
    metadata.Get(DEFERRED_PROCESSING_TYPE_KEY, type);
    if (type == DeferredProcessingType::DPS_BACKGROUND) {
        backgroundJobMap_.emplace(imageId, jobPtr);
    } else {
        DP_INFO_LOG("add offline job, imageId: %s", imageId.c_str());
        offlineJobList_.push_back(jobPtr);
        offlineJobMap_.emplace(imageId, jobPtr);
    }
    jobPtr->SetPhotoJobType(type);
    bool priorityChanged = jobPtr->SetJobPriority(PhotoJobPriority::NORMAL);
    bool statusChanged = jobPtr->SetJobStatus(PhotoJobStatus::PENDING);
    UpdateRunningCountUnLocked(statusChanged, jobPtr);
    NotifyJobChangedUnLocked(priorityChanged, statusChanged, jobPtr);

    ReportEvent(jobPtr, DeferredProcessingServiceInterfaceCode::DPS_ADD_IMAGE);
    return;
}

void PhotoJobRepository::RemoveDeferredJob(const std::string& imageId, bool restorable)
{
    DP_INFO_LOG("entered, imageId: %s, restorable: %d", imageId.c_str(), restorable);
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    DeferredPhotoJobPtr jobPtr = GetJobUnLocked(imageId);
    if (jobPtr == nullptr) {
        DP_INFO_LOG("does not existed, imageId: %s", imageId.c_str());
        return;
    }

    bool priorityChanged = false;
    bool statusChanged = false;

    UpdateJobQueueUnLocked(false, jobPtr);

    if (restorable) {
        priorityChanged = jobPtr->SetJobPriority(PhotoJobPriority::LOW);
        statusChanged = jobPtr->SetJobStatus(PhotoJobStatus::PENDING);
    } else {
        priorityChanged = jobPtr->SetJobPriority(PhotoJobPriority::DELETED);
        statusChanged = jobPtr->SetJobStatus(PhotoJobStatus::DELETED);
        if (backgroundJobMap_.count(imageId) == 1) {
            backgroundJobMap_.erase(imageId);
            DP_INFO_LOG("background job removed, imageId: %s: ", imageId.c_str());
        } else if (offlineJobMap_.count(imageId) == 1) {
            auto it = std::find_if(offlineJobList_.begin(), offlineJobList_.end(),
                [jobPtr](const auto& ptr) { return ptr == jobPtr; });
            if (it != offlineJobList_.end()) {
                offlineJobList_.erase(it);
            }
            offlineJobMap_.erase(imageId);
            DP_INFO_LOG("offline job removed, imageId: %s: ", imageId.c_str());
        }
    }
    UpdateRunningCountUnLocked(statusChanged, jobPtr);
    NotifyJobChangedUnLocked(priorityChanged, statusChanged, jobPtr);
    ReportEvent(jobPtr, DeferredProcessingServiceInterfaceCode::DPS_REMOVE_IMAGE);
    return;
}

bool PhotoJobRepository::RequestJob(const std::string& imageId)
{
    DP_INFO_LOG("entered, imageId: %s: ", imageId.c_str());
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    DeferredPhotoJobPtr jobPtr = GetJobUnLocked(imageId);
    if (jobPtr == nullptr) {
        DP_INFO_LOG("does not existed, imageId: %s: ", imageId.c_str());
        return false;
    }
    if (jobPtr->GetDeferredProcType() == DeferredProcessingType::DPS_BACKGROUND) {
        return false;
    }
    bool priorityChanged = false;
    bool statusChanged = false;

    UpdateJobQueueUnLocked(true, jobPtr);

    priorityChanged = jobPtr->SetJobPriority(PhotoJobPriority::HIGH);

    if (jobPtr->GetCurStatus() == PhotoJobStatus::FAILED) {
        DP_INFO_LOG("FAILED to PENDING, imageId: %s: ", imageId.c_str());
        statusChanged = jobPtr->SetJobStatus(PhotoJobStatus::PENDING);
    }
    NotifyJobChangedUnLocked(priorityChanged, statusChanged, jobPtr);
    return true;
}

void PhotoJobRepository::CancelJob(const std::string& imageId)
{
    DP_INFO_LOG("entered, imageId: %s: ", imageId.c_str());
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    DeferredPhotoJobPtr jobPtr = GetJobUnLocked(imageId);
    if (jobPtr == nullptr) {
        DP_INFO_LOG("does not existed, imageId: %s: ", imageId.c_str());
        return;
    }
    bool priorityChanged = false;
    bool statusChanged = false;

    UpdateJobQueueUnLocked(false, jobPtr);

    priorityChanged = jobPtr->SetJobPriority(PhotoJobPriority::NORMAL);
    NotifyJobChangedUnLocked(priorityChanged, statusChanged, jobPtr);
    ReportEvent(jobPtr, DeferredProcessingServiceInterfaceCode::DPS_CANCEL_PROCESS_IMAGE);
    return;
}

void PhotoJobRepository::RestoreJob(const std::string& imageId)
{
    DP_INFO_LOG("entered, imageId: %s: ", imageId.c_str());
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    DeferredPhotoJobPtr jobPtr = GetJobUnLocked(imageId);
    if (jobPtr == nullptr) {
        DP_INFO_LOG("does not existed, imageId: %s: ", imageId.c_str());
        return;
    }
    bool priorityChanged = false;
    bool statusChanged = false;

    priorityChanged = jobPtr->SetJobPriority(PhotoJobPriority::NORMAL);
    NotifyJobChangedUnLocked(priorityChanged, statusChanged, jobPtr);
    ReportEvent(jobPtr, DeferredProcessingServiceInterfaceCode::DPS_RESTORE_IMAGE);
}

void PhotoJobRepository::SetJobPending(const std::string imageId)
{
    DP_INFO_LOG("entered, imageId: %s: ", imageId.c_str());
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    DeferredPhotoJobPtr jobPtr = GetJobUnLocked(imageId);
    if (jobPtr == nullptr) {
        DP_INFO_LOG("does not existed, imageId: %s: ", imageId.c_str());
        return;
    }
    bool priorityChanged = false;
    bool statusChanged = false;

    statusChanged = jobPtr->SetJobStatus(PhotoJobStatus::PENDING);
    UpdateRunningCountUnLocked(statusChanged, jobPtr);
    NotifyJobChangedUnLocked(priorityChanged, statusChanged, jobPtr);
}

void PhotoJobRepository::SetJobRunning(const std::string imageId)
{
    DP_INFO_LOG("entered, imageId: %s: ", imageId.c_str());
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    DeferredPhotoJobPtr jobPtr = GetJobUnLocked(imageId);
    if (jobPtr == nullptr) {
        DP_INFO_LOG("does not existed, imageId: %s: ", imageId.c_str());
        return;
    }
    bool priorityChanged = false;
    bool statusChanged = false;

    statusChanged = jobPtr->SetJobStatus(PhotoJobStatus::RUNNING);
    jobPtr->RecordJobRunningPriority();
    UpdateRunningCountUnLocked(statusChanged, jobPtr);
    NotifyJobChangedUnLocked(priorityChanged, statusChanged, jobPtr);
    ReportEvent(jobPtr, DeferredProcessingServiceInterfaceCode::DPS_PROCESS_IMAGE);
}

void PhotoJobRepository::SetJobCompleted(const std::string imageId)
{
    DP_INFO_LOG("entered, imageId: %s: ", imageId.c_str());
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    DeferredPhotoJobPtr jobPtr = GetJobUnLocked(imageId);
    if (jobPtr == nullptr) {
        DP_INFO_LOG("does not existed, imageId: %s: ", imageId.c_str());
        return;
    }
    bool priorityChanged = false;
    bool statusChanged = false;

    UpdateJobQueueUnLocked(false, jobPtr);

    priorityChanged = jobPtr->SetJobPriority(PhotoJobPriority::NORMAL);
    statusChanged = jobPtr->SetJobStatus(PhotoJobStatus::COMPLETED);
    UpdateRunningCountUnLocked(statusChanged, jobPtr);
    NotifyJobChangedUnLocked(priorityChanged, statusChanged, jobPtr);
}

void PhotoJobRepository::SetJobFailed(const std::string imageId)
{
    DP_INFO_LOG("entered, imageId: %s: ", imageId.c_str());
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    DeferredPhotoJobPtr jobPtr = GetJobUnLocked(imageId);
    if (jobPtr == nullptr) {
        DP_INFO_LOG("does not existed, imageId: %s: ", imageId.c_str());
        return;
    }
    bool priorityChanged = false;
    bool statusChanged = false;

    UpdateJobQueueUnLocked(false, jobPtr);

    priorityChanged = jobPtr->SetJobPriority(PhotoJobPriority::NORMAL);
    statusChanged = jobPtr->SetJobStatus(PhotoJobStatus::FAILED);
    UpdateRunningCountUnLocked(statusChanged, jobPtr);
    NotifyJobChangedUnLocked(priorityChanged, statusChanged, jobPtr);
}

PhotoJobStatus PhotoJobRepository::GetJobStatus(const std::string& imageId)
{
    DP_INFO_LOG("entered, imageId: %s: ", imageId.c_str());
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    DeferredPhotoJobPtr jobPtr = GetJobUnLocked(imageId);
    if (jobPtr == nullptr) {
        DP_INFO_LOG("does not existed, imageId: %s: ", imageId.c_str());
        return PhotoJobStatus::NONE;
    } else {
        return jobPtr->GetCurStatus();
    }
}

DeferredPhotoJobPtr PhotoJobRepository::GetLowPriorityJob()
{
    DP_INFO_LOG("entered, job queue size: %d, offline job list size: %d, background job size: %d, running num: %d",
        static_cast<int>(jobQueue_.size()), static_cast<int>(offlineJobList_.size()),
        static_cast<int>(backgroundJobMap_.size()), runningNum_);
    std::lock_guard<std::recursive_mutex> lock(mutex_);
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
    DP_INFO_LOG("entered, job queue size: %d, offline job list size: %d, background job size: %d, running num: %d",
        static_cast<int>(jobQueue_.size()), static_cast<int>(offlineJobList_.size()),
        static_cast<int>(backgroundJobMap_.size()), runningNum_);
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    auto it = std::find_if(offlineJobList_.begin(), offlineJobList_.end(), [](auto& jobPtr) {
        return (jobPtr->GetCurPriority() == PhotoJobPriority::NORMAL) &&
            (jobPtr->GetCurStatus() == PhotoJobStatus::PENDING);
    });
    if (it != offlineJobList_.end()) {
        return *it;
    }
    DP_INFO_LOG("no job pending, try reset failed to pending");
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
    DP_INFO_LOG("entered, job queue size: %d, offline job list size: %d, background job size: %d, running num: %d",
        static_cast<int>(jobQueue_.size()), static_cast<int>(offlineJobList_.size()),
        static_cast<int>(backgroundJobMap_.size()), runningNum_);
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    auto it = std::find_if(jobQueue_.begin(), jobQueue_.end(), [](auto& jobPtr) {
        return jobPtr->GetCurStatus() == PhotoJobStatus::PENDING;
    });
    return it != jobQueue_.end() ? *it : nullptr;
}

int PhotoJobRepository::GetRunningJobCounts()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    DP_DEBUG_LOG("running jobs num: %d", runningNum_);
    return runningNum_;
}

PhotoJobPriority PhotoJobRepository::GetJobPriority(std::string imageId)
{
    DP_INFO_LOG("entered");
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    DeferredPhotoJobPtr jobPtr = GetJobUnLocked(imageId);
    if (jobPtr == nullptr) {
        DP_INFO_LOG("does not existed, imageId: %s: ", imageId.c_str());
        return PhotoJobPriority::NONE;
    } else {
        return jobPtr->GetCurPriority();
    }
}

PhotoJobPriority PhotoJobRepository::GetJobRunningPriority(std::string imageId)
{
    DP_INFO_LOG("entered");
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    DeferredPhotoJobPtr jobPtr = GetJobUnLocked(imageId);
    if (jobPtr == nullptr) {
        DP_INFO_LOG("does not existed, imageId: %s: ", imageId.c_str());
        return PhotoJobPriority::NONE;
    } else {
        return jobPtr->GetRunningPriority();
    }
}

void PhotoJobRepository::NotifyJobChangedUnLocked(bool priorityChanged, bool statusChanged, DeferredPhotoJobPtr jobPtr)
{
    DP_INFO_LOG("entered, priorityChanged: %d, statusChanged: %d, imageId: %s: ",
        priorityChanged, statusChanged, jobPtr->GetImageId().c_str());
    for (auto& listenerWptr : jobListeners_) {
        if (auto listenerSptr = listenerWptr.lock()) {
            listenerSptr->OnPhotoJobChanged(priorityChanged, statusChanged, jobPtr);
        }
    }
    if (priorityChanged) {
        auto curJob = priotyToNum.find(jobPtr->GetCurPriority());
        if (curJob != priotyToNum.end()) {
            (curJob->second)++;
        }
        curJob = priotyToNum.find(jobPtr->GetPrePriority());
        if (curJob != priotyToNum.end()) {
            (curJob->second)--;
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
    DP_INFO_LOG("running jobs num: %d, imageId: %s", runningNum_, jobPtr->GetImageId().c_str());
    return;
}

void PhotoJobRepository::UpdateJobQueueUnLocked(bool saved, DeferredPhotoJobPtr jobPtr)
{
    if (saved) {
        auto it = std::find_if(jobQueue_.begin(), jobQueue_.end(), [jobPtr](const auto& ptr) { return ptr == jobPtr; });
        if (it != jobQueue_.end()) {
            jobQueue_.erase(it);
            DP_INFO_LOG("already existed, move to front, imageId: %s", jobPtr->GetImageId().c_str());
        }
        //最新的请求最先处理，所以要放到队首。GetHighPriorityJob取任务从队首取。如果确认是这样顺序，则应该用栈保存
        jobQueue_.push_front(jobPtr);
    } else {
        auto it = std::find_if(jobQueue_.begin(), jobQueue_.end(), [jobPtr](const auto& ptr) { return ptr == jobPtr; });
        if (it != jobQueue_.end()) {
            DP_INFO_LOG("erase high priority, imageId: %s", jobPtr->GetImageId().c_str());
            jobQueue_.erase(it);
        } else {
            DP_INFO_LOG("already not high priority, imageId: %s", jobPtr->GetImageId().c_str());
        }
    }
}

void PhotoJobRepository::RegisterJobListener(std::weak_ptr<IPhotoJobRepositoryListener> listener)
{
    DP_INFO_LOG("entered");
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    jobListeners_.emplace_back(listener);
    return;
}

DeferredPhotoJobPtr PhotoJobRepository::GetJobUnLocked(const std::string& imageId)
{
    DeferredPhotoJobPtr jobPtr = nullptr;
    if (backgroundJobMap_.count(imageId) == 1) {
        DP_INFO_LOG("background job, imageId: %s", imageId.c_str());
        jobPtr = backgroundJobMap_.find(imageId)->second;
    } else if (offlineJobMap_.count(imageId) == 1) {
        DP_INFO_LOG("offline job, imageId: %s", imageId.c_str());
        jobPtr = offlineJobMap_.find(imageId)->second;
    }
    return jobPtr;
}

int PhotoJobRepository::GetBackgroundJobSize()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    int size = static_cast<int>(backgroundJobMap_.size());
    DP_DEBUG_LOG("background job size: %d", size);
    return size;
}

int PhotoJobRepository::GetOfflineJobSize()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    int size = static_cast<int>(offlineJobMap_.size());
    DP_DEBUG_LOG("offline job size: %d", size);
    return size;
}

bool PhotoJobRepository::IsOfflineJob(std::string imageId)
{
    DP_DEBUG_LOG("entered");
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (offlineJobMap_.count(imageId) == 1) {
        return true;
    } else {
        return false;
    }
}

bool PhotoJobRepository::HasUnCompletedBackgroundJob()
{
    auto it = std::find_if(backgroundJobMap_.begin(), backgroundJobMap_.end(), [](auto& ptr) {
        return ptr.second->GetCurStatus() == PhotoJobStatus::PENDING;
    });
    return it != backgroundJobMap_.end();
}

void PhotoJobRepository::ReportEvent(DeferredPhotoJobPtr jobPtr, DeferredProcessingServiceInterfaceCode event)
{
    auto iter = priotyToNum.find(PhotoJobPriority::HIGH);
    int highJobNum = iter->second;
    iter = priotyToNum.find(PhotoJobPriority::NORMAL);
    int normalJobNum = iter->second;
    iter = priotyToNum.find(PhotoJobPriority::LOW);
    int lowJobNum = iter->second;
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