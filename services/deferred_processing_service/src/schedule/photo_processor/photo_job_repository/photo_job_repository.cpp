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

#include "photo_job_repository.h"

#include "deferred_photo_job.h"
#include "dp_log.h"
#include "dp_utils.h"
#include "dps.h"
#include "dps_event_report.h"
#include "events_monitor.h"
#include "notify_job_changed_command.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
PhotoJobStateListener::PhotoJobStateListener(const std::weak_ptr<PhotoJobRepository>& repository)
    : repository_(repository) {}

void PhotoJobStateListener::UpdateRunningJob(const std::string& imageId, bool running)
{
    DP_ERR_LOG("UpdateRunningJob: %{public}s, running state: %{public}d", imageId.c_str(), running);
    auto repository = repository_.lock();
    DP_CHECK_ERROR_RETURN_LOG(repository == nullptr, "PhotoJobRepository is nullptr.");
    repository->UpdateRunningJobUnLocked(imageId, running);
}

void PhotoJobStateListener::UpdatePriorityJob(JobPriority cur, JobPriority pre)
{
    DP_ERR_LOG("UpdatePriorityJob cur: %{public}d, pre: %{public}d", cur, pre);
    auto repository = repository_.lock();
    DP_CHECK_ERROR_RETURN_LOG(repository == nullptr, "PhotoJobRepository is nullptr.");
    repository->UpdatePriotyNumUnLocked(cur, pre);
}

void PhotoJobStateListener::UpdateJobSize()
{
    DP_ERR_LOG("UpdateJobSize");
    auto repository = repository_.lock();
    DP_CHECK_ERROR_RETURN_LOG(repository == nullptr, "PhotoJobRepository is nullptr.");
    repository->UpdateJobSizeUnLocked();
}

void PhotoJobStateListener::TryDoNextJob(const std::string& imageId, bool isTyrDo)
{
    DP_ERR_LOG("TryDoNextJob");
    auto repository = repository_.lock();
    DP_CHECK_ERROR_RETURN_LOG(repository == nullptr, "PhotoJobRepository is nullptr.");
    repository->NotifyJobChanged(imageId, isTyrDo);
}

PhotoJobRepository::PhotoJobRepository(const int32_t userId) : userId_(userId)
{
    DP_DEBUG_LOG("entered, userId: %{public}d", userId_);
    offlineJobQueue_ = std::make_unique<PhotoJobQueue>(
        [] (const DeferredPhotoJobPtr& a, const DeferredPhotoJobPtr& b) {return *a > *b;});
}

PhotoJobRepository::~PhotoJobRepository()
{
    DP_INFO_LOG("entered, userId: %{public}d", userId_);
    backgroundJobMap_.clear();
    priotyToNum_.clear();
    offlineJobQueue_->Clear();
    runningJob_.clear();
}

int32_t PhotoJobRepository::Initialize()
{
    jobChangeListener_ = std::make_shared<PhotoJobStateListener>(weak_from_this());
    return DP_OK;
}

void PhotoJobRepository::AddDeferredJob(const std::string& imageId, bool discardable, DpsMetadata& metadata)
{
    DeferredPhotoJobPtr jobPtrFind = GetJobUnLocked(imageId);
    DP_CHECK_RETURN_LOG(jobPtrFind != nullptr, "DPS_PHOTO: already existed, imageId: %{public}s", imageId.c_str());
    int32_t type;
    metadata.Get(DEFERRED_PROCESSING_TYPE_KEY, type);
    auto jobPtr =
        std::make_shared<DeferredPhotoJob>(imageId, static_cast<PhotoJobType>(type), discardable, jobChangeListener_);
    DP_INFO_LOG("DPS_PHOTO: AddJob imageId: %{public}s, type: %{public}d, discardable: %{public}d",
        imageId.c_str(), type, discardable);
    if (jobPtr->GetPhotoJobType() == PhotoJobType::BACKGROUND) {
        backgroundJobMap_.emplace(imageId, jobPtr);
    } else {
        offlineJobQueue_->Push(jobPtr);
    }
    jobPtr->Prepare();
    ReportEvent(jobPtr, DeferredProcessingServiceInterfaceCode::DPS_ADD_IMAGE);
}

void PhotoJobRepository::RemoveDeferredJob(const std::string& imageId, bool restorable)
{
    DeferredPhotoJobPtr jobPtr = GetJobUnLocked(imageId);
    DP_CHECK_ERROR_RETURN_LOG(jobPtr == nullptr, "Does not existed, imageId: %{public}s", imageId.c_str());
    DP_INFO_LOG("DPS_PHOTO: RemoveJob imageId: %{public}s, type: %{public}d, restorable: %{public}d",
        imageId.c_str(), jobPtr->GetPhotoJobType(), restorable);
    if (restorable) {
        jobPtr->SetJobPriority(JobPriority::LOW);
        offlineJobQueue_->Update(jobPtr);
        return;
    }

    if (jobPtr->GetPhotoJobType() == PhotoJobType::BACKGROUND) {
        backgroundJobMap_.erase(imageId);
    } else {
        offlineJobQueue_->Remove(jobPtr);
    }
    jobPtr->Delete();
    ReportEvent(jobPtr, DeferredProcessingServiceInterfaceCode::DPS_REMOVE_IMAGE);
}

bool PhotoJobRepository::RequestJob(const std::string& imageId)
{
    DeferredPhotoJobPtr jobPtr = GetJobUnLocked(imageId);
    DP_CHECK_ERROR_RETURN_RET_LOG(jobPtr == nullptr, false, "Does not existed, imageId: %{public}s", imageId.c_str());
    DP_INFO_LOG("DPS_PHOTO: RequestJob imageId: %{public}s", imageId.c_str());
    jobPtr->SetJobPriority(JobPriority::HIGH);
    DP_CHECK_EXECUTE(jobPtr->GetCurStatus() == JobState::FAILED, jobPtr->Prepare());
    NotifyJobChanged(imageId, true);
    return true;
}

void PhotoJobRepository::CancelJob(const std::string& imageId)
{
    DeferredPhotoJobPtr jobPtr = GetJobUnLocked(imageId);
    DP_CHECK_ERROR_RETURN_LOG(jobPtr == nullptr, "Does not existed, imageId: %{public}s", imageId.c_str());
    DP_INFO_LOG("DPS_PHOTO: CancelJob imageId: %{public}s", imageId.c_str());
    jobPtr->SetJobPriority(JobPriority::NORMAL);
    NotifyJobChanged(imageId, false);
    ReportEvent(jobPtr, DeferredProcessingServiceInterfaceCode::DPS_CANCEL_PROCESS_IMAGE);
}

void PhotoJobRepository::RestoreJob(const std::string& imageId)
{
    DeferredPhotoJobPtr jobPtr = GetJobUnLocked(imageId);
    DP_CHECK_ERROR_RETURN_LOG(jobPtr == nullptr, "Does not existed, imageId: %{public}s", imageId.c_str());
    DP_INFO_LOG("DPS_PHOTO: RestoreJob imageId: %{public}s", imageId.c_str());
    jobPtr->SetJobPriority(JobPriority::NORMAL);
    NotifyJobChanged(imageId, true);
    ReportEvent(jobPtr, DeferredProcessingServiceInterfaceCode::DPS_RESTORE_IMAGE);
}

JobState PhotoJobRepository::GetJobState(const std::string& imageId)
{
    DeferredPhotoJobPtr jobPtr = GetJobUnLocked(imageId);
    if (jobPtr == nullptr) {
        DP_INFO_LOG("Does not existed, imageId: %{public}s", imageId.c_str());
        return JobState::NONE;
    } else {
        return jobPtr->GetCurStatus();
    }
}

DeferredPhotoJobPtr PhotoJobRepository::GetJob()
{
    DP_INFO_LOG("DPS_PHOTO: offline size: %{public}d, background size: %{public}zu, running job: %{public}zu",
        offlineJobQueue_->GetSize(), backgroundJobMap_.size(), runningJob_.size());
    DeferredPhotoJobPtr jobPtr = offlineJobQueue_->Peek();
    DP_CHECK_RETURN_RET(jobPtr == nullptr || jobPtr->GetCurStatus() >= JobState::RUNNING, nullptr);
    return jobPtr;
}

JobPriority PhotoJobRepository::GetJobPriority(const std::string& imageId)
{
    DeferredPhotoJobPtr jobPtr = GetJobUnLocked(imageId);
    DP_CHECK_RETURN_RET(jobPtr == nullptr, JobPriority::NONE);
    return jobPtr->GetCurPriority();
}

JobPriority PhotoJobRepository::GetJobRunningPriority(const std::string& imageId)
{
    DeferredPhotoJobPtr jobPtr = GetJobUnLocked(imageId);
    DP_CHECK_RETURN_RET(jobPtr == nullptr, JobPriority::NONE);
    return jobPtr->GetRunningPriority();
}

uint32_t PhotoJobRepository::GetJobTimerId(const std::string& imageId)
{
    DeferredPhotoJobPtr jobPtr = GetJobUnLocked(imageId);
    DP_CHECK_RETURN_RET(jobPtr == nullptr, INVALID_TIMERID);
    return jobPtr->GetTimerId();
}

void PhotoJobRepository::NotifyJobChanged(const std::string& imageId, bool isTyrDo)
{
    offlineJobQueue_->UpdateById(imageId);
    DP_CHECK_RETURN(!isTyrDo);
    DP_INFO_LOG("DPS_PHOTO: NotifyJobChanged imageId %{public}s", imageId.c_str());
    auto ret = DPS_SendCommand<NotifyJobChangedCommand>(userId_);
    DP_CHECK_ERROR_RETURN_LOG(ret != DP_OK, "NotifyJobChanged failed, ret: %{public}d", ret);
}

void PhotoJobRepository::UpdateRunningJobUnLocked(const std::string& imageId, bool running)
{
    if (running) {
        runningJob_.emplace(imageId);
        ReportEvent(GetJobUnLocked(imageId), DeferredProcessingServiceInterfaceCode::DPS_PROCESS_IMAGE);
    } else {
        runningJob_.erase(imageId);
    }
    DP_INFO_LOG("DPS_PHOTO: running job: %{public}s, total size: %{public}zu", imageId.c_str(), runningJob_.size());
}

void PhotoJobRepository::UpdatePriotyNumUnLocked(JobPriority cur, JobPriority pre)
{
    auto it = priotyToNum_.find(cur);
    if (it != priotyToNum_.end()) {
        (it->second)++;
    }
    it = priotyToNum_.find(pre);
    if (it != priotyToNum_.end()) {
        (it->second)--;
    }
}

void PhotoJobRepository::UpdateJobSizeUnLocked()
{
    EventsMonitor::GetInstance().NotifyPhotoProcessSize(offlineJobQueue_->GetSize(), backgroundJobMap_.size());
}

DeferredPhotoJobPtr PhotoJobRepository::GetJobUnLocked(const std::string& imageId)
{
    auto jobPtr = offlineJobQueue_->GetJobById(imageId);
    if (jobPtr) {
        DP_DEBUG_LOG("DPS_PHOTO: offline job, imageId: %{public}s", imageId.c_str());
        return jobPtr;
    }

    auto item = backgroundJobMap_.find(imageId);
    if (item != backgroundJobMap_.end()) {
        DP_DEBUG_LOG("DPS_PHOTO: background job, imageId: %{public}s", imageId.c_str());
        return item->second;
    }

    return nullptr;
}

int32_t PhotoJobRepository::GetBackgroundJobSize()
{
    int32_t size = static_cast<int32_t>(backgroundJobMap_.size());
    DP_DEBUG_LOG("background job size: %{public}d", size);
    return size;
}

int32_t PhotoJobRepository::GetBackgroundIdleJobSize()
{
    int32_t size = std::count_if(backgroundJobMap_.begin(), backgroundJobMap_.end(), [](const auto& item) {
        return item.second->GetCurStatus() < JobState::COMPLETED;
    });
    DP_DEBUG_LOG("background idle job size: %{public}d", size);
    return size;
}

int32_t PhotoJobRepository::GetOfflineJobSize()
{
    DP_DEBUG_LOG("offline job size: %{public}d", offlineJobQueue_->GetSize());
    return offlineJobQueue_->GetSize();
}

int32_t PhotoJobRepository::GetOfflineIdleJobSize()
{
    auto list = offlineJobQueue_->GetAllElements();
    int32_t size = std::count_if(list.begin(), list.end(), [](const auto& jobPtr) {
        return jobPtr->GetCurStatus() < JobState::COMPLETED;
    });
    DP_DEBUG_LOG("offline idle job size: %{public}d", size);
    return size;
}

bool PhotoJobRepository::IsBackgroundJob(const std::string& imageId)
{
    return backgroundJobMap_.find(imageId) != backgroundJobMap_.end();
}

bool PhotoJobRepository::HasUnCompletedBackgroundJob()
{
    auto it = std::find_if(backgroundJobMap_.begin(), backgroundJobMap_.end(), [](auto& ptr) {
        return ptr.second->GetCurStatus() == JobState::PENDING;
    });
    return it != backgroundJobMap_.end();
}

bool PhotoJobRepository::IsNeedInterrupt()
{
    return std::any_of(runningJob_.begin(), runningJob_.end(), [&](const auto& imageId) {
        auto jobPtr = GetJobUnLocked(imageId);
        DP_CHECK_RETURN_RET(jobPtr == nullptr, false);
        return jobPtr->GetCurPriority() != JobPriority::HIGH;
    });
}

bool PhotoJobRepository::IsHighJob(const std::string& imageId)
{
    DeferredPhotoJobPtr jobPtr = GetJobUnLocked(imageId);
    DP_CHECK_RETURN_RET(jobPtr == nullptr, false);

    return jobPtr->GetCurPriority() ==  JobPriority::HIGH;
}

bool PhotoJobRepository::HasRunningJob()
{
    return !runningJob_.empty();
}

bool PhotoJobRepository::IsRunningJob(const std::string& imageId)
{
    return runningJob_.find(imageId) != runningJob_.end();
}

void PhotoJobRepository::ReportEvent(const DeferredPhotoJobPtr& jobPtr, DeferredProcessingServiceInterfaceCode event)
{
    DP_CHECK_ERROR_RETURN_LOG(jobPtr == nullptr, "DeferredPhotoJob is nullptr.");
    int32_t highJobNum = priotyToNum_.find(JobPriority::HIGH)->second;
    int32_t normalJobNum = priotyToNum_.find(JobPriority::NORMAL)->second;
    int32_t lowJobNum = priotyToNum_.find(JobPriority::LOW)->second;
    std::string imageId = jobPtr->GetImageId();
    DPSEventInfo dpsEventInfo;
    dpsEventInfo.imageId = imageId;
    dpsEventInfo.userId = userId_;
    dpsEventInfo.lowJobNum = lowJobNum;
    dpsEventInfo.normalJobNum = normalJobNum;
    dpsEventInfo.highJobNum = highJobNum;
    dpsEventInfo.discardable = jobPtr->GetDiscardable();
    dpsEventInfo.photoJobType = jobPtr->GetPhotoJobType();
    dpsEventInfo.operatorStage = event;
    uint64_t endTime = GetTimestampMilli();
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