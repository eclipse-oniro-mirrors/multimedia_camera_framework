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

#ifndef OHOS_CAMERA_DPS_PHOTO_JOB_REPOSITORY_H
#define OHOS_CAMERA_DPS_PHOTO_JOB_REPOSITORY_H

#include <unordered_map>
#include <map>
#include <list>
#include <deque>
#include <vector>
#include <string>
#include <set>
#include <mutex>

#include "deferred_photo_job.h"
#include "iphoto_job_repository_listener.h"
#include <deferred_processing_service_ipc_interface_code.h>

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {

class PhotoJobRepository {
public:
    PhotoJobRepository(int userId);
    ~PhotoJobRepository();
    void AddDeferredJob(const std::string& imageId, bool discardable, DpsMetadata& metadata);
    void RemoveDeferredJob(const std::string& imageId, bool restorable);
    bool RequestJob(const std::string& imageId);
    void CancelJob(const std::string& imageId);
    void RestoreJob(const std::string& imageId);
    void SetJobPending(const std::string imageId);
    void SetJobRunning(const std::string imageId);
    void SetJobCompleted(const std::string imageId);
    void SetJobFailed(const std::string imageId);

    PhotoJobStatus GetJobStatus(const std::string& imageId);
    DeferredPhotoJobPtr GetLowPriorityJob();
    DeferredPhotoJobPtr GetNormalPriorityJob();
    DeferredPhotoJobPtr GetHighPriorityJob();
    int GetRunningJobCounts();
    PhotoJobPriority GetJobPriority(std::string imageId);
    PhotoJobPriority GetJobRunningPriority(std::string imageId);
    void RegisterJobListener(std::weak_ptr<IPhotoJobRepositoryListener> listener);
    int GetBackgroundJobSize();
    int GetOfflineJobSize();
    bool IsOfflineJob(std::string imageId);
    bool HasUnCompletedBackgroundJob();

private:
    void NotifyJobChangedUnLocked(bool priorityChanged, bool statusChanged, DeferredPhotoJobPtr jobPtr);
    void UpdateRunningCountUnLocked(bool statusChanged, DeferredPhotoJobPtr jobPtr);
    void UpdateJobQueueUnLocked(bool saved, DeferredPhotoJobPtr jobPtr);
    DeferredPhotoJobPtr GetJobUnLocked(const std::string& imageId);
    void ReportEvent(DeferredPhotoJobPtr jobPtr, DeferredProcessingServiceInterfaceCode event);

    std::recursive_mutex mutex_;
    int userId_;
    int runningNum_;
    std::unordered_map<std::string, DeferredPhotoJobPtr> offlineJobMap_;
    std::unordered_map<std::string, DeferredPhotoJobPtr> backgroundJobMap_;
    std::list<DeferredPhotoJobPtr> offlineJobList_;
    std::deque<DeferredPhotoJobPtr> jobQueue_;
    std::vector<std::weak_ptr<IPhotoJobRepositoryListener>> jobListeners_;
    std::map<PhotoJobPriority, int> priotyToNum = {
        {PhotoJobPriority::HIGH, 0},
        {PhotoJobPriority::LOW, 0},
        {PhotoJobPriority::NORMAL, 0},
    };
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_PHOTO_JOB_REPOSITORY_H