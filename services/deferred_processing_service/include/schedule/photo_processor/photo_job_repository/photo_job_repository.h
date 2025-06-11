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

#ifndef OHOS_CAMERA_DPS_PHOTO_JOB_REPOSITORY_H
#define OHOS_CAMERA_DPS_PHOTO_JOB_REPOSITORY_H

#include <unordered_set>

#include "deferred_photo_job.h"
#include "dps_metadata_info.h"
#include "enable_shared_create.h"
#include "istate_change_listener.h"
#include "photo_job_queue.h"
#include "ideferred_photo_processing_session.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class PhotoJobRepository;
class PhotoJobStateListener : public IJobStateChangeListener {
public:
    explicit PhotoJobStateListener(const std::weak_ptr<PhotoJobRepository>& repository);
    ~PhotoJobStateListener() = default;

    void UpdateRunningJob(const std::string& imageId, bool running) override;
    void UpdatePriorityJob(JobPriority cur, JobPriority pre) override;
    void UpdateJobSize() override;
    void TryDoNextJob(const std::string& imageId, bool isTyrDo) override;

private:
    std::weak_ptr<PhotoJobRepository> repository_;
};

class PhotoJobRepository : public EnableSharedCreateInit<PhotoJobRepository> {
public:
    ~PhotoJobRepository();

    int32_t Initialize() override;
    void AddDeferredJob(const std::string& imageId, bool discardable, DpsMetadata& metadata);
    void RemoveDeferredJob(const std::string& imageId, bool restorable);
    bool RequestJob(const std::string& imageId);
    void CancelJob(const std::string& imageId);
    void RestoreJob(const std::string& imageId);
    DeferredPhotoJobPtr GetJob();
    DeferredPhotoJobPtr GetJobUnLocked(const std::string& imageId);
    JobState GetJobState(const std::string& imageId);
    JobPriority GetJobPriority(const std::string& imageId);
    JobPriority GetJobRunningPriority(const std::string& imageId);
    uint32_t GetJobTimerId(const std::string& imageId);
    int32_t GetBackgroundJobSize();
    int GetBackgroundIdleJobSize();
    int32_t GetOfflineJobSize();
    int32_t GetOfflineIdleJobSize();
    bool IsBackgroundJob(const std::string& imageId);
    bool HasUnCompletedBackgroundJob();
    bool IsNeedInterrupt();
    bool IsHighJob(const std::string& imageId);
    bool HasRunningJob();
    bool IsRunningJob(const std::string& imageId);
    void UpdateRunningJobUnLocked(const std::string& imageId, bool running);
    void UpdatePriotyNumUnLocked(JobPriority cur, JobPriority pre);
    void UpdateJobSizeUnLocked();
    void NotifyJobChanged(const std::string& imageId, bool isTyrDo);

protected:
    explicit PhotoJobRepository(const int32_t userId);

private:
    void ReportEvent(const DeferredPhotoJobPtr& jobPtr, IDeferredPhotoProcessingSessionIpcCode event);

    const int32_t userId_;
    std::unique_ptr<PhotoJobQueue> offlineJobQueue_ {nullptr};
    std::shared_ptr<PhotoJobStateListener> jobChangeListener_ {nullptr};
    std::unordered_set<std::string> runningJob_ {};
    std::unordered_map<std::string, DeferredPhotoJobPtr> backgroundJobMap_ {};
    std::unordered_map<JobPriority, int32_t> priotyToNum_ = {
        {JobPriority::HIGH, 0},
        {JobPriority::LOW, 0},
        {JobPriority::NORMAL, 0},
    };
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_PHOTO_JOB_REPOSITORY_H