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

#ifndef OHOS_CAMERA_DPS_VIDEO_JOB_REPOSITORY_H
#define OHOS_CAMERA_DPS_VIDEO_JOB_REPOSITORY_H

#include <unordered_set>

#include "deferred_video_job.h"
#include "ivideo_job_repository_listener.h"
#include "video_job_queue.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class VideoJobRepository {
public:
    VideoJobRepository(const int32_t userId);
    ~VideoJobRepository();
    
    void AddVideoJob(const std::string& videoId, const sptr<IPCFileDescriptor>& srcFd,
        const sptr<IPCFileDescriptor>& dstFd);
    bool RemoveVideoJob(const std::string& videoId, bool restorable);
    void RestoreVideoJob(const std::string& videoId);
    void SetJobPending(const std::string& videoId);
    void SetJobRunning(const std::string& videoId);
    void SetJobCompleted(const std::string& videoId);
    void SetJobFailed(const std::string& videoId);
    void SetJobPause(const std::string& videoId);
    void SetJobError(const std::string& videoId);

    DeferredVideoJobPtr GetJob();
    int32_t GetRunningJobCounts();
    void GetRunningJobList(std::vector<std::string>& list);
    void RegisterJobListener(const std::weak_ptr<IVideoJobRepositoryListener>& listener);

private:
    void NotifyJobChangedUnLocked(bool statusChanged, DeferredVideoJobPtr jobPtr);
    void UpdateRunningCountUnLocked(bool statusChanged, const DeferredVideoJobPtr& jobPtr);
    DeferredVideoJobPtr GetJobUnLocked(const std::string& videoId);
    void ClearCatch();

    const int32_t userId_;
    std::shared_ptr<VideoJobQueue> jobQueue_ {nullptr};
    std::unordered_map<std::string, DeferredVideoJobPtr> jobMap_ {};
    std::unordered_set<std::string> runningSet_ {};
    std::weak_ptr<IVideoJobRepositoryListener> jobListener_ ;
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_VIDEO_JOB_REPOSITORY_H