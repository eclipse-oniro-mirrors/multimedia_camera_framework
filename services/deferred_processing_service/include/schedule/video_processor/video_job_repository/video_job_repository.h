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

#include "enable_shared_create.h"
#include "video_info.h"
#include "video_job_queue.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class VideoJobRepository : public EnableSharedCreateInit<VideoJobRepository> {
public:
    ~VideoJobRepository();
    
    int32_t Initialize() override;
    void AddVideoJob(const std::string& videoId, const std::shared_ptr<VideoInfo>& info);
    bool RemoveVideoJob(const std::string& videoId, bool restorable);
    void RestoreVideoJob(const std::string& videoId);
    bool RequestJob(const std::string& videoId);
    void CancelJob(const std::string& videoId);
    void SetJobPending(const std::string& videoId);
    void SetJobRunning(const std::string& videoId);
    void SetJobCompleted(const std::string& videoId);
    void SetJobFailed(const std::string& videoId);
    void SetJobPause(const std::string& videoId);
    void SetJobError(const std::string& videoId);
    DeferredVideoJobPtr GetJob();
    DeferredVideoJobPtr GetJobUnLocked(const std::string& videoId);
    uint32_t GetJobTimerId(const std::string& videoId);
    void GetRunningJobList(std::vector<std::string>& list);
    bool HasRunningJob();
    bool IsHighJob(const std::string& videoId);
    bool IsRunningJob(const std::string& videoId);
    bool IsNeedStopJob();

protected:
    explicit VideoJobRepository(const int32_t userId);

private:
    void NotifyJobChangedUnLocked(const std::string& videoId);
    void UpdateRunningCountUnLocked(bool statusChanged, const DeferredVideoJobPtr& jobPtr);
    void ClearCatch();

    const int32_t userId_;
    std::unique_ptr<VideoJobQueue> jobQueue_ {nullptr};
    std::unordered_set<std::string> runningSet_ {};
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_VIDEO_JOB_REPOSITORY_H