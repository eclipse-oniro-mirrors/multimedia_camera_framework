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

#ifndef OHOS_CAMERA_DPS_DEFERRED_VIDEO_PROCESSOR_H
#define OHOS_CAMERA_DPS_DEFERRED_VIDEO_PROCESSOR_H

#include "deferred_video_result.h"
#include "ideferred_video_processing_session_callback.h"
#include "video_info.h"
#include "video_post_processor.h"
#include "video_job_repository.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class DeferredVideoProcessor;
class MovieProgress : public ProgressCallback {
public:
    MovieProgress(const std::string& videoId, const std::weak_ptr<DeferredVideoProcessor>& process);
    ~MovieProgress() override = default;

    void OnProgressUpdate(float progress) override;

private:
    const std::string videoId_;
    std::weak_ptr<DeferredVideoProcessor> process_;
};

class DeferredVideoProcessor : public EnableSharedCreateInit<DeferredVideoProcessor> {
public:
    ~DeferredVideoProcessor();

    int32_t Initialize() override;
    void AddVideo(const std::string& videoId, const std::shared_ptr<VideoInfo>& info);
    void RemoveVideo(const std::string& videoId, bool restorable);
    void RestoreVideo(const std::string& videoId);
    void ProcessVideo(const std::string& videoId);
    void CancelProcessVideo(const std::string& videoId);
    void DoProcess(const DeferredVideoJobPtr& job);

    void OnProcessSuccess(const int32_t userId, const std::string& videoId, std::unique_ptr<MediaUserInfo> userInfo);
    void OnProcessError(const int32_t userId, const std::string& videoId, DpsError error);
    void OnProcessProgress(const std::string& videoId, float progress);

    void PauseRequest(const SchedulerType& type);
    void SetDefaultExecutionMode();
    bool GetPendingVideos(std::vector<std::string>& pendingVideos);
    bool HasRunningJob();
    bool IsNeedStopJob();

    inline std::shared_ptr<VideoJobRepository> GetRepository()
    {
        return repository_;
    }

    inline std::shared_ptr<VideoPostProcessor> GetVideoPostProcessor()
    {
        return postProcessor_;
    }

protected:
    DeferredVideoProcessor(const int32_t userId, const std::shared_ptr<VideoJobRepository>& repository,
        const std::shared_ptr<VideoPostProcessor>& postProcessor);

private:
    void HandleSuccess(const int32_t userId, const std::string& videoId);
    void HandleError(const int32_t userId, const std::string& videoId, DpsError error);
    uint32_t StartTimer(const std::string& videoId);
    void StopTimer(const std::string& videoId);
    void ProcessVideoTimeout(const std::string& videoId);
    bool StartMpeg(const std::string& videoId, const DpsFdPtr& inputFd, int32_t width, int32_t height);
    bool StopMpeg(const MediaResult result, const DeferredVideoJobPtr& job);
    void ReleaseMpeg();
    void CopyFileByFd(const int srcFd, const int dstFd);
    sptr<IDeferredVideoProcessingSessionCallback> GetCallback();
    bool ProcessCatchResults(const std::string& videoId);

    const int32_t userId_;
    std::atomic_bool initialized_ {false};
    std::shared_ptr<DeferredVideoResult> result_ {nullptr};
    std::shared_ptr<MediaManagerIntf> mediaManagerProxy_ {nullptr};
    std::shared_ptr<VideoJobRepository> repository_;
    std::shared_ptr<VideoPostProcessor> postProcessor_;
    std::shared_ptr<MovieProgress> progress_ {nullptr};
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_DEFERRED_VIDEO_PROCESSOR_H