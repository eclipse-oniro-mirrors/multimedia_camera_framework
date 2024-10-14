/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023-2023. All rights reserved.
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

#include "ivideo_process_callbacks.h"
#include "video_post_processor.h"
#include "video_job_repository.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class DeferredVideoProcessor : public IVideoProcessCallbacks {
public:
    DeferredVideoProcessor(const int32_t userId, std::shared_ptr<VideoJobRepository> repository,
        std::shared_ptr<IVideoProcessCallbacks> callbacks);
    ~DeferredVideoProcessor();
    void Initialize();

    void AddVideo(const std::string& videoId, const sptr<IPCFileDescriptor>& srcFd,
        const sptr<IPCFileDescriptor>& dstFd);
    void RemoveVideo(const std::string& videoId, bool restorable);
    void RestoreVideo(const std::string& videoId);

    void OnProcessDone(const int32_t userId, const std::string& videoId, const sptr<IPCFileDescriptor>& ipcFd) override;
    void OnError(const int32_t userId, const std::string& videoId, DpsError errorCode) override;
    void OnStateChanged(const int32_t userId, DpsStatus statusCode) override;

    void PostProcess(const DeferredVideoWorkPtr& work);
    void PauseRequest(const ScheduleType& type);
    void SetDefaultExecutionMode();
    bool GetPendingVideos(std::vector<std::string>& pendingVideos);

private:
    bool IsFatalError(DpsError errorCode);

    const int32_t userId_;
    std::shared_ptr<VideoJobRepository> repository_;
    std::shared_ptr<IVideoProcessCallbacks> callbacks_;
    std::shared_ptr<VideoPostProcessor> postProcessor_;
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_DEFERRED_VIDEO_PROCESSOR_H