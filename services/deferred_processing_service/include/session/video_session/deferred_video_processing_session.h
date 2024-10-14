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

#ifndef OHOS_CAMERA_DPS_DEFERRED_VIDEO_PROCESSING_SESSION_H
#define OHOS_CAMERA_DPS_DEFERRED_VIDEO_PROCESSING_SESSION_H

#include "deferred_video_processing_session_stub.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
class DeferredVideoProcessingSession : public DeferredVideoProcessingSessionStub {
public:
    class VideoInfo {
    public:
        VideoInfo(const sptr<IPCFileDescriptor>& srcFd, const sptr<IPCFileDescriptor>& dstFd)
            : srcFd_(srcFd), dstFd_(dstFd)
        {}

        ~VideoInfo()
        {
            srcFd_ = nullptr;
            dstFd_ = nullptr;
        }

        sptr<IPCFileDescriptor> srcFd_;
        sptr<IPCFileDescriptor> dstFd_;
    };

    DeferredVideoProcessingSession(const int32_t userId);
    ~DeferredVideoProcessingSession();
    
    int32_t BeginSynchronize() override;
    int32_t EndSynchronize() override;
    int32_t AddVideo(const std::string& videoId, const sptr<IPCFileDescriptor>& srcFd,
        const sptr<IPCFileDescriptor>& dstFd) override;
    int32_t RemoveVideo(const std::string& videoId, bool restorable) override;
    int32_t RestoreVideo(const std::string& videoId) override;

private:
    std::mutex mutex_;
    const int32_t userId_;
    std::atomic<bool> inSync_ {false};
    std::unordered_map<std::string, std::shared_ptr<VideoInfo>> videoIds_ {};
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_DEFERRED_VIDEO_PROCESSING_SESSION_H