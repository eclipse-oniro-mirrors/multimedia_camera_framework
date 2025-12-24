/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_CAMERA_DPS_VIDEO_POST_PROCESSOR_H
#define OHOS_CAMERA_DPS_VIDEO_POST_PROCESSOR_H

#include <unordered_set>

#include "basic_definitions.h"
#include "deferred_video_job.h"
#include "enable_shared_create.h"
#include "iservstat_listener_hdi.h"
#include "media_manager_proxy.h"
#include "v1_5/types.h"
#include "v1_5/ivideo_process_session.h"
#include "video_process_result.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
using VideoSessionV1_3 = HDI::Camera::V1_3::IVideoProcessSession;
using VideoSessionV1_5 = HDI::Camera::V1_5::IVideoProcessSession;
using HDI::Camera::V1_3::StreamDescription;
using HDI::Camera::V1_1::StreamInfo_V1_1;
using HDI::Camera::V1_0::BufferProducerSequenceable;

struct VideoStreamInfo {
    VideoStreamInfo(const std::string& videoId) : videoId_(videoId) {}

    std::string videoId_;
    std::vector<StreamInfo_V1_1> infos_ {};
};

class VideoPostProcessor : public EnableSharedCreateInit<VideoPostProcessor> {
public:
    ~VideoPostProcessor();

    int32_t Initialize() override;
    bool GetPendingVideos(std::vector<std::string>& pendingVideos);
    void SetExecutionMode(ExecutionMode executionMode);
    void SetDefaultExecutionMode();
    std::vector<StreamDescription> PrepareStreams(const DeferredVideoJobPtr& job);
    void ProcessRequest(const std::string& videoId, const std::vector<StreamDescription>& streams,
        const std::shared_ptr<MediaManagerIntf>& mediaManagerIntf);
    void RemoveRequest(const std::string& videoId);
    void PauseRequest(const std::string& videoId, const SchedulerType& type);
    void OnStateChanged(HdiStatus hdiStatus);
    void OnSessionDied();
    void ReleaseStreams(const std::string& videoId);

protected:
    explicit VideoPostProcessor(const int32_t userId);

private:
    class VideoServiceListener;
    class SessionDeathRecipient;
    class VideoProcessListener;

    void ConnectService();
    void DisconnectService();
    bool ProcessStream(const StreamDescription& stream, const std::shared_ptr<MediaManagerIntf>& mediaManagerIntf);
    void SetStreamInfo(const StreamDescription& stream, sptr<BufferProducerSequenceable>& producer);
    HDI::Camera::V1_0::StreamIntent GetIntent(HDI::Camera::V1_3::MediaStreamType type);
    void OnServiceChange(const HDI::ServiceManager::V1_0::ServiceStatus& status);
    void RemoveNeedJbo(const sptr<VideoSessionV1_3>& session);
    

    template <typename T>
    inline sptr<T> GetVideoSession()
    {
        std::lock_guard<std::mutex> lock(sessionMutex_);
        if constexpr (std::is_same<T, HDI::Camera::V1_5::IVideoProcessSession>::value) {
            return T::CastFrom(sessionV1_3_);
        } else if constexpr (std::is_same<T, HDI::Camera::V1_3::IVideoProcessSession>::value) {
            return sessionV1_3_;
        }
        return nullptr;
    }

    inline void SetVideoSession(const sptr<VideoSessionV1_3>& session)
    {
        std::lock_guard<std::mutex> lock(sessionMutex_);
        sessionV1_3_ = session;
    }

    std::mutex mpegManagerMutex_;
    std::mutex sessionMutex_;
    const int32_t userId_;
    sptr<VideoSessionV1_3> sessionV1_3_ {nullptr};
    std::shared_ptr<VideoProcessResult> processResult_ {nullptr};
    sptr<VideoServiceListener> serviceListener_;
    sptr<SessionDeathRecipient> sessionDeathRecipient_;
    sptr<VideoProcessListener> processListener_;
    std::unique_ptr<VideoStreamInfo> streamInfo_ {};
    std::unordered_set<std::string> runningId_ {};
    std::mutex removeMutex_;
    std::list<std::string> removeNeededList_ {};
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_VIDEO_POST_PROCESSOR_H