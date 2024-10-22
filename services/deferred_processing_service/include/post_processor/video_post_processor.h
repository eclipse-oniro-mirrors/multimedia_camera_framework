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

#ifndef OHOS_CAMERA_DPS_VIDEO_POST_PROCESSOR_H
#define OHOS_CAMERA_DPS_VIDEO_POST_PROCESSOR_H

#include "basic_definitions.h"
#include "deferred_video_job.h"
#include "iservstat_listener_hdi.h"
#include "mpeg_manager.h"
#include "safe_map.h"
#include "v1_3/ivideo_process_service.h"
#include "v1_3/ivideo_process_session.h"
#include "v1_3/ivideo_process_callback.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
using OHOS::HDI::Camera::V1_3::IVideoProcessSession;
using OHOS::HDI::Camera::V1_3::StreamDescription;
using OHOS::HDI::Camera::V1_1::StreamInfo_V1_1;
using HDI::Camera::V1_0::BufferProducerSequenceable;

class VideoPostProcessor : public std::enable_shared_from_this<VideoPostProcessor> {
public:
    ~VideoPostProcessor();

    void Initialize();
    bool GetPendingVideos(std::vector<std::string>& pendingVideos);
    void SetExecutionMode(ExecutionMode executionMode);
    void SetDefaultExecutionMode();
    void ProcessRequest(const DeferredVideoWorkPtr& work);
    void RemoveRequest(const std::string& videoId);
    void PauseRequest(const std::string& videoId, const ScheduleType& type);

protected:
    explicit VideoPostProcessor(const int32_t userId);

private:
    class VideoServiceListener;
    class SessionDeathRecipient;
    class VideoProcessListener;

    void ConnectService();
    void DisconnectService();
    bool PrepareStreams(const std::string& videoId, const int inputFd);
    void CreateSurface(const std::string& name, const StreamDescription& stream, sptr<Surface>& surface);
    void SetStreamInfo(const StreamDescription& stream, sptr<BufferProducerSequenceable>& producer);
    bool StartMpeg(const std::string& videoId, const sptr<IPCFileDescriptor>& inputFd);
    bool StopMpeg(const MediaResult result, const DeferredVideoWorkPtr& work);
    void ReleaseMpeg();
    void StartTimer(const std::string& videoId, const DeferredVideoWorkPtr& work);
    void StopTimer(const std::string& videoId);
    void OnTimerOut(const std::string& videoId);
    void OnServiceChange(const HDI::ServiceManager::V1_0::ServiceStatus& status);
    void OnSessionDied();
    void OnProcessDone(const std::string& videoId);
    void OnError(const std::string& videoId, DpsError errorCode);
    void OnStateChanged(HdiStatus hdiStatus);
    DeferredVideoWorkPtr GetRunningWork(const std::string& videoId);
    void copyFileByFd(const int srcFd, const int dstFd);
    DpsError MapHdiError(OHOS::HDI::Camera::V1_2::ErrorCode errorCode);

    inline sptr<IVideoProcessSession> GetVideoSession()
    {
        std::lock_guard<std::mutex> lock(sessionMutex_);
        return session_;
    }

    inline void SetVideoSession(const sptr<IVideoProcessSession>& session)
    {
        std::lock_guard<std::mutex> lock(sessionMutex_);
        session_ = session;
    }
    
    inline sptr<MpegManager> GetMpegManager()
    {
        std::lock_guard<std::mutex> lock(mpegManagerMutex_);
        return mpegManager_;
    }
    
    inline void SetMpegManager(sptr<MpegManager> &mpegManager)
    {
        std::lock_guard<std::mutex> lock(mpegManagerMutex_);
        mpegManager_ = mpegManager;
    }

    std::mutex mpegManagerMutex_;
    std::mutex sessionMutex_;
    const int32_t userId_;
    int32_t timeoutCount_ {0};
    sptr<IVideoProcessSession> session_ {nullptr};
    std::shared_ptr<MpegManager> mpegManager_ {nullptr};
    sptr<VideoServiceListener> serviceListener_;
    sptr<SessionDeathRecipient> sessionDeathRecipient_;
    sptr<VideoProcessListener> processListener_;
    std::vector<StreamInfo_V1_1> allStreamInfo_ {};
    SafeMap<std::string, DeferredVideoWorkPtr> videoId2Handle_ {};
};
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS
#endif // OHOS_CAMERA_DPS_VIDEO_POST_PROCESSOR_H