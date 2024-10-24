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

#include "video_post_processor.h"

#include <sys/sendfile.h>
#include <sys/stat.h>

#include "dp_log.h"
#include "dp_timer.h"
#include "dps.h"
#include "dps_event_report.h"
#include "events_monitor.h"
#include "hdf_device_class.h"
#include "iproxy_broker.h"
#include "iservmgr_hdi.h"
#include "mpeg_manager_factory.h"
#include "service_died_command.h"
#include "video_process_command.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
namespace {
    const std::string VIDEO_SERVICE_NAME = "camera_video_process_service";
    constexpr uint32_t MAX_PROC_TIME_MS = 20 * 60 * 1000;
}

class VideoPostProcessor::VideoServiceListener : public HDI::ServiceManager::V1_0::ServStatListenerStub {
public:
    using StatusCallback = std::function<void(const HDI::ServiceManager::V1_0::ServiceStatus&)>;
    explicit VideoServiceListener(const std::weak_ptr<VideoPostProcessor>& processor) : processor_(processor)
    {
    }

    void OnReceive(const HDI::ServiceManager::V1_0::ServiceStatus& status)
    {
        auto process = processor_.lock();
        DP_CHECK_ERROR_RETURN_LOG(process == nullptr, "post process is nullptr.");
        process->OnServiceChange(status);
    }

private:
    std::weak_ptr<VideoPostProcessor> processor_;
};

class VideoPostProcessor::SessionDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    explicit SessionDeathRecipient(const std::weak_ptr<VideoPostProcessor>& processor) : processor_(processor)
    {
    }

    void OnRemoteDied(const wptr<IRemoteObject> &remote) override
    {
        DP_ERR_LOG("Remote died.");
        auto process = processor_.lock();
        DP_CHECK_ERROR_RETURN_LOG(process == nullptr, "post process is nullptr.");
        process->OnSessionDied();
    }

private:
    std::weak_ptr<VideoPostProcessor> processor_;
};

class VideoPostProcessor::VideoProcessListener : public OHOS::HDI::Camera::V1_3::IVideoProcessCallback {
public:
    explicit VideoProcessListener(const std::weak_ptr<VideoPostProcessor>& processor) : processor_(processor)
    {
    }

    int32_t OnStatusChanged(OHOS::HDI::Camera::V1_2::SessionStatus status) override;
    int32_t OnProcessDone(const std::string& videoId) override;
    int32_t OnError(const std::string& videoId, OHOS::HDI::Camera::V1_2::ErrorCode errorCode) override;
    void ReportEvent(const std::string& videoId);

private:
    std::weak_ptr<VideoPostProcessor> processor_;
};

int32_t VideoPostProcessor::VideoProcessListener::OnStatusChanged(OHOS::HDI::Camera::V1_2::SessionStatus status)
{
    DP_DEBUG_LOG("entered");
    auto process = processor_.lock();
    DP_CHECK_ERROR_RETURN_RET_LOG(process == nullptr, DP_ERR, "post process is nullptr.");
    return DP_OK;
}

int32_t VideoPostProcessor::VideoProcessListener::OnProcessDone(const std::string& videoId)
{
    DP_INFO_LOG("entered, videoId: %{public}s", videoId.c_str());
    auto process = processor_.lock();
    DP_CHECK_ERROR_RETURN_RET_LOG(process == nullptr, DP_ERR, "post process is nullptr.");
    process->OnProcessDone(videoId);
    return DP_OK;
}

int32_t VideoPostProcessor::VideoProcessListener::OnError(const std::string& videoId,
    OHOS::HDI::Camera::V1_2::ErrorCode errorCode)
{
    DP_INFO_LOG("entered, videoId: %{public}s, error: %{public}d", videoId.c_str(), errorCode);
    auto process = processor_.lock();
    DP_CHECK_ERROR_RETURN_RET_LOG(process == nullptr, DP_ERR, "post process is nullptr.");
    process->OnError(videoId, process->MapHdiError(errorCode));
    return DP_OK;
}

VideoPostProcessor::VideoPostProcessor(const int32_t userId)
    : userId_(userId), serviceListener_(nullptr), sessionDeathRecipient_(nullptr), processListener_(nullptr)
{
    DP_DEBUG_LOG("entered");
}

VideoPostProcessor::~VideoPostProcessor()
{
    DP_DEBUG_LOG("entered");
    DisconnectService();
    SetVideoSession(nullptr);
    allStreamInfo_.clear();
    videoId2Handle_.Clear();
}

void VideoPostProcessor::Initialize()
{
    DP_DEBUG_LOG("entered");
    sessionDeathRecipient_ = sptr<SessionDeathRecipient>::MakeSptr(weak_from_this());
    processListener_ = sptr<VideoProcessListener>::MakeSptr(weak_from_this());
    ConnectService();
}

bool VideoPostProcessor::GetPendingVideos(std::vector<std::string>& pendingVideos)
{
    auto session = GetVideoSession();
    DP_CHECK_ERROR_RETURN_RET_LOG(session == nullptr, false, "video session is nullptr.");
    int32_t ret = session->GetPendingVideos(pendingVideos);
    DP_INFO_LOG("GetPendingVideos size: %{public}d, ret: %{public}d",
        static_cast<int32_t>(pendingVideos.size()), ret);
    return ret == DP_OK;
}

void VideoPostProcessor::SetExecutionMode(ExecutionMode executionMode)
{
    DP_DEBUG_LOG("entered.");
}

void VideoPostProcessor::SetDefaultExecutionMode()
{
    DP_DEBUG_LOG("entered.");
}

void VideoPostProcessor::ProcessRequest(const DeferredVideoWorkPtr& work)
{
    auto session = GetVideoSession();
    auto videoId = work->GetDeferredVideoJob()->GetVideoId();
    if (session == nullptr) {
        DP_ERR_LOG("failed to process videoId: %{public}s, video session is nullptr", videoId.c_str());
        OnError(videoId, DpsError::DPS_ERROR_SESSION_NOT_READY_TEMPORARILY);
        return;
    }

    auto inFd = work->GetDeferredVideoJob()->GetInputFd();
    DP_CHECK_ERROR_RETURN_LOG(!StartMpeg(videoId, inFd), "mpeg start failed.");
    DP_CHECK_ERROR_RETURN_LOG(!PrepareStreams(videoId, inFd->GetFd()), "prepaer video failed.");

    StartTimer(videoId, work);
    auto mpegManager = GetMpegManager();
    DP_CHECK_ERROR_RETURN_LOG(!mpegManager, "mpegManager is nullptr");
    auto startTime = mpegManager->GetProcessTimeStamp();
    auto ret = session->ProcessVideo(videoId, startTime);
    DP_INFO_LOG("process video to ive, videoId: %{public}s, startTime: %{public}llu, ret: %{public}d",
        videoId.c_str(), static_cast<unsigned long long>(startTime), ret);
}

void VideoPostProcessor::RemoveRequest(const std::string& videoId)
{
    auto session = GetVideoSession();
    DP_CHECK_ERROR_RETURN_LOG(session == nullptr,
        "remove videoId: %{public}s failed, video session is nullptr.", videoId.c_str());
    std::string path = PATH + videoId + OUT_TAG;
    DP_CHECK_ERROR_PRINT_LOG(remove(path.c_str()) != 0, "Failed to remove file at path: %{public}s", path.c_str());
    auto ret = session->RemoveVideo(videoId);
    DP_INFO_LOG("remove video to ive, videoId: %{public}s, ret: %{public}d", videoId.c_str(), ret);
    // DPSEventReport::GetInstance().UpdateRemoveTime(imageId, userId_);
}

void VideoPostProcessor::PauseRequest(const std::string& videoId, const ScheduleType& type)
{
    auto session = GetVideoSession();
    DP_CHECK_ERROR_RETURN_LOG(session == nullptr, "video session is nullptr.");

    int32_t ret = session->Interrupt();
    DP_INFO_LOG("interrupt video to ive, videoId: %{public}s, ret: %{public}d", videoId.c_str(), ret);
    // DPSEventReport::GetInstance().UpdateRemoveTime(imageId, userId_);
}

bool VideoPostProcessor::PrepareStreams(const std::string& videoId, const int inputFd)
{
    auto session = GetVideoSession();
    DP_CHECK_ERROR_RETURN_RET_LOG(session == nullptr, false, "video session is nullptr.");
    allStreamInfo_.clear();
    std::vector<StreamDescription> streamDescs;
    auto ret = session->Prepare(videoId, inputFd, streamDescs);
    DP_INFO_LOG("prepare videoId: %{public}s, stream size: %{public}d, ret: %{public}d", videoId.c_str(),
        static_cast<int32_t>(streamDescs.size()), ret);
    for (const auto& stream : streamDescs) {
        DP_INFO_LOG("streamId: %{public}d, stream type: %{public}d", stream.streamId, stream.type);
        if (stream.type == 0) {
            auto mpegManager = GetMpegManager();
            DP_CHECK_ERROR_RETURN_RET_LOG(!mpegManager, false, "mpegManager is nullptr");
            auto producer = sptr<BufferProducerSequenceable>::MakeSptr(mpegManager->GetSurface()->GetProducer());
            SetStreamInfo(stream, producer);
        }
    }

    DP_INFO_LOG("prepare videoId: %{public}s, allStreamInfo size: %{public}d", videoId.c_str(),
        static_cast<int32_t>(allStreamInfo_.size()));
    DP_CHECK_ERROR_RETURN_RET_LOG(allStreamInfo_.empty(), false, "allStreamInfo is null.");
    ret = session->CreateStreams(allStreamInfo_);
    DP_INFO_LOG("create streams videoId: %{public}s, ret: %{public}d", videoId.c_str(), ret);
    std::vector<uint8_t> modeSetting;
    ret = session->CommitStreams(modeSetting);
    DP_INFO_LOG("commit streams videoId: %{public}s, ret: %{public}d", videoId.c_str(), ret);
    return true;
}

void VideoPostProcessor::CreateSurface(const std::string& name, const StreamDescription& stream,
    sptr<Surface>& surface)
{
    DP_INFO_LOG("entered, create %{public}s surface.", name.c_str());
    surface = Surface::CreateSurfaceAsConsumer(name);
    surface->SetDefaultUsage(BUFFER_USAGE_VIDEO_ENCODER);
    surface->SetDefaultWidthAndHeight(stream.width, stream.height);
    auto producer = sptr<BufferProducerSequenceable>::MakeSptr(surface->GetProducer());
    SetStreamInfo(stream, producer);
}

void VideoPostProcessor::SetStreamInfo(const StreamDescription& stream, sptr<BufferProducerSequenceable>& producer)
{
    StreamInfo_V1_1 streamInfo;
    streamInfo.v1_0.intent_ = HDI::Camera::V1_0::VIDEO;
    streamInfo.v1_0.tunneledMode_ = true;
    streamInfo.v1_0.streamId_ = stream.streamId;
    streamInfo.v1_0.width_ = stream.width;
    streamInfo.v1_0.height_ = stream.height;
    streamInfo.v1_0.format_ = stream.pixelFormat;
    streamInfo.v1_0.dataspace_ = stream.dataspace;
    streamInfo.v1_0.bufferQueue_ = producer;
    allStreamInfo_.emplace_back(streamInfo);
}

bool VideoPostProcessor::StartMpeg(const std::string& videoId, const sptr<IPCFileDescriptor>& inputFd)
{
    auto mpegManager = MpegManagerFactory::GetInstance().Acquire(videoId, inputFd);
    SetMpegManager(mpegManager);
    DP_CHECK_ERROR_RETURN_RET_LOG(mpegManager == nullptr, false, "mpeg manager is nullptr.");
    return true;
}

bool VideoPostProcessor::StopMpeg(const MediaResult result, const DeferredVideoWorkPtr& work)
{
    auto mpegManager = GetMpegManager();
    DP_CHECK_ERROR_RETURN_RET_LOG(mpegManager == nullptr, false, "mpegManager is nullptr");
    mpegManager->UnInit(result);

    bool ret = true;
    if (result == MediaResult::SUCCESS) {
        auto tempFd = mpegManager->GetResultFd()->GetFd();
        auto outFd = work->GetDeferredVideoJob()->GetOutputFd()->GetFd();
        auto videoId = work->GetDeferredVideoJob()->GetVideoId();
        DP_INFO_LOG("video process done, videoId: %{public}s, tempFd: %{public}d, outFd: %{public}d",
            videoId.c_str(), tempFd, outFd);
        copyFileByFd(tempFd, outFd);
        if (IsFileEmpty(outFd)) {
            DP_ERR_LOG("videoId: %{public}s size is empty.", videoId.c_str());
            OnError(videoId, DPS_ERROR_VIDEO_PROC_FAILED);
            ret = false;
        }
    }
    ReleaseMpeg();
    return ret;
}

void VideoPostProcessor::ReleaseMpeg()
{
    auto mpegManager = GetMpegManager();
    DP_CHECK_ERROR_RETURN_LOG(mpegManager == nullptr, "mpegManager is nullptr");
    MpegManagerFactory::GetInstance().Release(mpegManager);
    mpegManager.reset();
    DP_INFO_LOG("release mpeg success.");
}

void VideoPostProcessor::StartTimer(const std::string& videoId, const DeferredVideoWorkPtr& work)
{
    uint32_t timeId = DpsTimer::GetInstance().StartTimer([&, videoId]() {OnTimerOut(videoId);}, MAX_PROC_TIME_MS);
    work->SetTimeId(timeId);
    DP_INFO_LOG("DpsTimer start, videoId: %{public}s, timeId: %{public}u", videoId.c_str(), timeId);
    videoId2Handle_.Insert(videoId, work);
}

void VideoPostProcessor::StopTimer(const std::string& videoId)
{
    DeferredVideoWorkPtr work;
    DP_CHECK_RETURN(!videoId2Handle_.Find(videoId, work));
    
    auto timeId = work->GetTimeId();
    DP_INFO_LOG("DpsTimer stop, videoId: %{public}s, timeId: %{public}u", videoId.c_str(), timeId);
    DpsTimer::GetInstance().StopTimer(timeId);
    auto session = GetVideoSession();
    DP_CHECK_ERROR_RETURN_LOG(session == nullptr,
        "release videoId: %{public}s failed, video session is nullptr.", videoId.c_str());

    auto ret = session->ReleaseStreams(allStreamInfo_);
    allStreamInfo_.clear();
    DP_INFO_LOG("release streams videoId: %{public}s, ret: %{public}d", videoId.c_str(), ret);
}

DeferredVideoWorkPtr VideoPostProcessor::GetRunningWork(const std::string& videoId)
{
    DeferredVideoWorkPtr work;
    videoId2Handle_.Find(videoId, work);
    return work;
}

void VideoPostProcessor::OnSessionDied()
{
    DP_ERR_LOG("entered, session died!");
    SetVideoSession(nullptr);

    std::vector<std::string> crashJobs;
    videoId2Handle_.Iterate([&](const std::string& videoId, const DeferredVideoWorkPtr& work) {
        crashJobs.emplace_back(work->GetDeferredVideoJob()->GetVideoId());
    });
    for (const auto& id : crashJobs) {
        OnError(id, DPS_ERROR_VIDEO_PROC_INTERRUPTED);
    }
    crashJobs.clear();
    auto ret = DPS_SendCommand<ServiceDiedCommand>(userId_);
    DP_CHECK_ERROR_PRINT_LOG(ret != DP_OK, "failed. ret: %{public}d", ret);
}

void VideoPostProcessor::OnProcessDone(const std::string& videoId)
{
    auto work = GetRunningWork(videoId);
    DP_CHECK_ERROR_RETURN_LOG(work == nullptr, "not find running video work.");
    StopTimer(videoId);
    DP_CHECK_ERROR_RETURN_LOG(!StopMpeg(MediaResult::SUCCESS, work), "success: mpeg stop failed.");
    
    auto ret = DPS_SendCommand<VideoProcessSuccessCommand>(userId_, work);
    DP_CHECK_ERROR_RETURN_LOG(ret != DP_OK,
        "process success videoId: %{public}s failed. ret: %{public}d", videoId.c_str(), ret);
    videoId2Handle_.Erase(videoId);
}

void VideoPostProcessor::OnError(const std::string& videoId, DpsError errorCode)
{
    auto work = GetRunningWork(videoId);
    StopTimer(videoId);
    DP_CHECK_ERROR_RETURN_LOG(work == nullptr, "no running video work.");

    if (errorCode == DPS_ERROR_VIDEO_PROC_INTERRUPTED) {
        DP_CHECK_ERROR_RETURN_LOG(!StopMpeg(MediaResult::PAUSE, work), "pause: mpeg stop failed.");
    } else {
        DP_CHECK_ERROR_RETURN_LOG(!StopMpeg(MediaResult::FAIL, work), "error or outtime: mpeg stop failed.");
    }

    DP_INFO_LOG("video process error, videoId: %{public}s, error: %{public}d", videoId.c_str(), errorCode);
    auto ret = DPS_SendCommand<VideoProcessFailedCommand>(userId_, work, errorCode);
    DP_CHECK_ERROR_RETURN_LOG(ret != DP_OK,
        "process error videoId: %{public}s failed. ret: %{public}d", videoId.c_str(), ret);
    videoId2Handle_.Erase(videoId);
}

void VideoPostProcessor::OnStateChanged(HdiStatus hdiStatus)
{
    DP_INFO_LOG("entered, HdiStatus: %{public}d", hdiStatus);
    EventsMonitor::GetInstance().NotifyImageEnhanceStatus(hdiStatus);
}

void VideoPostProcessor::OnTimerOut(const std::string& videoId)
{
    DP_INFO_LOG("DpsTimer executed, videoId: %{public}s", videoId.c_str());
    OnError(videoId, DpsError::DPS_ERROR_IMAGE_PROC_TIMEOUT);
}

void VideoPostProcessor::ConnectService()
{
    auto svcMgr = HDI::ServiceManager::V1_0::IServiceManager::Get();
    DP_CHECK_ERROR_RETURN_LOG(svcMgr == nullptr, "IServiceManager init failed.");

    serviceListener_ = sptr<VideoServiceListener>::MakeSptr(weak_from_this());
    auto ret  = svcMgr->RegisterServiceStatusListener(serviceListener_, DEVICE_CLASS_DEFAULT);
    DP_CHECK_ERROR_RETURN_LOG(ret != 0, "RegisterServiceStatusListener failed.");
}

void VideoPostProcessor::DisconnectService()
{
    auto session = GetVideoSession();
    DP_CHECK_ERROR_RETURN_LOG(session == nullptr, "video session is nullptr.");

    const sptr<IRemoteObject> &remote = OHOS::HDI::hdi_objcast<IVideoProcessSession>(session);
    bool result = remote->RemoveDeathRecipient(sessionDeathRecipient_);
    DP_CHECK_ERROR_RETURN_LOG(!result, "remove DeathRecipient for VideoProcessSession failed.");

    auto svcMgr = HDI::ServiceManager::V1_0::IServiceManager::Get();
    DP_CHECK_ERROR_RETURN_LOG(svcMgr == nullptr, "IServiceManager init failed.");

    auto ret  = svcMgr->UnregisterServiceStatusListener(serviceListener_);
    DP_CHECK_ERROR_RETURN_LOG(ret != 0, "RegisterServiceStatusListener failed.");
}

void VideoPostProcessor::OnServiceChange(const HDI::ServiceManager::V1_0::ServiceStatus& status)
{
    DP_CHECK_RETURN(status.serviceName != VIDEO_SERVICE_NAME);
    DP_CHECK_RETURN_LOG(status.status != HDI::ServiceManager::V1_0::SERVIE_STATUS_START,
        "video service state: %{public}d", status.status);
    DP_CHECK_RETURN(GetVideoSession() != nullptr);
    
    sptr<HDI::Camera::V1_3::IVideoProcessService> proxy =
        HDI::Camera::V1_3::IVideoProcessService::Get(status.serviceName);
    DP_CHECK_ERROR_RETURN_LOG(proxy == nullptr, "get VideoProcessService failed.");

    sptr<IVideoProcessSession> session;
    proxy->CreateVideoProcessSession(userId_, processListener_, session);
    DP_CHECK_ERROR_RETURN_LOG(session == nullptr, "get VideoProcessSession failed.");

    const sptr<IRemoteObject> &remote = OHOS::HDI::hdi_objcast<IVideoProcessSession>(session);
    bool result = remote->AddDeathRecipient(sessionDeathRecipient_);
    DP_CHECK_ERROR_RETURN_LOG(!result, "add DeathRecipient for VideoProcessSession failed.");
    
    SetVideoSession(session);
    OnStateChanged(HdiStatus::HDI_READY);
}

void VideoPostProcessor::copyFileByFd(const int srcFd, const int dstFd)
{
    struct stat buffer;
    DP_CHECK_ERROR_RETURN_LOG(fstat(srcFd, &buffer) == -1,
        "get out fd status failed, err: %{public}s", std::strerror(errno));

    off_t offset = 0;
    ssize_t bytesSent;
    while (offset < buffer.st_size) {
        bytesSent = sendfile(dstFd, srcFd, &offset, buffer.st_size - offset);
        DP_CHECK_ERROR_RETURN_LOG(bytesSent == -1, "copy file failed, err: %{public}s", std::strerror(errno));
    }
}

DpsError VideoPostProcessor::MapHdiError(OHOS::HDI::Camera::V1_2::ErrorCode errorCode)
{
    DpsError code = DpsError::DPS_ERROR_UNKNOW;
    switch (errorCode) {
        case OHOS::HDI::Camera::V1_2::ErrorCode::ERROR_INVALID_ID:
            code = DpsError::DPS_ERROR_VIDEO_PROC_INVALID_VIDEO_ID;
            break;
        case OHOS::HDI::Camera::V1_2::ErrorCode::ERROR_PROCESS:
            code = DpsError::DPS_ERROR_VIDEO_PROC_FAILED;
            break;
        case OHOS::HDI::Camera::V1_2::ErrorCode::ERROR_TIMEOUT:
            code = DpsError::DPS_ERROR_VIDEO_PROC_TIMEOUT;
            break;
        case OHOS::HDI::Camera::V1_2::ErrorCode::ERROR_ABORT:
            code = DpsError::DPS_ERROR_VIDEO_PROC_INTERRUPTED;
            break;
        default:
            DP_ERR_LOG("unexpected error code: %{public}d.", errorCode);
            break;
    }
    return code;
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS