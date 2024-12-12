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
#include "v1_3/types.h"
#include "video_process_command.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
namespace {
    const std::string VIDEO_SERVICE_NAME = "camera_video_process_service";
    constexpr uint32_t MAX_PROC_TIME_MS = 20 * 60 * 1000;
}

DpsError MapHdiVideoError(OHOS::HDI::Camera::V1_2::ErrorCode errorCode)
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
    explicit SessionDeathRecipient(const std::weak_ptr<VideoProcessResult>& processResult)
        : processResult_(processResult)
    {
        DP_DEBUG_LOG("entered.");
    }

    void OnRemoteDied(const wptr<IRemoteObject> &remote) override
    {
        auto processResult = processResult_.lock();
        DP_CHECK_ERROR_RETURN_LOG(processResult == nullptr, "VideoProcessResult is nullptr.");

        processResult->OnVideoSessionDied();
    }

private:
    std::weak_ptr<VideoProcessResult> processResult_;
};

class VideoPostProcessor::VideoProcessListener : public OHOS::HDI::Camera::V1_3::IVideoProcessCallback {
public:
    explicit VideoProcessListener(const std::weak_ptr<VideoProcessResult>& processResult)
        : processResult_(processResult)
    {
        DP_DEBUG_LOG("entered.");
    }

    int32_t OnProcessDone(const std::string& videoId) override
    {
        DP_INFO_LOG("DPS_VIDEO: videoId: %{public}s", videoId.c_str());
        auto processResult = processResult_.lock();
        DP_CHECK_ERROR_RETURN_RET_LOG(processResult == nullptr, DP_OK, "VideoProcessResult is nullptr.");

        processResult->OnProcessDone(videoId);
        return DP_OK;
    }

    int32_t OnError(const std::string& videoId, OHOS::HDI::Camera::V1_2::ErrorCode errorCode) override
    {
        DP_INFO_LOG("DPS_VIDEO: videoId: %{public}s, error: %{public}d", videoId.c_str(), errorCode);
        auto processResult = processResult_.lock();
        DP_CHECK_ERROR_RETURN_RET_LOG(processResult == nullptr, DP_OK, "VideoProcessResult is nullptr.");

        processResult->OnError(videoId, MapHdiVideoError(errorCode));
        return DP_OK;
    }

    int32_t OnStatusChanged(OHOS::HDI::Camera::V1_2::SessionStatus status) override
    {
        DP_DEBUG_LOG("entered.");
        return DP_OK;
    }

private:
    std::weak_ptr<VideoProcessResult> processResult_;
};

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
    runningWork_.clear();
}

void VideoPostProcessor::Initialize()
{
    DP_DEBUG_LOG("entered");
    processResult_ = std::make_shared<VideoProcessResult>(userId_);
    sessionDeathRecipient_ = sptr<SessionDeathRecipient>::MakeSptr(processResult_);
    processListener_ = sptr<VideoProcessListener>::MakeSptr(processResult_);
    ConnectService();
}

bool VideoPostProcessor::GetPendingVideos(std::vector<std::string>& pendingVideos)
{
    auto session = GetVideoSession();
    DP_CHECK_ERROR_RETURN_RET_LOG(session == nullptr, false, "video session is nullptr.");
    int32_t ret = session->GetPendingVideos(pendingVideos);
    DP_INFO_LOG("DPS_VIDEO: GetPendingVideos size: %{public}d, ret: %{public}d",
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
        DP_ERR_LOG("process videoId: %{public}s failed, video session is nullptr", videoId.c_str());
        OnError(videoId, DpsError::DPS_ERROR_SESSION_NOT_READY_TEMPORARILY);
        return;
    }

    auto inFd = work->GetDeferredVideoJob()->GetInputFd();
    DP_CHECK_ERROR_RETURN_LOG(!StartMpeg(videoId, inFd), "mpeg start failed.");
    DP_CHECK_ERROR_RETURN_LOG(!PrepareStreams(videoId, inFd->GetFd()), "prepaer video failed.");

    StartTimer(videoId, work);
    auto startTime = mpegManager_->GetProcessTimeStamp();
    auto ret = session->ProcessVideo(videoId, startTime);
    DP_INFO_LOG("DPS_VIDEO: ProcessVideo to ive, videoId: %{public}s, startTime: %{public}" PRIu64 ", ret: %{public}d",
        videoId.c_str(), startTime, ret);
}

void VideoPostProcessor::RemoveRequest(const std::string& videoId)
{
    auto session = GetVideoSession();
    DP_CHECK_ERROR_RETURN_LOG(session == nullptr,
        "remove videoId: %{public}s failed, video session is nullptr.", videoId.c_str());
    std::string path = PATH + videoId + OUT_TAG;
    DP_CHECK_ERROR_PRINT_LOG(remove(path.c_str()) != 0, "Failed to remove file at path: %{public}s", path.c_str());
    auto ret = session->RemoveVideo(videoId);
    DP_INFO_LOG("DPS_VIDEO: RemoveVideo to ive, videoId: %{public}s, ret: %{public}d", videoId.c_str(), ret);
}

void VideoPostProcessor::PauseRequest(const std::string& videoId, const ScheduleType& type)
{
    auto session = GetVideoSession();
    DP_CHECK_ERROR_RETURN_LOG(session == nullptr, "video session is nullptr.");

    int32_t ret = session->Interrupt();
    DP_INFO_LOG("DPS_VIDEO: Interrupt video to ive, videoId: %{public}s, ret: %{public}d", videoId.c_str(), ret);
}

bool VideoPostProcessor::PrepareStreams(const std::string& videoId, const int inputFd)
{
    auto session = GetVideoSession();
    DP_CHECK_ERROR_RETURN_RET_LOG(session == nullptr, false, "video session is nullptr.");

    allStreamInfo_.clear();
    std::vector<StreamDescription> streamDescs;
    auto ret = session->Prepare(videoId, inputFd, streamDescs);
    DP_INFO_LOG("DPS_VIDEO: Prepare videoId: %{public}s, stream size: %{public}d, ret: %{public}d",
        videoId.c_str(), static_cast<int32_t>(streamDescs.size()), ret);

    for (const auto& stream : streamDescs) {
        DP_LOOP_ERROR_RETURN_RET_LOG(!ProcessStream(stream), false,
            "ProcessStream failed streamType: %{public}d", stream.type);
    }

    DP_INFO_LOG("DPS_VIDEO: Prepare videoId: %{public}s, create stream size: %{public}d", videoId.c_str(),
        static_cast<int32_t>(allStreamInfo_.size()));
    DP_CHECK_ERROR_RETURN_RET_LOG(allStreamInfo_.empty(), false, "allStreamInfo is null.");

    ret = session->CreateStreams(allStreamInfo_);
    DP_INFO_LOG("DPS_VIDEO: CreateStreams videoId: %{public}s, ret: %{public}d", videoId.c_str(), ret);

    std::vector<uint8_t> modeSetting;
    ret = session->CommitStreams(modeSetting);
    DP_INFO_LOG("DPS_VIDEO: CommitStreams videoId: %{public}s, ret: %{public}d", videoId.c_str(), ret);
    return true;
}

bool VideoPostProcessor::ProcessStream(const StreamDescription& stream)
{
    DP_INFO_LOG("DPS_VIDEO: streamId: %{public}d, stream type: %{public}d", stream.streamId, stream.type);
    sptr<Surface> surface = nullptr;
    if (stream.type == HDI::Camera::V1_3::MEDIA_STREAM_TYPE_VIDEO) {
        surface = mpegManager_->GetSurface();
    } else if (stream.type == HDI::Camera::V1_3::MEDIA_STREAM_TYPE_MAKER) {
        surface = mpegManager_->GetMakerSurface();
    }
    DP_CHECK_ERROR_RETURN_RET_LOG(surface == nullptr, false, "Surface is nullptr.");

    auto producer = sptr<BufferProducerSequenceable>::MakeSptr(surface->GetProducer());
    DP_CHECK_ERROR_RETURN_RET_LOG(producer == nullptr, false, "BufferProducer is nullptr.");

    SetStreamInfo(stream, producer);
    return true;
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
    mpegManager_ = MpegManagerFactory::GetInstance().Acquire(videoId, inputFd);
    DP_CHECK_ERROR_RETURN_RET_LOG(mpegManager_ == nullptr, false, "mpeg manager is nullptr.");
    DP_INFO_LOG("DPS_VIDEO: Acquire MpegManager.");
    return true;
}

bool VideoPostProcessor::StopMpeg(const MediaResult result, const DeferredVideoWorkPtr& work)
{
    DP_CHECK_ERROR_RETURN_RET_LOG(mpegManager_ == nullptr, false, "mpegManager is nullptr");
    mpegManager_->UnInit(result);

    if (result != MediaResult::SUCCESS) {
        ReleaseMpeg();
        return true;
    }

    auto videoId = work->GetDeferredVideoJob()->GetVideoId();
    auto resultFd = mpegManager_->GetResultFd();
    if (resultFd == nullptr) {
        DP_ERR_LOG("get video fd failed, videoId: %{public}s", videoId.c_str());
        OnError(videoId, DPS_ERROR_VIDEO_PROC_FAILED);
        return false;
    }

    auto tempFd = resultFd->GetFd();
    auto outFd = work->GetDeferredVideoJob()->GetOutputFd()->GetFd();
    DP_INFO_LOG("DPS_VIDEO: Video process done, videoId: %{public}s, tempFd: %{public}d, outFd: %{public}d",
                videoId.c_str(), tempFd, outFd);
    copyFileByFd(tempFd, outFd);
    if (IsFileEmpty(outFd)) {
        DP_ERR_LOG("muxer video size is empty, videoId: %{public}s", videoId.c_str());
        OnError(videoId, DPS_ERROR_VIDEO_PROC_FAILED);
        return false;
    }

    ReleaseMpeg();
    return true;
}

void VideoPostProcessor::ReleaseMpeg()
{
    MpegManagerFactory::GetInstance().Release(mpegManager_);
    mpegManager_.reset();
    DP_INFO_LOG("DPS_VIDEO: Release MpegManager.");
}

void VideoPostProcessor::StartTimer(const std::string& videoId, const DeferredVideoWorkPtr& work)
{
    uint32_t timeId = DpsTimer::GetInstance().StartTimer([&, videoId]() {OnTimerOut(videoId);}, MAX_PROC_TIME_MS);
    work->SetTimeId(timeId);
    DP_INFO_LOG("DpsTimer start, videoId: %{public}s, timeId: %{public}u", videoId.c_str(), timeId);
    runningWork_.emplace(videoId, work);
}

void VideoPostProcessor::StopTimer(const DeferredVideoWorkPtr& work)
{
    DP_CHECK_RETURN(work == nullptr);
    auto videoId = work->GetDeferredVideoJob()->GetVideoId();
    runningWork_.erase(videoId);
    auto timeId = work->GetTimeId();
    DP_INFO_LOG("DpsTimer stop, videoId: %{public}s, timeId: %{public}u", videoId.c_str(), timeId);
    DpsTimer::GetInstance().StopTimer(timeId);

    auto session = GetVideoSession();
    DP_CHECK_ERROR_RETURN_LOG(session == nullptr,
        "release videoId: %{public}s failed, video session is nullptr.", videoId.c_str());

    auto ret = session->ReleaseStreams(allStreamInfo_);
    allStreamInfo_.clear();
    DP_INFO_LOG("DPS_VIDEO: ReleaseStreams videoId: %{public}s, ret: %{public}d", videoId.c_str(), ret);
}

DeferredVideoWorkPtr VideoPostProcessor::GetRunningWork(const std::string& videoId)
{
    auto it = runningWork_.find(videoId);
    DP_CHECK_ERROR_RETURN_RET_LOG(it == runningWork_.end(), nullptr,
        "GetRunningWork not found for videoId: %{public}s", videoId.c_str());
    return it->second;
}

void VideoPostProcessor::OnSessionDied()
{
    DP_ERR_LOG("DPS_VIDEO: session died!");
    SetVideoSession(nullptr);
    std::vector<std::string> crashJobs;
    for (const auto& item : runningWork_) {
        crashJobs.emplace_back(item.first);
    }
    for (const auto& videoId : crashJobs) {
        OnError(videoId, DPS_ERROR_VIDEO_PROC_INTERRUPTED);
    }
    crashJobs.clear();
    OnStateChanged(HdiStatus::HDI_DISCONNECTED);
}

void VideoPostProcessor::OnProcessDone(const std::string& videoId)
{
    auto work = GetRunningWork(videoId);
    DP_CHECK_ERROR_RETURN_LOG(work == nullptr, "video work is nullptr.");
    DP_CHECK_ERROR_RETURN_LOG(!StopMpeg(MediaResult::SUCCESS, work), "success: mpeg stop failed.");

    DP_INFO_LOG("DPS_VIDEO: video process done, videoId: %{public}s", videoId.c_str());
    StopTimer(work);
    if (auto schedulerManager = DPS_GetSchedulerManager()) {
        if (auto videoController = schedulerManager->GetVideoController(userId_)) {
            videoController->HandleSuccess(work);
        }
    }
}

void VideoPostProcessor::OnError(const std::string& videoId, DpsError errorCode)
{
    auto work = GetRunningWork(videoId);
    DP_CHECK_ERROR_RETURN_LOG(work == nullptr, "video work is nullptr.");
    if (errorCode == DPS_ERROR_VIDEO_PROC_INTERRUPTED) {
        DP_CHECK_ERROR_PRINT_LOG(!StopMpeg(MediaResult::PAUSE, work), "pause: mpeg stop failed.");
    } else {
        DP_CHECK_ERROR_PRINT_LOG(!StopMpeg(MediaResult::FAIL, work), "error or outtime: mpeg stop failed.");
    }

    DP_INFO_LOG("DPS_VIDEO: video process error, videoId: %{public}s, error: %{public}d",
        work->GetDeferredVideoJob()->GetVideoId().c_str(), errorCode);
    StopTimer(work);
    if (auto schedulerManager = DPS_GetSchedulerManager()) {
        if (auto videoController = schedulerManager->GetVideoController(userId_)) {
            videoController->HandleError(work, errorCode);
        }
    }
}

void VideoPostProcessor::OnStateChanged(HdiStatus hdiStatus)
{
    DP_INFO_LOG("DPS_VIDEO: HdiStatus: %{public}d", hdiStatus);
    EventsMonitor::GetInstance().NotifyVideoEnhanceStatus(hdiStatus);
}

void VideoPostProcessor::OnTimerOut(const std::string& videoId)
{
    DP_INFO_LOG("DpsTimer end, videoId: %{public}s", videoId.c_str());
    OnError(videoId, DpsError::DPS_ERROR_VIDEO_PROC_TIMEOUT);
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
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS