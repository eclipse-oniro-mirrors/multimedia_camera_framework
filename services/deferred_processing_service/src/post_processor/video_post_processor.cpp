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
#include "events_info.h"
#include "events_monitor.h"
#include "hdf_device_class.h"
#include "iproxy_broker.h"
#include "iservmgr_hdi.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
namespace {
    const std::string VIDEO_SERVICE_NAME = "camera_video_process_service";
    constexpr uint32_t MAX_PROC_TIME_MS = 20 * 60 * 1000;
}

// LCOV_EXCL_START
HdiStatus MapHdiVideoStatus(OHOS::HDI::Camera::V1_2::SessionStatus statusCode)
{
    HdiStatus code = HdiStatus::HDI_DISCONNECTED;
    switch (statusCode) {
        case OHOS::HDI::Camera::V1_2::SessionStatus::SESSION_STATUS_READY:
            code = HdiStatus::HDI_READY;
            break;
        case OHOS::HDI::Camera::V1_2::SessionStatus::SESSION_STATUS_READY_SPACE_LIMIT_REACHED:
            code = HdiStatus::HDI_READY_SPACE_LIMIT_REACHED;
            break;
        case OHOS::HDI::Camera::V1_2::SessionStatus::SESSSON_STATUS_NOT_READY_TEMPORARILY:
            code = HdiStatus::HDI_NOT_READY_TEMPORARILY;
            break;
        case OHOS::HDI::Camera::V1_2::SessionStatus::SESSION_STATUS_NOT_READY_OVERHEAT:
            code = HdiStatus::HDI_NOT_READY_OVERHEAT;
            break;
        case OHOS::HDI::Camera::V1_2::SessionStatus::SESSION_STATUS_NOT_READY_PREEMPTED:
            code = HdiStatus::HDI_NOT_READY_PREEMPTED;
            break;
        default:
            DP_ERR_LOG("unexpected error code: %{public}d.", statusCode);
            break;
    }
    return code;
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
DpsError MapHdiVideoError(OHOS::HDI::Camera::V1_2::ErrorCode errorCode)
{
    DpsError code = DPS_ERROR_UNKNOW;
    switch (errorCode) {
        case OHOS::HDI::Camera::V1_2::ErrorCode::ERROR_INVALID_ID:
            code = DPS_ERROR_VIDEO_PROC_INVALID_VIDEO_ID;
            break;
        case OHOS::HDI::Camera::V1_2::ErrorCode::ERROR_PROCESS:
            code = DPS_ERROR_VIDEO_PROC_FAILED;
            break;
        case OHOS::HDI::Camera::V1_2::ErrorCode::ERROR_TIMEOUT:
            code = DPS_ERROR_VIDEO_PROC_TIMEOUT;
            break;
        case OHOS::HDI::Camera::V1_2::ErrorCode::ERROR_ABORT:
            code = DPS_ERROR_VIDEO_PROC_INTERRUPTED;
            break;
        default:
            DP_ERR_LOG("unexpected error code: %{public}d.", errorCode);
            break;
    }
    return code;
}
// LCOV_EXCL_STOP

class VideoPostProcessor::VideoServiceListener : public HDI::ServiceManager::V1_0::ServStatListenerStub {
public:
    using StatusCallback = std::function<void(const HDI::ServiceManager::V1_0::ServiceStatus&)>;
    explicit VideoServiceListener(const std::weak_ptr<VideoPostProcessor>& processor) : processor_(processor)
    {
        DP_DEBUG_LOG("entered.");
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
    // LCOV_EXCL_START
    void OnRemoteDied(const wptr<IRemoteObject> &remote) override
    {
        auto processResult = processResult_.lock();
        DP_CHECK_ERROR_RETURN_LOG(processResult == nullptr, "VideoProcessResult is nullptr.");

        processResult->OnVideoSessionDied();
    }
    // LCOV_EXCL_STOP

private:
    std::weak_ptr<VideoProcessResult> processResult_;
};

class VideoPostProcessor::VideoProcessListener : public HDI::Camera::V1_4::IVideoProcessCallback {
public:
    explicit VideoProcessListener(const std::weak_ptr<VideoProcessResult>& processResult)
        : processResult_(processResult)
    {
        DP_DEBUG_LOG("entered.");
    }

    // LCOV_EXCL_START
    int32_t OnProcessDone(const std::string& videoId) override
    {
        DP_INFO_LOG("DPS_VIDEO: videoId: %{public}s", videoId.c_str());
        auto processResult = processResult_.lock();
        DP_CHECK_ERROR_RETURN_RET_LOG(processResult == nullptr, DP_OK, "VideoProcessResult is nullptr.");

        processResult->OnProcessDone(videoId);
        return DP_OK;
    }

    int32_t OnProcessDone(const std::string& videoId,
        const sptr<HDI::Camera::V1_0::MapDataSequenceable>& metaData) override
    {
        DP_INFO_LOG("DPS_VIDEO: videoId: %{public}s", videoId.c_str());
        auto processResult = processResult_.lock();
        DP_CHECK_ERROR_RETURN_RET_LOG(processResult == nullptr, DP_OK, "VideoProcessResult is nullptr.");

        auto ret = processResult->ProcessVideoInfo(videoId, metaData);
        if (ret != DP_OK) {
            DP_ERR_LOG("process done failed videoId: %{public}s.", videoId.c_str());
            processResult->OnError(videoId, DPS_ERROR_IMAGE_PROC_FAILED);
        }
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
        DP_INFO_LOG("DPS_VIDEO: HdiStatus: %{public}d", status);
        auto processResult = processResult_.lock();
        DP_CHECK_ERROR_RETURN_RET_LOG(processResult == nullptr, DP_OK, "VideoProcessResult is nullptr.");

        processResult->OnStateChanged(MapHdiVideoStatus(status));
        return DP_OK;
    }
    // LCOV_EXCL_STOP

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
    StartTimer(videoId, work);
    if (session == nullptr) {
        DP_ERR_LOG("Process videoId: %{public}s failed, video session is nullptr", videoId.c_str());
        DP_CHECK_EXECUTE(processResult_, processResult_->OnError(videoId, DPS_ERROR_SESSION_NOT_READY_TEMPORARILY));
        return;
    }

    auto inFd = work->GetDeferredVideoJob()->GetInputFd();
    if (!StartMpeg(videoId, inFd)) {
        DP_CHECK_EXECUTE(processResult_, processResult_->OnError(videoId, DPS_ERROR_VIDEO_PROC_FAILED));
        return;
    }

    auto error = PrepareStreams(videoId, inFd->GetFd());
    if (error != DPS_NO_ERROR) {
        DP_CHECK_EXECUTE(processResult_, processResult_->OnError(videoId, error));
        return;
    }
    DP_CHECK_ERROR_RETURN_LOG(mediaManagerProxy_ == nullptr, "MediaManager is nullptr.");
    auto startTime = mediaManagerProxy_->MpegGetProcessTimeStamp();
    auto ret = session->ProcessVideo(videoId, startTime);
    DP_INFO_LOG("DPS_VIDEO: ProcessVideo to ive, videoId: %{public}s, startTime: %{public}" PRIu64 ", ret: %{public}d",
        videoId.c_str(), startTime, ret);
}

void VideoPostProcessor::RemoveRequest(const std::string& videoId)
{
    auto session = GetVideoSession();
    DP_CHECK_ERROR_RETURN_LOG(session == nullptr,
        "failed to remove videoId: %{public}s, video session is nullptr.", videoId.c_str());
    std::string path = PATH + videoId + OUT_TAG;
    DP_CHECK_ERROR_PRINT_LOG(remove(path.c_str()) != 0, "Failed to remove file at path: %{public}s", path.c_str());
    auto ret = session->RemoveVideo(videoId);
    DP_INFO_LOG("DPS_VIDEO: RemoveVideo to ive, videoId: %{public}s, ret: %{public}d", videoId.c_str(), ret);
}

void VideoPostProcessor::PauseRequest(const std::string& videoId, const SchedulerType& type)
{
    auto session = GetVideoSession();
    DP_CHECK_ERROR_RETURN_LOG(session == nullptr, "video session is nullptr.");

    int32_t ret = session->Interrupt();
    DP_INFO_LOG("DPS_VIDEO: Interrupt video to ive, videoId: %{public}s, ret: %{public}d", videoId.c_str(), ret);
}

DpsError VideoPostProcessor::PrepareStreams(const std::string& videoId, const int inputFd)
{
    auto session = GetVideoSession();
    DP_CHECK_ERROR_RETURN_RET_LOG(session == nullptr, DPS_ERROR_VIDEO_PROC_FAILED, "video session is nullptr.");
    // LCOV_EXCL_START

    allStreamInfo_.clear();
    std::vector<StreamDescription> streamDescs;
    auto ret = session->Prepare(videoId, inputFd, streamDescs);
    DP_INFO_LOG("DPS_VIDEO: Prepare videoId: %{public}s, stream size: %{public}zu, ret: %{public}d",
        videoId.c_str(), streamDescs.size(), ret);

    for (const auto& stream : streamDescs) {
        DP_LOOP_ERROR_RETURN_RET_LOG(!ProcessStream(stream), DPS_ERROR_VIDEO_PROC_FAILED,
            "ProcessStream failed streamType: %{public}d", stream.type);
    }
    DP_CHECK_ERROR_RETURN_RET_LOG(allStreamInfo_.empty(), DPS_ERROR_VIDEO_PROC_FAILED, "allStreamInfo is null.");

    if (EventsInfo::GetInstance().IsCameraOpen()) {
        allStreamInfo_.clear();
        return DPS_ERROR_VIDEO_PROC_INTERRUPTED;
    }
    ret = session->CreateStreams(allStreamInfo_);
    DP_INFO_LOG("DPS_VIDEO: CreateStreams videoId: %{public}s, ret: %{public}d", videoId.c_str(), ret);

    std::vector<uint8_t> modeSetting;
    ret = session->CommitStreams(modeSetting);
    DP_INFO_LOG("DPS_VIDEO: CommitStreams videoId: %{public}s, ret: %{public}d", videoId.c_str(), ret);
    return DPS_NO_ERROR;
    // LCOV_EXCL_STOP
}

// LCOV_EXCL_START
bool VideoPostProcessor::ProcessStream(const StreamDescription& stream)
{
    DP_CHECK_ERROR_RETURN_RET_LOG(mediaManagerProxy_ == nullptr, false, "MediaManager is nullptr.");
    DP_INFO_LOG("DPS_VIDEO: streamId: %{public}d, stream type: %{public}d", stream.streamId, stream.type);
    sptr<Surface> surface = nullptr;
    if (stream.type == HDI::Camera::V1_3::MEDIA_STREAM_TYPE_VIDEO) {
        surface = mediaManagerProxy_->MpegGetSurface();
    } else if (stream.type == HDI::Camera::V1_3::MEDIA_STREAM_TYPE_MAKER) {
        surface = mediaManagerProxy_->MpegGetMakerSurface();
        DP_CHECK_EXECUTE(mediaManagerProxy_, mediaManagerProxy_->MpegSetMarkSize(stream.width * stream.height));
    }
    DP_CHECK_ERROR_RETURN_RET_LOG(surface == nullptr, false, "Surface is nullptr.");

    auto producer = sptr<BufferProducerSequenceable>::MakeSptr(surface->GetProducer());
    DP_CHECK_ERROR_RETURN_RET_LOG(producer == nullptr, false, "BufferProducer is nullptr.");

    SetStreamInfo(stream, producer);
    return true;
}
// LCOV_EXCL_STOP

void VideoPostProcessor::ReleaseStreams()
{
    DP_CHECK_RETURN(allStreamInfo_.empty());

    auto session = GetVideoSession();
    DP_CHECK_ERROR_RETURN_LOG(session == nullptr, "Release streams failed, video session is nullptr.");

    auto ret = session->ReleaseStreams(allStreamInfo_);
    allStreamInfo_.clear();
    DP_INFO_LOG("DPS_VIDEO: ReleaseStreams ret: %{public}d", ret);
}

void VideoPostProcessor::SetStreamInfo(const StreamDescription& stream, sptr<BufferProducerSequenceable>& producer)
{
    StreamInfo_V1_1 streamInfo;
    streamInfo.v1_0.intent_ = GetIntent(stream.type);
    streamInfo.v1_0.tunneledMode_ = true;
    streamInfo.v1_0.streamId_ = stream.streamId;
    streamInfo.v1_0.width_ = stream.width;
    streamInfo.v1_0.height_ = stream.height;
    streamInfo.v1_0.format_ = stream.pixelFormat;
    streamInfo.v1_0.dataspace_ = stream.dataspace;
    streamInfo.v1_0.bufferQueue_ = producer;
    DP_CHECK_ERROR_RETURN_LOG(allStreamInfo_.empty(), "allStreamInfo_ is empty");
    allStreamInfo_.emplace_back(streamInfo);
}

HDI::Camera::V1_0::StreamIntent VideoPostProcessor::GetIntent(HDI::Camera::V1_3::MediaStreamType type)
{
    HDI::Camera::V1_0::StreamIntent intent = HDI::Camera::V1_0::PREVIEW;
    switch (type) {
        case HDI::Camera::V1_3::MEDIA_STREAM_TYPE_MAKER:
            intent = HDI::Camera::V1_0::CUSTOM;
            break;
        case HDI::Camera::V1_3::MEDIA_STREAM_TYPE_VIDEO:
            intent = HDI::Camera::V1_0::VIDEO;
            break;
        default:
            DP_ERR_LOG("unexpected error type: %{public}d.", type);
            break;
    }
    return intent;
}

bool VideoPostProcessor::StartMpeg(const std::string& videoId, const sptr<IPCFileDescriptor>& inputFd)
{
    DP_CHECK_EXECUTE(mediaManagerProxy_ == nullptr,
        mediaManagerProxy_ = MediaManagerProxy::CreateMediaManagerProxy());
    DP_CHECK_ERROR_RETURN_RET_LOG(mediaManagerProxy_ == nullptr, false, "MediaManagerProxy is nullptr.");
    int32_t ret = mediaManagerProxy_->MpegAcquire(videoId, inputFd);
    DP_CHECK_ERROR_RETURN_RET_LOG(ret != DP_OK, false, "MpegAcquire failed");
    DP_DEBUG_LOG("DPS_VIDEO: Acquire MpegManager.");
    return true;
}

bool VideoPostProcessor::StopMpeg(const MediaResult result, const DeferredVideoWorkPtr& work)
{
    DP_CHECK_ERROR_RETURN_RET_LOG(mediaManagerProxy_ == nullptr, false, "mpegManager is nullptr");
    // LCOV_EXCL_START
    auto ret = mediaManagerProxy_->MpegUnInit(static_cast<int32_t>(result));
    if (ret != DP_OK) {
        ReleaseMpeg();
        return false;
    }

    if (result != MediaResult::SUCCESS) {
        ReleaseMpeg();
        return true;
    }

    auto videoId = work->GetDeferredVideoJob()->GetVideoId();
    auto resultFd = mediaManagerProxy_->MpegGetResultFd();
    DP_CHECK_ERROR_RETURN_RET_LOG(resultFd == nullptr, false,
        "Get video fd failed, videoId: %{public}s", videoId.c_str());

    auto tempFd = resultFd->GetFd();
    auto outFd = work->GetDeferredVideoJob()->GetOutputFd()->GetFd();
    DP_INFO_LOG("DPS_VIDEO: Video process done, videoId: %{public}s, tempFd: %{public}d, outFd: %{public}d",
        videoId.c_str(), tempFd, outFd);
    copyFileByFd(tempFd, outFd);
    DP_CHECK_ERROR_RETURN_RET_LOG(IsFileEmpty(outFd), false,
        "Video size is empty, videoId: %{public}s", videoId.c_str());

    ReleaseMpeg();
    return true;
    // LCOV_EXCL_STOP
}

// LCOV_EXCL_START
void VideoPostProcessor::ReleaseMpeg()
{
    DP_CHECK_ERROR_RETURN_LOG(mediaManagerProxy_ == nullptr, "mpegManager is nullptr");
    mediaManagerProxy_->MpegRelease();
    mediaManagerProxy_.reset();
    DP_INFO_LOG("DPS_VIDEO: Release MpegManager.");
}
// LCOV_EXCL_STOP

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
    SetVideoSession(nullptr);
    std::vector<std::string> crashJobs;
    for (const auto& item : runningWork_) {
        crashJobs.emplace_back(item.first);
    }
    for (const auto& videoId : crashJobs) {
        DP_CHECK_EXECUTE(processResult_, processResult_->OnError(videoId, DPS_ERROR_VIDEO_PROC_INTERRUPTED));
    }
    crashJobs.clear();
    OnStateChanged(HdiStatus::HDI_DISCONNECTED);
}

void VideoPostProcessor::OnProcessDone(const std::string& videoId, std::unique_ptr<MediaUserInfo> userInfo)
{
    ReleaseStreams();
    auto work = GetRunningWork(videoId);
    DP_CHECK_ERROR_RETURN_LOG(work == nullptr, "video work is nullptr.");
    // LCOV_EXCL_START
    if (userInfo) {
        DP_CHECK_EXECUTE(mediaManagerProxy_, mediaManagerProxy_->MpegAddUserMeta(std::move(userInfo)));
    }
    auto ret = StopMpeg(MediaResult::SUCCESS, work);
    if (!ret) {
        DP_CHECK_EXECUTE(processResult_, processResult_->OnError(videoId, DPS_ERROR_VIDEO_PROC_FAILED));
        return;
    }

    DP_INFO_LOG("DPS_VIDEO: video process done, videoId: %{public}s", videoId.c_str());
    StopTimer(work);
    if (auto schedulerManager = DPS_GetSchedulerManager()) {
        if (auto videoController = schedulerManager->GetVideoController(userId_)) {
            videoController->HandleSuccess(work);
        }
    }
    // LCOV_EXCL_STOP
}

void VideoPostProcessor::OnError(const std::string& videoId, DpsError errorCode)
{
    ReleaseStreams();
    auto work = GetRunningWork(videoId);
    DP_CHECK_ERROR_RETURN_LOG(work == nullptr, "video work is nullptr.");
    MediaResult resule = errorCode == DPS_ERROR_VIDEO_PROC_INTERRUPTED ? MediaResult::PAUSE : MediaResult::FAIL;
    StopMpeg(resule, work);

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
    EventsMonitor::GetInstance().NotifyVideoEnhanceStatus(hdiStatus);
}

void VideoPostProcessor::OnTimerOut(const std::string& videoId)
{
    DP_INFO_LOG("DpsTimer end, videoId: %{public}s", videoId.c_str());
    DP_CHECK_EXECUTE(processResult_, processResult_->OnError(videoId, DPS_ERROR_VIDEO_PROC_TIMEOUT));
}

void VideoPostProcessor::ConnectService()
{
    auto svcMgr = HDI::ServiceManager::V1_0::IServiceManager::Get();
    DP_CHECK_ERROR_RETURN_LOG(svcMgr == nullptr, "IServiceManager init failed.");

    serviceListener_ = sptr<VideoServiceListener>::MakeSptr(weak_from_this());
    auto ret  = svcMgr->RegisterServiceStatusListener(serviceListener_, DEVICE_CLASS_DEFAULT);
    DP_CHECK_ERROR_RETURN_LOG(ret != 0, "Register Video ServiceStatusListener failed.");
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
    DP_CHECK_ERROR_RETURN_LOG(ret != 0, "Unregister Video ServiceStatusListener failed.");
}

void VideoPostProcessor::OnServiceChange(const HDI::ServiceManager::V1_0::ServiceStatus& status)
{
    DP_CHECK_RETURN(status.serviceName != VIDEO_SERVICE_NAME);
    DP_CHECK_RETURN_LOG(status.status != HDI::ServiceManager::V1_0::SERVIE_STATUS_START,
        "video service state: %{public}d", status.status);
    DP_CHECK_RETURN(GetVideoSession() != nullptr);
    
    auto proxyV1_3 = HDI::Camera::V1_3::IVideoProcessService::Get(status.serviceName);
    DP_CHECK_ERROR_RETURN_LOG(proxyV1_3 == nullptr, "get VideoProcessService failed.");

    uint32_t majorVer = 0;
    uint32_t minorVer = 0;
    proxyV1_3->GetVersion(majorVer, minorVer);
    int32_t versionId = GetVersionId(majorVer, minorVer);
    sptr<IVideoProcessSession> session = nullptr;
    sptr<HDI::Camera::V1_4::IVideoProcessService> proxyV1_4 = nullptr;
    // LCOV_EXCL_START
    if (versionId >= HDI_VERSION_ID_1_4) {
        proxyV1_4 = HDI::Camera::V1_4::IVideoProcessService::CastFrom(proxyV1_3);
    }
    if (proxyV1_4 != nullptr) {
        DP_INFO_LOG("CreateVideoProcessSession_V1_4 version=%{public}d_%{public}d", majorVer, minorVer);
        proxyV1_4->CreateVideoProcessSession_V1_4(userId_, processListener_, session);
    } else if (proxyV1_3 != nullptr) {
        DP_INFO_LOG("CreateVideoProcessSession version=%{public}d_%{public}d", majorVer, minorVer);
        proxyV1_3->CreateVideoProcessSession(userId_, processListener_, session);
    }
    // LCOV_EXCL_STOP
    DP_CHECK_ERROR_RETURN_LOG(session == nullptr, "get VideoProcessSession failed.");

    const sptr<IRemoteObject>& remote = HDI::hdi_objcast<IVideoProcessSession>(session);
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