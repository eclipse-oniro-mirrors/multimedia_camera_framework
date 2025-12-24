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

#include "basic_definitions.h"
#include "dp_log.h"
#include "dps.h"
#include "events_info.h"
#include "events_monitor.h"
#include "hdf_device_class.h"
#include "iproxy_broker.h"
#include "iservmgr_hdi.h"
#include "v1_5/ivideo_process_service.h"
#include "v1_1/types.h"
#include <memory>

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
namespace {
    constexpr char VIDEO_SERVICE_NAME[] = "camera_video_process_service";
}

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

    int32_t OnProcessDone(const std::string& videoId) override;
    int32_t OnProcessDone(const std::string& videoId,
        const sptr<HDI::Camera::V1_0::MapDataSequenceable>& metaData) override;
    int32_t OnError(const std::string& videoId, HDI::Camera::V1_2::ErrorCode errorCode) override;
    int32_t OnStatusChanged(HDI::Camera::V1_2::SessionStatus status) override;

private:
    std::weak_ptr<VideoProcessResult> processResult_;
};
// LCOV_EXCL_START
int32_t VideoPostProcessor::VideoProcessListener::OnProcessDone(const std::string& videoId)
{
    DP_INFO_LOG("DPS_VIDEO: videoId: %{public}s", videoId.c_str());
    auto processResult = processResult_.lock();
    DP_CHECK_ERROR_RETURN_RET_LOG(processResult == nullptr, DP_OK, "VideoProcessResult is nullptr.");

    processResult->OnProcessDone(videoId);
    return DP_OK;
}

int32_t VideoPostProcessor::VideoProcessListener::OnProcessDone(const std::string& videoId,
    const sptr<HDI::Camera::V1_0::MapDataSequenceable>& metaData)
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

int32_t VideoPostProcessor::VideoProcessListener::OnError(const std::string& videoId,
    HDI::Camera::V1_2::ErrorCode errorCode)
{
    HILOG_COMM_INFO("DPS_VIDEO: videoId: %{public}s, error: %{public}d", videoId.c_str(), errorCode);
    auto processResult = processResult_.lock();
    DP_CHECK_ERROR_RETURN_RET_LOG(processResult == nullptr, DP_OK, "VideoProcessResult is nullptr.");

    processResult->OnError(videoId, MapHdiVideoError(errorCode));
    return DP_OK;
}

int32_t VideoPostProcessor::VideoProcessListener::OnStatusChanged(HDI::Camera::V1_2::SessionStatus status)
{
    DP_INFO_LOG("DPS_VIDEO: HdiStatus: %{public}d", status);
    auto processResult = processResult_.lock();
    DP_CHECK_ERROR_RETURN_RET_LOG(processResult == nullptr, DP_OK, "VideoProcessResult is nullptr.");

    processResult->OnStateChanged(MapHdiStatus(status));
    return DP_OK;
}
// LCOV_EXCL_STOP
VideoPostProcessor::VideoPostProcessor(const int32_t userId)
    : userId_(userId), serviceListener_(nullptr), sessionDeathRecipient_(nullptr), processListener_(nullptr)
{
    DP_DEBUG_LOG("entered");
}

VideoPostProcessor::~VideoPostProcessor()
{
    DP_INFO_LOG("entered");
    DisconnectService();
    SetVideoSession(nullptr);
    runningId_.clear();
    removeNeededList_.clear();
}

int32_t VideoPostProcessor::Initialize()
{
    processResult_ = std::make_shared<VideoProcessResult>(userId_);
    sessionDeathRecipient_ = sptr<SessionDeathRecipient>::MakeSptr(processResult_);
    processListener_ = sptr<VideoProcessListener>::MakeSptr(processResult_);
    ConnectService();
    return DP_OK;
}

bool VideoPostProcessor::GetPendingVideos(std::vector<std::string>& pendingVideos)
{
    auto session = GetVideoSession<VideoSessionV1_3>();
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

std::vector<StreamDescription> VideoPostProcessor::PrepareStreams(const DeferredVideoJobPtr& job)
{
    std::vector<StreamDescription> streamDescs;
    auto videoId = job->GetVideoId();
    auto session = GetVideoSession<VideoSessionV1_3>();
    if (session == nullptr) {
        DP_ERR_LOG("Process videoId: %{public}s failed, video session is nullptr", videoId.c_str());
        DP_CHECK_EXECUTE(processResult_, processResult_->OnError(videoId, DPS_ERROR_SESSION_NOT_READY_TEMPORARILY));
        return streamDescs;
    }

    int32_t ret;
    if (job->isMoving()) {
        auto sessionV1_5 = GetVideoSession<VideoSessionV1_5>();
        DP_CHECK_ERROR_RETURN_RET_LOG(sessionV1_5 == nullptr, streamDescs, "video sessionV1_5 is nullptr.");
        std::vector<int> fds = {
            job->GetMovieFd()->GetFd(),
            job->GetMovieCopyFd()->GetFd(),
            job->GetInputFd()->GetFd()
        };
        ret = sessionV1_5->Prepare(videoId, fds, streamDescs);
    } else {
        ret = session->Prepare(videoId, job->GetInputFd()->GetFd(), streamDescs);
    }
    DP_INFO_LOG("DPS_VIDEO: PrepareStreams videoId: %{public}s, stream size: %{public}zu, ret: %{public}d",
        videoId.c_str(), streamDescs.size(), ret);
    return streamDescs;
}

void VideoPostProcessor::ProcessRequest(const std::string& videoId, const std::vector<StreamDescription>& streams,
    const std::shared_ptr<MediaManagerIntf>& mediaManagerIntf)
{
    if (mediaManagerIntf == nullptr) {
        DP_ERR_LOG("Process videoId: %{public}s failed, mpegManage is nullptr", videoId.c_str());
        DP_CHECK_EXECUTE(processResult_, processResult_->OnError(videoId, DPS_ERROR_VIDEO_PROC_FAILED));
        return;
    }
    auto session = GetVideoSession<VideoSessionV1_3>();
    if (session == nullptr) {
        DP_ERR_LOG("Process videoId: %{public}s failed, video session is nullptr", videoId.c_str());
        DP_CHECK_EXECUTE(processResult_, processResult_->OnError(videoId, DPS_ERROR_SESSION_NOT_READY_TEMPORARILY));
        return;
    }
    streamInfo_ = std::make_unique<VideoStreamInfo>(videoId);
    for (const auto& stream : streams) {
        ProcessStream(stream, mediaManagerIntf);
    }
    if (streamInfo_->infos_.empty()) {
        DP_ERR_LOG("Process videoId: %{public}s failed, allStreamInfo is null", videoId.c_str());
        DP_CHECK_EXECUTE(processResult_, processResult_->OnError(videoId, DPS_ERROR_VIDEO_PROC_FAILED));
        return;
    }
    DP_CHECK_EXECUTE_AND_RETURN(EventsInfo::GetInstance().IsCameraOpen(),
        DP_CHECK_EXECUTE(processResult_, processResult_->OnError(videoId, DPS_ERROR_VIDEO_PROC_INTERRUPTED)));

    auto ret = session->CreateStreams(streamInfo_->infos_);
    DP_INFO_LOG("DPS_VIDEO: CreateStreams videoId: %{public}s, ret: %{public}d", videoId.c_str(), ret);
    if (ret != HDF_SUCCESS) {
        DP_CHECK_EXECUTE(processResult_, processResult_->OnError(videoId, DPS_ERROR_VIDEO_PROC_INTERRUPTED));
        return;
    }
    std::vector<uint8_t> modeSetting;
    ret = session->CommitStreams(modeSetting);
    DP_INFO_LOG("DPS_VIDEO: CommitStreams videoId: %{public}s, ret: %{public}d", videoId.c_str(), ret);
    if (ret != HDF_SUCCESS) {
        DP_CHECK_EXECUTE(processResult_, processResult_->OnError(videoId, DPS_ERROR_VIDEO_PROC_INTERRUPTED));
        return;
    }
    auto startTime = mediaManagerIntf->MpegGetProcessTimeStamp();
    ret = session->ProcessVideo(videoId, startTime);
    HILOG_COMM_INFO("DPS_VIDEO: Process video to ive, videoId: %{public}s, startTime: %{public}" PRIu64
        ", ret: %{public}d", videoId.c_str(), startTime, ret);
    if (ret != HDF_SUCCESS) {
        DP_CHECK_EXECUTE(processResult_, processResult_->OnError(videoId, DPS_ERROR_VIDEO_PROC_INTERRUPTED));
        return;
    }
    runningId_.emplace(videoId);
}

void VideoPostProcessor::RemoveRequest(const std::string& videoId)
{
    runningId_.erase(videoId);
    auto session = GetVideoSession<VideoSessionV1_3>();
    if (session == nullptr) {
        DP_ERR_LOG("video session is nullptr.");
        std::lock_guard<std::mutex> lock(removeMutex_);
        removeNeededList_.emplace_back(videoId);
        return;
    }
    std::string path = PATH + videoId + OUT_TAG;
    DP_CHECK_ERROR_PRINT_LOG(remove(path.c_str()) != 0, "Failed to remove file at path: %{private}s", path.c_str());
    auto ret = session->RemoveVideo(videoId);
    DP_INFO_LOG("DPS_VIDEO: Remove video to ive, videoId: %{public}s, ret: %{public}d", videoId.c_str(), ret);
}

void VideoPostProcessor::PauseRequest(const std::string& videoId, const SchedulerType& type)
{
    auto session = GetVideoSession<VideoSessionV1_3>();
    DP_CHECK_ERROR_RETURN_LOG(session == nullptr, "video session is nullptr.");

    int32_t ret = session->Interrupt();
    HILOG_COMM_INFO("DPS_VIDEO: Interrupt video to ive, videoId: %{public}s, ret: %{public}d", videoId.c_str(), ret);
}

bool VideoPostProcessor::ProcessStream(const StreamDescription& stream,
    const std::shared_ptr<MediaManagerIntf>& mediaManagerIntf)
{
    DP_CHECK_ERROR_RETURN_RET_LOG(mediaManagerIntf == nullptr, false, "MpegManager is nullptr.");
    DP_INFO_LOG("DPS_VIDEO: streamId: %{public}d, stream type: %{public}d", stream.streamId, stream.type);
    sptr<Surface> surface = nullptr;
    if (stream.type == HDI::Camera::V1_3::MEDIA_STREAM_TYPE_VIDEO) {
        surface = mediaManagerIntf->MpegGetSurface();
    } else if (stream.type == HDI::Camera::V1_3::MEDIA_STREAM_TYPE_MAKER) {
        surface = mediaManagerIntf->MpegGetMakerSurface();
    }
    DP_CHECK_ERROR_RETURN_RET_LOG(surface == nullptr, false, "Surface is nullptr.");

    auto producer = sptr<BufferProducerSequenceable>::MakeSptr(surface->GetProducer());
    DP_CHECK_ERROR_RETURN_RET_LOG(producer == nullptr, false, "BufferProducer is nullptr.");

    SetStreamInfo(stream, producer);
    return true;
}

void VideoPostProcessor::ReleaseStreams(const std::string& videoId)
{
    DP_CHECK_RETURN(streamInfo_ == nullptr || streamInfo_->infos_.empty());
    DP_CHECK_ERROR_RETURN_LOG(streamInfo_->videoId_ != videoId,
        "running videoId: %{public}s, release videoId: %{public}s", streamInfo_->videoId_.c_str(), videoId.c_str());

    auto session = GetVideoSession<VideoSessionV1_3>();
    DP_CHECK_ERROR_RETURN_LOG(session == nullptr, "Release streams failed, video session is nullptr.");

    auto ret = session->ReleaseStreams(streamInfo_->infos_);
    HILOG_COMM_INFO("DPS_VIDEO: ReleaseStreams ret: %{public}d", ret);
    streamInfo_.reset();
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
    DP_CHECK_ERROR_RETURN_LOG(streamInfo_ == nullptr, "streamInfo_ is nullptr");
    streamInfo_->infos_.emplace_back(streamInfo);
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

void VideoPostProcessor::OnSessionDied()
{
    SetVideoSession(nullptr);
    for (auto id : runningId_) {
        DP_CHECK_EXECUTE(processResult_, processResult_->OnError(id, DPS_ERROR_SESSION_NOT_READY_TEMPORARILY));
    }
    OnStateChanged(HdiStatus::HDI_DISCONNECTED);
}

void VideoPostProcessor::OnStateChanged(HdiStatus hdiStatus)
{
    EventsMonitor::GetInstance().NotifyVideoEnhanceStatus(hdiStatus);
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
    auto session = GetVideoSession<VideoSessionV1_3>();
    DP_CHECK_ERROR_RETURN_LOG(session == nullptr, "video session is nullptr.");
    auto remote = HDI::hdi_objcast<VideoSessionV1_3>(session);
    DP_CHECK_ERROR_RETURN_LOG(remote == nullptr, "IRemoteObject is nullptr.");
    bool result = remote->RemoveDeathRecipient(sessionDeathRecipient_);
    DP_CHECK_ERROR_RETURN_LOG(!result, "remove DeathRecipient for VideoProcessSession failed.");

    auto svcMgr = HDI::ServiceManager::V1_0::IServiceManager::Get();
    DP_CHECK_ERROR_RETURN_LOG(svcMgr == nullptr, "IServiceManager init failed.");

    auto ret  = svcMgr->UnregisterServiceStatusListener(serviceListener_);
    DP_CHECK_ERROR_RETURN_LOG(ret != 0, "Unregister Video ServiceStatusListener failed.");
}

void VideoPostProcessor::OnServiceChange(const HDI::ServiceManager::V1_0::ServiceStatus& status)
{
    // LCOV_EXCL_START
    DP_CHECK_RETURN(status.serviceName != VIDEO_SERVICE_NAME);
    DP_CHECK_RETURN_LOG(status.status != HDI::ServiceManager::V1_0::SERVIE_STATUS_START,
        "video service state: %{public}d", status.status);
    DP_CHECK_RETURN(GetVideoSession<VideoSessionV1_3>() != nullptr);

    auto proxyV1_3 = HDI::Camera::V1_3::IVideoProcessService::Get(status.serviceName);
    DP_CHECK_ERROR_RETURN_LOG(proxyV1_3 == nullptr, "get VideoProcessService failed.");

    uint32_t majorVer = 0;
    uint32_t minorVer = 0;
    proxyV1_3->GetVersion(majorVer, minorVer);
    int32_t versionId = GetVersionId(majorVer, minorVer);

    sptr<VideoSessionV1_3> sessionV1_3;
    sptr<VideoSessionV1_5> sessionV1_5;
    sptr<HDI::Camera::V1_5::IVideoProcessService> proxyV1_4;
    sptr<HDI::Camera::V1_5::IVideoProcessService> proxyV1_5;
    if (versionId >= HDI_VERSION_ID_1_5) {
        proxyV1_5 = HDI::Camera::V1_5::IVideoProcessService::CastFrom(proxyV1_3);
    } else if (versionId >= HDI_VERSION_ID_1_4) {
        proxyV1_4 = HDI::Camera::V1_5::IVideoProcessService::CastFrom(proxyV1_3);
    }

    if (proxyV1_5 != nullptr) {
        DP_INFO_LOG("CreateVideoProcessSession_V1_5 version=%{public}d_%{public}d", majorVer, minorVer);
        proxyV1_5->CreateVideoProcessSession_V1_5(userId_, processListener_, sessionV1_5);
        sessionV1_3 = sessionV1_5.GetRefPtr();
    } else if (proxyV1_4 != nullptr) {
        DP_INFO_LOG("CreateVideoProcessSession_V1_4 version=%{public}d_%{public}d", majorVer, minorVer);
        proxyV1_4->CreateVideoProcessSession_V1_4(userId_, processListener_, sessionV1_3);
    } else if (proxyV1_3 != nullptr) {
        DP_INFO_LOG("CreateVideoProcessSession version=%{public}d_%{public}d", majorVer, minorVer);
        proxyV1_3->CreateVideoProcessSession(userId_, processListener_, sessionV1_3);
    }
    DP_CHECK_ERROR_RETURN_LOG(sessionV1_3 == nullptr, "get VideoProcessSession failed.");

    const sptr<IRemoteObject>& remote = HDI::hdi_objcast<VideoSessionV1_3>(sessionV1_3);
    bool result = remote->AddDeathRecipient(sessionDeathRecipient_);
    DP_CHECK_ERROR_RETURN_LOG(!result, "add DeathRecipient for VideoProcessSession failed.");

    SetVideoSession(sessionV1_3);
    OnStateChanged(HdiStatus::HDI_READY);
    // LCOV_EXCL_STOP
}

void VideoPostProcessor::RemoveNeedJbo(const sptr<VideoSessionV1_3>& session)
{
    std::lock_guard<std::mutex> lock(removeMutex_);
    for (const auto& videoId : removeNeededList_) {
        int32_t ret = session->RemoveVideo(videoId);
        DP_INFO_LOG("DPS_PHOTO: RemoveVideo videoId: %{public}s, ret: %{public}d", videoId.c_str(), ret);
    }
    removeNeededList_.clear();
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS