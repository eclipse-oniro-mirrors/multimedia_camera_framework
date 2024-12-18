/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "session_coordinator.h"
#include <mutex>

#include "dp_log.h"
#include "buffer_info.h"
#include "dps_event_report.h"
#include "steady_clock.h"
#include "picture.h"
#include "video_session_info.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
ErrorCode MapDpsErrorCode(DpsError errorCode)
{
    ErrorCode code = ErrorCode::ERROR_IMAGE_PROC_ABNORMAL;
    switch (errorCode) {
        case DpsError::DPS_ERROR_SESSION_SYNC_NEEDED:
            code = ErrorCode::ERROR_SESSION_SYNC_NEEDED;
            break;
        case DpsError::DPS_ERROR_SESSION_NOT_READY_TEMPORARILY:
            code = ErrorCode::ERROR_SESSION_NOT_READY_TEMPORARILY;
            break;
        case DpsError::DPS_ERROR_IMAGE_PROC_INVALID_PHOTO_ID:
            code = ErrorCode::ERROR_IMAGE_PROC_INVALID_PHOTO_ID;
            break;
        case DpsError::DPS_ERROR_IMAGE_PROC_FAILED:
            code = ErrorCode::ERROR_IMAGE_PROC_FAILED;
            break;
        case DpsError::DPS_ERROR_IMAGE_PROC_TIMEOUT:
            code = ErrorCode::ERROR_IMAGE_PROC_TIMEOUT;
            break;
        case DpsError::DPS_ERROR_IMAGE_PROC_ABNORMAL:
            code = ErrorCode::ERROR_IMAGE_PROC_ABNORMAL;
            break;
        case DpsError::DPS_ERROR_IMAGE_PROC_INTERRUPTED:
            code = ErrorCode::ERROR_IMAGE_PROC_INTERRUPTED;
            break;
        case DpsError::DPS_ERROR_VIDEO_PROC_INVALID_VIDEO_ID:
            code = ErrorCode::ERROR_VIDEO_PROC_INVALID_VIDEO_ID;
            break;
        case DpsError::DPS_ERROR_VIDEO_PROC_FAILED:
            code = ErrorCode::ERROR_VIDEO_PROC_FAILED;
            break;
        case DpsError::DPS_ERROR_VIDEO_PROC_TIMEOUT:
            code = ErrorCode::ERROR_VIDEO_PROC_TIMEOUT;
            break;
        case DpsError::DPS_ERROR_VIDEO_PROC_INTERRUPTED:
            code = ErrorCode::ERROR_VIDEO_PROC_INTERRUPTED;
            break;
        default:
            DP_WARNING_LOG("unexpected error code: %{public}d", errorCode);
            break;
    }
    return code;
}

StatusCode MapDpsStatus(DpsStatus statusCode)
{
    StatusCode code = StatusCode::SESSION_STATE_IDLE;
    switch (statusCode) {
        case DpsStatus::DPS_SESSION_STATE_IDLE:
            code = StatusCode::SESSION_STATE_IDLE;
            break;
        case DpsStatus::DPS_SESSION_STATE_RUNNALBE:
            code = StatusCode::SESSION_STATE_RUNNALBE;
            break;
        case DpsStatus::DPS_SESSION_STATE_RUNNING:
            code = StatusCode::SESSION_STATE_RUNNING;
            break;
        case DpsStatus::DPS_SESSION_STATE_SUSPENDED:
            code = StatusCode::SESSION_STATE_SUSPENDED;
            break;
        default:
            DP_WARNING_LOG("unexpected error code: %{public}d", statusCode);
            break;
    }
    return code;
}

class SessionCoordinator::ImageProcCallbacks : public IImageProcessCallbacks {
public:
    explicit ImageProcCallbacks(const std::weak_ptr<SessionCoordinator>& coordinator) : coordinator_(coordinator)
    {
        DP_DEBUG_LOG("entered.");
    }

    ~ImageProcCallbacks() = default;

    void OnProcessDone(const int32_t userId, const std::string& imageId,
        const std::shared_ptr<BufferInfo>& bufferInfo) override
    {
        DP_CHECK_ERROR_RETURN_LOG(bufferInfo == nullptr, "bufferInfo is nullptr.");
        sptr<IPCFileDescriptor> ipcFd = bufferInfo->GetIPCFileDescriptor();
        int32_t dataSize = bufferInfo->GetDataSize();
        bool isCloudImageEnhanceSupported = bufferInfo->IsCloudImageEnhanceSupported();
        if (auto coordinator = coordinator_.lock()) {
            coordinator->OnProcessDone(userId, imageId, ipcFd, dataSize, isCloudImageEnhanceSupported);
        }
    }

    void OnProcessDoneExt(int userId, const std::string& imageId,
        const std::shared_ptr<BufferInfoExt>& bufferInfo) override
    {
        DP_CHECK_ERROR_RETURN_LOG(bufferInfo == nullptr, "bufferInfo is nullptr.");
        bool isCloudImageEnhanceSupported = bufferInfo->IsCloudImageEnhanceSupported();
        if (auto coordinator = coordinator_.lock()) {
            coordinator->OnProcessDoneExt(userId, imageId,
                bufferInfo->GetPicture(), isCloudImageEnhanceSupported);
        }
    }

    void OnError(const int userId, const std::string& imageId, DpsError errorCode) override
    {
        if (auto coordinator = coordinator_.lock()) {
            coordinator->OnError(userId, imageId, errorCode);
        }
    }

    void OnStateChanged(const int32_t userId, DpsStatus statusCode) override
    {
        if (auto coordinator = coordinator_.lock()) {
            coordinator->OnStateChanged(userId, statusCode);
        }
    }

private:
    std::weak_ptr<SessionCoordinator> coordinator_;
};

class SessionCoordinator::VideoProcCallbacks : public IVideoProcessCallbacks {
public:
    explicit VideoProcCallbacks(const std::weak_ptr<SessionCoordinator>& coordinator) : coordinator_(coordinator)
    {
    }

    ~VideoProcCallbacks() = default;

    void OnProcessDone(const int32_t userId, const std::string& videoId,
        const sptr<IPCFileDescriptor>& ipcFd) override
    {
        auto video = coordinator_.lock();
        DP_CHECK_ERROR_RETURN_LOG(video == nullptr, "SessionCoordinator is nullptr.");
        video->OnVideoProcessDone(userId, videoId, ipcFd);
    }

    void OnError(const int32_t userId, const std::string& videoId, DpsError errorCode) override
    {
        auto video = coordinator_.lock();
        DP_CHECK_ERROR_RETURN_LOG(video == nullptr, "SessionCoordinator is nullptr.");
        video->OnVideoError(userId, videoId, errorCode);
    }

    void OnStateChanged(const int32_t userId, DpsStatus statusCode) override
    {
        auto video = coordinator_.lock();
        DP_CHECK_ERROR_RETURN_LOG(video == nullptr, "SessionCoordinator is nullptr.");
        video->OnStateChanged(userId, statusCode);
    }

private:
    std::weak_ptr<SessionCoordinator> coordinator_;
};

SessionCoordinator::SessionCoordinator()
{
    DP_DEBUG_LOG("entered.");
}

SessionCoordinator::~SessionCoordinator()
{
    DP_DEBUG_LOG("entered.");
    photoCallbackMap_.clear();
    pendingImageResults_.clear();
    videoCallbackMap_.clear();
    pendingRequestResults_.clear();
}

void SessionCoordinator::Initialize()
{
    imageProcCallbacks_ = std::make_shared<ImageProcCallbacks>(weak_from_this());
    videoProcCallbacks_ = std::make_shared<VideoProcCallbacks>(weak_from_this());
}

void SessionCoordinator::Start()
{
    //dps_log
}

void SessionCoordinator::Stop()
{
    //dps_log
}

std::shared_ptr<IImageProcessCallbacks> SessionCoordinator::GetImageProcCallbacks()
{
    return imageProcCallbacks_;
}

std::shared_ptr<IVideoProcessCallbacks> SessionCoordinator::GetVideoProcCallbacks()
{
    return videoProcCallbacks_;
}

void SessionCoordinator::AddPhotoSession(const sptr<PhotoSessionInfo>& sessionInfo)
{
    int32_t userId = sessionInfo->GetUserId();
    DP_INFO_LOG("Add photo session userId: %{public}d", userId);
    auto callback = sessionInfo->GetRemoteCallback();
    if (callback != nullptr) {
        photoCallbackMap_[userId] = callback;
    }
}

void SessionCoordinator::DeletePhotoSession(const int32_t userId)
{
    if (photoCallbackMap_.find(userId) != photoCallbackMap_.end()) {
        DP_INFO_LOG("Delete photo session userId: %{public}d", userId);
        photoCallbackMap_.erase(userId);
    }
}

void SessionCoordinator::OnProcessDone(const int32_t userId, const std::string& imageId,
    const sptr<IPCFileDescriptor>& ipcFd, const int32_t dataSize, bool isCloudImageEnhanceSupported)
{
    DP_INFO_LOG("DPS_OHOTO: userId: %{public}d, imageId: %{public}s, map size: %{public}d.",
        userId, imageId.c_str(), static_cast<int32_t>(photoCallbackMap_.size()));
    auto callback = GetRemoteImageCallback(userId);
    if (callback != nullptr) {
        callback->OnProcessImageDone(imageId, ipcFd, dataSize, isCloudImageEnhanceSupported);
    } else {
        DP_INFO_LOG("callback is null, cache request imageId: %{public}s.", imageId.c_str());
        pendingImageResults_.push_back({ CallbackType::ON_PROCESS_DONE, userId, imageId, ipcFd, dataSize,
            DpsError::DPS_ERROR_SESSION_SYNC_NEEDED, DpsStatus::DPS_SESSION_STATE_IDLE, isCloudImageEnhanceSupported });
    }
}

void SessionCoordinator::OnProcessDoneExt(int userId, const std::string& imageId,
    std::shared_ptr<Media::Picture> picture, bool isCloudImageEnhanceSupported)
{
    DP_INFO_LOG("DPS_OHOTO: userId: %{public}d, imageId: %{public}s, map size: %{public}d.",
        userId, imageId.c_str(), static_cast<int32_t>(photoCallbackMap_.size()));
    auto callback = GetRemoteImageCallback(userId);
    if (callback != nullptr) {
        DP_INFO_LOG("entered, imageId: %s", imageId.c_str());
        callback->OnProcessImageDone(imageId, picture, isCloudImageEnhanceSupported);
    } else {
        DP_INFO_LOG("callback is null, cache request imageId: %{public}s.", imageId.c_str());
    }
}

void SessionCoordinator::OnError(const int userId, const std::string& imageId, DpsError errorCode)
{
    DP_INFO_LOG("DPS_OHOTO: userId: %{public}d, imageId: %{public}s, map size: %{public}d.",
        userId, imageId.c_str(), static_cast<int32_t>(photoCallbackMap_.size()));
    auto callback = GetRemoteImageCallback(userId);
    if (callback != nullptr) {
        callback->OnError(imageId, MapDpsErrorCode(errorCode));
    } else {
        DP_INFO_LOG("callback is null, cache request imageId: %{public}s, errorCode: %{public}d.",
            imageId.c_str(), errorCode);
        pendingImageResults_.push_back({ CallbackType::ON_ERROR, userId, imageId, nullptr, 0, errorCode });
    }
}

void SessionCoordinator::OnStateChanged(const int32_t userId, DpsStatus statusCode)
{
    DP_INFO_LOG("DPS_OHOTO: userId: %{public}d, map size: %{public}d.",
        userId, static_cast<int32_t>(photoCallbackMap_.size()));
    sptr<IDeferredPhotoProcessingSessionCallback> spCallback = GetRemoteImageCallback(userId);
    if (spCallback != nullptr) {
        spCallback->OnStateChanged(MapDpsStatus(statusCode));
    } else {
        DP_INFO_LOG("callback is null, cache request statusCode: %{public}d.", statusCode);
        pendingImageResults_.push_back({CallbackType::ON_STATE_CHANGED, userId, "", nullptr, 0,
            DpsError::DPS_ERROR_IMAGE_PROC_ABNORMAL, statusCode});
    }
}

void SessionCoordinator::ProcessPendingResults(sptr<IDeferredPhotoProcessingSessionCallback> callback)
{
    DP_INFO_LOG("entered.");
    while (!pendingImageResults_.empty()) {
        auto result = pendingImageResults_.front();
        if (result.callbackType == CallbackType::ON_PROCESS_DONE) {
            callback->OnProcessImageDone(result.imageId, result.ipcFd, result.dataSize,
                result.isCloudImageEnhanceSupported);
            uint64_t endTime = SteadyClock::GetTimestampMilli();
            DPSEventReport::GetInstance().ReportImageProcessResult(result.imageId, result.userId, endTime);
        }
        if (result.callbackType == CallbackType::ON_ERROR) {
            callback->OnError(result.imageId, MapDpsErrorCode(result.errorCode));
        }
        if (result.callbackType == CallbackType::ON_STATE_CHANGED) {
            callback->OnStateChanged(MapDpsStatus(result.statusCode));
        }
        pendingImageResults_.pop_front();
    }
}

void SessionCoordinator::AddVideoSession(const sptr<VideoSessionInfo>& sessionInfo)
{
    int32_t userId = sessionInfo->GetUserId();
    DP_INFO_LOG("Add vidoe session userId: %{public}d", userId);
    auto callback = sessionInfo->GetRemoteCallback();
    if (callback != nullptr) {
        videoCallbackMap_[userId] = callback;
    }
}

void SessionCoordinator::DeleteVideoSession(const int32_t userId)
{
    if (videoCallbackMap_.erase(userId) > 0) {
        DP_INFO_LOG("Delete VideoSession userId: %{public}d", userId);
    }
}

void SessionCoordinator::OnVideoProcessDone(const int32_t userId, const std::string& videoId,
    const sptr<IPCFileDescriptor> &ipcFd)
{
    DP_INFO_LOG("DPS_VIDEO: userId: %{public}d, userMap size: %{public}d",
        userId, static_cast<int32_t>(videoCallbackMap_.size()));
    auto callback = GetRemoteVideoCallback(userId);
    if (callback != nullptr) {
        callback->OnProcessVideoDone(videoId, ipcFd);
    } else {
        DP_INFO_LOG("callback is null, videoId: %{public}s.", videoId.c_str());
    }
}

void SessionCoordinator::OnVideoError(const int32_t userId, const std::string& videoId, DpsError errorCode)
{
    DP_INFO_LOG("DPS_VIDEO: userId: %{public}d, userMap: %{public}d, videoId: %{public}s, error: %{public}d",
        userId, static_cast<int32_t>(videoCallbackMap_.size()), videoId.c_str(), errorCode);
    auto callback = GetRemoteVideoCallback(userId);
    if (callback != nullptr) {
        callback->OnError(videoId, MapDpsErrorCode(errorCode));
    } else {
        DP_INFO_LOG("callback is null, videoId: %{public}s, errorCode: %{public}d", videoId.c_str(), errorCode);
    }
}

void SessionCoordinator::OnVideoStateChanged(const int32_t userId, DpsStatus statusCode)
{
    DP_DEBUG_LOG("entered.");
}

void SessionCoordinator::ProcessVideoResults(sptr<IDeferredVideoProcessingSessionCallback> callback)
{
    DP_DEBUG_LOG("entered.");
    while (!pendingRequestResults_.empty()) {
        auto result = pendingRequestResults_.front();
        if (result.callbackType == CallbackType::ON_PROCESS_DONE) {
            callback->OnProcessVideoDone(result.requestId, result.ipcFd);
        }
        if (result.callbackType == CallbackType::ON_ERROR) {
            callback->OnError(result.requestId, MapDpsErrorCode(result.errorCode));
        }
        if (result.callbackType == CallbackType::ON_STATE_CHANGED) {
            callback->OnStateChanged(MapDpsStatus(result.statusCode));
        }
        pendingRequestResults_.pop_front();
    }
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS