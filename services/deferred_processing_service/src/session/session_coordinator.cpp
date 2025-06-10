/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include "dp_log.h"
#include "dps_event_report.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
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
    videoCallbackMap_.clear();
    pendingRequestResults_.clear();
}

int32_t SessionCoordinator::Initialize()
{
    videoProcCallbacks_ = std::make_shared<VideoProcCallbacks>(weak_from_this());
    return DP_OK;
}

void SessionCoordinator::Start()
{
    //dps_log
}

void SessionCoordinator::Stop()
{
    //dps_log
}

std::shared_ptr<IVideoProcessCallbacks> SessionCoordinator::GetVideoProcCallbacks()
{
    return videoProcCallbacks_;
}

void SessionCoordinator::OnStateChanged(const int32_t userId, DpsStatus statusCode)
{
    DP_INFO_LOG("DPS_OHOTO: userId: %{public}d, statusCode: %{public}d", userId, statusCode);
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
    DP_INFO_LOG("DPS_VIDEO: userId: %{public}d, userMap size: %{public}zu", userId, videoCallbackMap_.size());
    auto callback = GetRemoteVideoCallback(userId);
    if (callback != nullptr) {
        callback->OnProcessVideoDone(videoId, ipcFd);
    } else {
        DP_INFO_LOG("callback is null, videoId: %{public}s.", videoId.c_str());
    }
}

void SessionCoordinator::OnVideoError(const int32_t userId, const std::string& videoId, DpsError errorCode)
{
    DP_INFO_LOG("DPS_VIDEO: userId: %{public}d, userMap: %{public}zu, videoId: %{public}s, error: %{public}d",
        userId, videoCallbackMap_.size(), videoId.c_str(), errorCode);
    auto callback = GetRemoteVideoCallback(userId);
    if (callback != nullptr) {
        callback->OnError(videoId, static_cast<int32_t>(MapDpsErrorCode(errorCode)));
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
            callback->OnError(result.requestId, static_cast<int32_t>(MapDpsErrorCode(result.errorCode)));
        }
        if (result.callbackType == CallbackType::ON_STATE_CHANGED) {
            callback->OnStateChanged(static_cast<int32_t>(MapDpsStatus(result.statusCode)));
        }
        pendingRequestResults_.pop_front();
    }
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS