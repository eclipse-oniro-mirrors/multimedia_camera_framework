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
#include <vector>
#include <shared_mutex>
#include <iostream>
#include "dp_log.h"
#include "session_coordinator.h"
#include "iimage_process_callbacks.h"
#include "buffer_info.h"
#include "dps_event_report.h"
#include "steady_clock.h"

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
        default:
            DP_WARNING_LOG("unexpected error code: %d.", errorCode);
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
            DP_WARNING_LOG("unexpected error code: %d.", statusCode);
            break;
    }
    return code;
}

class SessionCoordinator::ImageProcCallbacks : public IImageProcessCallbacks {
public:
    explicit ImageProcCallbacks(SessionCoordinator* coordinator) : coordinator_(coordinator)
    {
    }

    ~ImageProcCallbacks() override
    {
        coordinator_ = nullptr;
    }

    void OnProcessDone(const int userId, const std::string& imageId,
        const std::shared_ptr<BufferInfo> bufferInfo) override
    {
        sptr<IPCFileDescriptor> ipcFd = bufferInfo->GetIPCFileDescriptor();
        long dataSize = bufferInfo->GetDataSize();
        if (coordinator_) {
            coordinator_->OnProcessDone(userId, imageId, ipcFd, dataSize);
        }
    }

    void OnError(int userId, const std::string& imageId, DpsError errorCode) override
    {
        if (coordinator_) {
            coordinator_->OnError(userId, imageId, errorCode);
        }
    }

    void OnStateChanged(int userId, DpsStatus statusCode) override
    {
        if (coordinator_) {
            coordinator_->OnStateChanged(userId, statusCode);
        }
    }

private:
    SessionCoordinator* coordinator_;
};

SessionCoordinator::SessionCoordinator()
    : imageProcCallbacks_(nullptr),
      remoteImageCallbacksMap_(),
      pendingImageResults_()
{
    DP_DEBUG_LOG("entered.");
}

SessionCoordinator::~SessionCoordinator()
{
    DP_DEBUG_LOG("entered.");
}

void SessionCoordinator::Initialize()
{
    imageProcCallbacks_ = std::make_shared<ImageProcCallbacks>(this);
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

void SessionCoordinator::OnProcessDone(int userId, const std::string& imageId,
    sptr<IPCFileDescriptor> ipcFd, long dataSize)
{
    auto iter = remoteImageCallbacksMap_.find(userId);
    if (iter != remoteImageCallbacksMap_.end()) {
        auto wpCallback = iter->second;
        sptr<IDeferredPhotoProcessingSessionCallback> spCallback = wpCallback.promote();
        DP_INFO_LOG("entered, imageId: %s", imageId.c_str());
        spCallback->OnProcessImageDone(imageId, ipcFd, dataSize);
    } else {
        DP_INFO_LOG("callback is null, cache request, imageId: %s.", imageId.c_str());
        pendingImageResults_.push_back({CallbackType::ON_PROCESS_DONE, userId, imageId, ipcFd, dataSize});
    }
    return;
}

void SessionCoordinator::OnError(int userId, const std::string& imageId, DpsError errorCode)
{
    auto iter = remoteImageCallbacksMap_.find(userId);
    if (iter != remoteImageCallbacksMap_.end()) {
        auto wpCallback = iter->second;
        sptr<IDeferredPhotoProcessingSessionCallback> spCallback = wpCallback.promote();
        DP_INFO_LOG("entered, userId: %d", userId);
        spCallback->OnError(imageId, MapDpsErrorCode(errorCode));
    } else {
        DP_INFO_LOG("callback is null, cache request, imageId: %s, errorCode: %d.", imageId.c_str(), errorCode);
        pendingImageResults_.push_back({CallbackType::ON_ERROR, userId, imageId, nullptr, 0, errorCode});
    }
}

void SessionCoordinator::OnStateChanged(int userId, DpsStatus statusCode)
{
    auto iter = remoteImageCallbacksMap_.find(userId);
    if (iter != remoteImageCallbacksMap_.end()) {
        auto wpCallback = iter->second;
        sptr<IDeferredPhotoProcessingSessionCallback> spCallback = wpCallback.promote();
        DP_INFO_LOG("entered, userId: %d", userId);
        spCallback->OnStateChanged(MapDpsStatus(statusCode));
    } else {
        DP_INFO_LOG("cache request, statusCode: %d.", statusCode);
        pendingImageResults_.push_back({CallbackType::ON_STATE_CHANGED, userId, "", nullptr, 0,
            DpsError::DPS_ERROR_IMAGE_PROC_ABNORMAL, statusCode});
    }
}

void SessionCoordinator::NotifySessionCreated(int userId, sptr<IDeferredPhotoProcessingSessionCallback> callback)
{
    if (callback) {
        remoteImageCallbacksMap_[userId] = callback;
        ProcessPendingResults(callback);
    }
}

void SessionCoordinator::ProcessPendingResults(sptr<IDeferredPhotoProcessingSessionCallback> callback)
{
    DP_INFO_LOG("entered.");
    while (!pendingImageResults_.empty()) {
        auto result = pendingImageResults_.front();
        if (result.callbackType == CallbackType::ON_PROCESS_DONE) {
            callback->OnProcessImageDone(result.imageId, result.ipcFd, result.dataSize);
            uint64_t endTime = SteadyClock::GetTimestampMilli();
            DPSEventReport::GetInstance()
                    .ReportImageProcessResult(result.imageId, result.userId, endTime);
        }
        if (result.callbackType == CallbackType::ON_ERROR) {
            callback->OnError(result.imageId, MapDpsErrorCode(result.errorCode));
        }
        if (result.callbackType == CallbackType::ON_STATE_CHANGED) {
            callback->OnStateChanged(MapDpsStatus(result.statusCode));
        }
        pendingImageResults_.pop_back();
    }
}

void SessionCoordinator::NotifyCallbackDestroyed(int userId)
{
    if (remoteImageCallbacksMap_.count(userId) != 0) {
        DP_INFO_LOG("session userId: %d destroyed.", userId);
        remoteImageCallbacksMap_.erase(userId);
    }
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS