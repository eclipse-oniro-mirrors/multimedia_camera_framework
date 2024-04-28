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
#include <refbase.h>

#include "deferred_photo_job.h"
#include "photo_post_processor.h"
#include "iproxy_broker.h"
#include "dp_utils.h"
#include "dp_log.h"
#include "basic_definitions.h"
#include "events_monitor.h"
#include "dps_event_report.h"
#include "steady_clock.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
constexpr uint32_t MAX_CONSECUTIVE_TIMEOUT_COUNT = 3;

DpsError MapHdiError(OHOS::HDI::Camera::V1_2::ErrorCode errorCode)
{
    DpsError code = DpsError::DPS_ERROR_IMAGE_PROC_ABNORMAL;
    switch (errorCode) {
        case OHOS::HDI::Camera::V1_2::ErrorCode::ERROR_INVALID_ID:
            code = DpsError::DPS_ERROR_IMAGE_PROC_INVALID_PHOTO_ID;
            break;
        case OHOS::HDI::Camera::V1_2::ErrorCode::ERROR_PROCESS:
            code = DpsError::DPS_ERROR_IMAGE_PROC_FAILED;
            break;
        case OHOS::HDI::Camera::V1_2::ErrorCode::ERROR_TIMEOUT:
            code = DpsError::DPS_ERROR_IMAGE_PROC_TIMEOUT;
            break;
        case OHOS::HDI::Camera::V1_2::ErrorCode::ERROR_HIGH_TEMPERATURE:
            code = DpsError::DPS_ERROR_IMAGE_PROC_HIGH_TEMPERATURE;
            break;
        case OHOS::HDI::Camera::V1_2::ErrorCode::ERROR_ABNORMAL:
            code = DpsError::DPS_ERROR_IMAGE_PROC_ABNORMAL;
            break;
        case OHOS::HDI::Camera::V1_2::ErrorCode::ERROR_ABORT:
            code = DpsError::DPS_ERROR_IMAGE_PROC_INTERRUPTED;
            break;
        default:
            DP_ERR_LOG("unexpected error code: %d.", errorCode);
            break;
    }
    return code;
}

HdiStatus MapHdiStatus(OHOS::HDI::Camera::V1_2::SessionStatus statusCode)
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
            DP_ERR_LOG("unexpected error code: %d.", statusCode);
            break;
    }
    return code;
}

OHOS::HDI::Camera::V1_2::ExecutionMode MapToHdiExecutionMode(ExecutionMode executionMode)
{
    auto mode = OHOS::HDI::Camera::V1_2::ExecutionMode::LOW_POWER;
    switch (executionMode) {
        case ExecutionMode::HIGH_PERFORMANCE:
            mode = OHOS::HDI::Camera::V1_2::ExecutionMode::HIGH_PREFORMANCE;
            break;
        case ExecutionMode::LOAD_BALANCE:
            mode = OHOS::HDI::Camera::V1_2::ExecutionMode::BALANCED;
            break;
        case ExecutionMode::LOW_POWER:
            mode = OHOS::HDI::Camera::V1_2::ExecutionMode::LOW_POWER;
            break;
        default:
            DP_ERR_LOG("unexpected error code: %d.", executionMode);
            break;
    }
    return mode;
}

class PhotoPostProcessor::PhotoProcessListener : public OHOS::HDI::Camera::V1_2::IImageProcessCallback {
public:
    explicit PhotoProcessListener(PhotoPostProcessor* photoPostProcessor) : photoPostProcessor_(photoPostProcessor)
    {
    }

    ~PhotoProcessListener()
    {
        photoPostProcessor_ = nullptr;
    }

    int32_t OnProcessDone(const std::string& imageId, const OHOS::HDI::Camera::V1_2::ImageBufferInfo& buffer) override;

    int32_t OnError(const std::string& imageId,  OHOS::HDI::Camera::V1_2::ErrorCode errorCode) override;

    int32_t OnStatusChanged(OHOS::HDI::Camera::V1_2::SessionStatus status) override;

    void ReportEvent(const std::string& imageId);

private:
    PhotoPostProcessor* photoPostProcessor_;
};

int32_t PhotoPostProcessor::PhotoProcessListener::OnProcessDone(const std::string& imageId,
    const OHOS::HDI::Camera::V1_2::ImageBufferInfo& buffer)
{
    DP_INFO_LOG("entered");
    auto bufferHandle = buffer.imageHandle->GetBufferHandle();
    int hdiFd = bufferHandle->fd;
    DP_DEBUG_LOG("entered, hdiFd: %d", hdiFd);
    int fd = dup(hdiFd);
    DP_DEBUG_LOG("entered, dup fd: %d", fd);
    close(hdiFd);
    int size = bufferHandle->size;
    int32_t isDegradedImage = 0;
    int32_t dataSize = size;
    if (buffer.metadata) {
        int32_t retImageQuality = buffer.metadata->Get("isDegradedImage", isDegradedImage);
        int32_t retDataSize = buffer.metadata->Get("dataSize", dataSize);
        DP_INFO_LOG("retImageQuality: %d, retDataSize: %d", static_cast<int>(retImageQuality),
            static_cast<int>(retDataSize));
    }
    DP_INFO_LOG("bufferHandle param, size: %d, dataSize: %d, isDegradedImage: %d", size, static_cast<int>(dataSize),
        isDegradedImage);
    sptr<IPCFileDescriptor> ipcFileDescriptor = sptr<IPCFileDescriptor>::MakeSptr(fd);
    std::shared_ptr<BufferInfo> bufferInfo = std::make_shared<BufferInfo>(ipcFileDescriptor, dataSize,
        isDegradedImage == 0);
    ReportEvent(imageId);
    photoPostProcessor_->OnProcessDone(imageId, bufferInfo);
    return 0;
}

void PhotoPostProcessor::PhotoProcessListener::ReportEvent(const std::string& imageId)
{
    DPSEventReport::GetInstance()
        .UpdateProcessDoneTime(imageId, photoPostProcessor_->GetUserId());
}


int32_t PhotoPostProcessor::PhotoProcessListener::OnError(const std::string& imageId,
    OHOS::HDI::Camera::V1_2::ErrorCode errorCode)
{
    DP_INFO_LOG("entered, imageId: %s", imageId.c_str());
    DpsError dpsErrorCode = MapHdiError(errorCode);
    photoPostProcessor_->OnError(imageId, dpsErrorCode);
    return 0;
}

int32_t PhotoPostProcessor::PhotoProcessListener::OnStatusChanged(OHOS::HDI::Camera::V1_2::SessionStatus status)
{
    DP_INFO_LOG("entered");
    HdiStatus hdiStatus = MapHdiStatus(status);
    photoPostProcessor_->OnStateChanged(hdiStatus);
    return 0;
}

class PhotoPostProcessor::SessionDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    explicit SessionDeathRecipient(PhotoPostProcessor* processor)
        : photoPostProcessor_(processor)
    {
    }
    ~SessionDeathRecipient()
    {
        photoPostProcessor_ = nullptr;
    }

    void OnRemoteDied(const wptr<IRemoteObject> &remote) override
    {
        DP_ERR_LOG("Remote died.");
        if (photoPostProcessor_ == nullptr) {
            return;
        }
        photoPostProcessor_->OnSessionDied();
    }

private:
    PhotoPostProcessor* photoPostProcessor_;
};


PhotoPostProcessor::PhotoPostProcessor(int userId, TaskManager* taskManager, IImageProcessCallbacks* callbacks)
    : userId_(userId),
      taskManager_(taskManager),
      imageProcessCallacks_(callbacks),
      listener_(nullptr),
      imageProcessSession_(nullptr),
      sessionDeathRecipient_(nullptr),
      imageId2Handle_(),
      consecutiveTimeoutCount_(0)
{
    DP_DEBUG_LOG("entered");
}

PhotoPostProcessor::~PhotoPostProcessor()
{
    DP_DEBUG_LOG("entered");
    DisconnectServiceIfNecessary();
    taskManager_ = nullptr;
    imageProcessSession_ = nullptr;
    sessionDeathRecipient_ = nullptr;
    listener_ = nullptr;
    imageId2Handle_.clear();
    consecutiveTimeoutCount_ = 0;
}

void PhotoPostProcessor::Initialize()
{
    DP_DEBUG_LOG("entered");
    sessionDeathRecipient_ = new SessionDeathRecipient(this); // sptr<SessionDeathRecipient>::MakeSptr(this);
    listener_ = new PhotoProcessListener(this); // sptr<PhotoProcessListener>::MakeSptr(this);
    ConnectServiceIfNecessary();
}

int PhotoPostProcessor::GetUserId()
{
    return userId_;
}

int PhotoPostProcessor::GetConcurrency(ExecutionMode mode)
{
    std::lock_guard<std::mutex> lock(mutex_);
    int count = 1;
    if (imageProcessSession_) {
        int32_t ret = imageProcessSession_->GetCoucurrency(OHOS::HDI::Camera::V1_2::ExecutionMode::BALANCED, count);
        DP_INFO_LOG("getConcurrency, ret: %d", ret);
    }
    DP_INFO_LOG("entered, count: %d", count);
    return count;
}

bool PhotoPostProcessor::GetPendingImages(std::vector<std::string>& pendingImages)
{
    std::lock_guard<std::mutex> lock(mutex_);
    DP_INFO_LOG("entered");
    if (imageProcessSession_) {
        int32_t ret = imageProcessSession_->GetPendingImages(pendingImages);
        DP_INFO_LOG("getPendingImages, ret: %d", ret);
        if (ret == 0) {
        return true;
        }
    }
    return false;
}

void PhotoPostProcessor::SetExecutionMode(ExecutionMode executionMode)
{
    std::lock_guard<std::mutex> lock(mutex_);
    DP_INFO_LOG("entered, executionMode: %d", executionMode);
    if (imageProcessSession_) {
        int32_t ret = imageProcessSession_->SetExecutionMode(MapToHdiExecutionMode(executionMode));
        DP_INFO_LOG("setExecutionMode, ret: %d", ret);
    }
}

void PhotoPostProcessor::ProcessImage(std::string imageId)
{
    DP_INFO_LOG("entered, imageId: %s", imageId.c_str());
    if (!ConnectServiceIfNecessary()) {
        DP_INFO_LOG("failed to process image (%s) due to connect service failed", imageId.c_str());
        OnError(imageId, DpsError::DPS_ERROR_SESSION_NOT_READY_TEMPORARILY);
        return;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    int32_t ret = imageProcessSession_->ProcessImage(imageId);
    DP_INFO_LOG("processImage, ret: %d", ret);
    uint32_t callbackHandle;
    int userId = userId_;
    constexpr uint32_t maxProcessingTimeMs = 11 * 1000;
    GetGlobalWatchdog().StartMonitor(callbackHandle, maxProcessingTimeMs, [this, &userId, imageId](uint32_t handle) {
        DP_INFO_LOG("PhotoPostProcessor-ProcessImage-Watchdog executed, userId: %d, handle: %d",
            userId, static_cast<int>(handle));
        OnError(imageId, DpsError::DPS_ERROR_IMAGE_PROC_TIMEOUT);
    });
    DP_INFO_LOG("PhotoPostProcessor-ProcessImage-Watchdog registered, userId: %d, handle: %d",
        userId, static_cast<int>(callbackHandle));
    imageId2Handle_.emplace(imageId, callbackHandle);
}

void PhotoPostProcessor::RemoveImage(std::string imageId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    DP_INFO_LOG("entered, imageId: %s", imageId.c_str());
    if (imageProcessSession_) {
        int32_t ret = imageProcessSession_->RemoveImage(imageId);
        DP_INFO_LOG("removeImage, imageId: %s, ret: %d", imageId.c_str(), ret);
        DPSEventReport::GetInstance().UpdateRemoveTime(imageId, userId_);
    }
}

void PhotoPostProcessor::Interrupt()
{
    std::lock_guard<std::mutex> lock(mutex_);
    DP_INFO_LOG("entered");
    if (imageProcessSession_) {
        int32_t ret = imageProcessSession_->Interrupt();
        DP_INFO_LOG("interrupt, ret: %d", ret);
    }
}

void PhotoPostProcessor::Reset()
{
    std::lock_guard<std::mutex> lock(mutex_);
    DP_INFO_LOG("entered");
    if (imageProcessSession_) {
        int32_t ret = imageProcessSession_->Reset();
        DP_INFO_LOG("reset, ret: %d", ret);
    }
}

void PhotoPostProcessor::OnProcessDone(const std::string& imageId, std::shared_ptr<BufferInfo>  bufferInfo)
{
    DP_INFO_LOG("entered, imageId: %s", imageId.c_str());
    consecutiveTimeoutCount_ = 0;
    if (imageId2Handle_.count(imageId) == 1) {
        uint32_t callbackHandle = imageId2Handle_.find(imageId)->second;
        imageId2Handle_.erase(imageId);
        GetGlobalWatchdog().StopMonitor(callbackHandle);
    }
    if (imageProcessCallacks_) {
        taskManager_->SubmitTask([this, imageId, bufferInfo = std::move(bufferInfo)]() {
            imageProcessCallacks_->OnProcessDone(userId_, imageId, std::move(bufferInfo));
        });
    }
}

void PhotoPostProcessor::OnError(const std::string& imageId, DpsError errorCode)
{
    DP_INFO_LOG("entered, imageId: %s", imageId.c_str());
    if (imageId2Handle_.count(imageId) == 1) {
        uint32_t callbackHandle = imageId2Handle_.find(imageId)->second;
        imageId2Handle_.erase(imageId);
        GetGlobalWatchdog().StopMonitor(callbackHandle);
    }
    if (errorCode == DpsError::DPS_ERROR_IMAGE_PROC_TIMEOUT) {
        consecutiveTimeoutCount_++;
        if (consecutiveTimeoutCount_ >= static_cast<int>(MAX_CONSECUTIVE_TIMEOUT_COUNT)) {
            Reset();
            consecutiveTimeoutCount_ = 0;
        }
    } else {
        consecutiveTimeoutCount_ = 0;
    }
    if (imageProcessCallacks_) {
        taskManager_->SubmitTask([this, imageId, errorCode]() {
            imageProcessCallacks_->OnError(userId_, imageId, errorCode);
        });
    }
}

void PhotoPostProcessor::OnStateChanged(HdiStatus hdiStatus)
{
    DP_INFO_LOG("entered, HdiStatus: %d", hdiStatus);
    EventsMonitor::GetInstance().NotifyImageEnhanceStatus(hdiStatus);
}

void PhotoPostProcessor::OnSessionDied()
{
    DP_INFO_LOG("entered, session died!");
    std::lock_guard<std::mutex> lock(mutex_);
    imageProcessSession_ = nullptr;
    consecutiveTimeoutCount_ = 0;
    OnStateChanged(HdiStatus::HDI_DISCONNECTED);
    ScheduleConnectService();
}

bool PhotoPostProcessor::ConnectServiceIfNecessary()
{
    DP_INFO_LOG("entered.");
    std::lock_guard<std::mutex> lock(mutex_);
    if (imageProcessSession_ != nullptr) {
        DP_INFO_LOG("connected");
        return true;
    }
    sptr<OHOS::HDI::Camera::V1_2::IImageProcessService> imageProcessServiceProxy =
        OHOS::HDI::Camera::V1_2::IImageProcessService::Get(std::string("camera_image_process_service"));
    if (imageProcessServiceProxy == nullptr) {
        DP_INFO_LOG("Failed to get ImageProcessService");
        ScheduleConnectService();
        return false;
    }
    imageProcessServiceProxy->CreateImageProcessSession(userId_, listener_, imageProcessSession_);
    if (imageProcessSession_ == nullptr) {
        DP_INFO_LOG("Failed to CreateImageProcessSession");
        ScheduleConnectService();
        return false;
    }
    const sptr<IRemoteObject> &remote =
        OHOS::HDI::hdi_objcast<OHOS::HDI::Camera::V1_2::IImageProcessSession>(imageProcessSession_);
    bool result = remote->AddDeathRecipient(sessionDeathRecipient_);
    if (!result) {
        DP_INFO_LOG("AddDeathRecipient for ImageProcessSession failed.");
        return false;
    }
    OnStateChanged(HdiStatus::HDI_READY);
    return true;
}

void PhotoPostProcessor::DisconnectServiceIfNecessary()
{
    std::lock_guard<std::mutex> lock(mutex_);
    const sptr<IRemoteObject> &remote =
        OHOS::HDI::hdi_objcast<OHOS::HDI::Camera::V1_2::IImageProcessSession>(imageProcessSession_);
    bool result = remote->RemoveDeathRecipient(sessionDeathRecipient_);
    imageProcessSession_ = nullptr;
    if (!result) {
        DP_INFO_LOG("RemoveDeathRecipient for ImageProcessSession failed.");
        return;
    }
}

void PhotoPostProcessor::ScheduleConnectService()
{
    DP_INFO_LOG("entered.");
    if (!imageProcessSession_) {
        constexpr uint32_t delayMilli = 10 * 1000;
        uint32_t callbackHandle;
        GetGlobalWatchdog().StartMonitor(callbackHandle, delayMilli, [this](uint32_t handle) {
            DP_INFO_LOG("PhotoPostProcessor Watchdog executed, handle: %d", static_cast<int>(handle));
            ConnectServiceIfNecessary();
        });
        DP_INFO_LOG("PhotoPostProcessor Watchdog registered, handle: %d", static_cast<int>(callbackHandle));
    } else {
        DP_INFO_LOG("already connected.");
    }
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS