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
#include "photo_post_processor.h"

#include <cstdint>
#include <string>
#include <sys/mman.h>

#include "iproxy_broker.h"
#include "v1_3/types.h"
#include "shared_buffer.h"
#include "dp_utils.h"
#include "events_monitor.h"
#include "dps_event_report.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
constexpr uint32_t MAX_CONSECUTIVE_TIMEOUT_COUNT = 3;
constexpr uint32_t MAX_CONSECUTIVE_CRASH_COUNT = 3;

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
            DP_ERR_LOG("unexpected error code: %{public}d.", errorCode);
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
            DP_ERR_LOG("unexpected error code: %{public}d.", statusCode);
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
            DP_ERR_LOG("unexpected error code: %{public}d.", executionMode);
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

private:
    void ReportEvent(const std::string& imageId);
    int32_t processBufferInfo(const std::string& imageId, const OHOS::HDI::Camera::V1_2::ImageBufferInfo& buffer);

    PhotoPostProcessor* photoPostProcessor_;
};

int32_t PhotoPostProcessor::PhotoProcessListener::OnProcessDone(const std::string& imageId,
    const OHOS::HDI::Camera::V1_2::ImageBufferInfo& buffer)
{
    DP_DEBUG_LOG("imageId: %{public}s", imageId.c_str());
    auto ret = processBufferInfo(imageId, buffer);
    if (ret != DP_OK) {
        DP_ERR_LOG("process done failed imageId: %{public}s.", imageId.c_str());
        photoPostProcessor_->OnError(imageId, DPS_ERROR_IMAGE_PROC_FAILED);
    }
    return DP_OK;
}

int32_t PhotoPostProcessor::PhotoProcessListener::processBufferInfo(const std::string& imageId,
    const OHOS::HDI::Camera::V1_2::ImageBufferInfo& buffer)
{
    auto bufferHandle = buffer.imageHandle->GetBufferHandle();
    DP_CHECK_AND_RETURN_RET_LOG(bufferHandle != nullptr, DPS_ERROR_IMAGE_PROC_FAILED, "bufferHandle is nullptr.");

    int32_t size = bufferHandle->size;
    int32_t isDegradedImage = 0;
    int32_t dataSize = size;
    if (buffer.metadata) {
        int32_t retImageQuality = buffer.metadata->Get("isDegradedImage", isDegradedImage);
        int32_t retDataSize = buffer.metadata->Get("dataSize", dataSize);
        DP_DEBUG_LOG("retImageQuality: %{public}d, retDataSize: %{public}d", static_cast<int>(retImageQuality),
            static_cast<int>(retDataSize));
    }
    DP_INFO_LOG("bufferHandle param, size: %{public}d, dataSize: %{public}d, isDegradedImage: %{public}d",
        size, static_cast<int>(dataSize), isDegradedImage);
    auto bufferPtr = std::make_shared<SharedBuffer>(dataSize);
    DP_CHECK_AND_RETURN_RET_LOG(bufferPtr->Initialize() == DP_OK, DPS_ERROR_IMAGE_PROC_FAILED,
        "failed to initialize shared buffer.");
    
    uint8_t* addr = static_cast<uint8_t*>(
        mmap(nullptr, dataSize, PROT_READ | PROT_WRITE, MAP_SHARED, bufferHandle->fd, 0));
    if (bufferPtr->CopyFrom(addr, dataSize) == DP_OK) {
        DP_INFO_LOG("bufferPtr fd: %{public}d, fd: %{public}d", bufferHandle->fd, bufferPtr->GetFd());
        std::shared_ptr<BufferInfo> bufferInfo = std::make_shared<BufferInfo>(bufferPtr, dataSize,
            isDegradedImage == 0);
        ReportEvent(imageId);
        photoPostProcessor_->OnProcessDone(imageId, bufferInfo);
    }
    munmap(addr, dataSize);
    return DP_OK;
}

void PhotoPostProcessor::PhotoProcessListener::ReportEvent(const std::string& imageId)
{
    DPSEventReport::GetInstance()
        .UpdateProcessDoneTime(imageId, photoPostProcessor_->GetUserId());
}


int32_t PhotoPostProcessor::PhotoProcessListener::OnError(const std::string& imageId,
    OHOS::HDI::Camera::V1_2::ErrorCode errorCode)
{
    DP_INFO_LOG("entered, imageId: %{public}s", imageId.c_str());
    DpsError dpsErrorCode = MapHdiError(errorCode);
    photoPostProcessor_->OnError(imageId, dpsErrorCode);
    return DP_OK;
}

int32_t PhotoPostProcessor::PhotoProcessListener::OnStatusChanged(OHOS::HDI::Camera::V1_2::SessionStatus status)
{
    DP_INFO_LOG("entered");
    HdiStatus hdiStatus = MapHdiStatus(status);
    photoPostProcessor_->OnStateChanged(hdiStatus);
    return DP_OK;
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


PhotoPostProcessor::PhotoPostProcessor(const int32_t userId,
    TaskManager* taskManager, IImageProcessCallbacks* callbacks)
    : userId_(userId),
      taskManager_(taskManager),
      processCallacks_(callbacks),
      listener_(nullptr),
      session_(nullptr),
      sessionDeathRecipient_(nullptr),
      imageId2Handle_(),
      imageId2CrashCount_(),
      removeNeededList_(),
      consecutiveTimeoutCount_(0)
{
    DP_DEBUG_LOG("entered");
}

PhotoPostProcessor::~PhotoPostProcessor()
{
    DP_DEBUG_LOG("entered");
    DisconnectServiceIfNecessary();
    taskManager_ = nullptr;
    processCallacks_ = nullptr;
    session_ = nullptr;
    sessionDeathRecipient_ = nullptr;
    listener_ = nullptr;
    imageId2Handle_.Clear();
    consecutiveTimeoutCount_ = 0;
}

void PhotoPostProcessor::Initialize()
{
    DP_DEBUG_LOG("entered");
    sessionDeathRecipient_ = new SessionDeathRecipient(this); // sptr<SessionDeathRecipient>::MakeSptr(this);
    listener_ = new PhotoProcessListener(this); // sptr<PhotoProcessListener>::MakeSptr(this);
    ConnectServiceIfNecessary();
}

int32_t PhotoPostProcessor::GetUserId()
{
    return userId_;
}

int PhotoPostProcessor::GetConcurrency(ExecutionMode mode)
{
    std::lock_guard<std::mutex> lock(mutex_);
    int count = 1;
    if (session_) {
        int32_t ret = session_->GetCoucurrency(OHOS::HDI::Camera::V1_2::ExecutionMode::BALANCED, count);
        DP_INFO_LOG("getConcurrency, ret: %{public}d", ret);
    }
    DP_INFO_LOG("entered, count: %{public}d", count);
    return count;
}

bool PhotoPostProcessor::GetPendingImages(std::vector<std::string>& pendingImages)
{
    std::lock_guard<std::mutex> lock(mutex_);
    DP_INFO_LOG("entered");
    if (session_) {
        int32_t ret = session_->GetPendingImages(pendingImages);
        DP_INFO_LOG("getPendingImages, ret: %{public}d", ret);
        if (ret == 0) {
        return true;
        }
    }
    return false;
}

void PhotoPostProcessor::SetExecutionMode(ExecutionMode executionMode)
{
    std::lock_guard<std::mutex> lock(mutex_);
    DP_INFO_LOG("entered, executionMode: %{public}d", executionMode);
    if (session_) {
        int32_t ret = session_->SetExecutionMode(MapToHdiExecutionMode(executionMode));
        DP_INFO_LOG("setExecutionMode, ret: %{public}d", ret);
    }
}

void PhotoPostProcessor::SetDefaultExecutionMode()
{
    // 采用直接新增方法，不适配1_2 和 1_3 模式的差异点
    std::lock_guard<std::mutex> lock(mutex_);
    DP_INFO_LOG("entered.");
    if (session_) {
        int32_t ret = session_->SetExecutionMode(
            static_cast<OHOS::HDI::Camera::V1_2::ExecutionMode>(OHOS::HDI::Camera::V1_3::ExecutionMode::DEFAULT));
        DP_INFO_LOG("setExecutionMode, ret: %{public}d", ret);
    }
}

void PhotoPostProcessor::ProcessImage(std::string imageId)
{
    DP_INFO_LOG("entered, imageId: %{public}s", imageId.c_str());
    if (!ConnectServiceIfNecessary()) {
        DP_INFO_LOG("failed to process image (%{public}s) due to connect service failed", imageId.c_str());
        OnError(imageId, DpsError::DPS_ERROR_SESSION_NOT_READY_TEMPORARILY);
        return;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    DP_CHECK_AND_RETURN_LOG(session_ != nullptr, "PhotoPostProcessor::ProcessImage imageProcessSession is nullptr");
    int32_t ret = session_->ProcessImage(imageId);
    DP_INFO_LOG("processImage, ret: %{public}d", ret);
    uint32_t callbackHandle;
    constexpr uint32_t maxProcessingTimeMs = 11 * 1000;
    GetGlobalWatchdog().StartMonitor(callbackHandle, maxProcessingTimeMs, [this, imageId](uint32_t handle) {
        DP_INFO_LOG("PhotoPostProcessor-ProcessImage-Watchdog executed, userId: %{public}d, handle: %{public}d",
            userId_, static_cast<int>(handle));
        OnError(imageId, DpsError::DPS_ERROR_IMAGE_PROC_TIMEOUT);
    });
    DP_INFO_LOG("PhotoPostProcessor-ProcessImage-Watchdog registered, userId: %{public}d, handle: %{public}d",
        userId_, static_cast<int>(callbackHandle));
    imageId2Handle_.Insert(imageId, callbackHandle);
}

void PhotoPostProcessor::RemoveImage(std::string imageId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    DP_INFO_LOG("entered, imageId: %{public}s", imageId.c_str());
    if (session_) {
        int32_t ret = session_->RemoveImage(imageId);
        DP_INFO_LOG("removeImage, imageId: %{public}s, ret: %{public}d", imageId.c_str(), ret);
        imageId2CrashCount_.erase(imageId);
        DPSEventReport::GetInstance().UpdateRemoveTime(imageId, userId_);
    } else {
        removeNeededList_.emplace_back(imageId);
    }
}

void PhotoPostProcessor::Interrupt()
{
    std::lock_guard<std::mutex> lock(mutex_);
    DP_INFO_LOG("entered");
    if (session_) {
        int32_t ret = session_->Interrupt();
        DP_INFO_LOG("interrupt, ret: %{public}d", ret);
    }
}

void PhotoPostProcessor::Reset()
{
    std::lock_guard<std::mutex> lock(mutex_);
    DP_INFO_LOG("entered");
    if (session_) {
        int32_t ret = session_->Reset();
        DP_INFO_LOG("reset, ret: %{public}d", ret);
    }
}

void PhotoPostProcessor::OnProcessDone(const std::string& imageId, std::shared_ptr<BufferInfo> bufferInfo)
{
    DP_INFO_LOG("entered, imageId: %{public}s", imageId.c_str());
    consecutiveTimeoutCount_ = 0;
    StopTimer(imageId);
    if (processCallacks_) {
        taskManager_->SubmitTask([this, imageId, bufferInfo = std::move(bufferInfo)]() {
            processCallacks_->OnProcessDone(userId_, imageId, std::move(bufferInfo));
        });
    }
}

void PhotoPostProcessor::OnError(const std::string& imageId, DpsError errorCode)
{
    DP_INFO_LOG("entered, imageId: %{public}s", imageId.c_str());
    StopTimer(imageId);
    if (errorCode == DpsError::DPS_ERROR_IMAGE_PROC_TIMEOUT) {
        consecutiveTimeoutCount_++;
        if (consecutiveTimeoutCount_ >= static_cast<int>(MAX_CONSECUTIVE_TIMEOUT_COUNT)) {
            Reset();
            consecutiveTimeoutCount_ = 0;
        }
    } else {
        consecutiveTimeoutCount_ = 0;
    }
    if (processCallacks_) {
        taskManager_->SubmitTask([this, imageId, errorCode]() {
            processCallacks_->OnError(userId_, imageId, errorCode);
        });
    }
}

void PhotoPostProcessor::OnStateChanged(HdiStatus hdiStatus)
{
    DP_INFO_LOG("entered, HdiStatus: %{public}d", hdiStatus);
    EventsMonitor::GetInstance().NotifyImageEnhanceStatus(hdiStatus);
}

void PhotoPostProcessor::OnSessionDied()
{
    DP_INFO_LOG("entered, session died!");
    std::lock_guard<std::mutex> lock(mutex_);
    session_ = nullptr;
    consecutiveTimeoutCount_ = 0;
    OnStateChanged(HdiStatus::HDI_DISCONNECTED);
    std::vector<std::string> crashJobs;
    imageId2Handle_.Iterate([&](const std::string& imageId, const uint32_t value) {
        crashJobs.emplace_back(imageId);
    });
    for (const auto& id : crashJobs) {
        DP_INFO_LOG("failed to process imageId(%{public}s) due to connect service failed", id.c_str());
        if (imageId2CrashCount_.count(id) == 0) {
            imageId2CrashCount_.emplace(id, 1);
        } else {
            imageId2CrashCount_[id] += 1;
        }
        if (imageId2CrashCount_[id] >= MAX_CONSECUTIVE_CRASH_COUNT) {
            OnError(id, DpsError::DPS_ERROR_IMAGE_PROC_FAILED);
        } else {
            OnError(id, DpsError::DPS_ERROR_SESSION_NOT_READY_TEMPORARILY);
        }
    }
    ScheduleConnectService();
}

bool PhotoPostProcessor::ConnectServiceIfNecessary()
{
    DP_INFO_LOG("entered.");
    std::lock_guard<std::mutex> lock(mutex_);
    if (session_ != nullptr) {
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

    imageProcessServiceProxy->CreateImageProcessSession(userId_, listener_, session_);
    if (session_ == nullptr) {
        DP_INFO_LOG("Failed to CreateImageProcessSession");
        ScheduleConnectService();
        return false;
    }

    for (const auto& imageId : removeNeededList_) {
        int32_t ret = session_->RemoveImage(imageId);
        DP_INFO_LOG("removeImage, imageId: %{public}s, ret: %{public}d", imageId.c_str(), ret);
    }
    removeNeededList_.clear();
    const sptr<IRemoteObject>& remote =
        OHOS::HDI::hdi_objcast<OHOS::HDI::Camera::V1_2::IImageProcessSession>(session_);
    DP_CHECK_AND_RETURN_RET_LOG(remote->AddDeathRecipient(sessionDeathRecipient_),
        false, "AddDeathRecipient for ImageProcessSession failed.");
    OnStateChanged(HdiStatus::HDI_READY);
    return true;
}

void PhotoPostProcessor::DisconnectServiceIfNecessary()
{
    std::lock_guard<std::mutex> lock(mutex_);
    DP_CHECK_AND_RETURN_LOG(session_ != nullptr, "imageProcessSession is nullptr");
    const sptr<IRemoteObject> &remote =
        OHOS::HDI::hdi_objcast<OHOS::HDI::Camera::V1_2::IImageProcessSession>(session_);
    DP_CHECK_ERROR_PRINT_LOG(!remote->RemoveDeathRecipient(sessionDeathRecipient_),
        "RemoveDeathRecipient for ImageProcessSession failed.");
    session_ = nullptr;
}

void PhotoPostProcessor::ScheduleConnectService()
{
    DP_INFO_LOG("entered.");
    if (session_ == nullptr) {
        constexpr uint32_t delayMilli = 10 * 1000;
        uint32_t callbackHandle;
        GetGlobalWatchdog().StartMonitor(callbackHandle, delayMilli, [this](uint32_t handle) {
            DP_INFO_LOG("PhotoPostProcessor Watchdog executed, handle: %{public}d", static_cast<int>(handle));
            ConnectServiceIfNecessary();
        });
        DP_INFO_LOG("PhotoPostProcessor Watchdog registered, handle: %{public}d", static_cast<int>(callbackHandle));
    } else {
        DP_INFO_LOG("already connected.");
    }
}

void PhotoPostProcessor::StopTimer(const std::string& imageId)
{
    uint32_t callbackHandle;
    DP_CHECK_AND_RETURN_LOG(imageId2Handle_.Find(imageId, callbackHandle),
        "stoptimer failed not find imageId: %{public}s", imageId.c_str());
    imageId2Handle_.Erase(imageId);
    GetGlobalWatchdog().StopMonitor(callbackHandle);
    DP_INFO_LOG("stoptimer success, imageId: %{public}s", imageId.c_str());
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS