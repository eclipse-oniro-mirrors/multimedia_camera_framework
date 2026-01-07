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

#include "photo_post_processor.h"

#include "dp_log.h"
#include "dp_utils.h"
#include "dps_event_report.h"
#include "events_monitor.h"
#include "iproxy_broker.h"
#include "iservmgr_hdi.h"
#include "v1_5/iimage_process_service.h"
#include "v1_5/iimage_process_callback.h"
#include "v1_5/types.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
namespace {
    constexpr char PHOTO_SERVICE_NAME[] = "camera_image_process_service";
}

class PhotoPostProcessor::PhotoServiceListener : public HDI::ServiceManager::V1_0::ServStatListenerStub {
public:
    using StatusCallback = std::function<void(const HDI::ServiceManager::V1_0::ServiceStatus&)>;
    explicit PhotoServiceListener(const std::weak_ptr<PhotoPostProcessor>& processor) : processor_(processor)
    {
        DP_DEBUG_LOG("entered.");
    }

    void OnReceive(const HDI::ServiceManager::V1_0::ServiceStatus& status)
    {
        if (auto process = processor_.lock()) {
            process->OnServiceChange(status);
        }
    }

private:
    std::weak_ptr<PhotoPostProcessor> processor_;
};

class PhotoPostProcessor::SessionDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    explicit SessionDeathRecipient(const std::weak_ptr<PhotoProcessResult>& processResult)
        : processResult_(processResult)
    {
        DP_DEBUG_LOG("entered.");
    }

    void OnRemoteDied(const wptr<IRemoteObject> &remote) override
    {
        if (auto processResult = processResult_.lock()) {
            processResult->OnPhotoSessionDied();
        }
    }

private:
    std::weak_ptr<PhotoProcessResult> processResult_;
};

class PhotoPostProcessor::PhotoProcessListener : public OHOS::HDI::Camera::V1_5::IImageProcessCallback {
public:
    explicit PhotoProcessListener(const std::weak_ptr<PhotoProcessResult>& processResult)
        : processResult_(processResult)
    {
        DP_DEBUG_LOG("entered.");
    }

    int32_t OnProcessDone(const std::string& imageId, const OHOS::HDI::Camera::V1_2::ImageBufferInfo& buffer) override
    {
        DP_INFO_LOG("DPS_PHOTO: imageId: %{public}s", imageId.c_str());
        auto processResult = processResult_.lock();
        DP_CHECK_ERROR_RETURN_RET_LOG(processResult == nullptr, DP_OK, "PhotoProcessResult is nullptr.");

        auto ret = processResult->ProcessBufferInfo(imageId, buffer);
        if (ret != DP_OK) {
            HILOG_COMM_ERROR("Process done failed imageId: %{public}s.", imageId.c_str());
            processResult->OnError(imageId, DPS_ERROR_IMAGE_PROC_FAILED);
        }
        return DP_OK;
    }

    int32_t OnProcessDoneExt(const std::string& imageId,
        const OHOS::HDI::Camera::V1_3::ImageBufferInfoExt& buffer) override
    {
        DP_INFO_LOG("DPS_PHOTO: imageId: %{public}s", imageId.c_str());
        auto processResult = processResult_.lock();
        DP_CHECK_ERROR_RETURN_RET_LOG(processResult == nullptr, DP_OK, "PhotoProcessResult is nullptr.");

        auto ret = processResult->ProcessPictureInfoV1_3(imageId, buffer);
        if (ret != DP_OK) {
            HILOG_COMM_ERROR("Process yuv done failed imageId: %{public}s.", imageId.c_str());
            processResult->OnError(imageId, DPS_ERROR_IMAGE_PROC_FAILED);
        }
        return DP_OK;
    }

    int32_t OnProcessDone_V1_4(
        const std::string& imageId, const OHOS::HDI::Camera::V1_5::ImageBufferInfo_V1_4& buffer) override
    {
        DP_INFO_LOG("DPS_PHOTO: imageId: %{public}s", imageId.c_str());
        auto processResult = processResult_.lock();
        DP_CHECK_ERROR_RETURN_RET_LOG(processResult == nullptr, DP_OK, "PhotoProcessResult is nullptr.");

        auto ret = processResult->ProcessPictureInfoV1_4(imageId, buffer);
        if (ret != DP_OK) {
            HILOG_COMM_ERROR("Process yuv1_4 done failed imageId: %{public}s.", imageId.c_str());
            processResult->OnError(imageId, DPS_ERROR_IMAGE_PROC_FAILED);
        }
        return DP_OK;
    }

    int32_t OnError(const std::string& imageId,  OHOS::HDI::Camera::V1_2::ErrorCode errorCode) override
    {
        HILOG_COMM_ERROR("DPS_PHOTO: imageId: %{public}s, ive error: %{public}d", imageId.c_str(), errorCode);
        auto processResult = processResult_.lock();
        DP_CHECK_ERROR_RETURN_RET_LOG(processResult == nullptr, DP_OK, "PhotoProcessResult is nullptr.");

        processResult->OnError(imageId, MapHdiError(errorCode));
        return DP_OK;
    }

    int32_t OnStatusChanged(OHOS::HDI::Camera::V1_2::SessionStatus status) override
    {
        DP_INFO_LOG("DPS_PHOTO: IVEState: %{public}d", status);
        auto processResult = processResult_.lock();
        DP_CHECK_ERROR_RETURN_RET_LOG(processResult == nullptr, DP_OK, "PhotoProcessResult is nullptr.");

        processResult->OnStateChanged(MapHdiStatus(status));
        return DP_OK;
    }

private:
    std::weak_ptr<PhotoProcessResult> processResult_;
};

PhotoPostProcessor::PhotoPostProcessor(const int32_t userId)
    : userId_(userId), serviceListener_(nullptr), processListener_(nullptr), sessionDeathRecipient_(nullptr)
{
    DP_DEBUG_LOG("entered");
}

PhotoPostProcessor::~PhotoPostProcessor()
{
    DP_INFO_LOG("entered");
    DisconnectService();
    SetPhotoSession(nullptr);
    removeNeededList_.clear();
    runningId_.clear();
}

int32_t PhotoPostProcessor::Initialize()
{
    DP_DEBUG_LOG("entered");
    processResult_ = std::make_shared<PhotoProcessResult>(userId_);
    sessionDeathRecipient_ = sptr<SessionDeathRecipient>::MakeSptr(processResult_);
    processListener_ = sptr<PhotoProcessListener>::MakeSptr(processResult_);
    ConnectService();
    return DP_OK;
}

int32_t PhotoPostProcessor::GetConcurrency(ExecutionMode mode)
{
    int32_t count = 1;
    auto session = GetPhotoSession();
    DP_CHECK_ERROR_RETURN_RET_LOG(session == nullptr, count, "photo session is nullptr, count: %{public}d", count);

    int32_t ret = session->GetCoucurrency(OHOS::HDI::Camera::V1_2::ExecutionMode::BALANCED, count);
    DP_INFO_LOG("DPS_PHOTO: GetCoucurrency to ive, ret: %{public}d", ret);
    return count;
}

bool PhotoPostProcessor::GetPendingImages(std::vector<std::string>& pendingImages)
{
    auto session = GetPhotoSession();
    DP_CHECK_ERROR_RETURN_RET_LOG(session == nullptr, false, "photo session is nullptr.");

    int32_t ret = session->GetPendingImages(pendingImages);
    DP_INFO_LOG("DPS_PHOTO: GetPendingImages to ive, ret: %{public}d", ret);
    return ret == DP_OK;
}

void PhotoPostProcessor::SetExecutionMode(ExecutionMode executionMode)
{
    auto session = GetPhotoSession();
    DP_CHECK_ERROR_RETURN_LOG(session == nullptr, "photo session is nullptr.");

    int32_t ret = session->SetExecutionMode(MapToHdiExecutionMode(executionMode));
    DP_INFO_LOG("DPS_PHOTO: SetExecutionMode to ive, ret: %{public}d", ret);
}

void PhotoPostProcessor::SetDefaultExecutionMode()
{
    // 采用直接新增方法，不适配1_2 和 1_3 模式的差异点
    auto session = GetPhotoSession();
    DP_CHECK_ERROR_RETURN_LOG(session == nullptr, "photo session is nullptr.");

    int32_t ret = session->SetExecutionMode(
        static_cast<OHOS::HDI::Camera::V1_2::ExecutionMode>(OHOS::HDI::Camera::V1_3::ExecutionMode::DEFAULT));
    DP_INFO_LOG("DPS_PHOTO: SetDefaultExecutionMode to ive, ret: %{public}d", ret);
}

void PhotoPostProcessor::ProcessImage(const std::string& imageId)
{
    auto session = GetPhotoSession();
    if (session == nullptr) {
        DP_ERR_LOG("Failed to process imageId: %{public}s, photo session is nullptr", imageId.c_str());
        DP_CHECK_EXECUTE(processResult_, processResult_->OnError(imageId, DPS_ERROR_SESSION_NOT_READY_TEMPORARILY));
        return;
    }

    int32_t ret = session->ProcessImage(imageId);
    HILOG_COMM_INFO("DPS_PHOTO: Process photo to ive, imageId: %{public}s, ret: %{public}d", imageId.c_str(), ret);
    runningId_.emplace(imageId);
}

void PhotoPostProcessor::RemoveImage(const std::string& imageId)
{
    runningId_.erase(imageId);
    auto session = GetPhotoSession();
    if (session == nullptr) {
        DP_ERR_LOG("photo session is nullptr.");
        std::lock_guard<std::mutex> lock(removeMutex_);
        removeNeededList_.emplace_back(imageId);
        return;
    }

    int32_t ret = session->RemoveImage(imageId);
    DP_INFO_LOG("DPS_PHOTO: Remove photo to ive, imageId: %{public}s, ret: %{public}d", imageId.c_str(), ret);
    DPSEventReport::GetInstance().UpdateRemoveTime(imageId, userId_);
}

void PhotoPostProcessor::Interrupt()
{
    auto session = GetPhotoSession();
    DP_CHECK_ERROR_RETURN_LOG(session == nullptr, "photo session is nullptr.");

    int32_t ret = session->Interrupt();
    HILOG_COMM_INFO("DPS_PHOTO: Interrupt photo to ive, ret: %{public}d", ret);
    session->SetExecutionMode(
        static_cast<OHOS::HDI::Camera::V1_2::ExecutionMode>(OHOS::HDI::Camera::V1_3::ExecutionMode::DEFAULT));
}

void PhotoPostProcessor::Reset()
{
    auto session = GetPhotoSession();
    DP_CHECK_ERROR_RETURN_LOG(session == nullptr, "photo session is nullptr.");

    int32_t ret = session->Reset();
    DP_INFO_LOG("DPS_PHOTO: Reset to ive, ret: %{public}d", ret);
}

void PhotoPostProcessor::NotifyHalStateChanged(HdiStatus hdiStatus)
{
    EventsMonitor::GetInstance().NotifyImageEnhanceStatus(hdiStatus);
}

void PhotoPostProcessor::OnSessionDied()
{
    SetPhotoSession(nullptr);
    for (auto id : runningId_) {
        DP_CHECK_EXECUTE(processResult_, processResult_->OnError(id, DPS_ERROR_SESSION_NOT_READY_TEMPORARILY));
    }
    NotifyHalStateChanged(HdiStatus::HDI_DISCONNECTED);
}

#ifdef CAMERA_CAPTURE_YUV
void PhotoPostProcessor::SetProcessBundleNameResult(const std::string& bundleName)
{
    DP_CHECK_EXECUTE(processResult_, processResult_->SetBundleName(bundleName));
}
#endif

void PhotoPostProcessor::ConnectService()
{
    auto svcMgr = HDI::ServiceManager::V1_0::IServiceManager::Get();
    DP_CHECK_ERROR_RETURN_LOG(svcMgr == nullptr, "IServiceManager init failed.");
    serviceListener_ = sptr<PhotoServiceListener>::MakeSptr(weak_from_this());
    auto ret  = svcMgr->RegisterServiceStatusListener(serviceListener_, DEVICE_CLASS_DEFAULT);
    DP_CHECK_ERROR_RETURN_LOG(ret != 0, "Register Photo ServiceStatusListener failed.");
}

void PhotoPostProcessor::DisconnectService()
{
    auto session = GetPhotoSession();
    DP_CHECK_ERROR_RETURN_LOG(session == nullptr, "PhotoSession is nullptr.");

    const sptr<IRemoteObject> &remote = OHOS::HDI::hdi_objcast<IImageProcessSession>(session);
    bool result = remote->RemoveDeathRecipient(sessionDeathRecipient_);
    DP_CHECK_ERROR_RETURN_LOG(!result, "Remove DeathRecipient for PhotoProcessSession failed.");
    auto svcMgr = HDI::ServiceManager::V1_0::IServiceManager::Get();
    DP_CHECK_ERROR_RETURN_LOG(svcMgr == nullptr, "IServiceManager init failed.");

    auto ret  = svcMgr->UnregisterServiceStatusListener(serviceListener_);
    DP_CHECK_ERROR_RETURN_LOG(ret != 0, "Unregister Photo ServiceStatusListener failed.");
}

void PhotoPostProcessor::OnServiceChange(const HDI::ServiceManager::V1_0::ServiceStatus& status)
{
    DP_CHECK_RETURN(status.serviceName != PHOTO_SERVICE_NAME);
    DP_CHECK_RETURN_LOG(status.status != HDI::ServiceManager::V1_0::SERVIE_STATUS_START,
        "photo service state: %{public}d", status.status);
    DP_CHECK_RETURN(GetPhotoSession() != nullptr);

    sptr<OHOS::HDI::Camera::V1_2::IImageProcessService> proxyV1_2 =
        OHOS::HDI::Camera::V1_2::IImageProcessService::Get(status.serviceName);
    DP_CHECK_ERROR_RETURN_LOG(proxyV1_2 == nullptr, "get ImageProcessService failed.");

    uint32_t majorVer = 0;
    uint32_t minorVer = 0;
    proxyV1_2->GetVersion(majorVer, minorVer);
    int32_t versionId = GetVersionId(majorVer, minorVer);
    sptr<IImageProcessSession> session;
    sptr<OHOS::HDI::Camera::V1_3::IImageProcessService> proxyV1_3;
    sptr<OHOS::HDI::Camera::V1_5::IImageProcessService> proxyV1_4;
    // LCOV_EXCL_START
    if (versionId >= HDI_VERSION_ID_1_4) {
        proxyV1_4 = OHOS::HDI::Camera::V1_5::IImageProcessService::CastFrom(proxyV1_2);
    } else if (versionId >= HDI_VERSION_ID_1_3) {
        proxyV1_3 = OHOS::HDI::Camera::V1_3::IImageProcessService::CastFrom(proxyV1_2);
    }
    if (proxyV1_4 != nullptr) {
        DP_INFO_LOG("CreateImageProcessSession_V1_4 version=%{public}d_%{public}d", majorVer, minorVer);
        proxyV1_4->CreateImageProcessSession_V1_4(userId_, processListener_, session);
    } else if (proxyV1_3 != nullptr) {
        DP_INFO_LOG("CreateImageProcessSessionExt version=%{public}d_%{public}d", majorVer, minorVer);
        proxyV1_3->CreateImageProcessSessionExt(userId_, processListener_, session);
    } else {
        DP_INFO_LOG("CreateImageProcessSession version=%{public}d_%{public}d", majorVer, minorVer);
        proxyV1_2->CreateImageProcessSession(userId_, processListener_, session);
    }
    // LCOV_EXCL_STOP
    DP_CHECK_ERROR_RETURN_LOG(session == nullptr, "get ImageProcessSession failed.");

    const sptr<IRemoteObject>& remote = OHOS::HDI::hdi_objcast<IImageProcessSession>(session);
    bool result = remote->AddDeathRecipient(sessionDeathRecipient_);
    DP_CHECK_ERROR_RETURN_LOG(!result, "add DeathRecipient for ImageProcessSession failed.");

    RemoveNeedJbo(session);
    SetPhotoSession(session);
    NotifyHalStateChanged(HdiStatus::HDI_READY);
}

void PhotoPostProcessor::RemoveNeedJbo(const sptr<IImageProcessSession>& session)
{
    std::lock_guard<std::mutex> lock(removeMutex_);
    for (const auto& imageId : removeNeededList_) {
        int32_t ret = session->RemoveImage(imageId);
        DP_INFO_LOG("DPS_PHOTO: RemoveImage imageId: %{public}s, ret: %{public}d", imageId.c_str(), ret);
    }
    removeNeededList_.clear();
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS