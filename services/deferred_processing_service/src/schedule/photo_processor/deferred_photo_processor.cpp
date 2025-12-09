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

#include "deferred_photo_processor.h"

#include "basic_definitions.h"
#include "deferred_photo_result.h"
#include "dp_log.h"
#include "dp_timer.h"
#include "dp_utils.h"
#include "dps.h"
#include "dps_event_report.h"
#include "events_info.h"
#include "photo_process_command.h"

namespace OHOS {
namespace CameraStandard {
namespace DeferredProcessing {
namespace {
    constexpr uint32_t MAX_PROC_TIME_MS = 11 * 1000;
}

DeferredPhotoProcessor::DeferredPhotoProcessor(const int32_t userId,
    const std::shared_ptr<PhotoJobRepository>& repository, const std::shared_ptr<PhotoPostProcessor>& postProcessor)
    : userId_(userId), repository_(repository), postProcessor_(postProcessor)
{
    DP_DEBUG_LOG("entered.");
}

DeferredPhotoProcessor::~DeferredPhotoProcessor()
{
    DP_INFO_LOG("entered, userId: %{public}d", userId_);
}

int32_t DeferredPhotoProcessor::Initialize()
{
    DP_CHECK_ERROR_RETURN_RET_LOG(repository_ == nullptr, DP_NULL_POINTER, "PhotoRepository is nullptr");
    DP_CHECK_ERROR_RETURN_RET_LOG(postProcessor_ == nullptr, DP_NULL_POINTER, "PhotoPostProcessor is nullptr");
    result_ = DeferredPhotoResult::Create();
    DP_CHECK_ERROR_RETURN_RET_LOG(result_ == nullptr, DP_NULL_POINTER, "DeferredPhotoResult is nullptr");
    initialized_ = true;
    return DP_OK;
}

void DeferredPhotoProcessor::AddImage(const std::string& imageId, bool discardable, DpsMetadata& metadata,
    const std::string& bundleName)
{
    DP_CHECK_EXECUTE(postProcessor_, postProcessor_->SetProcessBundleNameResult(bundleName));
    bool isProcess = ProcessCatchResults(imageId);
    DP_CHECK_RETURN(isProcess);
    repository_->AddDeferredJob(imageId, discardable, metadata);
}

void DeferredPhotoProcessor::RemoveImage(const std::string& imageId, bool restorable)
{
    result_->DeRecordHigh(imageId);
    repository_->RemoveDeferredJob(imageId, restorable);
    DP_CHECK_RETURN(restorable);
    DP_CHECK_EXECUTE(repository_->IsRunningJob(imageId), postProcessor_->Interrupt());
    postProcessor_->RemoveImage(imageId);
    result_->DeRecordResult(imageId);
}

void DeferredPhotoProcessor::RestoreImage(const std::string& imageId)
{
    repository_->RestoreJob(imageId);
}

void DeferredPhotoProcessor::ProcessImage(const std::string& appName, const std::string& imageId)
{
    DP_CHECK_RETURN_LOG(repository_->IsBackgroundJob(imageId),
        "DPS_PHOTO: imageId is backgroundJob %{public}s", imageId.c_str());
    if (!repository_->RequestJob(imageId)) {
        OnProcessError(userId_, imageId, DpsError::DPS_ERROR_IMAGE_PROC_INVALID_PHOTO_ID);
        return;
    }
    result_->RecordHigh(imageId);
}

void DeferredPhotoProcessor::CancelProcessImage(const std::string& imageId)
{
    DP_CHECK_RETURN_LOG(repository_->IsBackgroundJob(imageId),
        "DPS_PHOTO: imageId is backgroundJob %{public}s", imageId.c_str());
    result_->DeRecordHigh(imageId);
    repository_->CancelJob(imageId);
}

bool DeferredPhotoProcessor::ProcessBPCache()
{
    return ProcessCatchResults(result_->GetBPCacheId());
}

void DeferredPhotoProcessor::DoProcess(const DeferredPhotoJobPtr& job)
{
    auto executionMode = job->GetExecutionMode();
    auto imageId = job->GetImageId();
    DP_INFO_LOG("DPS_PHOTO: imageId: %{public}s, executionMode: %{public}d", imageId.c_str(), executionMode);
    uint32_t timerId = StartTimer(imageId);
    job->Start(timerId);
    result_->DeRecordHigh(imageId);
    postProcessor_->SetExecutionMode(executionMode);
    DPSEventReport::GetInstance().UpdateExecutionMode(imageId, userId_, executionMode);
    DPSEventReport::GetInstance().ReportImageModeChange(executionMode,
        EventsInfo::GetInstance().GetAvailableMemory());
    postProcessor_->ProcessImage(imageId);
}

void DeferredPhotoProcessor::OnProcessSuccess(const int32_t userId, const std::string& imageId,
    std::unique_ptr<ImageInfo> imageInfo)
{
    DP_CHECK_ERROR_RETURN_LOG(!initialized_, "Not initialized.");
    DP_INFO_LOG("DPS_PHOTO: userId: %{public}d, imageId: %{public}s, bufferQuality: %{public}d",
        userId, imageId.c_str(), imageInfo->IsHighQuality());
    HandleSuccess(userId, imageId, std::move(imageInfo));
}

void DeferredPhotoProcessor::OnProcessError(const int32_t userId, const std::string& imageId, DpsError error)
{
    DP_CHECK_ERROR_RETURN_LOG(!initialized_, "Not initialized.");
    DP_ERR_LOG("DPS_PHOTO: userId: %{public}d, imageId: %{public}s, dps error: %{public}d.",
        userId, imageId.c_str(), error);
    bool isHighJob = repository_->IsHighJob(imageId);
    HandleError(userId, imageId, error, isHighJob);
}

void DeferredPhotoProcessor::NotifyScheduleState(DpsStatus status)
{
    auto statusCode = MapDpsStatus(status);
    if (auto callback = GetCallback()) {
        DP_INFO_LOG("DPS_OHOTO: statusCode: %{public}d", statusCode);
        callback->OnStateChanged(statusCode);
    }
}

void DeferredPhotoProcessor::Interrupt()
{
    postProcessor_->Interrupt();
}

void DeferredPhotoProcessor::SetDefaultExecutionMode()
{
    postProcessor_->SetDefaultExecutionMode();
}

bool DeferredPhotoProcessor::GetPendingImages(std::vector<std::string>& pendingImages)
{
    return postProcessor_->GetPendingImages(pendingImages);
}

bool DeferredPhotoProcessor::HasRunningJob()
{
    return repository_->HasRunningJob();
}

bool DeferredPhotoProcessor::IsIdleState()
{
    DP_DEBUG_LOG("entered.");
    return repository_->GetOfflineIdleJobSize() == DEFAULT_COUNT &&
        repository_->GetBackgroundIdleJobSize() == DEFAULT_COUNT;
}

std::shared_ptr<PhotoJobRepository> DeferredPhotoProcessor::GetRepository()
{
    return repository_;
}

std::shared_ptr<PhotoPostProcessor> DeferredPhotoProcessor::GetPhotoPostProcessor()
{
    return postProcessor_;
}

void DeferredPhotoProcessor::HandleSuccess(const int32_t userId, const std::string& imageId,
    std::unique_ptr<ImageInfo> imageInfo)
{
    StopTimer(imageId);
    result_->OnSuccess(imageId);
    auto jobPtr = repository_->GetJobUnLocked(imageId);
    auto callback = GetCallback();
    if (jobPtr == nullptr || callback == nullptr) {
        result_->RecordResult(imageId, std::move(imageInfo), false);
        return;
    }

    if (EventsInfo::GetInstance().IsMediaBusy() && jobPtr->GetCurPriority() != JobPriority::HIGH) {
        result_->RecordResult(imageId, std::move(imageInfo), true);
        return;
    }

    jobPtr->Complete();
    DP_INFO_LOG("DPS_PHOTO: userId: %{public}d, imageId: %{public}s", userId, imageId.c_str());
    uint32_t cloudFlag = imageInfo->GetCloudFlag();
    switch (imageInfo->GetType()) {
        case CallbackType::IMAGE_PROCESS_DONE: {
            int32_t dataSize = imageInfo->GetDataSize();
            sptr<IPCFileDescriptor> ipcFd = imageInfo->GetIPCFileDescriptor();
            callback->OnProcessImageDone(imageId, ipcFd, dataSize, cloudFlag);
            break;
        }
        case CallbackType::IMAGE_PROCESS_YUV_DONE: {
            std::shared_ptr<PictureIntf> picture = imageInfo->GetPicture();
            callback->OnProcessImageDone(imageId, picture, cloudFlag);
            break;
        }
        default:
            DP_ERR_LOG("Unexpected callback type: %{public}d for imageId: %{public}s",
                static_cast<int>(imageInfo->GetType()), imageId.c_str());
            break;
    }
    EventsInfo::GetInstance().SetMediaLibraryState(MediaLibraryStatus::MEDIA_LIBRARY_BUSY);
}

void DeferredPhotoProcessor::HandleError(const int32_t userId, const std::string& imageId,
    DpsError error, bool isHighJob)
{
    StopTimer(imageId);
    ErrorType ret = result_->OnError(imageId, error, isHighJob);
    auto jobPtr = repository_->GetJobUnLocked(imageId);
    auto callback = GetCallback();
    if (jobPtr == nullptr || callback == nullptr) {
        auto errors = std::make_unique<ImageInfo>();
        errors->SetError(error);
        result_->RecordResult(imageId, std::move(errors), false);
        return;
    }

    bool needNotify = false;
    switch (ret) {
        case ErrorType::RETRY:
            jobPtr->Prepare();
            break;
        case ErrorType::NORMAL_FAILED:
            jobPtr->Fail();
            break;
        case ErrorType::FATAL_NOTIFY:
            jobPtr->Error();
            needNotify = true;
            break;
        case ErrorType::FAILED_NOTIFY:
        case ErrorType::HIGH_FAILED:
            jobPtr->Fail();
            needNotify = true;
            break;
    }
    DP_CHECK_RETURN(!needNotify);

    auto errorCode = MapDpsErrorCode(error);
    DP_INFO_LOG("DPS_OHOTO: userId: %{public}d, imageId: %{public}s, error: %{public}d",
        userId, imageId.c_str(), errorCode);
    callback->OnError(imageId, errorCode);
}

uint32_t DeferredPhotoProcessor::StartTimer(const std::string& imageId)
{
    auto thisPtr = weak_from_this();
    uint32_t timerId = DpsTimer::GetInstance().StartTimer([thisPtr, imageId]() {
        auto process = thisPtr.lock();
        DP_CHECK_EXECUTE(process != nullptr, process->ProcessPhotoTimeout(imageId));
    }, MAX_PROC_TIME_MS);
    DP_INFO_LOG("DPS_TIMER: Start imageId: %{public}s, timerId: %{public}u", imageId.c_str(), timerId);
    return timerId;
}

void DeferredPhotoProcessor::StopTimer(const std::string& imageId)
{
    uint32_t timerId = repository_->GetJobTimerId(imageId);
    DP_INFO_LOG("DPS_TIMER: Stop imageId: %{public}s, timeId: %{public}u", imageId.c_str(), timerId);
    DpsTimer::GetInstance().StopTimer(timerId);
}

void DeferredPhotoProcessor::ProcessPhotoTimeout(const std::string& imageId)
{
    HILOG_COMM_INFO("DPS_TIMER: Executed imageId: %{public}s", imageId.c_str());
    DP_CHECK_EXECUTE(result_->IsNeedReset(), postProcessor_->Reset());
    auto ret = DPS_SendCommand<PhotoProcessTimeOutCommand>(userId_, imageId, DPS_ERROR_IMAGE_PROC_TIMEOUT);
    DP_CHECK_ERROR_RETURN_LOG(ret != DP_OK,
        "process photo timeout imageId: %{public}s failed. ret: %{public}d", imageId.c_str(), ret);
}

sptr<IDeferredPhotoProcessingSessionCallback> DeferredPhotoProcessor::GetCallback()
{
    if (auto session = DPS_GetSessionManager()) {
        return session->GetCallback(userId_);
    }
    return nullptr;
}

bool DeferredPhotoProcessor::ProcessCatchResults(const std::string& imageId)
{
    auto result = result_->GetCacheResult(imageId);
    DP_CHECK_RETURN_RET(result == nullptr, false);
    auto callback = GetCallback();
    DP_CHECK_RETURN_RET(callback == nullptr, false);

    DP_INFO_LOG("DPS_PHOTO: ProcessCatchResults imageId: %{public}s", imageId.c_str());
    switch (result->GetType()) {
        case CallbackType::IMAGE_PROCESS_DONE:
            callback->OnProcessImageDone(imageId, result->GetIPCFileDescriptor(),
                result->GetDataSize(), result->GetCloudFlag());
            break;
        case CallbackType::IMAGE_PROCESS_YUV_DONE:
            callback->OnProcessImageDone(imageId, result->GetPicture(), result->GetCloudFlag());
            break;
        case CallbackType::IMAGE_ERROR:
            callback->OnError(imageId, MapDpsErrorCode(result->GetErrorCode()));
            break;
        default:
            break;
    }
    result_->DeRecordResult(imageId);
    return true;
}
} // namespace DeferredProcessing
} // namespace CameraStandard
} // namespace OHOS